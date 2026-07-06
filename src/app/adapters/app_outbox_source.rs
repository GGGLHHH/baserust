//! `infra::outbox::OutboxSource` 的 app 侧适配器:把 app 自己的 `PgAppOutbox`/`InMemoryAppOutbox`
//! (`AppOutboxRecord`)接成 relay 认的窄端口。`impl` 特意放在适配器层而非 `features::profile`,
//! 让 profile 模块保持对 relay/NATS 一无所知(镜像 `idm_outbox_source.rs` 的风格)。
//!
//! 注:`PgAppOutbox`/`InMemoryAppOutbox` 自身已有同名的 inherent `poll_unpublished`/
//! `mark_published`(返回 `AppOutboxRecord`)。Rust 方法解析对同名方法**优先选 inherent**,
//! 故本文件里 `self.poll_unpublished(..)` 调的是那两个 inherent 方法而非递归自己 —— 消费方要走
//! `OutboxSource` 版本,需经 trait object(`Arc<dyn OutboxSource>`)或显式 `OutboxSource::` 调用。

use async_trait::async_trait;

use crate::features::profile::{AppOutboxRecord, InMemoryAppOutbox, PgAppOutbox};
use crate::infra::error::AppError;
use crate::infra::outbox::{build_outbox_item, OutboxItem, OutboxSource};

fn to_item(rec: AppOutboxRecord) -> OutboxItem {
    build_outbox_item(
        "app",
        rec.id,
        &rec.event_type,
        rec.aggregate_id,
        &rec.payload,
    )
}

#[async_trait]
impl OutboxSource for PgAppOutbox {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxItem>, AppError> {
        Ok(self
            .poll_unpublished(limit)
            .await?
            .into_iter()
            .map(to_item)
            .collect())
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        self.mark_published(ids).await
    }
}

#[async_trait]
impl OutboxSource for InMemoryAppOutbox {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxItem>, AppError> {
        Ok(self
            .poll_unpublished(limit)
            .await?
            .into_iter()
            .map(to_item)
            .collect())
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        self.mark_published(ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::profile::{InMemoryProfileRepo, ProfileFields, ProfileRepo};
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn maps_profile_updated_record_and_delegates_mark_published() {
        let profiles = InMemoryProfileRepo::new();
        let outbox = InMemoryAppOutbox::sharing_with(&profiles);
        let user_id = Uuid::now_v7();
        profiles
            .upsert(
                user_id,
                ProfileFields {
                    display_name: Some("Alice".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        // 走 trait object,避免 inherent 方法同名遮蔽。
        let source: Arc<dyn OutboxSource> = Arc::new(outbox);

        let items = source.poll_unpublished(10).await.unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.subject, "events.app.profile.updated");
        assert_eq!(item.event_id, format!("app-{}", item.id));

        let envelope: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(envelope["schema"], "app");
        assert_eq!(envelope["type"], "profile.updated");
        assert_eq!(envelope["aggregate_id"], user_id.to_string());

        // poll → mark → poll 空:适配器纯转调、不吞不重放。
        source.mark_published(&[item.id]).await.unwrap();
        assert!(source.poll_unpublished(10).await.unwrap().is_empty());
    }
}

//! `infra::outbox::OutboxSource` 的 idm 侧适配器:把 idm 的 `Arc<dyn idm::OutboxRepo>`
//! (`OutboxRecord`)翻译成 relay 认的窄端口(`OutboxItem`)。薄翻译(map + 转调,无业务判断),
//! 镜像 `idm_user_directory.rs` 的风格。

use std::sync::Arc;

use async_trait::async_trait;
use idm::OutboxRepo;

use crate::infra::error::AppError;
use crate::infra::outbox::{build_outbox_item, OutboxItem, OutboxSource};

pub struct IdmOutboxSource {
    repo: Arc<dyn OutboxRepo>,
}

impl IdmOutboxSource {
    pub fn new(repo: Arc<dyn OutboxRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl OutboxSource for IdmOutboxSource {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxItem>, AppError> {
        let records = self.repo.poll_unpublished(limit).await?;
        Ok(records
            .into_iter()
            .map(|r| build_outbox_item("idm", r.id, &r.event_type, r.aggregate_id, &r.payload))
            .collect())
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        self.repo.mark_published(ids).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idm::{IdmError, OutboxRecord};
    use serde_json::json;
    use std::sync::Mutex;
    use time::OffsetDateTime;
    use uuid::Uuid;

    /// 测试专用假 idm 发件箱仓储:直接构造 `OutboxRecord`,不依赖 idm 内部 emit 时机拼的 json 形状。
    struct FakeIdmOutboxRepo {
        rows: Vec<OutboxRecord>,
        published: Mutex<Vec<i64>>,
    }

    #[async_trait]
    impl OutboxRepo for FakeIdmOutboxRepo {
        async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
            let published = self.published.lock().expect("锁未中毒");
            Ok(self
                .rows
                .iter()
                .filter(|r| !published.contains(&r.id))
                .take(limit.max(0) as usize)
                .cloned()
                .collect())
        }

        async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
            self.published
                .lock()
                .expect("锁未中毒")
                .extend_from_slice(ids);
            Ok(())
        }
    }

    #[tokio::test]
    async fn maps_user_created_record_and_delegates_mark_published() {
        let aggregate_id = Uuid::now_v7();
        let payload = json!({"username": "alice"});
        let record = OutboxRecord {
            id: 42,
            event_type: "user.created".to_owned(),
            aggregate_id,
            payload: payload.clone(),
            created_at: OffsetDateTime::now_utc(),
        };
        let repo = Arc::new(FakeIdmOutboxRepo {
            rows: vec![record],
            published: Mutex::new(Vec::new()),
        });
        let source = IdmOutboxSource::new(repo);

        let items = source.poll_unpublished(10).await.unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.id, 42);
        assert_eq!(item.subject, "events.idm.user.created");
        assert_eq!(item.event_id, "idm-42");

        let envelope: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(envelope["schema"], "idm");
        assert_eq!(envelope["type"], "user.created");
        assert_eq!(envelope["seq"], 42);
        assert_eq!(envelope["aggregate_id"], aggregate_id.to_string());
        assert_eq!(envelope["data"], payload);

        // poll → mark → poll 空:适配器纯转调、不吞不重放。
        source.mark_published(&[item.id]).await.unwrap();
        assert!(source.poll_unpublished(10).await.unwrap().is_empty());
    }
}

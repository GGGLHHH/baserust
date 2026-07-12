//! `users::ProfileDirectory` 的**进程内适配器**:复用 app 的 `ProfileRepo` 批量读 + 映射成 `ProfileBrief`。
//! 薄翻译(map + 转调,无业务判断)。单体 `Both` 用它;分进程 idm(无 app pool)→ `StaticProfileDirectory::empty()`。
//! avatar_url 复用 profile 现成口径:`avatar_content_id` → 相对 preview 路径;无绑定 → None。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::ProfileRepo;
use crate::features::users::{ProfileBrief, ProfileDirectory};
use crate::infra::error::AppError;

pub struct InProcessProfileDirectory {
    repo: Arc<dyn ProfileRepo>,
}

impl InProcessProfileDirectory {
    pub fn new(repo: Arc<dyn ProfileRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl ProfileDirectory for InProcessProfileDirectory {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, ProfileBrief>, AppError> {
        // 一次 find_by_ids(WHERE user_id = ANY ...)→ 映射成瘦 brief。两条独立 SQL,绝不跨 schema join。
        let profiles = self.repo.find_by_ids(user_ids).await?;
        Ok(profiles
            .into_iter()
            .map(|p| {
                // 头像端点相对路径(按 user_id;单域名哲学);无绑定 → None。悬空(content 已删)不在此校验 —— 列表富化不探测。
                let avatar_url = p
                    .avatar_content_id
                    .map(|_cid| format!("/api/v1/frontend/profiles/{}/avatar", p.user_id));
                (
                    p.user_id,
                    ProfileBrief {
                        display_name: p.display_name,
                        avatar_url,
                    },
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::profile::{InMemoryProfileRepo, ProfileFields};

    #[tokio::test]
    async fn batch_maps_profiles_and_omits_missing() {
        let repo = Arc::new(InMemoryProfileRepo::new());
        let with_avatar = Uuid::now_v7();
        let no_avatar = Uuid::now_v7();
        let cid = Uuid::now_v7();
        repo.upsert(
            with_avatar,
            ProfileFields {
                display_name: Some("Alice".into()),
                phone: None,
                avatar_content_id: Some(cid),
            },
            None,
        )
        .await
        .unwrap();
        repo.upsert(no_avatar, ProfileFields::default(), None)
            .await
            .unwrap();

        let dir = InProcessProfileDirectory::new(repo);
        let missing = Uuid::now_v7();
        let got = dir.batch(&[with_avatar, no_avatar, missing]).await.unwrap();

        assert_eq!(
            got.get(&with_avatar).unwrap().display_name.as_deref(),
            Some("Alice")
        );
        assert_eq!(
            got.get(&with_avatar).unwrap().avatar_url.as_deref(),
            Some(format!("/api/v1/frontend/profiles/{with_avatar}/avatar").as_str())
        );
        let brief = got.get(&no_avatar).unwrap();
        assert!(brief.display_name.is_none());
        assert!(brief.avatar_url.is_none());
        // 查不到的 id 不进 map(调用方降级 null)
        assert!(!got.contains_key(&missing));
    }
}

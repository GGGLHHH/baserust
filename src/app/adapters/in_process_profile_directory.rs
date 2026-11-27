//! `users::ProfileDirectory` / `tenants::MemberProfiles` 的**进程内适配器**:复用 app 的 `ProfileRepo` 批量读 +
//! 映射成各自的瘦快照(两个消费方各定义自己的端口,同一份资料源)。
//! 薄翻译(map + 转调,无业务判断)。单体 `Both` 用它;分进程 idm(无 app pool)→ `StaticProfileDirectory::new()`。
//! avatar_url 复用 profile 现成口径:`avatar_content_id` → 相对 preview 路径;无绑定 → None。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::ProfileRepo;
use crate::features::tenants::{MemberProfile, MemberProfiles};
use crate::features::users::{ProfileBrief, ProfileDirectory};
use crate::kernel::app_error::AppError;

/// 账号列表 / 成员列表富化用的资料目录:同进程直接读 app 的 `ProfileRepo`。
pub struct InProcessProfileDirectory {
    repo: Arc<dyn ProfileRepo>,
}

impl InProcessProfileDirectory {
    #[must_use]
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
            .map(|profile| {
                // 头像端点相对路径(按 user_id;单域名哲学);无绑定 → None。悬空(content 已删)不在此校验 —— 列表富化不探测。
                let avatar_url = profile.avatar_content_id.map(|_content_id| {
                    format!("/api/v1/frontend/profiles/{}/avatar", profile.user_id)
                });
                (
                    profile.user_id,
                    ProfileBrief {
                        display_name: profile.display_name,
                        avatar_url,
                    },
                )
            })
            .collect())
    }
}

#[async_trait]
impl MemberProfiles for InProcessProfileDirectory {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, MemberProfile>, AppError> {
        // 同一份映射口径(display_name + 相对头像路径),换成 tenants 的瘦类型。
        Ok(ProfileDirectory::batch(self, user_ids)
            .await?
            .into_iter()
            .map(|(id, brief)| {
                (
                    id,
                    MemberProfile {
                        display_name: brief.display_name,
                        avatar_url: brief.avatar_url,
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
        let content_id = Uuid::now_v7();
        repo.upsert(
            with_avatar,
            ProfileFields {
                display_name: Some("Alice".into()),
                phone: None,
                avatar_content_id: Some(content_id),
            },
            None,
        )
        .await
        .unwrap();
        repo.upsert(no_avatar, ProfileFields::default(), None)
            .await
            .unwrap();

        let directory = InProcessProfileDirectory::new(repo);
        let missing = Uuid::now_v7();
        let got = ProfileDirectory::batch(&directory, &[with_avatar, no_avatar, missing])
            .await
            .unwrap();

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

        // tenants 的端口:同一份口径
        let members = MemberProfiles::batch(&directory, &[with_avatar, missing])
            .await
            .unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[&with_avatar].avatar_url.as_deref(),
            Some(format!("/api/v1/frontend/profiles/{with_avatar}/avatar").as_str())
        );
    }
}

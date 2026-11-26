//! tenants 端口的**内存适配器**:资料富化的静态替身(单测 / 无富化源时的降级占位)。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use super::ports::{MemberProfile, MemberProfiles};
use crate::kernel::error::AppError;

/// 静态实现:预置 map 回答。
pub struct StaticMemberProfiles(pub HashMap<Uuid, MemberProfile>);

impl StaticMemberProfiles {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl MemberProfiles for StaticMemberProfiles {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, MemberProfile>, AppError> {
        Ok(user_ids
            .iter()
            .filter_map(|id| self.0.get(id).map(|p| (*id, p.clone())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_seeded_and_skips_missing() {
        let id = Uuid::now_v7();
        let d = StaticMemberProfiles(HashMap::from([(
            id,
            MemberProfile {
                display_name: Some("A".into()),
                avatar_url: None,
            },
        )]));
        let got = d.batch(&[id, Uuid::now_v7()]).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[&id].display_name.as_deref(), Some("A"));
        assert!(StaticMemberProfiles::empty()
            .batch(&[id])
            .await
            .unwrap()
            .is_empty());
    }
}

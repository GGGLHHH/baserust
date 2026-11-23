//! users 端口的**内存适配器**:富化目录的静态替身(单测 / 无富化源时的降级占位)。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::users::ports::{ProfileBrief, ProfileDirectory};
use crate::kernel::error::AppError;

/// 静态实现:预置 map 回答 —— 单测 / 无富化源(分进程降级)占位用。
pub struct StaticProfileDirectory(pub HashMap<Uuid, ProfileBrief>);

impl StaticProfileDirectory {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl ProfileDirectory for StaticProfileDirectory {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, ProfileBrief>, AppError> {
        Ok(user_ids
            .iter()
            .filter_map(|id| self.0.get(id).map(|b| (*id, b.clone())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_directory_returns_seeded_and_empty_degrades() {
        let id = Uuid::now_v7();
        let mut m = HashMap::new();
        m.insert(
            id,
            ProfileBrief {
                display_name: Some("Alice".into()),
                avatar_url: None,
            },
        );
        let d = StaticProfileDirectory(m);
        let got = d.batch(&[id]).await.unwrap();
        assert_eq!(got.get(&id).unwrap().display_name.as_deref(), Some("Alice"));
        // 不在预置集里的 id 不进 map;empty() 全降级
        assert!(d.batch(&[Uuid::now_v7()]).await.unwrap().is_empty());
        assert!(StaticProfileDirectory::empty()
            .batch(&[id])
            .await
            .unwrap()
            .is_empty());
    }
}

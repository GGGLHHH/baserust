//! users 的**跨模块富化端口**:按 user_id 批量取 profile 瘦快照(display_name/avatar_url)。
//! 端口归消费方(users 不 import profile);适配在组合根 `app/adapters/`。
//! 镜像 `profile::AvatarProbe`/`StaticAvatarProbe` 与 `widget::UserDirectory` 的结构。

use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infra::error::AppError;
use crate::infra::pagination::PageParams;
use crate::infra::sort::SortOrder;

/// profile 瘦快照 —— 只含 users 列表要展示的两个富化字段(窄接口)。
#[derive(Clone, Debug, Default)]
pub struct ProfileBrief {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// 富化端口。查不到的 id **不在** map(调用方降级 null)。批量防 N+1。
#[async_trait]
pub trait ProfileDirectory: Send + Sync {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, ProfileBrief>, AppError>;
}

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

/// users 的**只读检索端口**:列表/搜索走 search 模块的 CQRS 投影,但 users 不 import search
/// 的具体类型(`IndexQuery`/`AdminUserIndexRow` 等)——只认这套窄类型。适配在 `app/adapters/`。
#[derive(Debug, Clone, Default)]
pub struct UserSearchFilter {
    pub username: Option<String>,
    pub q: Option<String>,
    pub roles_any: Vec<String>,
    pub roles_none: Vec<String>,
    pub created_from: Option<OffsetDateTime>,
    pub created_to: Option<OffsetDateTime>,
}

/// 排序键白名单(防注入)。一一对应 search 投影的 `IndexSort`,但类型不共享。
#[derive(Debug, Clone, Copy)]
pub enum UserSearchSort {
    CreatedAt,
    Username,
    DisplayName,
    Email,
}

/// 列表一行。**不含 avatar_url**——投影不存 avatar,service 用 [`ProfileDirectory`] 另行补齐。
/// `display_name` 取自投影(可搜键),`username`/`created_at` 恒有值(适配器映射时已保证)。
#[derive(Debug, Clone)]
pub struct UserSearchRow {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: OffsetDateTime,
    pub roles: Vec<String>,
    pub display_name: Option<String>,
}

/// `UserSearchIndex::query` 结果。`total`/`next_after` 语义同分页范式(互斥,见 `infra::pagination`)。
#[derive(Debug)]
pub struct UserSearchPage {
    pub rows: Vec<UserSearchRow>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

#[async_trait]
pub trait UserSearchIndex: Send + Sync {
    async fn query(
        &self,
        filter: &UserSearchFilter,
        sort: UserSearchSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<UserSearchPage, AppError>;
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

//! users 的**端口**(核心对外要用的能力,端口归消费方;实现在组合根 `app/adapters/`):
//! - [`ProfileDirectory`] 跨模块富化:按 user_id 批量取 profile 瘦快照(users 不 import profile)
//! - [`UserSearchIndex`] 只读检索:列表/搜索走 search 模块的 CQRS 投影(users 不 import search)
//!
//! 身份写侧的端口是 idm 领域库自己的 trait(`idm::UserRepo` / `RoleRepo` / `SessionRepo` / `PwHasher`)。
//! 测试替身 `StaticProfileDirectory` 在 `adapters::memory`。

use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::kernel::error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort::SortOrder;

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

/// `UserSearchIndex::query` 结果。`total`/`next_after` 语义同分页范式(互斥,见 `kernel::pagination`)。
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

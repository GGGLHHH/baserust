//! tenants 的**端口**(端口归消费方;实现在组合根 `app/adapters/`):
//! - [`MemberSearchIndex`] 只读检索:成员列表走 search 模块的**租户成员索引**投影(tenants 不 import search)
//! - [`MemberProfiles`] 跨模块富化:按 user_id 批量取资料瘦快照(tenants 不 import profile)
//!
//! 租户 / 成员 / 会话 / 账号的写侧端口是 idm 领域库自己的 trait(`idm::TenantRepo` / `MemberRepo` /
//! `SessionRepo` / `UserRepo` / `RoleRepo`)。测试替身 `StaticMemberProfiles` 在 `memory`。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::kernel::error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::tenant::TenantId;

/// 资料瘦快照(成员列表要展示的两个富化字段)。
#[derive(Clone, Debug, Default)]
pub struct MemberProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// 资料富化端口。查不到的 id **不在** map(调用方降级 null)。批量防 N+1。
#[async_trait]
pub trait MemberProfiles: Send + Sync {
    async fn batch(&self, user_ids: &[Uuid]) -> Result<HashMap<Uuid, MemberProfile>, AppError>;
}

/// 成员索引的一行(只含成员列表要的列)。`roles` = 该租户里的租户角色名;`status` = 成员状态的线上串。
#[derive(Debug, Clone)]
pub struct MemberSearchRow {
    pub user_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub status: Option<String>,
}

/// `MemberSearchIndex::query` 结果。`total` / `next_after` 语义同分页范式(互斥,见 `kernel::pagination`)。
#[derive(Debug)]
pub struct MemberSearchPage {
    pub rows: Vec<MemberSearchRow>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

/// 成员列表的**只读检索端口**:读 search 的租户成员索引(按租户 RLS;已移出 / 已删账号不出现),
/// 默认按账号创建时间倒序。实现在请求路径上走运行时池 + 租户事务。
#[async_trait]
pub trait MemberSearchIndex: Send + Sync {
    async fn query(
        &self,
        tenant: TenantId,
        q: Option<&str>,
        page: &PageParams,
    ) -> Result<MemberSearchPage, AppError>;
}

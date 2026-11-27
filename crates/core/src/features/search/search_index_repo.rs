//! search 的**端口**:读模型仓储(实现:`in_memory_search_index_repo` / `adapters::pg_search_index_repo`)。
//!
//! 守卫 upsert 是全模块的重点:idm 账号、profile、idm 成员是三个独立来源,各自的领域事件到达顺序不保证
//! (乱序 / 重放),**每个来源只准写自己的列** + 各自的水位(`idm_seq` / `profile_seq` / `member_seq`),
//! 事件 `sequence` 不大于当前水位就跳过 —— 这样重放 / 乱序投影天然幂等,不会用旧事件覆盖新状态。
//!
//! **写方法跨租户**(`user.*` / `profile.updated` 要改该用户在所有租户里的行):PG 实现必须用 search 的
//! **system 池**(BYPASSRLS)装配写侧(投影器、rebuild);读方法 `query` / `get_member` 每次在租户事务里
//! (`set_config('app.tenant_id', …, true)`)执行,请求路径用运行时池。

use async_trait::async_trait;
use uuid::Uuid;

use super::model::{
    AccountCreated, AccountIndexRow, AccountUpdated, AdminUserIndexRow, IndexQuery,
    IndexQueryResult, IndexSort,
};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort_order::SortOrder;
use crate::kernel::tenant_id::TenantId;

/// 仓储端口。所有 `apply_*` 方法都是**守卫 upsert**:仅当 `sequence` 严格大于该行当前的对应水位
/// (未见过的行水位视作最小值,即"必应用")才写入;否则该行 no-op。
#[async_trait]
pub trait SearchIndexRepo: Send + Sync {
    /// idm `user.created`:账号目录写 username/email/email_verified/roles(平台角色)/created_at +
    /// `deleted=false` + `idm_seq`;该用户已有的成员行同步账号列(不含 roles)。守卫:`sequence > idm_seq`。
    async fn apply_user_created(
        &self,
        account: AccountCreated<'_>,
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `user.updated`:只写 username/email/email_verified + `idm_seq`(账号目录 + 该用户所有成员行)。
    async fn apply_user_updated(
        &self,
        account: AccountUpdated<'_>,
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `user.roles_set`(**平台角色**):只写账号目录的 roles + `idm_seq`。成员行的 roles 是租户角色,不动。
    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `user.deleted`:`deleted=true` + `idm_seq`(账号目录 + 该用户所有成员行)。
    async fn apply_user_deleted(&self, user_id: Uuid, sequence: i64) -> Result<(), AppError>;

    /// profile `profile.updated`:只写 display_name + `profile_seq`(账号目录 + 该用户**所有租户**的成员行;
    /// 资料全局一份,spec §6.3)。
    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `tenant.member_added`:成员行写 status/roles(租户角色)+ `removed=false` + `member_seq`。
    /// 新行的账号列从账号目录抄(还没有账号行 → 留空,等 `user.*` 补)。
    async fn apply_member_added(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `tenant.member_updated`:只写 status + `member_seq`。
    async fn apply_member_updated(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `tenant.member_roles_set`:只写 roles(租户角色)+ `member_seq`。
    async fn apply_member_roles_set(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `tenant.member_removed`:`removed=true` + `member_seq`(墓碑;查询不再返回)。
    async fn apply_member_removed(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        sequence: i64,
    ) -> Result<(), AppError>;

    /// idm `tenant.deleted`:该租户全部成员行 `removed=true`(水位落后于 `sequence` 的行)。
    async fn apply_tenant_deleted(&self, tenant: TenantId, sequence: i64) -> Result<(), AppError>;

    /// 重建 bin 用:**无守卫**全量覆写账号目录一行。
    async fn rebuild_account(&self, row: AccountIndexRow) -> Result<(), AppError>;

    /// 重建 bin 用:**无守卫**全量覆写一条成员行。
    async fn rebuild_member(&self, row: AdminUserIndexRow) -> Result<(), AppError>;

    /// 测试 / 运维用:按 user_id 读账号目录一行;不存在 → `None`。
    async fn get_account(&self, user_id: Uuid) -> Result<Option<AccountIndexRow>, AppError>;

    /// 按 (租户, user_id) 读成员行(**含**已移出 / 已删的行);不存在 → `None`。
    async fn get_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
    ) -> Result<Option<AdminUserIndexRow>, AppError>;

    /// CQRS 读路径:**某租户**的成员列表,动态 filter + 排序 + 分页。基线过滤
    /// (`username IS NOT NULL AND !deleted AND !removed`)恒生效 —— 半行(账号列未落地)、已删账号、
    /// 已移出的成员永不出现在结果里。cursor 分页是 `user_id` 上的 keyset,方向跟随 `order`(不跟随
    /// `sort`)——因此只在默认 `created_at` 排序时才与 `order` 语义一致(handler 层对非默认 `sort_by` +
    /// cursor 组合 422)。
    async fn query(
        &self,
        tenant: TenantId,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError>;

    /// **平台账号列表**(账号目录 `account_index`,全局,不分租户):过滤 / 排序 / 分页口径同 [`Self::query`],
    /// roles 是平台角色。基线 `username IS NOT NULL AND !deleted`。表不开 RLS,运行时池可读。
    async fn query_accounts(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult<AccountIndexRow>, AppError>;
}

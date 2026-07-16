//! 租户仓储:契约 + 两实现装配点。
//! **与 widget 的刻意差异**:本模块查询全为固定语句 → 直接 const SQL(sqlx 静态串),
//! 不引 sea-query/Iden/COLS —— 那套是给动态查询(可选 filter/分页)的,这里没有。
//! (与 profile/repo/mod.rs 同口径。)

mod memory;
mod postgres;

use async_trait::async_trait;
use uuid::Uuid;

use super::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

pub use memory::InMemoryTenantRepo;
pub use postgres::PgTenantRepo;

/// 仓储端口。
///
/// **消费方只有三个**,别加第四个的方法(YAGNI):
/// 1. `TenantRoleRepo`(P2,组合根) —— 铸币时读 `memberships` / `active`
/// 2. 切换端点(P2)—— `membership` 校验 + `set_active`
/// 3. `seed::apply`(P2)—— `upsert_tenant` / `upsert_member`
///
/// # 两侧行为的**已知分歧**(不属于端口契约)
///
/// 下面这些约束**只在 PG 侧强制**,内存实现一概不检查 —— 它们是 DB 约束,
/// 不是端口语义。调用方**不得**依赖任一侧的行为,必须自己保证前置条件:
///
/// - **引用完整性**:`tenant_members.{user_id,tenant_id}` 与
///   `user_active_tenant.{user_id,tenant_id}` 都有真 FK(见
///   `migrations/idm/0004_add_tenants.up.sql`)。给 `set_active` / `upsert_member`
///   传一个不存在的 user 或 tenant:**PG → FK 违约 → `Internal`(500);内存 → 静默成功**。
/// - **`tenants.name` 唯一性**:仅对存活行(partial unique index)。同名建两个租户:
///   **PG → 唯一违约 → `Internal`;内存 → 静默接受**。
///
/// 后果:只跑内存模式(CI 默认)的代码看不见这两类错误。碰这些方法的新代码,
/// PG conformance(`just test-pg`)是唯一能暴露它的地方。
#[async_trait]
pub trait TenantRepo: Send + Sync {
    /// 该用户的全部**有效**成员资格。
    ///
    /// **契约(不可协商)**:恒 join tenants 并过滤 `deleted_at is null and status = 'active'`。
    /// 这样"停用租户"复用「成员被踢,下次 refresh 自动掉出」的同一机制 ——
    /// ≤ IDM_ACCESS_TTL_SECS 内自动失效,无需撤销名单。见 spec §4.4。
    /// 这是 `base_select()` 的同位物:过滤写在契约里,不留给调用方记。
    ///
    /// 顺序:按 `granted_at` 升序(最早加入的在前)—— `TenantRoleRepo` 的
    /// `.or(ms.first())` 回退依赖这个顺序,不是随意的。
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError>;

    /// 单条成员资格校验(切换端点的安全支点)。**同样过滤停用/软删租户。**
    /// 非成员 → `Ok(None)`(路由译 404,不是 403 —— 不泄露该租户存在)。
    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError>;

    /// 当前激活租户 id。未设 → `None`。
    /// **不校验它是否仍是有效成员** —— 那是调用方的事(`TenantRoleRepo` 用
    /// `active.and_then(|t| ms.iter().find(..)).or(ms.first())` 做回退)。
    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError>;

    /// 设置激活租户(upsert)。**不校验成员资格** —— 调用方必须先 `membership()` 校验。
    /// 租户/用户是否存在同样不校验(PG 侧靠 FK 兜、内存侧不兜,见 trait 头的「已知分歧」)。
    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError>;

    /// 建/替租户(seed 用)。按 `id` upsert。
    ///
    /// **不复活软删行**:已被软删的租户(`deleted_at` 非空)保持软删,`upsert_tenant`
    /// 不会把它悄悄改回 null —— 软删是 spec §4.4 当作安全控制的机制(停用租户必须真的
    /// 切断访问),而 `seed::apply`(P2)每次启动都会重跑,不能让一次重启就无声撤销
    /// 运维手工做的停用决定。要恢复必须走显式操作(P1 无此方法,YAGNI)。
    ///
    /// `name` 唯一性只在 PG 侧强制 —— 见 trait 头的「已知分歧」。
    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError>;

    /// 建/替成员资格(seed 用)。按 `(user_id, tenant_id)` upsert。
    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError>;
}

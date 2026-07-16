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
/// 1. `TenantRoleRepo`(P2,组合根) —— 铸币时读 `memberships`(含 is_active)
/// 2. 切换端点(P2)—— `membership` 校验 + `set_active`
/// 3. `seed::apply`(P2)—— `upsert_tenant` / `upsert_member`
///
/// # `by` 的语义
///
/// `by` = 审计主体(来自 `AuditContext`,见 `infra::audit::Actor::audit_id`)。
/// **`None` 会把对应的审计列写成 NULL,不是「保持不变」** —— 与 `profile/repo/postgres.rs`
/// 的 `UPSERT_SQL` 同口径(那里也是 `updated_by = excluded.updated_by`,无 coalesce)。
/// 这是有意的:`None` 表示「这次写入没有可归属的主体」,NULL 如实记录「不知道是谁」;
/// coalesce 会**说谎** —— 宣称上一个人做了这次他没做的更新。
/// ⇒ 调用方要保留归属就必须传 `Some(..)`。P2 的 `seed::apply` 每次启动都重跑 upsert,
///   若传 None 会把人工运维留下的归属抹成 NULL —— 那是 seed 该传 `Some("system")`,
///   不是本端口该 coalesce。
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
/// - **文本列的存储约束**:PG 的 text 列不接受 NUL 字节(`U+0000`),而 Rust `String` 合法
///   容纳它;`tenants.name` 还受 btree 索引行上限约束(高熵内容约 2.6KB 即
///   `index row size ... exceeds btree maximum 2704`,可压缩内容因 TOAST 不触发)。
///   两者都是 **PG → `Internal`;内存 → 静默接受**。
/// - **`updated_by`**:PG 落库,内存**不存**(它不参与任何保留语义、端口也不暴露,
///   存了就是死字段)。`created_by` / `granted_by` 的**保留语义**两侧一致且有测试钉住。
///   P2 若给 `Membership` 加审计字段,内存会因缺字段编译不过 —— 类型系统会逼它补齐。
///
/// 后果:只跑内存模式(CI 默认)的代码看不见这几类错误。碰这些方法的新代码,
/// PG conformance(`just test-pg`)是唯一能暴露它的地方。
#[async_trait]
pub trait TenantRepo: Send + Sync {
    /// 该用户的全部**有效**成员资格,含「哪条是当前激活的」(`Membership::is_active`)。
    ///
    /// **契约(不可协商)**:恒 join tenants 并过滤 `deleted_at is null and status = 'active'`。
    /// 这样"停用租户"复用「成员被踢,下次 refresh 自动掉出」的同一机制 ——
    /// ≤ IDM_ACCESS_TTL_SECS 内自动失效,无需撤销名单。见 spec §4.4。
    /// 这是 `base_select()` 的同位物:过滤写在契约里,不留给调用方记。
    ///
    /// 顺序:按 `seq` 升序(最早加入的在前)—— `TenantRoleRepo` 的 `.or(ms.first())`
    /// 回退依赖这个顺序,它决定用户默认落进哪家公司,不是随意的。
    /// `seq` 是 `Uuid::now_v7()` 而非时间戳,理由见 migration 的注释。
    ///
    /// **`active` 刻意不是独立方法**:两个已知消费方(§4.1 铸币、§4.9 租户列表)都同时要
    /// 「成员资格 + 谁激活」,从没有单独查 active 的场景。拆开只会让每次铸币多一次往返,
    /// 且两次读非同一快照(并发 set_active 时可能读到不一致的组合)。
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError>;

    /// 单条成员资格校验(切换端点的安全支点)。**同样过滤停用/软删租户。**
    /// 非成员 → `Ok(None)`(路由译 404,不是 403 —— 不泄露该租户存在)。
    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError>;

    /// 设置激活租户(upsert)。**不校验成员资格** —— 调用方必须先 `membership()` 校验。
    /// 租户/用户是否存在同样不校验(PG 侧靠 FK 兜、内存侧不兜,见 trait 头的「已知分歧」)。
    ///
    /// 值未变时**不写**(PG 侧 `where ... is distinct from ...` 守卫)⇒ `updated_at` 的语义是
    /// 「最近一次真正切换」,不会被「每次请求都无脑调一遍兜底」的调用模式污染成「最近一次请求」。
    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError>;

    /// 建/替租户(seed 用)。按 `id` upsert。
    ///
    /// **不复活软删行**:已被软删的租户(`deleted_at` 非空)保持软删,`upsert_tenant`
    /// 不会把它悄悄改回 null —— 软删是 spec §4.4 当作安全控制的机制(停用租户必须真的
    /// 切断访问),而 `seed::apply`(P2)每次启动都会重跑,不能让一次重启就无声撤销
    /// 运维手工做的停用决定。要恢复必须走显式操作(P1 无此方法,YAGNI)。
    ///
    /// **`created_by` 建时落、替时保留**;`updated_by` 每次替换都按 `by` 覆盖(含 None → NULL,
    /// 见 trait 头的「`by` 的语义」)。`name` 唯一性只在 PG 侧强制 —— 见「已知分歧」。
    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError>;

    /// 建/替成员资格(seed 用)。按 `(user_id, tenant_id)` upsert。
    ///
    /// **替换只改 `role`**。`seq` / `granted_at` / `granted_by` 三者都**冻结不动** ——
    /// 它们共同描述「这个人何时、被谁加进来」这一次事件,改个角色并不让它重新发生。
    /// (曾经只冻 seq/granted_at 而让 granted_by 随写覆盖,结果是 `granted_by=bob,
    ///  granted_at=T1` 这种从未发生过的审计记录:bob 在 T1 可能还不是本租户成员。)
    /// ⇒ P1 不记录「谁改了角色」。真要时加一列 `role_updated_by`,别让两列语义脱钩。
    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError>;
}

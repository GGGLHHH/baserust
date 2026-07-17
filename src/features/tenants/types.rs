//! 租户类型。**闭集枚举而非裸 String** —— 照 closed-enums skill:
//! 有限已知取值必须是枚举,否则前端生成的 union 会漂移成 string。
//!
//! 枚举↔DB 裸值的互转靠 `#[derive(sqlx::Type)]` + 每变体 `#[sqlx(rename)]`(照
//! `auth_audit/types.rs` 的既有范式)—— sqlx 直接 Encode/Decode,`.bind(role)` 即可,
//! 不用手写 as_db/parse_db,坏值自动经 sqlx 的 decode 错误 fail-closed。

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 租户状态。DB 侧有 `tenants_status_ck` check 约束双保险。
///
/// P6 的租户管理端点(`GET /admin/auth/tenants` 列表、`PUT` 改状态)要序列化/接收它,
/// 故挣回了 `Serialize`/`ToSchema`(闭集枚举 → 前端生成 union,不漂成 string)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text")]
pub enum TenantStatus {
    #[sqlx(rename = "active")]
    Active,
    #[sqlx(rename = "suspended")]
    Suspended,
}

/// **租户级**角色:某人在**某一家**公司里是 admin 还是 member。
///
/// 与平台级的 [`RoleName`](crate::infra::authz::RoleName) 是两个类型,**这是刻意的** ——
/// 平台角色骑在租户边界之上、由 `Policy` 映射成平台范围的 `Perm`;租户角色关在租户边界
/// 之内、存 `tenant_members.role`。把它做成 `RoleName` 的变体试过一次:`Policy` 没有租户
/// 维度,于是 `tn:admin` 被映射成**平台范围**的 `:all` 权限,一家 5 人公司的管理员就成了
/// 全平台的事实管理员。两个类型让那件事编译不过。
///
/// serde/sqlx 的串都是 DB 裸值(`admin`/`member`),与 `tenant_members_role_ck` 一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text")]
pub enum TenantRole {
    #[sqlx(rename = "admin")]
    Admin,
    #[sqlx(rename = "member")]
    Member,
}

/// 一条**有效**成员资格(已过滤停用/软删租户,见 `TenantRepo::memberships` 契约)。
///
/// `is_active` = 「这条是不是该用户当前激活的租户」。它由 `memberships`/`membership`
/// 一次 LEFT JOIN `user_active_tenant` 算出,**不是**单独查一次拼出来的 —— 那样两次读
/// 非同一快照,并发 set_active 时铸币路径可能读到不一致的组合。
///
/// 「active 未设」与「active 指向一个已失效(停用/软删/已退出)的租户」两种情况**刻意坍缩**成
/// 同一个结果:没有任何一条 `is_active = true`。spec §4.1 的回退逻辑对两者的处理本就相同
/// (都退到 `.first()`),不需要区分。
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Membership {
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub role: TenantRole,
    pub is_active: bool,
}

/// 一整个租户(P6 的平台管理端点 `GET/POST/PUT /admin/auth/tenants` 用)。
///
/// **不含 `deleted_at`**:DTO 从不暴露软删标记(同 widget 的 `Widget`)。列表只回存活行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    /// 机器码 slug(`acme`)。**唯一**(存活行内),代码/引用用。
    pub name: String,
    /// 展示名(`Acme 公司`)。UI 用,可改。
    pub display_name: String,
    pub status: TenantStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

/// 成员资格**原始事实**(repo 层返回)。**没有 username** —— 那是 `users` 表的字段,
/// 而 `users` 归 idm,内存 repo 根本没有它。username 由 `TenantAdminService` 富化上去
/// (照 widget 富化 created_by 的 `cross-module-enrichment` 范式:repo 出事实,组合侧补展示)。
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TenantMemberFact {
    pub user_id: Uuid,
    pub role: TenantRole,
    #[allow(dead_code)] // 富化时透传给 TenantMember;直接字段读发生在 service
    pub granted_at: time::OffsetDateTime,
}

/// 一个租户的一名成员(P6 的成员管理端点 `GET /.../members` 的一行)。
///
/// 与 `Membership` 相反的视角:`Membership` 是「某用户在**哪些**租户」(用户视角),
/// 这个是「某租户里有**哪些**成员」(租户视角)。`username` 由 service 从 idm 富化。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TenantMember {
    pub user_id: Uuid,
    pub username: String,
    pub role: TenantRole,
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: time::OffsetDateTime,
}

// ── 请求 DTO(入参:Deserialize + ToSchema + Validate)──

/// 平台开通一个租户(`POST /admin/auth/tenants`)。可选带一个初始管理员。
///
/// **PUT/POST 全量**:name 是机器码 slug(建后不改,像 username);display_name 可后续 PUT 改。
/// `admin_identifier` 给了就把该已有用户设为这个租户的第一个 `tn:admin` —— 平台开通即交钥匙,
/// 之后由租户管理员自助邀请其余人(spec §7:平台开通 + 租户内部邀请)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateTenantRequest {
    #[garde(length(min = 2, max = 64))]
    pub name: String,
    #[garde(length(min = 1, max = 128))]
    pub display_name: String,
    /// 初始管理员的 username 或 email(必须是已有账号)。不给 = 建空租户。
    #[garde(inner(length(min = 1, max = 320)))]
    pub admin_identifier: Option<String>,
}

/// 全量更新一个租户(`PUT /admin/auth/tenants/{id}`)。**PUT 全量替换,不是 PATCH**:
/// display_name 与 status 都必传(status 用它来停用/恢复)。name(slug)刻意不可改。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateTenantRequest {
    #[garde(length(min = 1, max = 128))]
    pub display_name: String,
    #[garde(skip)]
    pub status: TenantStatus,
}

/// 邀请一名成员进租户(`POST /admin/auth/tenants/{id}/members` 或自助
/// `POST /frontend/auth/tenants/members`)。`identifier` = 已有账号的 username/email。
///
/// **被邀请者必须先有账号**:0 租户是常规状态(register 的常规出口,spec §1.1)——
/// 人先注册、再被邀请进公司。查无此人 → 404。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct AddMemberRequest {
    #[garde(length(min = 1, max = 320))]
    pub identifier: String,
    #[garde(skip)]
    pub role: TenantRole,
}

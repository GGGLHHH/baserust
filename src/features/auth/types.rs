//! auth 对外 DTO(契约数据形状)+ 与 idm 库领域类型的边界转换。
//! 入参 `Deserialize + ToSchema + Validate`(校验在 app 边界做);出参 `Serialize + ToSchema`。
//! idm 库零 HTTP、不认识这些 DTO —— 这里 `From<DTO> for idm::*Input` / `From<idm::UserView> for UserResponse` 做翻译。

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::features::tenants::{Membership, TenantRole};
use crate::infra::authz::RoleName;

/// 注册请求(公开)。username 必填、唯一;email 可选;password 至少 3 位。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterRequest {
    #[garde(length(min = 3, max = 32))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
    #[garde(length(min = 3))]
    pub password: String,
}

/// 登录请求(公开)。`identifier` = username 或 email,由 idm 自动识别。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
    /// 上限 320 = email 的最大合法长度(64 local + @ + 255 domain);username 上限 32 更窄,取宽的那个。
    /// **必须有上限**:登录失败时本字段被原样写进审计事件(`identifier_attempted`),经 outbox →
    /// NATS → 投影落 `auth_events`,而这条路是**未认证**可达的。没上限时唯一的界是 axum 的 2MB
    /// body 上限(限流还是 opt-in),等于放任匿名者每次瞎登录就持久化 ~2MB 攻击者可控文本;
    /// 这些行之后还会被后台 `q` 过滤 ILIKE 全表扫,成本反复付。
    #[garde(length(min = 1, max = 320))]
    pub identifier: String,
    #[garde(length(min = 1))]
    pub password: String,
}

/// **全量更新**当前用户(PUT 语义)。username 必填;email 给值=设置、给 null 或缺省=清空。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateMeRequest {
    #[garde(length(min = 3, max = 32))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
}

/// 注销账户(需密码确认)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct DeleteMeRequest {
    #[garde(length(min = 1))]
    pub password: String,
}

/// 修改密码。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ChangePasswordRequest {
    #[garde(length(min = 1))]
    pub current_password: String,
    #[garde(length(min = 8))]
    pub new_password: String,
}

/// 当前用户(me / 登录注册响应)。token 不进此体(走 httponly cookie)。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    /// 角色名(闭集,生成前端 union)。
    pub roles: Vec<RoleName>,
}

/// 我的一个租户(`GET /auth/tenants` 的一行)。
///
/// `name` 是机器码 slug(与 `idm.tenants.name` 同名,**不叫 slug**);`role` 是 DB 裸值
/// (`admin`/`member`),**不是** JWT claim 里那个带 `tn:` 前缀的串 —— 见 `TenantRole::claim`。
#[derive(Debug, Serialize, ToSchema)]
pub struct MyTenantResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    /// 我在这个租户里的角色(闭集,生成前端 union)。
    pub role: TenantRole,
    /// 是不是当前激活的那个。
    pub is_active: bool,
}

impl From<Membership> for MyTenantResponse {
    fn from(m: Membership) -> Self {
        Self {
            id: m.tenant_id,
            name: m.name,
            display_name: m.display_name,
            role: m.role,
            is_active: m.is_active,
        }
    }
}

/// 切换激活租户(`PUT /auth/active-tenant`)。**PUT 全量替换**,不是 PATCH。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetActiveTenantRequest {
    /// 目标租户。**非本人成员 → 404**(不是 403 —— 不泄露该租户是否存在)。
    #[garde(skip)]
    pub tenant_id: Uuid,
}

// ── 边界转换:app DTO ↔ idm 领域类型 ──

impl From<RegisterRequest> for idm::RegisterInput {
    fn from(r: RegisterRequest) -> Self {
        idm::RegisterInput {
            username: r.username,
            email: r.email,
            password: r.password,
        }
    }
}

impl From<LoginRequest> for idm::LoginInput {
    fn from(r: LoginRequest) -> Self {
        idm::LoginInput {
            identifier: r.identifier,
            password: r.password,
        }
    }
}

impl From<UpdateMeRequest> for idm::UpdateMeInput {
    fn from(r: UpdateMeRequest) -> Self {
        idm::UpdateMeInput {
            username: r.username,
            email: r.email,
        }
    }
}

impl From<ChangePasswordRequest> for idm::ChangePasswordInput {
    fn from(r: ChangePasswordRequest) -> Self {
        idm::ChangePasswordInput {
            current_password: r.current_password,
            new_password: r.new_password,
        }
    }
}

impl From<idm::UserView> for UserResponse {
    fn from(u: idm::UserView) -> Self {
        UserResponse {
            id: u.id,
            username: u.username,
            email: u.email,
            email_verified: u.email_verified,
            roles: RoleName::parse_lossy(strip_tenant_sentinel(u.roles)),
        }
    }
}

/// 剥掉 `TenantRoleRepo` 塞的 `t:{uuid}` 哨兵 —— **roles 泄漏到 API 的收口点**(spec §4.8)。
///
/// # 为什么这里非有不可
///
/// 哨兵**确实会走到这**:`AuthService` 用同一个 `RoleRepo` 服务两条路径 ——
/// - `issue_session` → `sign()` → `split_tenant` 摘掉它(JWT 里干净);
/// - **`me()`** → `UserView.roles` → 本转换 → HTTP 响应(`rust-idm/src/service.rs:153`)。
///
/// 后者不经过 `sign()`。§2.4 的「只包给铸币路径」在 `AuthService` 这一层做不到 ——
/// 它内部两条路径共用同一个注入的 repo。
///
/// # 为什么不能靠 parse_lossy 兜
///
/// `parse_lossy` 确实会把哨兵当未知角色丢掉 —— 但那是**巧合不是设计**,而且它会打一条
/// `角色名不在 RoleName 闭集内(存量脏数据?)` 的 warn:**那句话是错的**(这不是脏数据,
/// 是我们自己按设计塞的),它会把真正的存量脏数据告警淹掉,也会误导排查的人。
/// 更危险的是:哪天有人给 `RoleName` 加了个 `t:` 开头的变体,哨兵就会**直接泄漏进响应**。
fn strip_tenant_sentinel(roles: Vec<String>) -> Vec<String> {
    roles.into_iter().filter(|r| !r.starts_with("t:")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **收口点**:哨兵不得泄漏进 API 响应,而租户角色(`tn:*`)要保留 ——
    /// 后者是用户在当前租户里的真实角色,前端要靠它渲染。
    ///
    /// 这条钉的是 `strip_tenant_sentinel` 的**显式**剥离。没有它,哨兵只是被
    /// `parse_lossy` 当未知值意外丢掉(还附带一句「存量脏数据?」的错误告警)——
    /// 而那个巧合会在有人给 `RoleName` 加 `t:` 开头变体的那天失效。
    #[test]
    fn user_response_strips_sentinel_keeps_tenant_role() {
        let t = Uuid::now_v7();
        let view = idm::UserView {
            id: Uuid::now_v7(),
            username: "u".into(),
            email: None,
            email_verified: false,
            roles: vec![
                "user".into(),
                format!("t:{t}"),  // TenantRoleRepo 的哨兵 —— 必须剥掉
                "tn:admin".into(), // 真实的租户角色 —— 必须保留
            ],
        };
        let resp: UserResponse = view.into();
        assert_eq!(
            resp.roles,
            vec![RoleName::User, RoleName::TenantAdmin],
            "哨兵必须剥掉;tn:* 是真角色要留下"
        );
    }

    /// 剥离是**按前缀**而非按「解析不出来」—— 后者是 parse_lossy 的兜底,不是本函数的职责。
    #[test]
    fn strip_only_touches_sentinel_prefix() {
        let out = strip_tenant_sentinel(vec![
            "user".into(),
            "t:whatever".into(), // 前缀命中即剥,不管后面是不是合法 uuid
            "tn:admin".into(),   // tn: 不是 t: —— 别误伤
            "trusted".into(),    // 以 t 开头但不是 t: —— 别误伤
        ]);
        assert_eq!(out, vec!["user", "tn:admin", "trusted"]);
    }
}

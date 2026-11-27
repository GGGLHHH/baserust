//! auth 对外 DTO(契约数据形状)+ 与 idm 库领域类型的边界转换。
//! 入参 `Deserialize + ToSchema + Validate`(校验在 app 边界做);出参 `Serialize + ToSchema`。
//! idm 库零 HTTP、不认识这些 DTO —— 这里 `From<DTO> for idm::*Input` / `From<idm::UserView> for UserResponse` 做翻译。

use garde::Validate;
use idm::{ChangePasswordInput, LoginInput, Membership, RegisterInput, UpdateMeInput, UserView};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::infra::authorization::RoleNameSchema;
use crate::kernel::authorization::RoleName;

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
    #[schema(value_type = Vec<RoleNameSchema>)]
    pub roles: Vec<RoleName>,
}

/// 切换当前租户(`POST /auth/switch-tenant`)。只能切到自己是**有效成员**的租户(成员 active + 租户 active)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SwitchTenantRequest {
    #[garde(skip)]
    pub tenant_id: Uuid,
}

/// 我的一个租户(`GET /auth/tenants` 的元素):当前账号**有效**的成员关系。
#[derive(Debug, Serialize, ToSchema)]
pub struct MyTenantView {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    /// 我在该租户内的角色(闭集,生成前端 union)。
    #[schema(value_type = Vec<RoleNameSchema>)]
    pub roles: Vec<RoleName>,
    /// 是否是当前 token 所在的租户。
    pub current: bool,
}

impl MyTenantView {
    /// 把一条成员关系投影成列表元素;`current` 是当前 token 所在的租户(平台上下文为 `None`),
    /// 用来标出 `current` 字段。闭集外的角色名被丢弃(`RoleName::parse_lossy`)。
    #[must_use]
    pub fn new_with_membership(membership: Membership, current: Option<Uuid>) -> Self {
        Self {
            id: membership.tenant.id,
            slug: membership.tenant.slug,
            name: membership.tenant.name,
            roles: RoleName::parse_lossy(membership.roles),
            current: current == Some(membership.tenant.id),
        }
    }
}

// ── 边界转换:app DTO ↔ idm 领域类型 ──

impl From<RegisterRequest> for RegisterInput {
    fn from(request: RegisterRequest) -> Self {
        Self {
            username: request.username,
            email: request.email,
            password: request.password,
        }
    }
}

impl From<LoginRequest> for LoginInput {
    fn from(request: LoginRequest) -> Self {
        Self {
            identifier: request.identifier,
            password: request.password,
        }
    }
}

impl From<UpdateMeRequest> for UpdateMeInput {
    fn from(request: UpdateMeRequest) -> Self {
        Self {
            username: request.username,
            email: request.email,
        }
    }
}

impl From<ChangePasswordRequest> for ChangePasswordInput {
    fn from(request: ChangePasswordRequest) -> Self {
        Self {
            current_password: request.current_password,
            new_password: request.new_password,
        }
    }
}

impl From<UserView> for UserResponse {
    fn from(view: UserView) -> Self {
        Self {
            id: view.id,
            username: view.username,
            email: view.email,
            email_verified: view.email_verified,
            roles: RoleName::parse_lossy(view.roles),
        }
    }
}

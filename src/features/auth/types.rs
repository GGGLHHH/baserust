//! auth 对外 DTO(契约数据形状)+ 与 idm 库领域类型的边界转换。
//! 入参 `Deserialize + ToSchema + Validate`(校验在 app 边界做);出参 `Serialize + ToSchema`。
//! idm 库零 HTTP、不认识这些 DTO —— 这里 `From<DTO> for idm::*Input` / `From<idm::UserView> for UserResponse` 做翻译。

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::features::auth::port::TenantBrief;
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
/// `name` 是机器码 slug(与 `idm.tenants.name` 同名,**不叫 slug**)。
///
/// **没有 `role`**:见 `port::TenantBrief` 的 doc —— 切换器要的是「有哪几家、我现在在哪」。
///
/// **不实现 `From<TenantBrief>`**:`is_active` 只有 claim 知道(见 `list_my_tenants`),
/// `From` 填不出来。给它一个「默认 false」的 From 就是给下一个人埋雷 —— 他会写出
/// `brief.into()` 然后得到一个所有项都没选中的列表,而且没有任何东西会报错。
/// 构造它必须同时给出 active,所以只有 `with_active` 这一条路。
#[derive(Debug, Serialize, ToSchema)]
pub struct MyTenantResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    /// 是不是**本会话当前生效**的那个。
    pub is_active: bool,
}

impl MyTenantResponse {
    /// `active` = 本会话实际生效的租户(来自已验签的 claim),**不是**
    /// `user_active_tenant` 里显式设过的那个 —— 后者对从没切过的用户(即每个人的
    /// 初始状态)是空的,拿它当依据会让整个列表一个都不选中。
    pub fn with_active(t: TenantBrief, active: Option<Uuid>) -> Self {
        Self {
            is_active: Some(t.id) == active,
            id: t.id,
            name: t.name,
            display_name: t.display_name,
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
            roles: RoleName::parse_lossy(u.roles),
        }
    }
}

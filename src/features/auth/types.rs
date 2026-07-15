//! auth 对外 DTO(契约数据形状)+ 与 idm 库领域类型的边界转换。
//! 入参 `Deserialize + ToSchema + Validate`(校验在 app 边界做);出参 `Serialize + ToSchema`。
//! idm 库零 HTTP、不认识这些 DTO —— 这里 `From<DTO> for idm::*Input` / `From<idm::UserView> for UserResponse` 做翻译。

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

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

//! 审计上下文 + 鉴权身份提取器(HTTP 关注点,归 app)。范式 —— 请求边界产 `AuditContext`,
//! 经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 鉴权中间件(`features::auth::authenticate`)验过 JWT 后,在 `request.extensions` 塞一个
//! [`idm::AuthUser`];`AuditContext` 与 `CurrentUser` 都只**读** extension —— token 校验是单一
//! 真相源(中间件 / `idm::AuthService::authenticate_token`),这两个提取器不碰 JWT。
//!
//! 身份类型 `AuthUser` 由 idm 库提供(`authenticate_token` 的产物);这里只做 HTTP 提取。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::infra::error::AppError;
use idm::AuthUser;

/// 操作主体。`User` 由鉴权中间件经 extension 填充;`System` 给 seeder/job;`Anonymous` 给未认证请求。
#[derive(Clone, Debug)]
pub enum Actor {
    /// 真·系统操作:seeder / 后台 job / 迁移(无人类发起者)。
    System,
    /// 未认证请求(无有效 token)。
    Anonymous,
    /// 已认证用户(从 extension 的 `AuthUser` 来)。
    User { id: String },
}

impl Actor {
    /// 落到 `created_by`/`updated_by` 的值;不知道是谁就 `None`(写 NULL)。
    pub fn audit_id(&self) -> Option<String> {
        match self {
            Actor::System => Some("system".to_owned()),
            Actor::Anonymous => None,
            Actor::User { id } => Some(id.clone()),
        }
    }
}

/// 请求作用域审计上下文 —— 写操作经它取审计主体。
#[derive(Clone, Debug)]
pub struct AuditContext {
    pub actor: Actor,
}

impl AuditContext {
    /// 系统链路(无 HTTP 请求):seeder / 后台 job 用。
    pub fn system() -> Self {
        Self {
            actor: Actor::System,
        }
    }

    pub fn anonymous() -> Self {
        Self {
            actor: Actor::Anonymous,
        }
    }

    /// 写操作要落库的审计主体(created_by/updated_by)。
    pub fn audit_id(&self) -> Option<String> {
        self.actor.audit_id()
    }
}

/// extractor:鉴权中间件验过 JWT 会在 extensions 塞 `AuthUser`;有 → `User`,无 → `Anonymous`。
/// 下游 handler 签名不变,审计列(created_by/updated_by)自动从这里灌入。
impl<S: Send + Sync> FromRequestParts<S> for AuditContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let actor = match parts.extensions.get::<AuthUser>() {
            Some(u) => Actor::User {
                id: u.id.to_string(),
            },
            None => Actor::Anonymous,
        };
        Ok(Self { actor })
    }
}

/// 受保护端点提取器:**必须已认证**。读鉴权中间件塞的 `AuthUser`;无(未带/非法 token)→ 401。
pub struct CurrentUser(pub AuthUser);

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(CurrentUser)
            .ok_or(AppError::Unauthorized)
    }
}

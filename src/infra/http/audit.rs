//! 审计上下文 / 鉴权身份的 **HTTP 提取器**。`AuditContext` / `Actor` 本身是核心数据(`kernel::audit`),
//! 这里只负责从请求里把它取出来:请求边界产 `AuditContext`,经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 鉴权中间件(`features::auth::authenticate`)验过 JWT 后,在 `request.extensions` 塞一个
//! [`idm::AuthUser`];`AuditContext` 与 `CurrentUser` 都只**读** extension —— token 校验是单一
//! 真相源(中间件 / `idm::AuthService::authenticate_token`),这两个提取器不碰 JWT。
//!
//! 身份类型 `AuthUser` 由 idm 库提供(`authenticate_token` 的产物);这里只做 HTTP 提取。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::infra::http::error::ApiError;
use crate::kernel::audit::{Actor, AuditContext};
use crate::kernel::error::AppError;
use idm::AuthUser;

/// 审计上下文提取器(handler 写 `Audit(ctx): Audit`):鉴权中间件验过 JWT 会在 extensions 塞 `AuthUser`;
/// 有 → `User`,无 → `Anonymous`。`AuditContext` 在核心 crate,孤儿规则不许直接给它实现 axum 提取器 —— 包一层。
pub struct Audit(pub AuditContext);

impl<S: Send + Sync> FromRequestParts<S> for Audit {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let actor = match parts.extensions.get::<AuthUser>() {
            Some(u) => Actor::User {
                id: u.id.to_string(),
            },
            None => Actor::Anonymous,
        };
        Ok(Self(AuditContext { actor }))
    }
}

/// 受保护端点提取器:**必须已认证**。读鉴权中间件塞的 `AuthUser`;无(未带/非法 token)→ 401。
pub struct CurrentUser(pub AuthUser);

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(CurrentUser)
            .ok_or(ApiError(AppError::Unauthorized))
    }
}

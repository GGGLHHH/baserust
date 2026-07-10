//! 鉴权中间件:**best-effort** 解析 token,验过就把 `idm::AuthUser` 塞进 `request.extensions`。
//!
//! best-effort = 无 / 非法 token **不报错、不塞、放行** —— 由下游决定:
//! - `CurrentUser` 提取器(受保护端点)读不到 → 401;
//! - `AuditContext` 读不到 → 降级 `Anonymous`(created_by 写 NULL)。
//!
//! token 校验是这里**唯一**的真相源(`AppTokenVerifier::verify_with_scope`),提取器只读 extension。
//! 具体 over `AppState`(直接持 `AuthService`)—— 不再需要 idm 旧版的 `HasAuth` 泛型机关。

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;

use crate::app::state::AppState;
use crate::infra::authz::TokenScope;

/// 鉴权:**httponly cookie 优先,`Authorization: Bearer` 兜底**。
pub async fn authenticate(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_owned())
        .or_else(|| bearer_token(&req).map(str::to_owned));
    if let Some(token) = token {
        // 单次验签同时出身份 + scope(热路径;语义 == idm::authenticate_token + scope_of)。
        if let Ok((user, scope)) = state.token_verifier.verify_with_scope(&token) {
            req.extensions_mut().insert(user);
            req.extensions_mut().insert(TokenScope(scope));
        }
    }
    next.run(req).await
}

/// 从 `Authorization: Bearer <jwt>` 取出 token。无 header / 非 Bearer → `None`。
fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

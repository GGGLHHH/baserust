//! 鉴权中间件:**best-effort** 解析 Bearer JWT,验过就把 `AuthUser` 塞进 `request.extensions`。
//!
//! best-effort = 无 / 非法 token **不报错、不塞、放行** —— 由下游决定:
//! - `CurrentUser` 提取器(受保护端点)读不到 → 401;
//! - `AuditContext` 读不到 → 降级 `Anonymous`(created_by 写 NULL)。
//!
//! token 校验是这里**唯一**的真相源,提取器只读 extension、不碰 JWT。

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;

use crate::state::HasAuth;

/// 鉴权:**httponly cookie 优先,`Authorization: Bearer` 兜底**。泛型 over `S: HasAuth`,
/// 故 idm 独立跑(IdmState)与 app 集成(AppState)共用这一份 —— state 只需能给出 `AuthService`。
pub async fn authenticate<S: HasAuth>(
    State(state): State<S>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let token = jar
        .get("access_token")
        .map(|c| c.value().to_owned())
        .or_else(|| bearer_token(&req).map(str::to_owned));
    if let Some(token) = token {
        if let Ok(user) = state.auth().authenticate_token(&token) {
            req.extensions_mut().insert(user);
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

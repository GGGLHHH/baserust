//! auth 业务模块 —— **app 拥有的认证 HTTP 边界**:端点 + DTO + 校验 + httponly cookie + 鉴权中间件。
//! 业务逻辑(注册/登录/会话轮换/改密)全委托给 idm 库的 `AuthService`(零 HTTP)。
//!
//! 这是 idm 从"自带 HTTP 的框架"改回"纯领域库"后,app 侧的 HTTP 壳 —— 结构同 widget:
//! `routes`(handler,薄)→ idm `AuthService`(service)→ idm `repo`。DTO 与校验在 `types`。

mod middleware;
mod routes;
mod token;
mod types;

pub use middleware::authenticate;
pub use token::AppTokens;
pub use types::UserResponse;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// auth 路由 + OpenAPI。端点 path 已含 `/auth/*`,由 `build_router` nest `/api/v1` → `/api/v1/auth/*`。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::register))
        .routes(routes!(routes::login))
        .routes(routes!(routes::refresh))
        .routes(routes!(routes::logout))
        .routes(routes!(routes::logout_all))
        .routes(routes!(
            routes::get_me,
            routes::update_me,
            routes::delete_me
        ))
        .routes(routes!(routes::change_password))
}

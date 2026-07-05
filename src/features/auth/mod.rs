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
pub use token::{AppTokenSigner, AppTokenVerifier, NoopSigner};
pub use types::UserResponse;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// public 组(无闸):注册/登录/刷新/登出。
pub fn public_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::register))
        .routes(routes!(routes::login))
        .routes(routes!(routes::refresh))
        .routes(routes!(routes::logout))
}

/// frontend 组(闸:登录):当前用户资料/改密/全登出。
pub fn me_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::logout_all))
        .routes(routes!(
            routes::get_me,
            routes::update_me,
            routes::delete_me
        ))
        .routes(routes!(routes::change_password))
}

/// admin 组闸内:当前管理员。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_get_me))
}

/// admin 组闸外:后台登录(public 语义 —— 未认证请求闸挡不了,验密后 handler 自查 users:admin)。
pub fn admin_login_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_login))
}

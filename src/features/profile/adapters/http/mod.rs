//! profile 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// 本模块路由 + OpenAPI,挂到主 router(/api/v1 由 nest 加)。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::get_my_profile, routes::put_my_profile))
        .routes(routes!(routes::upload_my_avatar))
        .routes(routes!(routes::get_profile, routes::put_profile))
        .routes(routes!(routes::get_user_avatar))
}

/// 后台资料管理(admin 组;路径在 /users/{id} 下,与 users::admin_router 并挂)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::get_user_profile, routes::set_user_profile))
        .routes(routes!(routes::set_user_avatar))
}

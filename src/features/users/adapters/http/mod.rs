//! users 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// admin 组(组闸「admin:login」由 composition root 上;端点内再 gate「users:admin」)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_users, routes::create_user))
        .routes(routes!(
            routes::get_user,
            routes::update_user,
            routes::delete_user
        ))
        .routes(routes!(routes::set_user_roles))
        .routes(routes!(routes::reset_user_password))
        .routes(routes!(routes::list_roles))
}

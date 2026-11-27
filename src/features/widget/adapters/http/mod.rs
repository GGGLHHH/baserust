//! widget 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// frontend 组(组闸「需登录」由 composition root 上):CRUD / 仅登录样板 / SSE。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_widgets, routes::create_widget))
        .routes(routes!(
            routes::get_widget,
            routes::update_widget,
            routes::delete_widget
        ))
        .routes(routes!(routes::widget_stats))
        .routes(routes!(routes::my_widget_count))
        .routes(routes!(routes::purge_preview))
        .routes(routes!(routes::widget_overview))
        .routes(routes!(routes::widget_events))
}

/// admin 组(组闸「后台准入」= 当前租户 admin:login 或任一平台级权限,由 composition root 上)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_list_widgets))
}

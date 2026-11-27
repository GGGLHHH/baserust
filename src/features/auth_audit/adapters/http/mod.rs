//! auth_audit 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// admin 组(组闸「admin:login」由 composition root 上;端点内再 gate「audit:read」,superadmin 独占)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_user_auth_events))
        .routes(routes!(routes::list_auth_events))
        .routes(routes!(routes::stats_auth_events))
        .routes(routes!(routes::stream_auth_events))
}

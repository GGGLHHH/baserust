//! 健康检查 —— 最简端点,无需分层,展示「单文件模块」形态。

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(health))
}

/// 存活探针。
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses((status = 200, description = "服务存活", body = str))
)]
async fn health() -> &'static str {
    "ok"
}

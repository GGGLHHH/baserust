//! content 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// 本模块路由 + OpenAPI,挂到主 router(`/api/v1` 前缀由组合根的 nest 加)。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_contents, routes::create_content))
        .routes(routes!(routes::upload_content))
        .routes(routes!(routes::prepare_upload))
        .routes(routes!(routes::confirm_upload))
        .routes(routes!(
            routes::get_content,
            routes::update_content,
            routes::delete_content
        ))
        .routes(routes!(routes::download_content))
        .routes(routes!(routes::preview_content))
        .routes(routes!(routes::list_content_objects))
        .routes(routes!(
            routes::get_content_metadata,
            routes::set_content_metadata
        ))
}

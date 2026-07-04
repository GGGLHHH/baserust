//! content 业务模块 —— **HTTP 边界归 app**,领域/服务由 `content` 库提供(零 HTTP)。
//!
//! 与 widget 不同:这里**没有** service/repo/types 的领域实现(都在 `content` 库),app 只拥有
//! `routes`(handler,薄)+ `types`(对外 DTO + 投影/校验)。service 在组合根 `app::state` 装配
//! (注入内存/PG 仓储 + minio/内存 ObjectStore),经 `AppState.contents` 取用。

mod routes;
mod types;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

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

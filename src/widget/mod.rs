//! 示例业务模块 —— 标准分层范式的活样板。复制这套文件结构来加真实业务。
//!
//! 分层:`routes`(handler,薄) → `service`(业务逻辑/校验) → `repo`(trait + 实现)。
//! `types` 放 DTO。每个新业务域照抄此结构。

mod repo;
mod routes;
mod service;
mod types;

pub use repo::{InMemoryWidgetRepo, PgWidgetRepo, WidgetRepo};
pub use service::WidgetService;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::state::AppState;

/// 本模块的路由 + OpenAPI,挂到主 router。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_widgets, routes::create_widget))
        .routes(routes!(
            routes::get_widget,
            routes::update_widget,
            routes::delete_widget
        ))
}

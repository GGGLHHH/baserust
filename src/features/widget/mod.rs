//! 示例业务模块 —— 标准分层范式的活样板。复制这套文件结构来加真实业务。
//!
//! 分层:`routes`(handler,薄) → `service`(业务逻辑/校验) → `repo`(trait + 实现)。
//! `types` 放 DTO。每个新业务域照抄此结构。

mod port;
mod repo;
mod routes;
mod service;
mod types;
mod view;

pub use port::{StaticUserDirectory, UserBrief, UserDirectory};
pub use repo::{InMemoryWidgetRepo, PgWidgetRepo, WidgetRepo};
pub use service::WidgetService;
pub use view::WidgetView;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// 本模块的路由 + OpenAPI,挂到主 router。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_widgets, routes::create_widget))
        .routes(routes!(
            routes::get_widget,
            routes::update_widget,
            routes::delete_widget
        ))
        // 授权形态样板:public / 仅登录 / superadmin-only(各自独立路径,分开 routes!)
        .routes(routes!(routes::widget_stats))
        .routes(routes!(routes::my_widget_count))
        .routes(routes!(routes::admin_list_widgets))
}

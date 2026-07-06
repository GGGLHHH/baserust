//! 示例业务模块 —— 标准分层范式的活样板。复制这套文件结构来加真实业务。
//!
//! 分层:`routes`(handler,薄) → `service`(业务逻辑/校验) → `repo`(trait + 实现)。
//! `types` 放 DTO。每个新业务域照抄此结构。

mod events;
mod port;
mod repo;
mod routes;
mod service;
mod types;
mod view;

pub use events::{
    EventBus, EventSubscription, MemoryEventBus, NatsEventBus, PgEventBus, WidgetEvent,
};
pub use port::{StaticUserDirectory, UserBrief, UserDirectory};
pub use repo::{InMemoryWidgetRepo, PgWidgetRepo, WidgetRepo};
pub use service::WidgetService;
pub use types::WidgetSortField;
pub use view::WidgetView;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// frontend 组(组闸「需登录」由 composition root 上):CRUD / 仅登录样板 / SSE。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_widgets, routes::create_widget))
        .routes(routes!(
            routes::get_widget,
            routes::update_widget,
            routes::delete_widget
        ))
        .routes(routes!(routes::my_widget_count))
        .routes(routes!(routes::purge_preview))
        .routes(routes!(routes::widget_overview))
        .routes(routes!(routes::widget_events))
}

/// public 组(无闸):公开样板。
pub fn public_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::widget_stats))
}

/// admin 组(组闸「users:admin」由 composition root 上)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_list_widgets))
}

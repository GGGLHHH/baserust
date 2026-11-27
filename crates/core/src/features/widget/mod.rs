//! widget 的**核心**:领域模型、端口、用例、领域事件,以及内存适配器(纯 Rust 的默认实现 + 测试替身)。
//! 数据库 / HTTP / 消息适配器在主 crate 的 `features::widget::adapters`。

pub mod in_memory_widget_repo;
pub mod memory_event_bus;
pub mod model;
pub mod ports;
pub mod static_user_directory;
pub mod widget_event;
mod widget_service;

pub use in_memory_widget_repo::InMemoryWidgetRepo;
pub use memory_event_bus::MemoryEventBus;
pub use model::{WidgetSortField, WidgetView};
pub use ports::{EventBus, EventSubscription, UserBrief, UserDirectory, WidgetRepo};
pub use static_user_directory::StaticUserDirectory;
pub use widget_event::WidgetEvent;
pub use widget_service::WidgetService;

//! widget 的**核心**:领域模型、端口、用例、领域事件,以及内存适配器(纯 Rust 的默认实现 + 测试替身)。
//! 数据库 / HTTP / 消息适配器在主 crate 的 `features::widget::adapters`。

pub mod events;
pub mod memory;
pub mod model;
pub mod ports;
mod service;

pub use events::WidgetEvent;
pub use memory::{InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory};
pub use model::{WidgetSortField, WidgetView};
pub use ports::{EventBus, EventSubscription, UserBrief, UserDirectory, WidgetRepo};
pub use service::WidgetService;

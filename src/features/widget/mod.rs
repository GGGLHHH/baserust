//! 示例业务模块 —— **六边形分层(端口与适配器)的活样板**。复制这套文件结构来加真实业务。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP —— `tests/architecture.rs` 扫源码钉死):
//! - `model`   领域模型、命令(含校验规则)、读模型、可排序字段 —— 纯 Rust
//! - `events`  领域事件
//! - `ports`   端口:仓储、跨模块用户目录、事件总线(trait,归消费方)
//! - `service` 用例:编排、校验、发事件;只依赖端口
//!
//! **适配器**(`adapters/`;实现端口或驱动核心,依赖只向内指):
//! - `adapters::memory`   内存仓储 / 内存总线 / 静态用户目录(默认实现 + 核心单测的假适配器)
//! - `adapters::postgres` 数据库行(`FromRow`)↔ 领域模型,sea-query + sqlx
//! - `adapters::bus`      PG NOTIFY / NATS 总线
//! - `adapters::http`     axum handler + 请求/响应 DTO(serde / utoipa)↔ 领域
//!
//! 装配(选哪个实现、注入)在组合根 `app/`;跨模块的端口实现在 `app/adapters/`。

pub mod adapters;
pub mod events;
pub mod model;
pub mod ports;
mod service;

pub use adapters::bus::{NatsEventBus, PgEventBus};
pub use adapters::http::{admin_router, public_router, router};
pub use adapters::memory::{InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory};
pub use adapters::postgres::PgWidgetRepo;
pub use events::WidgetEvent;
pub use model::{WidgetSortField, WidgetView};
pub use ports::{EventBus, EventSubscription, UserBrief, UserDirectory, WidgetRepo};
pub use service::WidgetService;

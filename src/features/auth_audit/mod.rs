//! 认证审计模块:把 idm 发的 `auth.*` 事件投影成可查询的审计读模型,admin 端点查询 / 统计 / 实时推送。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP):`model`(事件闭集 / 读写模型 / 统计)、
//! `ports`(仓储)、`service`(用例)、`events`(进程内推送总线)、`retention`(90 天保留任务)。
//! **适配器**(`adapters/`):`http`、`projector`(JetStream 消费)、`memory` / `postgres`(仓储)。

pub mod adapters;
pub mod events;
pub mod model;
pub mod ports;
pub mod retention;
mod service;

pub use adapters::http::admin_router;
pub use adapters::memory::InMemoryAuthEventRepo;
pub use adapters::postgres::PgAuthEventRepo;
pub use events::AuthEventBus;
pub use model::{
    AuthChannel, AuthEventQuery, AuthEventRow, AuthEventType, AuthOutcome, AuthStats,
    FailureReason, NewAuthEvent,
};
pub use ports::AuthEventRepo;
pub use retention::AuthRetentionJob;
pub use service::AuthAuditService;

//! 认证审计的**核心**:领域模型(含闭集枚举)、端口、用例、进程内事件总线、保留期 job + 内存仓储。
//! PG 仓储 / projector / HTTP 适配器在主 crate。

pub mod events;
pub mod memory;
pub mod model;
pub mod ports;
pub mod retention;
mod service;

pub use events::AuthEventBus;
pub use memory::InMemoryAuthEventRepo;
pub use model::{
    AuthChannel, AuthEventQuery, AuthEventRow, AuthEventType, AuthOutcome, AuthStats,
    FailureReason, NewAuthEvent,
};
pub use ports::AuthEventRepo;
pub use retention::AuthRetentionJob;
pub use service::AuthAuditService;

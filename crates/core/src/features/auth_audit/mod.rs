//! 认证审计的**核心**:领域模型(含闭集枚举)、端口、用例、进程内事件总线、保留期 job + 内存仓储。
//! PG 仓储 / projector / HTTP 适配器在主 crate。

mod auth_audit_service;
pub mod auth_event_bus;
pub mod auth_event_repo;
pub mod auth_retention_job;
pub mod in_memory_auth_event_repo;
pub mod model;

pub use auth_audit_service::AuthAuditService;
pub use auth_event_bus::AuthEventBus;
pub use auth_event_repo::AuthEventRepo;
pub use auth_retention_job::AuthRetentionJob;
pub use in_memory_auth_event_repo::InMemoryAuthEventRepo;
pub use model::{
    AuthChannel, AuthEventQuery, AuthEventRow, AuthEventType, AuthOutcome, AuthStats,
    FailureReason, NewAuthEvent,
};

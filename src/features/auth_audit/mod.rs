//! 认证审计模块:把 idm 发的 `auth.*` 事件投影成可查询的审计读模型,admin 端点查询 / 统计 / 实时推送。
//!
//! **核心**(核心 crate;不依赖框架、数据库、HTTP):`model`(事件闭集 / 读写模型 / 统计)、
//! `auth_event_repo`(仓储端口)、`AuthAuditService`(用例)、`auth_event_bus`(进程内推送总线)、
//! `auth_retention_job`(90 天保留任务)、`in_memory_auth_event_repo`(内存仓储)。
//! **适配器**(`adapters/`):`http`、`auth_event_projector`(JetStream 消费)、`pg_auth_event_repo`(PG 仓储)。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里按名重新导出(不用 glob,见 CLAUDE.md「代码风格」),
//! 原有路径(`features::auth_audit::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::auth_audit::{
    auth_event_bus, auth_event_repo, auth_retention_job, in_memory_auth_event_repo, model,
    AuthAuditService, AuthChannel, AuthEventBus, AuthEventQuery, AuthEventRepo, AuthEventRow,
    AuthEventType, AuthOutcome, AuthRetentionJob, AuthStats, FailureReason, InMemoryAuthEventRepo,
    NewAuthEvent,
};

pub mod adapters;

pub use adapters::http::admin_router;
pub use adapters::pg_auth_event_repo::PgAuthEventRepo;

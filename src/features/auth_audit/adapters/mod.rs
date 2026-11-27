//! auth_audit 的**适配器**(外层):HTTP(驱动侧)、JetStream 投影器(驱动侧)、内存 / Postgres 仓储。

pub mod auth_event_projector;
pub mod http;
pub mod pg_auth_event_repo;

/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里按名重新导出。
pub use baserust_core::features::auth_audit::in_memory_auth_event_repo;

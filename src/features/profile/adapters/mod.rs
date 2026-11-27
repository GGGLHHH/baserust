//! profile 的**适配器**(外层):HTTP、内存 / Postgres 仓储、app schema 发件箱、头像探针替身。

pub mod http;
pub mod pg_app_outbox;
pub mod pg_profile_repo;

/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里按名重新导出。
pub use baserust_core::features::profile::{in_memory_profile_repo, static_avatar_probe};

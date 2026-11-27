//! search 的**适配器**(外层):JetStream 投影器(驱动侧)、内存 / Postgres 仓储。

pub mod pg_search_index_repo;
pub mod projector;

/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里按名重新导出。
pub use baserust_core::features::search::in_memory_search_index_repo;

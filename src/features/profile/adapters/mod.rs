//! profile 的**适配器**(外层):HTTP、内存 / Postgres 仓储、app schema 发件箱、头像探针替身。

pub mod http;
/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里重新导出,路径不变。
pub use baserust_core::features::profile::memory;
pub mod outbox;
pub mod postgres;

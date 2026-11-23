//! auth_audit 的**适配器**(外层):HTTP(驱动侧)、JetStream 投影器(驱动侧)、内存 / Postgres 仓储。

pub mod http;
/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里重新导出,路径不变。
pub use baserust_core::features::auth_audit::memory;
pub mod postgres;
pub mod projector;

//! search 的**适配器**(外层):JetStream 投影器(驱动侧)、内存 / Postgres 仓储。

pub mod memory;
pub mod postgres;
pub mod projector;

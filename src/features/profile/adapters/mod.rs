//! profile 的**适配器**(外层):HTTP、内存 / Postgres 仓储、app schema 发件箱、头像探针替身。

pub mod http;
pub mod memory;
pub mod outbox;
pub mod postgres;

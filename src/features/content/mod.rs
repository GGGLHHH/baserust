//! content 业务模块 —— **核心在 `content` 领域库**(领域模型、用例、端口:仓储 / 对象存储;零 HTTP),
//! 本模块只拥有它的**驱动侧适配器**:HTTP handler(`adapters::http::routes`)+ 线格式
//! (`adapters::http::dto`,投影库的领域类型、入参校验)。
//!
//! 库的 service 在组合根 `app::state` 装配(注入内存/PG 仓储 + minio/内存 ObjectStore),经
//! `AppState.contents` 取用。

pub mod adapters;

pub use adapters::http::router;

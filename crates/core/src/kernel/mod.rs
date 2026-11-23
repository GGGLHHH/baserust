//! 共享内核(shared kernel):各业务模块的**核心**(领域模型、用例、端口)共用的纯 Rust 件。
//!
//! 六边形架构的最内层:这里**不依赖任何框架、数据库、HTTP**(不 import axum / tower / utoipa /
//! sqlx / sea-query / 消息队列 / 对象存储客户端),由 `tests/architecture.rs` 扫源码钉死。
//! 这些件的线格式(HTTP 状态码、JSON 形状、query 解析、opaque cursor)归适配层 `infra::http`,
//! 数据库侧的映射(sea-query 排序方向等)归 `infra::pg`。

pub mod audit;
pub mod authz;
pub mod error;
pub mod pagination;
pub mod sort;

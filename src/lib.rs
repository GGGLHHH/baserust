//! xchangeai 库根 —— 挂模块,供 bin(main.rs)与集成测试(tests/)共用。
//!
//! 分层:
//! - `infra`  框架管线 + 领域无关共享(config/error/extract/openapi/audit/pagination)
//! - `app`    装配层(AppState + build_router),组合根
//! - `features` 业务模块层(widget/ + 将来 user/order/...)
//! - `health` 探针(单文件模块)

pub mod app;
pub mod features;
pub mod health;
pub mod infra;

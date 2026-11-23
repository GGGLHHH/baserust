//! baserust 库根 —— 挂模块,供 bin(main.rs)与集成测试(tests/)共用。
//!
//! 分层:
//! - `kernel` 共享内核:核心共用的纯件(错误/分页/排序/审计主体),不依赖框架、数据库、HTTP
//! - `infra`  适配器侧横切件(config/HTTP 适配/openapi/鉴权/消息/对象存储/pg)
//! - `app`    装配层(AppState + build_router),组合根
//! - `features` 业务模块层(widget/ + 将来 user/order/...)
//! - `health` 探针(单文件模块)

pub mod app;
pub mod features;
pub mod health;
pub mod infra;
pub mod kernel;

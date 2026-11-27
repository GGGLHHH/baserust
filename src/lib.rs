//! baserust 库根 —— 挂模块,供 bin(main.rs)与集成测试(tests/)共用。
//!
//! 分层:
//! - `kernel` 共享内核:核心共用的纯件(错误/分页/排序/审计主体),不依赖框架、数据库、HTTP
//! - `infra`  适配器侧横切件(config/HTTP 适配/openapi/鉴权/消息/对象存储/pg)
//! - `app`    装配层(AppState + build_router),组合根
//! - `features` 业务模块层的适配器(auth / auth_audit / content / profile / search / tenants / users / widget;
//!   核心在 `baserust-core`,这里按名重新导出)
//! - `health` 探针(单文件模块)

// Google Rust 风格指南:必须 panic 时用 expect("原因") 说明不变量,不用 unwrap。
#![warn(clippy::unwrap_used)]

pub mod app;
pub mod features;
pub mod health;
pub mod infra;
/// 共享内核在核心 crate(`baserust-core`),重新导出保持 `crate::kernel::…` 路径不变。
pub use baserust_core::kernel;

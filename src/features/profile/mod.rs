//! 用户资料模块:显示名 / 电话 / 头像(头像经 content,富化为相对头像端点路径)。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP):`model`(实体 / 命令 / 读模型 / 头像准入)、
//! `ports`(仓储、头像探针)、`service`(用例)。
//! **适配器**(`adapters/`):`http`、`memory` / `postgres`(仓储)、`outbox`(app schema 发件箱)。
//! 头像探针的真实现(经 content 领域库)在组合根 `app/adapters/`。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里整体重新导出,
//! 原有路径(`features::profile::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::profile::*;

pub mod adapters;

pub use adapters::http::{admin_router, router};
pub use adapters::outbox::PgAppOutbox;
pub use adapters::postgres::PgProfileRepo;

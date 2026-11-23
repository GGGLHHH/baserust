//! 示例业务模块 —— **六边形分层(端口与适配器)的活样板**。复制这套文件结构来加真实业务。
//!
//! **核心**(在核心 crate `crates/core/src/features/widget/`;不依赖框架、数据库、HTTP —— 核心 crate 的依赖里根本没有它们):
//! - `model`   领域模型、命令(含校验规则)、读模型、可排序字段 —— 纯 Rust
//! - `events`  领域事件
//! - `ports`   端口:仓储、跨模块用户目录、事件总线(trait,归消费方)
//! - `service` 用例:编排、校验、发事件;只依赖端口
//!
//! **适配器**(`adapters/`;实现端口或驱动核心,依赖只向内指):
//! - `memory`             内存仓储 / 内存总线 / 静态用户目录(纯 Rust,也在核心 crate;`adapters::memory` 重新导出)
//! - `adapters::postgres` 数据库行(`FromRow`)↔ 领域模型,sea-query + sqlx
//! - `adapters::bus`      PG NOTIFY / NATS 总线
//! - `adapters::http`     axum handler + 请求/响应 DTO(serde / utoipa)↔ 领域
//!
//! 装配(选哪个实现、注入)在组合根 `app/`;跨模块的端口实现在 `app/adapters/`。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里整体重新导出,
//! 原有路径(`features::widget::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::widget::*;

pub mod adapters;

pub use adapters::bus::{NatsEventBus, PgEventBus};
pub use adapters::http::{admin_router, public_router, router};
pub use adapters::postgres::PgWidgetRepo;

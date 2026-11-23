//! **baserust 的核心**(六边形架构的内圈):共享内核 + 各业务模块的领域模型、端口(trait)、用例,
//! 以及纯 Rust 的内存适配器(默认实现 + 核心单测的假适配器)。
//!
//! 依赖规则由**编译器**保证:本 crate 的 `Cargo.toml` 里没有 axum / tower / utoipa / sqlx / sea-query /
//! NATS / S3 / JWT —— 核心代码想用也 import 不到。`tests/architecture.rs`(主 crate)再守两条编译器管不到的:
//! 依赖清单不许加回这些 crate、模块之间不许直接互相 import(协作走端口)。
//!
//! 适配器(HTTP / Postgres / NATS / S3 / JWT)与组合根在主 crate `baserust`。

pub mod features;
pub mod kernel;

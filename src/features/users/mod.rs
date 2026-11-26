//! 后台用户管理模块 —— 身份原语在 idm 领域库,本模块编排 + 读侧富化 app.profiles(强一致,零事件)。
//! 全挂 admin 组、gate 平台级 `users:admin`(平台管理员 + superadmin);对持平台角色的账号动手另要 `platform:roles`(只有 superadmin)。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP):`model`(读模型/命令/排序/过滤)、
//! `ports`(富化目录、检索投影)、`service`(用例)。
//! **适配器**(`adapters/`):`http`(handler + DTO)、`memory`(富化目录替身)。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里整体重新导出,
//! 原有路径(`features::users::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::users::*;

pub mod adapters;

pub use adapters::http::admin_router;

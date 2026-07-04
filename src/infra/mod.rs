//! 基础设施层:框架管线(config/error/extract/openapi)+ 领域无关共享件(audit/pagination)。
//! 业务模块单向依赖此层;此层不依赖任何业务。

pub mod audit;
pub mod authz;
pub mod config;
pub mod error;
pub mod extract;
pub mod objectstore;
pub mod op_perms;
pub mod openapi;
pub mod pagination;

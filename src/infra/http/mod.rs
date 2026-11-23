//! HTTP 适配层的共享件(axum / utoipa 侧):统一错误响应、提取器、分页与排序的线格式、
//! 审计主体提取。业务模块的 `http/` 子模块(handler + DTO)用它们;核心(`kernel`、各模块的
//! model/service/端口)不碰这里。

pub mod audit;
pub mod error;
pub mod extract;
pub mod pagination;
pub mod schema;
pub mod sort;

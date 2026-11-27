//! 基础设施层(适配器侧的横切件):配置、HTTP 适配(`http`)、OpenAPI、鉴权、消息、对象存储、
//! Postgres 小件(`pg`)。领域无关的**核心**共享件(错误 / 分页 / 排序 / 审计主体)不在这里,在 `kernel`。
//! 业务模块单向依赖此层;此层不依赖任何业务。

pub mod authorization;
pub mod client_context;
pub mod config;
pub mod http;
pub mod jet_stream_publisher;
pub mod monitor;
pub mod openapi;
pub mod operation_permissions;
pub mod outbox;
pub mod percent;
pub mod pg;
pub mod s3_object_store;
pub mod telemetry;

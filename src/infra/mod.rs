//! 基础设施层(适配器侧的横切件):配置、HTTP 适配(`http`)、OpenAPI、鉴权、消息、对象存储、
//! Postgres 小件(`pg`)。领域无关的**核心**共享件(错误 / 分页 / 排序 / 审计主体)不在这里,在 `kernel`。
//! 业务模块单向依赖此层;此层不依赖任何业务。

pub mod authz;
pub mod client_context;
pub mod config;
pub mod http;
pub mod jetstream;
pub mod objectstore;
pub mod op_perms;
pub mod openapi;
pub mod outbox;
pub mod percent;
pub mod pg;

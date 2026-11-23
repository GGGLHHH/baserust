//! search 模块 —— CQRS 读模型(`admin_user_index`)。投影器经 [`SearchIndexRepo`] 把 idm/profile
//! 领域事件投影进读模型;users 列表经组合根的适配器读它。本模块无 HTTP 面。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP):`model`(读模型行 / 查询条件)、`ports`(仓储)、
//! `rebuild`(从源真相全量回填的用例)。
//! **适配器**(`adapters/`):`projector`(JetStream 消费)、`memory` / `postgres`(仓储)。

pub mod adapters;
pub mod model;
pub mod ports;
pub mod rebuild;

pub use adapters::memory::InMemorySearchIndexRepo;
pub use adapters::postgres::PgSearchIndexRepo;
pub use adapters::projector;
pub use model::{AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort};
pub use ports::SearchIndexRepo;
pub use rebuild::{rebuild, DisplayNameSource};

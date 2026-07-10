//! search 模块 —— CQRS 读模型仓储(`admin_user_index`)。[`projector::Projector`] 经 [`SearchIndexRepo`]
//! 把 idm/profile 领域事件投影进读模型;P4 的 list 端点经它读。
//! 本模块暂无 routes/service/HTTP 面 —— 挂载(AppState 装配 projector)留给消费方任务。

pub mod projector;
pub mod rebuild;
pub mod repo;
pub mod types;

pub use rebuild::{rebuild, DisplayNameSource};
pub use repo::{InMemorySearchIndexRepo, PgSearchIndexRepo, SearchIndexRepo};
pub use types::{AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort};

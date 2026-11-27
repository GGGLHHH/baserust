//! 用户搜索投影(账号目录 + 租户成员索引)的**核心**:读模型、端口、全量重建用例 + 内存仓储。PG 仓储与 projector 在主 crate。

pub mod in_memory_search_index_repo;
pub mod model;
pub mod rebuild;
pub mod search_index_repo;

pub use in_memory_search_index_repo::InMemorySearchIndexRepo;
pub use model::{
    AccountCreated, AccountIndexRow, AccountUpdated, AdminUserIndexRow, IndexQuery,
    IndexQueryResult, IndexSort,
};
pub use rebuild::{rebuild, DisplayNameSource, IdmSources, RebuildCounts, Watermarks};
pub use search_index_repo::SearchIndexRepo;

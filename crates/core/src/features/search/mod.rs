//! 用户搜索投影(账号目录 + 租户成员索引)的**核心**:读模型、端口、全量重建用例 + 内存仓储。PG 仓储与 projector 在主 crate。

pub mod memory;
pub mod model;
pub mod ports;
pub mod rebuild;

pub use memory::InMemorySearchIndexRepo;
pub use model::{AccountIndexRow, AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort};
pub use ports::SearchIndexRepo;
pub use rebuild::{rebuild, DisplayNameSource, IdmSources, RebuildCounts};

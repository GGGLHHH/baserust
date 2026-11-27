//! search 模块 —— CQRS 读模型(`admin_user_index`)。投影器经 [`SearchIndexRepo`] 把 idm/profile
//! 领域事件投影进读模型;users 列表经组合根的适配器读它。本模块无 HTTP 面。
//!
//! **核心**(核心 crate;不依赖框架、数据库、HTTP):`model`(读模型行 / 查询条件)、`search_index_repo`(仓储端口)、
//! `rebuild`(从源真相全量回填的用例)、`in_memory_search_index_repo`(内存仓储)。
//! **适配器**(`adapters/`):`projector`(JetStream 消费)、`pg_search_index_repo`(PG 仓储)。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里按名重新导出(不用 glob,见 CLAUDE.md「代码风格」),
//! 原有路径(`features::search::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::search::{
    in_memory_search_index_repo, model, rebuild, search_index_repo, AccountCreated,
    AccountIndexRow, AccountUpdated, AdminUserIndexRow, DisplayNameSource, IdmSources,
    InMemorySearchIndexRepo, IndexQuery, IndexQueryResult, IndexSort, RebuildCounts,
    SearchIndexRepo, Watermarks,
};

pub mod adapters;

pub use adapters::pg_search_index_repo::PgSearchIndexRepo;
pub use adapters::projector;

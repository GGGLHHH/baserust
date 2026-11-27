//! 业务模块层:每个子模块是一个业务域。核心(`model` / `ports` / `<m>_service` …)在 `baserust-core`,
//! 子模块根 `mod.rs` 按名重新导出;本 crate 只放 `adapters/`(http / postgres / bus / projector …)。
//! 加业务:在此 `pub mod xxx;`,照抄 widget/ 的结构(清单见 `adding-a-feature` skill)。

pub mod auth;
pub mod auth_audit;
pub mod content;
pub mod profile;
pub mod search;
pub mod tenants;
pub mod users;
pub mod widget;

//! 装配层(composition root):AppState 注入 + 路由组装。
//! 依赖方向与 infra 相反 —— 它 import 各业务模块的 repo/router,是唯一耦合所有模块之处。

pub mod account_guard;
pub mod adapters;
pub mod avatar_repair;
pub mod client_errors;
pub mod mock;
pub mod monitoring;
pub mod policy_repo;
pub mod probes;
pub mod router;
pub mod runtime;
pub mod seed;
pub mod state;

pub use router::{build_router, Mount};
pub use runtime::run;
pub use state::AppState;

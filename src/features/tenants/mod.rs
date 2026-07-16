//! 租户:成员资格与激活租户的存储。
//!
//! **住在 idm schema**(不是 app)—— 铸 token 的进程(Mount::Idm)没有 app_pool,
//! 而「每租户一套角色」要求铸币时就知道租户。见 spec §2.1。
//!
//! P1 只有存储层,**无 HTTP 端点** —— 切换/列表端点在 P2,且必须挂 `/auth/` 前缀
//! (nginx 只把 `/{public,frontend,admin}/auth/` 分流进 idm 进程)。

pub mod repo;
pub mod types;

pub use repo::{InMemoryTenantRepo, PgTenantRepo, TenantRepo};
pub use types::{Membership, TenantRole, TenantStatus};

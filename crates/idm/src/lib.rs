//! idm —— 自包含的认证服务 crate(领域层 + HTTP + 自带 `IdmError`/audit/state)。
//!
//! 被 app 当 lib 依赖:单体 `merge(idm::router::<AppState>())` + 挂 `idm::authenticate::<AppState>`
//! (FromRef substate 共享同一 AuthService),widget 等用 `idm::{AuditContext, CurrentUser}` 读当前
//! 用户;也能 `idm::app(state)` 独立起完整服务 / oneshot 测试 / 分进程部署。
//!
//! 错误靠**约定**对齐:`IdmError` 自带,`IntoResponse` 输出与 app `AppError` 相同的
//! `ErrorBody {code,error}`;app 侧 `From<IdmError> for AppError` 接回应用错误体系。
//!
//! 分层同 app 范式:`routes → service → repo(trait + memory/postgres) → types`,service 依赖
//! trait 而非实现。迁移表见 `migrations/`(app 手动 copy 进自己的 migrations/idm 跑)。

mod audit;
mod error;
mod extract;
mod jwt;
mod middleware;
pub mod password;
mod repo;
mod routes;
mod service;
mod state;
pub mod types;

pub use audit::{Actor, AuditContext, AuthUser, CurrentUser};
pub use error::{ErrorBody, IdmError};
pub use middleware::authenticate;
pub use password::{Argon2Hasher, FakeHasher, PwHasher};
pub use repo::{
    InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, PgRoleRepo, PgSessionRepo, PgUserRepo,
    RoleRepo, Session, SessionRepo, User, UserRepo, UserWithHash,
};
pub use routes::{app, router};
pub use service::{AuthOutcome, AuthService};
pub use state::{HasAuth, IdmState};

//! idm:身份 / 认证模块。register/login/refresh/logout(-all) + me 的 取/改/注销/改密。
//!
//! 第一版只定**对外契约骨架**(端点签名 + DTO + OpenAPI);实现逻辑(密码 hash / JWT /
//! refresh 轮换 / repo / 鉴权中间件 / AuditContext.User 灌入)留待 GREEN 阶段。

mod jwt;
mod middleware;
pub mod password;
mod repo;
mod routes;
mod service;
pub mod types;

pub use middleware::authenticate;
pub use password::{Argon2Hasher, FakeHasher, PwHasher};
pub use repo::{
    InMemorySessionRepo, InMemoryUserRepo, PgRoleRepo, PgSessionRepo, PgUserRepo, RoleRepo,
    Session, SessionRepo, User, UserRepo, UserWithHash,
};
pub use routes::router;
pub use service::{AuthOutcome, AuthService};

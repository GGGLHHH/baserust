//! idm 仓储:`UserRepo`(users + user_password 凭据分表,同事务)、`SessionRepo`(sessions)、
//! `RoleRepo`(roles + user_roles)。范式同 widget:trait 端口 + 内存/PG 实现分文件,service 依赖 trait。

mod memory;
mod postgres;

use async_trait::async_trait;
use sea_query::Iden;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infra::error::AppError;

pub use memory::{InMemorySessionRepo, InMemoryUserRepo};
pub use postgres::{PgRoleRepo, PgSessionRepo, PgUserRepo};

/// 用户内部实体。`FromRow` 供 PG 查映射;对外 DTO `UserResponse` 由 service 转,审计字段不进 DTO。
#[derive(Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

/// 用户 + 密码 hash —— **仅** `find_by_email` 返回(登录验密用)。绝不进 DTO / 日志 / 响应。
pub struct UserWithHash {
    pub user: User,
    pub password_hash: String,
}

/// 会话内部实体。`id` 同时作 JWT 的 `jti`。
#[derive(Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
}

// ── sea-query 表/列标识(snake_case:`Users::Table` -> "users"、`EmailVerified` -> "email_verified")──
#[derive(Iden)]
pub(crate) enum Users {
    Table,
    Id,
    Username,
    Email,
    EmailVerified,
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}
#[derive(Iden)]
pub(crate) enum UserPassword {
    Table,
    UserId,
    PasswordHash,
}
#[derive(Iden)]
pub(crate) enum Sessions {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    CreatedBy,
    UpdatedBy,
}
#[derive(Iden)]
pub(crate) enum Roles {
    Table,
    Id,
    Name,
    DisplayName,
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}
#[derive(Iden)]
pub(crate) enum UserRoles {
    Table,
    UserId,
    RoleId,
    GrantedBy,
}

/// 用户仓储端口。写操作的 `by` = 审计主体(created_by),来自 `AuditContext`。
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// 同事务建 user + user_password(凭据分表)。username 或 email 已被存活用户占用 → `Conflict`(409)。
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        by: Option<String>,
    ) -> Result<User, AppError>;

    /// 按 identifier(username 或 email)查存活用户 + 密码 hash(登录用)。
    /// 不存在 → `None`(防枚举,由 service 统一成 401)。
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, AppError>;

    /// 按 id 查存活用户。不存在 / 已软删 → `NotFound`。
    async fn find_by_id(&self, id: Uuid) -> Result<User, AppError>;
}

/// 会话仓储端口。
#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// 建会话(refresh token 只落 SHA-256 hash,明文不入库)。返回的 `Session.id` 即 JWT `jti`。
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<String>,
    ) -> Result<Session, AppError>;
}

/// 角色仓储端口(seed / RBAC 用)。
#[async_trait]
pub trait RoleRepo: Send + Sync {
    /// 幂等:存活同名角色已存在 → 返回其 id;否则创建。
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Uuid, AppError>;

    /// 幂等授予用户角色(`user_roles` 复合主键冲突即跳过)。
    async fn grant(&self, user_id: Uuid, role_id: Uuid, by: Option<String>)
        -> Result<(), AppError>;
}

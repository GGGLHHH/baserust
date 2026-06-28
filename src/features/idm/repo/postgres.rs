//! idm 仓储 Postgres 实现 —— sea-query 构建 + sqlx 执行(idm role 连接,search_path=idm)。

use async_trait::async_trait;
use sea_query::{Condition, Expr, ExprTrait, OnConflict, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool, Postgres};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    RoleRepo, Roles, Session, SessionRepo, Sessions, User, UserPassword, UserRepo, UserRoles,
    UserWithHash, Users,
};
use crate::infra::error::AppError;

/// 唯一冲突(撞存活唯一索引)→ `Conflict`;其它库错误 → `Internal`(原始进日志)。
fn map_unique(e: sqlx::Error, msg: &str) -> AppError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_unique_violation() {
            return AppError::Conflict(msg.to_owned());
        }
    }
    AppError::Internal(e.into())
}

// ── 用户 ──

pub struct PgUserRepo {
    pool: PgPool,
}
impl PgUserRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// find_by_identifier 的 join 行(users + user_password 扁平),转 `UserWithHash`。
#[derive(sqlx::FromRow)]
struct UserHashRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    password_hash: String,
}

#[async_trait]
impl UserRepo for PgUserRepo {
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        by: Option<String>,
    ) -> Result<User, AppError> {
        let id = Uuid::now_v7();
        // 同事务:users + user_password,任一失败回滚(凭据分表不会半截)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        let (usql, uvalues) = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::CreatedBy,
                Users::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                username.to_owned().into(),
                email.map(str::to_owned).into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
            ]))
            .build_sqlx(PostgresQueryBuilder);
        let user = sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(usql), uvalues)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_unique(e, "用户名或邮箱已被占用"))?;

        let (psql, pvalues) = Query::insert()
            .into_table(UserPassword::Table)
            .columns([UserPassword::UserId, UserPassword::PasswordHash])
            .values_panic([id.into(), password_hash.to_owned().into()])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(psql), pvalues)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, AppError> {
        // WHERE (username = $ OR email = $) AND deleted_at IS NULL
        let (sql, values) = Query::select()
            .column((Users::Table, Users::Id))
            .column((Users::Table, Users::Username))
            .column((Users::Table, Users::Email))
            .column((Users::Table, Users::EmailVerified))
            .column((UserPassword::Table, UserPassword::PasswordHash))
            .from(Users::Table)
            .inner_join(
                UserPassword::Table,
                Expr::col((UserPassword::Table, UserPassword::UserId))
                    .equals((Users::Table, Users::Id)),
            )
            .cond_where(
                Condition::any()
                    .add(Expr::col((Users::Table, Users::Username)).eq(identifier))
                    .add(Expr::col((Users::Table, Users::Email)).eq(identifier)),
            )
            .and_where(Expr::col((Users::Table, Users::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let row = sqlx::query_as_with::<Postgres, UserHashRow, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(row.map(|r| UserWithHash {
            user: User {
                id: r.id,
                username: r.username,
                email: r.email,
                email_verified: r.email_verified,
            },
            password_hash: r.password_hash,
        }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, AppError> {
        let (sql, values) = Query::select()
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)
    }
}

// ── 会话 ──

pub struct PgSessionRepo {
    pool: PgPool,
}
impl PgSessionRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepo for PgSessionRepo {
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<String>,
    ) -> Result<Session, AppError> {
        let id = Uuid::now_v7();
        let (sql, values) = Query::insert()
            .into_table(Sessions::Table)
            .columns([
                Sessions::Id,
                Sessions::UserId,
                Sessions::TokenHash,
                Sessions::ExpiresAt,
                Sessions::CreatedBy,
                Sessions::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                user_id.into(),
                token_hash.to_owned().into(),
                expires_at.into(),
                by.clone().into(),
                by.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(Session { id, user_id })
    }
}

// ── 角色 ──

pub struct PgRoleRepo {
    pool: PgPool,
}
impl PgRoleRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepo for PgRoleRepo {
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Uuid, AppError> {
        // 幂等:先查存活同名(seed 单次串行跑,并发竞态可忽略;真要强一致再加 ON CONFLICT)。
        let (ssql, svalues) = Query::select()
            .column(Roles::Id)
            .from(Roles::Table)
            .and_where(Expr::col(Roles::Name).eq(name))
            .and_where(Expr::col(Roles::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        if let Some(id) = sqlx::query_scalar_with::<Postgres, Uuid, _>(AssertSqlSafe(ssql), svalues)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
        {
            return Ok(id);
        }
        let id = Uuid::now_v7();
        let (isql, ivalues) = Query::insert()
            .into_table(Roles::Table)
            .columns([
                Roles::Id,
                Roles::Name,
                Roles::DisplayName,
                Roles::CreatedBy,
                Roles::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                name.to_owned().into(),
                display_name.to_owned().into(),
                by.clone().into(),
                by.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(isql), ivalues)
            .execute(&self.pool)
            .await
            .map_err(|e| map_unique(e, "角色名已存在"))?;
        Ok(id)
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let (sql, values) = Query::insert()
            .into_table(UserRoles::Table)
            .columns([UserRoles::UserId, UserRoles::RoleId, UserRoles::GrantedBy])
            .values_panic([user_id.into(), role_id.into(), by.into()])
            .on_conflict(
                OnConflict::columns([UserRoles::UserId, UserRoles::RoleId])
                    .do_nothing()
                    .to_owned(),
            )
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }
}

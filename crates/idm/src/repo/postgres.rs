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
use crate::error::IdmError;

/// 唯一冲突(撞存活唯一索引)→ `Conflict`;其它库错误 → `Internal`(原始进日志)。
fn map_unique(e: sqlx::Error, msg: &str) -> IdmError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_unique_violation() {
            return IdmError::Conflict(msg.to_owned());
        }
    }
    IdmError::Internal(e.into())
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
    ) -> Result<User, IdmError> {
        let id = Uuid::now_v7();
        // 同事务:users + user_password,任一失败回滚(凭据分表不会半截)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

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
            .map_err(|e| IdmError::Internal(e.into()))?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
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
            .map_err(|e| IdmError::Internal(e.into()))?;
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

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
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
            .map_err(|e| IdmError::Internal(e.into()))?
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        if ids.is_empty() {
            return Ok(Vec::new()); // 空集省一次查询,也避开空 IN ()
        }
        let (sql, values) = Query::select()
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).is_in(ids.iter().copied()))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<String>,
    ) -> Result<User, IdmError> {
        // PUT 全量替换:username/email 都 set(email 含清空 null),替换 email 即重置 email_verified。
        let (sql, values) = Query::update()
            .table(Users::Table)
            .value(Users::Username, username.to_owned())
            .value(Users::Email, email.map(str::to_owned))
            .value(Users::EmailVerified, false)
            .value(Users::UpdatedBy, by)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .returning(Query::returning().columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
            ]))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_unique(e, "用户名或邮箱已被占用"))?
            .ok_or(IdmError::NotFound)
    }

    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(Users::Table)
            .value(Users::DeletedAt, OffsetDateTime::now_utc())
            .value(Users::UpdatedBy, by)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        if res.rows_affected() == 0 {
            return Err(IdmError::NotFound);
        }
        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(UserPassword::Table)
            .value(UserPassword::PasswordHash, password_hash.to_owned())
            .value(UserPassword::PasswordUpdatedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(UserPassword::UserId).eq(user_id))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        // 仅存活用户:join users 过滤 deleted_at
        let (sql, values) = Query::select()
            .column((UserPassword::Table, UserPassword::PasswordHash))
            .from(UserPassword::Table)
            .inner_join(
                Users::Table,
                Expr::col((Users::Table, Users::Id))
                    .equals((UserPassword::Table, UserPassword::UserId)),
            )
            .and_where(Expr::col((Users::Table, Users::Id)).eq(user_id))
            .and_where(Expr::col((Users::Table, Users::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
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
    ) -> Result<Session, IdmError> {
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
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(Session { id, user_id })
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        let (sql, values) = Query::select()
            .columns([Sessions::Id, Sessions::UserId])
            .from(Sessions::Table)
            .and_where(Expr::col(Sessions::TokenHash).eq(token_hash))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .and_where(Expr::col(Sessions::ExpiresAt).gt(now))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, Session, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::Id).eq(session_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        let mut q = Query::update();
        q.table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::UserId).eq(user_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null());
        if let Some(id) = except {
            q.and_where(Expr::col(Sessions::Id).ne(id));
        }
        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
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
    ) -> Result<Uuid, IdmError> {
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
            .map_err(|e| IdmError::Internal(e.into()))?
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
    ) -> Result<(), IdmError> {
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
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        // SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
        //   WHERE ur.user_id = $ AND r.deleted_at IS NULL
        let (sql, values) = Query::select()
            .column((Roles::Table, Roles::Name))
            .from(UserRoles::Table)
            .inner_join(
                Roles::Table,
                Expr::col((Roles::Table, Roles::Id)).equals((UserRoles::Table, UserRoles::RoleId)),
            )
            .and_where(Expr::col((UserRoles::Table, UserRoles::UserId)).eq(user_id))
            .and_where(Expr::col((Roles::Table, Roles::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }
}

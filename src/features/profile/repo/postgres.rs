//! Postgres 实现。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,无需 AssertSqlSafe)。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ProfileFields, ProfileRepo};
use crate::features::profile::types::Profile;
use crate::infra::error::AppError;

pub struct PgProfileRepo {
    pool: PgPool,
}

impl PgProfileRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const GET_SQL: &str = "select user_id, first_name, middle_name, last_name, phone, \
     avatar_content_id, created_by, created_at, updated_by, updated_at \
     from profiles where user_id = $1";

/// 全量替换 upsert:conflict 分支**不碰 created_by/created_at**(替换保留),updated_at 归触发器。
/// `(xmax = 0)` ⇔ 本行由这条语句 INSERT(未走 UPDATE 分支)—— PG 惯用的"建 or 替"单语句判别,
/// 免二次查询/竞态。
const UPSERT_SQL: &str = "insert into profiles \
     (user_id, first_name, middle_name, last_name, phone, avatar_content_id, created_by, updated_by) \
     values ($1, $2, $3, $4, $5, $6, $7, $7) \
     on conflict (user_id) do update set \
       first_name = excluded.first_name, \
       middle_name = excluded.middle_name, \
       last_name = excluded.last_name, \
       phone = excluded.phone, \
       avatar_content_id = excluded.avatar_content_id, \
       updated_by = excluded.updated_by \
     returning user_id, first_name, middle_name, last_name, phone, avatar_content_id, \
       created_by, created_at, updated_by, updated_at, (xmax = 0) as inserted";

/// upsert 返回行 = Profile 平铺 + inserted 判别列。
#[derive(sqlx::FromRow)]
struct UpsertRow {
    #[sqlx(flatten)]
    profile: Profile,
    inserted: bool,
}

#[async_trait]
impl ProfileRepo for PgProfileRepo {
    async fn get(&self, user_id: Uuid) -> Result<Option<Profile>, AppError> {
        sqlx::query_as::<_, Profile>(GET_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        f: ProfileFields,
        by: Option<String>,
    ) -> Result<(Profile, bool), AppError> {
        let row = sqlx::query_as::<_, UpsertRow>(UPSERT_SQL)
            .bind(user_id)
            .bind(f.first_name)
            .bind(f.middle_name)
            .bind(f.last_name)
            .bind(f.phone)
            .bind(f.avatar_content_id)
            .bind(by)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok((row.profile, row.inserted))
    }
}

//! profile 仓储端口的 **Postgres 适配器**。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,
//! 无需 AssertSqlSafe)。数据库行 `ProfileRow` 只活在这里,出门即转成领域实体 `Profile`。

use async_trait::async_trait;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::pg_app_outbox::emit_outbox;
use crate::features::profile::model::{Profile, ProfileFields, UpsertedProfile};
use crate::features::profile::ports::ProfileRepo;
use crate::kernel::app_error::AppError;

/// `profiles` 一行(数据库形状)。
#[derive(FromRow)]
struct ProfileRow {
    user_id: Uuid,
    display_name: Option<String>,
    phone: Option<String>,
    avatar_content_id: Option<Uuid>,
    created_by: Option<String>,
    created_at: OffsetDateTime,
    updated_by: Option<String>,
    updated_at: OffsetDateTime,
}

impl From<ProfileRow> for Profile {
    fn from(row: ProfileRow) -> Self {
        Self {
            user_id: row.user_id,
            display_name: row.display_name,
            phone: row.phone,
            avatar_content_id: row.avatar_content_id,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

/// [`ProfileRepo`] 的 Postgres 实现(app schema 的 `profiles` 表;写方法同事务 emit 发件箱)。
pub struct PgProfileRepo {
    pool: PgPool,
}

impl PgProfileRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const GET_SQL: &str = "select user_id, display_name, phone, \
     avatar_content_id, created_by, created_at, updated_by, updated_at \
     from profiles where user_id = $1";

const FIND_BY_IDS_SQL: &str = "select user_id, display_name, phone, \
     avatar_content_id, created_by, created_at, updated_by, updated_at \
     from profiles where user_id = any($1)";

/// 全量替换 upsert:conflict 分支**不碰 created_by/created_at**(替换保留),updated_at 归触发器。
/// `(xmax = 0)` ⇔ 本行由这条语句 INSERT(未走 UPDATE 分支)—— PG 惯用的"建 or 替"单语句判别,
/// 免二次查询/竞态。
const UPSERT_SQL: &str = "insert into profiles \
     (user_id, display_name, phone, avatar_content_id, created_by, updated_by) \
     values ($1, $2, $3, $4, $5, $5) \
     on conflict (user_id) do update set \
       display_name = excluded.display_name, \
       phone = excluded.phone, \
       avatar_content_id = excluded.avatar_content_id, \
       updated_by = excluded.updated_by \
     returning user_id, display_name, phone, avatar_content_id, \
       created_by, created_at, updated_by, updated_at, (xmax = 0) as inserted";

/// upsert 返回行 = ProfileRow 平铺 + inserted 判别列。
#[derive(FromRow)]
struct UpsertRow {
    #[sqlx(flatten)]
    profile: ProfileRow,
    inserted: bool,
}

#[async_trait]
impl ProfileRepo for PgProfileRepo {
    #[tracing::instrument(name = "pg.profiles.get", skip_all)]
    async fn get(&self, user_id: Uuid) -> Result<Option<Profile>, AppError> {
        let row: Option<ProfileRow> = sqlx::query_as(GET_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(row.map(Profile::from))
    }

    #[tracing::instrument(name = "pg.profiles.find_by_ids", skip_all)]
    async fn find_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>, AppError> {
        if user_ids.is_empty() {
            return Ok(Vec::new()); // 空集省一次查询,也避开空 ANY
        }
        let rows: Vec<ProfileRow> = sqlx::query_as(FIND_BY_IDS_SQL)
            .bind(user_ids)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(rows.into_iter().map(Profile::from).collect())
    }

    #[tracing::instrument(name = "pg.profiles.upsert", skip_all)]
    async fn upsert(
        &self,
        user_id: Uuid,
        fields: ProfileFields,
        by: Option<String>,
    ) -> Result<UpsertedProfile, AppError> {
        // 事务:upsert + emit outbox 同提交(镜像 widget create_with_tags / idm 写方法的父子写范式)。
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        let avatar_content_id = fields.avatar_content_id;
        let row: UpsertRow = sqlx::query_as(UPSERT_SQL)
            .bind(user_id)
            .bind(fields.display_name)
            .bind(fields.phone)
            .bind(avatar_content_id)
            .bind(by)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // avatar_url:同 `ProfileService::enrich` 的头像端点口径(按 user_id,非 content id),但**不探测
        // 就绪性**——那是读侧关注(探测要 import content 模块,repo 层不做);这里只记录写入意图,
        // 悬空/未就绪由读侧消费者各自决定语义。
        let avatar_url =
            avatar_content_id.map(|_| format!("/api/v1/frontend/profiles/{user_id}/avatar"));
        emit_outbox(
            &mut transaction,
            "profile.updated",
            user_id,
            json!({
                "user_id": user_id,
                "display_name": &row.profile.display_name,
                "avatar_url": avatar_url,
            }),
        )
        .await?;

        transaction
            .commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(UpsertedProfile {
            profile: row.profile.into(),
            created: row.inserted,
        })
    }
}

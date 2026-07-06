//! Postgres 实现。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,无需 AssertSqlSafe)。

use async_trait::async_trait;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::outbox::emit_outbox;
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

    async fn find_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>, AppError> {
        if user_ids.is_empty() {
            return Ok(Vec::new()); // 空集省一次查询,也避开空 ANY
        }
        sqlx::query_as::<_, Profile>(FIND_BY_IDS_SQL)
            .bind(user_ids)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        f: ProfileFields,
        by: Option<String>,
    ) -> Result<(Profile, bool), AppError> {
        // 事务:upsert + emit outbox 同提交(镜像 widget create_with_tags / idm 写方法的父子写范式)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        let avatar_content_id = f.avatar_content_id;
        let row = sqlx::query_as::<_, UpsertRow>(UPSERT_SQL)
            .bind(user_id)
            .bind(f.display_name)
            .bind(f.phone)
            .bind(avatar_content_id)
            .bind(by)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // avatar_url:同 service::enrich 的相对 preview 口径,但**不探测就绪性**——那是读侧关注
        // (探测要 import content 模块,repo 层不做);这里只记录写入意图,悬空/未就绪由后续
        // relay/读侧消费者各自决定语义。
        let avatar_url =
            avatar_content_id.map(|cid| format!("/api/v1/frontend/contents/{cid}/preview"));
        emit_outbox(
            &mut tx,
            "profile.updated",
            user_id,
            json!({
                "user_id": user_id,
                "display_name": row.profile.display_name.clone(),
                "avatar_url": avatar_url,
            }),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok((row.profile, row.inserted))
    }
}

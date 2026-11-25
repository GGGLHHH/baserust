//! app schema 的事务性发件箱 **PG 实现**(内存实现与记录类型在核心 crate,这里重新导出)(transactional outbox)—— 镜像 idm 侧同名范式
//! (`rust-idm` `src/repo/postgres.rs` 的 `PgOutboxRepo` + `emit_outbox`,`src/repo/memory.rs` 的
//! `OutboxStore`/`InMemoryOutboxRepo`)。
//!
//! **本文件不是端口 trait** —— 只给具体的读端(`PgAppOutbox`/`InMemoryAppOutbox`),供
//! `PgProfileRepo::upsert`/`InMemoryProfileRepo::upsert` 在写成功后 emit(与业务写同一事务),
//! 以及组合根的 relay 轮询(`app/adapters/app_outbox_source.rs` 把它适配成通用 `OutboxSource` 端口)。
//! 发件箱是持久化机制,整个文件都是适配器;若后续有第二个业务模块也要写 app.outbox,再评估挪到共享位置。

use serde_json::Value;
use sqlx::{PgPool, Postgres};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::kernel::error::AppError;
pub use baserust_core::features::profile::outbox::{AppOutboxRecord, InMemoryAppOutbox};

/// 发件箱的数据库行(`FromRow` 只在适配器里);读出后转成核心的 [`AppOutboxRecord`]。
#[derive(sqlx::FromRow)]
struct OutboxRecordRow {
    id: i64,
    event_type: String,
    aggregate_id: Uuid,
    payload: Value,
    created_at: OffsetDateTime,
}

impl From<OutboxRecordRow> for AppOutboxRecord {
    fn from(r: OutboxRecordRow) -> Self {
        AppOutboxRecord {
            id: r.id,
            event_type: r.event_type,
            aggregate_id: r.aggregate_id,
            payload: r.payload,
            created_at: r.created_at,
        }
    }
}

// ── Postgres ──

const POLL_SQL: &str = "select id, event_type, aggregate_id, payload, created_at \
     from outbox where published_at is null order by id asc limit $1";

const MARK_SQL: &str = "update outbox set published_at = now() where id = any($1)";

const EMIT_SQL: &str = "insert into outbox (event_type, aggregate_id, payload) values ($1, $2, $3)";

pub struct PgAppOutbox {
    pool: PgPool,
}

impl PgAppOutbox {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 取最早的未发布记录(按 id 升序,FIFO),最多 `limit` 条。走部分索引
    /// `outbox_unpublished_idx`(WHERE published_at IS NULL)。
    pub async fn poll_unpublished(&self, limit: i64) -> Result<Vec<AppOutboxRecord>, AppError> {
        let rows = sqlx::query_as::<_, OutboxRecordRow>(POLL_SQL)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(rows.into_iter().map(AppOutboxRecord::from).collect())
    }

    /// 标记已发布(盖 published_at)。幂等(重复标记/标记不存在的 id 都 Ok)。
    pub async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        if ids.is_empty() {
            return Ok(()); // 空集省一次 UPDATE,也不建 span(relay 每轮都调)
        }
        self.mark_nonempty(ids).await
    }

    /// span 名带 `app_`:单进程模式下 idm 的发件箱也在同一个进程里打 `pg.outbox.*`,同名会并成一行统计。
    #[tracing::instrument(name = "pg.app_outbox.mark_published", skip_all)]
    async fn mark_nonempty(&self, ids: &[i64]) -> Result<(), AppError> {
        sqlx::query(MARK_SQL)
            .bind(ids)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }
}

/// 内部 emit 助手,由 `PgProfileRepo` 写方法在其**已有事务**上调用:在给定 `&mut Transaction` 上插
/// 一行 outbox,不参与 `PgAppOutbox` 自己的连接(`PgAppOutbox` 只 poll/mark,不进写事务)。
#[tracing::instrument(name = "pg.app_outbox.emit", skip_all)]
pub(crate) async fn emit_outbox(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    event_type: &str,
    aggregate_id: Uuid,
    payload: Value,
) -> Result<(), AppError> {
    sqlx::query(EMIT_SQL)
        .bind(event_type)
        .bind(aggregate_id)
        .bind(payload)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    Ok(())
}

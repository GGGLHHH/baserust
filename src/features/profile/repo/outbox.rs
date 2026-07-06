//! app schema 的事务性发件箱(transactional outbox)—— 镜像 idm 侧同名范式
//! (`rust-idm` `src/repo/postgres.rs` 的 `PgOutboxRepo` + `emit_outbox`,`src/repo/memory.rs` 的
//! `OutboxStore`/`InMemoryOutboxRepo`)。
//!
//! **本文件不是端口 trait** —— 只给具体的读端(`PgAppOutbox`/`InMemoryAppOutbox`),供
//! `PgProfileRepo::upsert`/`InMemoryProfileRepo::upsert` 在写成功后 emit,以及后续任务的
//! relay 轮询 / 适配成通用端口(Task 5+)。放在 `profile::repo` 下是本任务的落点;
//! 若后续有第二个业务模块也要写 app.outbox,再评估要不要挪到更共享的位置。

use std::sync::{Arc, Mutex};

use serde_json::Value;
use sqlx::{PgPool, Postgres};
use time::OffsetDateTime;
use uuid::Uuid;

use super::InMemoryProfileRepo;
use crate::infra::error::AppError;

/// 发件箱记录(`poll_unpublished` 返回)。不含 `published_at`——返回的行按定义都未发布。
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct AppOutboxRecord {
    pub id: i64,
    pub event_type: String,
    pub aggregate_id: Uuid,
    pub payload: Value,
    pub created_at: OffsetDateTime,
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
        sqlx::query_as::<_, AppOutboxRecord>(POLL_SQL)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    /// 标记已发布(盖 published_at)。幂等(重复标记/标记不存在的 id 都 Ok)。
    pub async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        if ids.is_empty() {
            return Ok(()); // 空集省一次 UPDATE
        }
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

// ── 内存 ──

/// 内存内部行:比 `AppOutboxRecord` 多 `published_at`(对外不暴露——poll 只返未发布行)。
struct OutboxRow {
    id: i64,
    event_type: String,
    aggregate_id: Uuid,
    payload: Value,
    created_at: OffsetDateTime,
    published_at: Option<OffsetDateTime>,
}

impl OutboxRow {
    fn to_record(&self) -> AppOutboxRecord {
        AppOutboxRecord {
            id: self.id,
            event_type: self.event_type.clone(),
            aggregate_id: self.aggregate_id,
            payload: self.payload.clone(),
            created_at: self.created_at,
        }
    }
}

/// 发件箱的**共享**存储:`InMemoryProfileRepo`(写方法内 emit)与 `InMemoryAppOutbox`(poll/mark)
/// 必须共用同一份 `Vec`,才能镜像 PG "同库不同表读写" 的语义。独立 `new()` 各自一份;
/// `InMemoryAppOutbox::sharing_with` 共享(同 idm `OutboxStore` 手法)。
#[derive(Default)]
pub(crate) struct OutboxStore {
    rows: Mutex<Vec<OutboxRow>>,
}

impl OutboxStore {
    /// 内部 emit 助手,由 `InMemoryProfileRepo::upsert` 在自己的锁内、写成功后调用:
    /// 追加一行(id 递增,未发布)。
    pub(crate) fn emit(&self, event_type: &str, aggregate_id: Uuid, payload: Value) {
        let mut rows = self.rows.lock().expect("锁未中毒");
        let id = rows.len() as i64 + 1;
        rows.push(OutboxRow {
            id,
            event_type: event_type.to_owned(),
            aggregate_id,
            payload,
            created_at: OffsetDateTime::now_utc(),
            published_at: None,
        });
    }
}

/// 发件箱内存实现:与 `InMemoryProfileRepo` 可共享同一份 `OutboxStore`(见 `sharing_with`),
/// 让 profile upsert emit 的行经本结构的 poll/mark 可见(镜像 PG "同库不同表" 的语义)。
pub struct InMemoryAppOutbox {
    inner: Arc<OutboxStore>,
}

impl InMemoryAppOutbox {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(OutboxStore::default()),
        }
    }

    /// 与给定 `InMemoryProfileRepo` **共享**发件箱存储。
    pub fn sharing_with(profiles: &InMemoryProfileRepo) -> Self {
        Self {
            inner: Arc::clone(profiles.outbox_store()),
        }
    }

    pub async fn poll_unpublished(&self, limit: i64) -> Result<Vec<AppOutboxRecord>, AppError> {
        let rows = self.inner.rows.lock().expect("锁未中毒");
        // 插入序即 id 升序(Vec 只追加),故直接按序取前 limit 条 = ORDER BY id ASC LIMIT。
        Ok(rows
            .iter()
            .filter(|r| r.published_at.is_none())
            .take(limit.max(0) as usize)
            .map(OutboxRow::to_record)
            .collect())
    }

    pub async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
        let mut rows = self.inner.rows.lock().expect("锁未中毒");
        let now = OffsetDateTime::now_utc();
        for r in rows.iter_mut() {
            if ids.contains(&r.id) {
                r.published_at.get_or_insert(now);
            }
        }
        Ok(())
    }
}

impl Default for InMemoryAppOutbox {
    fn default() -> Self {
        Self::new()
    }
}

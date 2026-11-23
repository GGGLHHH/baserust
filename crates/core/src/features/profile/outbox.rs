//! app schema 发件箱的**内存实现** + 记录类型(纯 Rust)。PG 实现(`PgAppOutbox` / `emit_outbox`)
//! 在主 crate 的 `features::profile::adapters::outbox`。内存实现住在核心,是因为
//! `InMemoryProfileRepo::upsert` 要在写资料的同一把锁里 emit(镜像 PG "同事务落地")。

use std::sync::{Arc, Mutex};

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::memory::InMemoryProfileRepo;
use crate::kernel::error::AppError;

/// 发件箱记录(`poll_unpublished` 返回)。不含 `published_at`——返回的行按定义都未发布。
#[derive(Clone, Debug)]
pub struct AppOutboxRecord {
    pub id: i64,
    pub event_type: String,
    pub aggregate_id: Uuid,
    pub payload: Value,
    pub created_at: OffsetDateTime,
}

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

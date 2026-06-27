use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::types::Widget;
use crate::error::AppError;

/// 仓储端口。范式:用 trait 定义数据访问契约,service 依赖 trait 而非具体实现。
/// 只有「需要多实现或要 mock」才抽 trait —— 这里需要(内存 ↔ Postgres 可拔插)。
#[async_trait]
pub trait WidgetRepo: Send + Sync {
    async fn list(&self) -> Result<Vec<Widget>, AppError>;
    async fn get(&self, id: Uuid) -> Result<Widget, AppError>;
    async fn create(&self, name: String) -> Result<Widget, AppError>;
}

/// 内存实现 —— 脚手架默认,无需数据库即可跑通全链路 + 写单测。
pub struct InMemoryWidgetRepo {
    // ponytail: Mutex<HashMap> 够脚手架用;真要高并发再换 DashMap 或直接走 DB
    store: Mutex<HashMap<Uuid, Widget>>,
}

impl InMemoryWidgetRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWidgetRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WidgetRepo for InMemoryWidgetRepo {
    async fn list(&self) -> Result<Vec<Widget>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        Ok(store.values().cloned().collect())
    }

    async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .cloned()
            .ok_or(AppError::NotFound)
    }

    async fn create(&self, name: String) -> Result<Widget, AppError> {
        let widget = Widget {
            id: Uuid::now_v7(),
            name,
        };
        self.store
            .lock()
            .expect("锁未中毒")
            .insert(widget.id, widget.clone());
        Ok(widget)
    }
}

/// Postgres 实现 —— sqlx 仓储范式。脚手架默认不启用(无 widgets 表);
/// 设了 DATABASE_URL 才注入。用 `query_as`(运行时查询),编译期无需连库。
pub struct PgWidgetRepo {
    pool: PgPool,
}

impl PgWidgetRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WidgetRepo for PgWidgetRepo {
    async fn list(&self) -> Result<Vec<Widget>, AppError> {
        let rows = sqlx::query_as::<_, Widget>("SELECT id, name FROM widgets ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(rows)
    }

    async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        sqlx::query_as::<_, Widget>("SELECT id, name FROM widgets WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)
    }

    async fn create(&self, name: String) -> Result<Widget, AppError> {
        let widget = sqlx::query_as::<_, Widget>(
            "INSERT INTO widgets (id, name) VALUES ($1, $2) RETURNING id, name",
        )
        .bind(Uuid::now_v7())
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        Ok(widget)
    }
}

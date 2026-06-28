//! widget 仓储的内存实现 —— 脚手架默认,无需数据库即可跑通全链路 + 写单测。
//! 镜像 PG 的软删过滤与排序(ORDER BY id DESC)保 parity。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::WidgetRepo;
use crate::features::widget::types::Widget;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};

/// 内存内部行:比 `Widget` 多 `deleted_at`(DTO 不暴露,但软删除要它)。
#[derive(Clone)]
struct Row {
    id: Uuid,
    name: String,
    created_by: Option<String>,
    created_at: OffsetDateTime,
    updated_by: Option<String>,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

impl Row {
    fn to_widget(&self) -> Widget {
        Widget {
            id: self.id,
            name: self.name.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at,
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at,
        }
    }
}

pub struct InMemoryWidgetRepo {
    store: Mutex<HashMap<Uuid, Row>>,
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
    async fn list(&self, page: &PageParams) -> Result<Page<Widget>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut alive: Vec<Row> = store
            .values()
            .filter(|r| r.deleted_at.is_none())
            .cloned()
            .collect();
        // ORDER BY id DESC(v7 id 即创建序倒序,最新在前)
        alive.sort_by(|a, b| b.id.cmp(&a.id));

        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let total = if *with_total {
                    Some(alive.len() as u64)
                } else {
                    None
                };
                let start = ((page.saturating_sub(1)) * size) as usize;
                let items: Vec<Widget> = alive
                    .iter()
                    .skip(start)
                    .take(*size as usize)
                    .map(Row::to_widget)
                    .collect();
                Ok(Page::offset(items, *page, *size, total))
            }
            PageParams::Cursor { after, limit } => {
                let mut items: Vec<Widget> = alive
                    .iter()
                    .filter(|r| match after {
                        Some(after) => r.id < *after, // id < cursor 配 ORDER BY id DESC
                        None => true,
                    })
                    .take((*limit + 1) as usize)
                    .map(Row::to_widget)
                    .collect();
                let has_more = items.len() as u64 > *limit;
                let next_cursor = if has_more {
                    items.truncate(*limit as usize);
                    items.last().map(|w| encode_cursor(w.id))
                } else {
                    None
                };
                Ok(Page::cursor(items, *limit, next_cursor))
            }
        }
    }

    async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(Row::to_widget)
            .ok_or(AppError::NotFound)
    }

    async fn create(&self, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let now = OffsetDateTime::now_utc();
        let row = Row {
            id: Uuid::now_v7(),
            name,
            created_by: by.clone(),
            created_at: now,
            updated_by: by,
            updated_at: now,
            deleted_at: None,
        };
        self.store
            .lock()
            .expect("锁未中毒")
            .insert(row.id, row.clone());
        Ok(row.to_widget())
    }

    async fn update(&self, id: Uuid, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                r.name = name;
                r.updated_by = by;
                r.updated_at = OffsetDateTime::now_utc();
                Ok(r.to_widget())
            }
            _ => Err(AppError::NotFound),
        }
    }

    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                let now = OffsetDateTime::now_utc();
                r.deleted_at = Some(now);
                r.updated_by = by;
                r.updated_at = now;
                Ok(())
            }
            _ => Err(AppError::NotFound),
        }
    }
}

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
    async fn list(&self, page: &PageParams, owner: Option<&str>) -> Result<Page<Widget>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut alive: Vec<Row> = store
            .values()
            .filter(|r| r.deleted_at.is_none())
            // ownership 过滤:owner=Some 只留自己创建的(created_by == owner);None 不过滤。
            .filter(|r| owner.is_none_or(|o| r.created_by.as_deref() == Some(o)))
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
        let mut store = self.store.lock().expect("锁未中毒");
        // name 在存活行内唯一(parity 于 PG 的部分唯一索引)→ 重名 Conflict(409)
        if store
            .values()
            .any(|r| r.deleted_at.is_none() && r.name == name)
        {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
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
        store.insert(row.id, row.clone());
        Ok(row.to_widget())
    }

    async fn update(&self, id: Uuid, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 目标须存活(parity 于 PG 的 WHERE id=? AND deleted_at IS NULL):缺 / 已删 → NotFound。
        if store.get(&id).is_none_or(|r| r.deleted_at.is_some()) {
            return Err(AppError::NotFound);
        }
        // 改名撞别的存活行 → Conflict(parity 于部分唯一索引;且 NotFound 先于 Conflict,同 PG 顺序)。
        if store
            .values()
            .any(|r| r.id != id && r.deleted_at.is_none() && r.name == name)
        {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        let r = store.get_mut(&id).expect("上面已确认存活");
        r.name = name;
        r.updated_by = by;
        r.updated_at = OffsetDateTime::now_utc();
        Ok(r.to_widget())
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

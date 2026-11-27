//! widget 仓储端口的**内存适配器**。脚手架默认 —— 无需数据库/broker
//! 即可跑通全链路;也是核心单测用的假适配器。纯 Rust(不依赖框架、数据库、HTTP)。
//!
//! 仓储镜像 PG 的软删过滤与排序保 parity(`widget_repo_conformance` 两边同一份契约)。
//! **租户**:内存实现没有 RLS,每个方法的 `tenant` 参数是唯一防线 —— 所有读写路径(含 cursor 锚点、
//! 唯一名校验、tag)都先按它过滤,别的租户的行当不存在。

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::widget::model::{Widget, WidgetSortField};
use crate::features::widget::ports::WidgetRepo;
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{OffsetPosition, Page, PageParams};
use crate::kernel::sort_order::SortOrder;
use crate::kernel::tenant_id::TenantId;

/// 内存内部行:比 `Widget` 多 `deleted_at`(领域模型不含,但软删除要它)。
#[derive(Clone)]
struct Row {
    tenant_id: TenantId,
    id: Uuid,
    name: String,
    created_by: Option<String>,
    created_at: OffsetDateTime,
    updated_by: Option<String>,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

impl Row {
    /// 本租户的存活行(列表 / 取 / 改 / 唯一名校验的共同前提)。
    fn alive_in(&self, tenant: TenantId) -> bool {
        self.tenant_id == tenant && self.deleted_at.is_none()
    }

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

/// 子表内存行(父子双表事务样板)。镜像 PG 的 `(widget_id, label)` 唯一。
struct TagRow {
    tenant_id: TenantId,
    widget_id: Uuid,
    label: String,
}

/// **同一把锁覆盖 widgets + tags** —— 事务方法在一次 `lock()` 内完成,即 PG `begin..commit` 的内存等价:
/// 锁住的临界区就是"全有或全无"的原子段。
#[derive(Default)]
struct MemoryStore {
    widgets: HashMap<Uuid, Row>,
    tags: Vec<TagRow>,
}

/// widget 仓储的内存实现(脚手架默认 / 测试替身),与 PG 实现跑同一份 conformance 契约。
#[derive(Default)]
pub struct InMemoryWidgetRepo {
    store: Mutex<MemoryStore>,
}

impl InMemoryWidgetRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WidgetRepo for InMemoryWidgetRepo {
    async fn list(
        &self,
        tenant: TenantId,
        page: &PageParams,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut alive: Vec<Row> = store
            .widgets
            .values()
            .filter(|r| r.alive_in(tenant))
            // ownership 过滤:owner=Some 只留自己创建的(created_by == owner);None 不过滤。
            .filter(|r| owner.is_none_or(|o| r.created_by.as_deref() == Some(o)))
            .cloned()
            .collect();

        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                // parity 于 PG offset:ORDER BY <sort_by> <order>, id <order>(id tiebreaker,方向随主键)。
                alive.sort_by(|left, right| {
                    let primary = match sort_by {
                        WidgetSortField::CreatedAt => left.created_at.cmp(&right.created_at),
                        WidgetSortField::Name => left.name.cmp(&right.name),
                    };
                    let ascending = primary.then_with(|| left.id.cmp(&right.id));
                    match order {
                        SortOrder::Asc => ascending,
                        SortOrder::Desc => ascending.reverse(),
                    }
                });
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
                Ok(Page::new_with_offset(
                    items,
                    OffsetPosition {
                        page: *page,
                        size: *size,
                    },
                    total,
                ))
            }
            PageParams::Cursor { after, limit } => {
                // 锚点行:**不过滤软删**(翻页途中锚点被软删,后续页仍要翻得下去),但**按租户过滤**
                // (别的租户的 id 当 cursor = 不是本租户发出的);查不到 → 400,parity 于 PG 的 `anchor()`。
                let anchor = match after {
                    Some(anchor_id) => Some(
                        store
                            .widgets
                            .get(anchor_id)
                            .filter(|r| r.tenant_id == tenant)
                            .ok_or_else(|| AppError::BadRequest("Invalid cursor".to_owned()))?
                            .to_widget(),
                    ),
                    None => None,
                };
                // 排序与谓词同键(parity 于 PG):created_at 序用 v7 id 单列,其余 (key, id) 复合。
                // `String::cmp` 是字节序 —— 对齐 PG 侧 `sort_expr` 的 `COLLATE "C"`,不对齐就漏行。
                let compare_keys = |left: &Row, right: &Row| match sort_by {
                    WidgetSortField::CreatedAt => left.id.cmp(&right.id),
                    WidgetSortField::Name => left
                        .name
                        .cmp(&right.name)
                        .then_with(|| left.id.cmp(&right.id)),
                };
                alive.sort_by(|left, right| match order {
                    SortOrder::Asc => compare_keys(left, right),
                    SortOrder::Desc => compare_keys(left, right).reverse(),
                });
                let mut items: Vec<Widget> = alive
                    .iter()
                    .filter(|row| match &anchor {
                        None => true,
                        // 严格不等:排除锚点行自身。
                        Some(anchor_widget) => {
                            let ordering = match sort_by {
                                WidgetSortField::CreatedAt => row.id.cmp(&anchor_widget.id),
                                WidgetSortField::Name => row
                                    .name
                                    .cmp(&anchor_widget.name)
                                    .then_with(|| row.id.cmp(&anchor_widget.id)),
                            };
                            match order {
                                SortOrder::Asc => ordering.is_gt(),
                                SortOrder::Desc => ordering.is_lt(),
                            }
                        }
                    })
                    .take((*limit + 1) as usize)
                    .map(Row::to_widget)
                    .collect();
                let has_more = items.len() as u64 > *limit;
                let next_after = if has_more {
                    items.truncate(*limit as usize);
                    items.last().map(|w| w.id)
                } else {
                    None
                };
                Ok(Page::new_with_cursor(items, *limit, next_after))
            }
        }
    }

    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        store
            .widgets
            .get(&id)
            .filter(|r| r.alive_in(tenant))
            .map(Row::to_widget)
            .ok_or(AppError::NotFound)
    }

    async fn create(
        &self,
        tenant: TenantId,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // name 在**本租户**存活行内唯一(parity 于 PG 的 (tenant_id, name) 部分唯一索引)→ 重名 Conflict(409)
        if store
            .widgets
            .values()
            .any(|r| r.alive_in(tenant) && r.name == name)
        {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        let now = OffsetDateTime::now_utc();
        let row = Row {
            tenant_id: tenant,
            id: Uuid::now_v7(),
            name,
            created_by: by.clone(),
            created_at: now,
            updated_by: by,
            updated_at: now,
            deleted_at: None,
        };
        let widget = row.to_widget();
        store.widgets.insert(row.id, row);
        Ok(widget)
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: Uuid,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 改名是否撞本租户别的存活行(parity 于部分唯一索引)。先算出来,报错顺序在下面定。
        let name_taken = store
            .widgets
            .values()
            .any(|r| r.id != id && r.alive_in(tenant) && r.name == name);
        // 目标须是本租户的存活行(parity 于 PG 的 WHERE tenant_id=? AND id=? AND deleted_at IS NULL):
        // 缺 / 已删 / 别的租户的 → NotFound。
        let Some(row) = store.widgets.get_mut(&id).filter(|r| r.alive_in(tenant)) else {
            return Err(AppError::NotFound);
        };
        // NotFound 先于 Conflict,同 PG 顺序。
        if name_taken {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        row.name = name;
        row.updated_by = by;
        row.updated_at = OffsetDateTime::now_utc();
        Ok(row.to_widget())
    }

    async fn soft_delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.widgets.get_mut(&id) {
            Some(row) if row.alive_in(tenant) => {
                let now = OffsetDateTime::now_utc();
                row.deleted_at = Some(now);
                row.updated_by = by;
                row.updated_at = now;
                Ok(())
            }
            _ => Err(AppError::NotFound),
        }
    }

    // ── 父子双表事务范式:一次 lock() 内"先全量校验、再整体落盘"= PG begin..commit 的内存等价。──
    async fn create_with_tags(
        &self,
        tenant: TenantId,
        name: String,
        labels: Vec<String>,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");

        // ── 先校验(此刻一行未动 = 回滚前状态)。任一失败提前 return = ROLLBACK。──
        // 父:widget 名在本租户存活唯一(parity 于部分唯一索引)。
        if store
            .widgets
            .values()
            .any(|r| r.alive_in(tenant) && r.name == name)
        {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        // 子:批内 label 重复 → 撞 (widget_id, label) 唯一(同一新 widget 内)。
        // 新 widget_id 是全新 uuid,与既有 tag 不可能撞,故只需查批内重复。
        let mut seen = HashSet::new();
        for label in &labels {
            if !seen.insert(label.as_str()) {
                return Err(AppError::Conflict("widget tag already exists".to_owned()));
            }
        }

        // ── 校验全过才落盘:父 + 子,同一把锁内 = 原子。**绝不先落盘再校验**,否则中途失败留下脏行。──
        let now = OffsetDateTime::now_utc();
        let widget_id = Uuid::now_v7();
        let row = Row {
            tenant_id: tenant,
            id: widget_id,
            name,
            created_by: by.clone(),
            created_at: now,
            updated_by: by,
            updated_at: now,
            deleted_at: None,
        };
        let widget = row.to_widget();
        store.widgets.insert(widget_id, row);
        for label in labels {
            store.tags.push(TagRow {
                tenant_id: tenant,
                widget_id,
                label,
            });
        }
        Ok(widget)
    }

    async fn tags_of(&self, tenant: TenantId, widget_id: Uuid) -> Result<Vec<String>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut labels: Vec<String> = store
            .tags
            .iter()
            .filter(|t| t.tenant_id == tenant && t.widget_id == widget_id)
            .map(|t| t.label.clone())
            .collect();
        labels.sort();
        Ok(labels)
    }
}

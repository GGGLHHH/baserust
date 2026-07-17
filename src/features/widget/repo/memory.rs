//! widget 仓储的内存实现 —— 脚手架默认,无需数据库即可跑通全链路 + 写单测。
//! 镜像 PG 的软删过滤与排序(ORDER BY id DESC)保 parity。

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::WidgetRepo;
use crate::features::widget::types::{Widget, WidgetSortField};
use crate::infra::authz::TenantId;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};
use crate::infra::sort::SortOrder;

/// 内存内部行:比 `Widget` 多 `deleted_at`(DTO 不暴露,但软删除要它)。
#[derive(Clone)]
struct Row {
    id: Uuid,
    tenant_id: Uuid,
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
            tenant_id: self.tenant_id,
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
    widget_id: Uuid,
    label: String,
}

/// **同一把锁覆盖 widgets + tags** —— 事务方法在一次 `lock()` 内完成,即 PG `begin..commit` 的内存等价:
/// 锁住的临界区就是"全有或全无"的原子段。
#[derive(Default)]
struct MemStore {
    widgets: HashMap<Uuid, Row>,
    tags: Vec<TagRow>,
}

pub struct InMemoryWidgetRepo {
    store: Mutex<MemStore>,
}

impl InMemoryWidgetRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(MemStore::default()),
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
            // **租户闸**:与软删过滤同级、同在这里 —— parity 于 PG 的 base_select。
            // 必须在切页之前:事后筛会让 total 与分页都错(同 owner 过滤的理由)。
            .filter(|r| r.tenant_id == tenant.get())
            .filter(|r| r.deleted_at.is_none())
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
                alive.sort_by(|a, b| {
                    let primary = match sort_by {
                        WidgetSortField::CreatedAt => a.created_at.cmp(&b.created_at),
                        WidgetSortField::Name => a.name.cmp(&b.name),
                    };
                    let asc = primary.then_with(|| a.id.cmp(&b.id));
                    match order {
                        SortOrder::Asc => asc,
                        SortOrder::Desc => asc.reverse(),
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
                Ok(Page::offset(items, *page, *size, total))
            }
            PageParams::Cursor { after, limit } => {
                // cursor keyset 恒按 id DESC(v7 id 即创建序倒序);sort_by 不参与(parity 于 PG)。
                alive.sort_by(|a, b| b.id.cmp(&a.id));
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

    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        store
            .widgets
            .get(&id)
            // **复合键 (tenant, id)**:别租户的 id → NotFound,与「不存在」无法区分。
            .filter(|r| r.tenant_id == tenant.get())
            .filter(|r| r.deleted_at.is_none())
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
        // name 在**本租户的**存活行内唯一(parity 于 PG 的 widgets_tenant_name_unique_alive)。
        // **租户维度不能漏**:漏了就是「别家用了这个名字,你就建不了」——
        // 既是功能 bug,也是个跨租户的存在性预言机(试名字看 201/409 即可枚举别家的 widget)。
        if store
            .widgets
            .values()
            .any(|r| r.tenant_id == tenant.get() && r.deleted_at.is_none() && r.name == name)
        {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        let now = OffsetDateTime::now_utc();
        let row = Row {
            id: Uuid::now_v7(),
            tenant_id: tenant.get(),
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
        // 目标须**本租户的**存活行(parity 于 PG 的 WHERE tenant_id=? AND id=? AND deleted_at IS NULL):
        // 缺 / 已删 / 别租户 → NotFound。
        if store
            .widgets
            .get(&id)
            .is_none_or(|r| r.tenant_id != tenant.get() || r.deleted_at.is_some())
        {
            return Err(AppError::NotFound);
        }
        // 改名撞**本租户**别的存活行 → Conflict(parity 于复合唯一索引;NotFound 先于 Conflict,同 PG 顺序)。
        if store.widgets.values().any(|r| {
            r.tenant_id == tenant.get() && r.id != id && r.deleted_at.is_none() && r.name == name
        }) {
            return Err(AppError::Conflict("widget name already exists".to_owned()));
        }
        let r = store.widgets.get_mut(&id).expect("上面已确认存活");
        r.name = name;
        r.updated_by = by;
        r.updated_at = OffsetDateTime::now_utc();
        Ok(r.to_widget())
    }

    async fn soft_delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.widgets.get_mut(&id) {
            Some(r) if r.tenant_id == tenant.get() && r.deleted_at.is_none() => {
                let now = OffsetDateTime::now_utc();
                r.deleted_at = Some(now);
                r.updated_by = by;
                r.updated_at = now;
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
        // 父:widget 名在**本租户内**存活唯一(parity 于 widgets_tenant_name_unique_alive)。
        if store
            .widgets
            .values()
            .any(|r| r.tenant_id == tenant.get() && r.deleted_at.is_none() && r.name == name)
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
            id: widget_id,
            tenant_id: tenant.get(),
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
            store.tags.push(TagRow { widget_id, label });
        }
        Ok(widget)
    }

    /// 子表无租户列 —— 经父表判定(parity 于 PG 的 join):
    /// 知道别租户的 widget id 也读不到它的标签。
    async fn tags_of(&self, tenant: TenantId, widget_id: Uuid) -> Result<Vec<String>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        // 父行必须是本租户的存活行 —— 否则等价于「查无此 widget」,返回空
        // (parity 于 PG:那边 inner join 直接筛掉,同样是空)。
        let visible = store
            .widgets
            .get(&widget_id)
            .is_some_and(|r| r.tenant_id == tenant.get() && r.deleted_at.is_none());
        if !visible {
            return Ok(Vec::new());
        }
        let mut labels: Vec<String> = store
            .tags
            .iter()
            .filter(|t| t.widget_id == widget_id)
            .map(|t| t.label.clone())
            .collect();
        labels.sort();
        Ok(labels)
    }
}

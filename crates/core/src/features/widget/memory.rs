//! widget 端口的**内存适配器**:仓储、事件总线、静态用户目录。脚手架默认 —— 无需数据库/broker
//! 即可跑通全链路;也是核心单测用的假适配器。纯 Rust(不依赖框架、数据库、HTTP)。
//!
//! 仓储镜像 PG 的软删过滤与排序保 parity(`widget_repo_conformance` 两边同一份契约)。
//! **租户**:内存实现没有 RLS,每个方法的 `tenant` 参数是唯一防线 —— 所有读写路径(含 cursor 锚点、
//! 唯一名校验、tag)都先按它过滤,别的租户的行当不存在。

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::features::widget::events::WidgetEvent;
use crate::features::widget::model::{Widget, WidgetSortField};
use crate::features::widget::ports::{
    EventBus, EventSubscription, UserBrief, UserDirectory, WidgetRepo,
};
use crate::kernel::error::AppError;
use crate::kernel::pagination::{Page, PageParams};
use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

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
                // 锚点行:**不过滤软删**(翻页途中锚点被软删,后续页仍要翻得下去),但**按租户过滤**
                // (别的租户的 id 当 cursor = 不是本租户发出的);查不到 → 400,parity 于 PG 的 `anchor()`。
                let anchor = match after {
                    Some(a) => Some(
                        store
                            .widgets
                            .get(a)
                            .filter(|r| r.tenant_id == tenant)
                            .ok_or_else(|| AppError::BadRequest("Invalid cursor".to_owned()))?
                            .to_widget(),
                    ),
                    None => None,
                };
                // 排序与谓词同键(parity 于 PG):created_at 序用 v7 id 单列,其余 (key, id) 复合。
                // `String::cmp` 是字节序 —— 对齐 PG 侧 `sort_expr` 的 `COLLATE "C"`,不对齐就漏行。
                let key_cmp = |a: &Row, b: &Row| match sort_by {
                    WidgetSortField::CreatedAt => a.id.cmp(&b.id),
                    WidgetSortField::Name => a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)),
                };
                alive.sort_by(|a, b| match order {
                    SortOrder::Asc => key_cmp(a, b),
                    SortOrder::Desc => key_cmp(a, b).reverse(),
                });
                let mut items: Vec<Widget> = alive
                    .iter()
                    .filter(|r| match &anchor {
                        None => true,
                        // 严格不等:排除锚点行自身。
                        Some(a) => {
                            let ord = match sort_by {
                                WidgetSortField::CreatedAt => r.id.cmp(&a.id),
                                WidgetSortField::Name => {
                                    r.name.cmp(&a.name).then_with(|| r.id.cmp(&a.id))
                                }
                            };
                            match order {
                                SortOrder::Asc => ord.is_gt(),
                                SortOrder::Desc => ord.is_lt(),
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
                Ok(Page::cursor(items, *limit, next_after))
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
        // 目标须是本租户的存活行(parity 于 PG 的 WHERE tenant_id=? AND id=? AND deleted_at IS NULL):
        // 缺 / 已删 / 别的租户的 → NotFound。
        if store.widgets.get(&id).is_none_or(|r| !r.alive_in(tenant)) {
            return Err(AppError::NotFound);
        }
        // 改名撞本租户别的存活行 → Conflict(parity 于部分唯一索引;且 NotFound 先于 Conflict,同 PG 顺序)。
        if store
            .widgets
            .values()
            .any(|r| r.id != id && r.alive_in(tenant) && r.name == name)
        {
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
            Some(r) if r.alive_in(tenant) => {
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

// ── 事件总线内存实现:tokio broadcast(零依赖默认,单进程测试/开发用)──

/// ponytail: 单实例 —— 多实例各见各的写;跨实例扇出设 NATS_URL(或 PG 退路),见模块头选择链。
pub struct MemoryEventBus {
    tx: broadcast::Sender<WidgetEvent>,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        // 64:突发缓冲。慢消费者超出即 Lagged(跳过),不是背压 —— SSE 场景丢旧事件可接受。
        Self {
            tx: broadcast::channel(64).0,
        }
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for MemoryEventBus {
    async fn publish(&self, event: WidgetEvent) {
        // 无订阅者时 send 返 Err —— 合法状态(没人在看),刻意忽略。
        let _ = self.tx.send(event);
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        Ok(Box::new(MemorySubscription(self.tx.subscribe())))
    }
}

struct MemorySubscription(broadcast::Receiver<WidgetEvent>);

#[async_trait]
impl EventSubscription for MemorySubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.recv().await {
                Ok(e) => return Some(e),
                // 掉队:跳过丢失的继续收,不断流(契约)。
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "事件订阅者掉队,跳过");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

// ── 用户目录静态实现 ──

/// 静态实现:用预置 map 回答 —— 脚手架测试 + 业务方测富化用(无需真连 idm)。
/// `empty()` 总返回空,可作"无富化源"占位(created_by_user 全 null)。
pub struct StaticUserDirectory(pub HashMap<Uuid, UserBrief>);

impl StaticUserDirectory {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl UserDirectory for StaticUserDirectory {
    async fn batch_by_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, UserBrief>, AppError> {
        Ok(ids
            .iter()
            .filter_map(|id| self.0.get(id).map(|b| (*id, b.clone())))
            .collect())
    }
}

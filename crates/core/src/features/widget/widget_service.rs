//! widget 用例:列表(含边缘富化)、计数、增删改;写成功后 fire-and-forget 发领域事件。

use std::collections::HashSet;
use std::sync::Arc;

use uuid::Uuid;

use super::model::{CreateWidget, UpdateWidget, Widget, WidgetSortField, WidgetView};
use super::ports::{EventBus, UserDirectory, WidgetRepo};
use super::widget_event::WidgetEvent;
use crate::kernel::app_error::AppError;
use crate::kernel::audit::AuditContext;
use crate::kernel::pagination::{Page, PageInfo, PageParams};
use crate::kernel::sort_order::SortOrder;
use crate::kernel::tenant_id::TenantId;

/// 用例层(核心)。范式:
/// - 只依赖端口(`Arc<dyn WidgetRepo>` 等),不关心底层是内存还是 Postgres、调用方是不是 HTTP。
/// - 在此做输入校验、编排;写操作从 `AuditContext` 取审计主体下传给 repo。
/// - **租户**:租户数据的用例第一个参数都是 `tenant`(边界从 `CurrentTenant` 取,只来自 token),原样下传 repo、
///   带进事件;核心**不兜底**(拿不到租户的调用方根本构造不出 `TenantId`,也没有「默认租户」可落)。
/// - `Clone` 廉价(只 clone Arc),可直接放进 `AppState`。
#[derive(Clone)]
pub struct WidgetService {
    repo: Arc<dyn WidgetRepo>,
    /// 跨模块富化端口(按 id 批量取用户)。widget **不知道**背后是 idm 还是 HTTP —— app 装配时注入。
    users: Arc<dyn UserDirectory>,
    /// 变更事件总线(SSE 范式)。fire-and-forget:publish 失败绝不影响写。
    events: Arc<dyn EventBus>,
}

impl WidgetService {
    pub fn new(
        repo: Arc<dyn WidgetRepo>,
        users: Arc<dyn UserDirectory>,
        events: Arc<dyn EventBus>,
    ) -> Self {
        Self {
            repo,
            users,
            events,
        }
    }

    /// 分页列表(纯,不富化)。分页参数由边界解析好(HTTP 侧是 `PageQuery::resolve`)。
    /// `owner = Some(id)` → 只列该用户创建的(数据所有权:user 只看自己的);`None` → 本租户全部(有 read:all 的角色)。
    pub async fn list(
        &self,
        tenant: TenantId,
        params: PageParams,
        owner: Option<Uuid>,
    ) -> Result<Page<Widget>, AppError> {
        let owner = owner.map(|id| id.to_string());
        // 无排序诉求的内部路径(count/测试)→ 默认序(created_at desc)。
        self.repo
            .list(
                tenant,
                &params,
                owner.as_deref(),
                WidgetSortField::default(),
                SortOrder::default(),
            )
            .await
    }

    /// 富化列表:list 后收集 distinct created_by → **一次** batch → 内存拼成 `WidgetView`。
    /// 防 N+1 的纪律在此:一次 `batch_by_ids`、不是每行一次;脏值('system'/NULL/非 UUID)与
    /// 已删用户优雅降级成 `created_by_user: null`,绝不报错、绝不跨 schema join。
    /// `owner` 同 [`Self::list`]:行级所有权过滤(在查询层,分页正确)。
    /// `params` 由边界解析(HTTP 侧 `resolve()`,cursor + 非 keyset 键的 422 校验也在那);`sort_by`/`order` 下传 repo。
    pub async fn list_enriched(
        &self,
        tenant: TenantId,
        params: PageParams,
        owner: Option<Uuid>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<WidgetView>, AppError> {
        let owner = owner.map(|id| id.to_string());
        let page = self
            .repo
            .list(tenant, &params, owner.as_deref(), sort_by, order)
            .await?;
        // 收集 distinct + parse 过滤:'system'/NULL/历史脏值 parse 失败的不当 user 查。
        let distinct: HashSet<Uuid> = page
            .items
            .iter()
            .filter_map(|w| w.created_by.as_deref())
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        let ids: Vec<Uuid> = distinct.into_iter().collect();
        let directory = self.users.batch_by_ids(&ids).await?;
        Ok(page.map_items(|w| WidgetView::new_with_directory(w, &directory)))
    }

    /// 本租户计数。复用 `list` 的 offset+total(size=1 少拉行)。`owner=Some` 只数自己创建的。
    // ponytail: demo 复用 list 取 total;真高频再加 `repo.count()`。
    pub async fn count(&self, tenant: TenantId, owner: Option<Uuid>) -> Result<u64, AppError> {
        let params = PageParams::Offset {
            page: 1,
            size: 1,
            with_total: true,
        };
        match self.list(tenant, params, owner).await?.page_info {
            PageInfo::Offset { total, .. } => Ok(total.unwrap_or(0)),
            PageInfo::Cursor { .. } => Ok(0), // 不会发生:上面固定 offset 模式
        }
    }

    /// 按 id 取本租户的存活行;不存在 / 已软删 / 别的租户的 → `NotFound`。
    pub async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError> {
        self.repo.get(tenant, id).await
    }

    /// 校验后创建(本租户内重名 → `Conflict`),成功后发布 `Created` 事件。
    pub async fn create(
        &self,
        tenant: TenantId,
        input: CreateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        use garde::Validate;

        input.validate()?;
        let widget = self.repo.create(tenant, input.name, ctx.audit_id()).await?;
        self.events
            .publish(WidgetEvent::Created {
                tenant_id: tenant,
                widget: widget.clone(),
            })
            .await;
        Ok(widget)
    }

    /// 校验后全量替换(改名),成功后发布 `Updated` 事件。不存在 → `NotFound`,重名 → `Conflict`。
    pub async fn update(
        &self,
        tenant: TenantId,
        id: Uuid,
        input: UpdateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        use garde::Validate;

        input.validate()?;
        let widget = self
            .repo
            .update(tenant, id, input.name, ctx.audit_id())
            .await?;
        self.events
            .publish(WidgetEvent::Updated {
                tenant_id: tenant,
                widget: widget.clone(),
            })
            .await;
        Ok(widget)
    }

    /// 软删除(非物理 DELETE)。
    /// 删前先 `get`:软删后行不可读,**只有这里能拿到 `created_by`** —— 事件带上它,订阅侧才能按
    /// ownership 逐帧过滤(见 `WidgetEvent::owner`)。多一次读换事件可过滤;`get` 的 NotFound 与
    /// `soft_delete` 的幂等 NotFound 同语义,不改对外契约。
    pub async fn delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        let created_by = self.repo.get(tenant, id).await?.created_by;
        self.repo.soft_delete(tenant, id, ctx.audit_id()).await?;
        self.events
            .publish(WidgetEvent::Deleted {
                tenant_id: tenant,
                id,
                created_by,
            })
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use tokio::time;

    use super::*;
    use crate::features::widget::in_memory_widget_repo::InMemoryWidgetRepo;
    use crate::features::widget::memory_event_bus::MemoryEventBus;
    use crate::features::widget::ports::UserBrief;
    use crate::features::widget::static_user_directory::StaticUserDirectory;
    use crate::kernel::tenant_id::DEFAULT_TENANT_ID as T;

    fn ctx() -> AuditContext {
        AuditContext::new_anonymous()
    }
    fn first_page() -> PageParams {
        PageParams::Offset {
            page: 1,
            size: 20,
            with_total: true,
        }
    }
    /// 测试用 service:内存 repo + 空富化目录(不富化的用例够用)。
    fn new_service() -> WidgetService {
        WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            Arc::new(MemoryEventBus::new()),
        )
    }

    #[tokio::test]
    async fn create_rejects_empty_name() {
        let service = new_service();
        let error = service
            .create(
                T,
                CreateWidget {
                    name: String::new(),
                },
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn create_then_list_roundtrips() {
        let service = new_service();
        service
            .create(
                T,
                CreateWidget {
                    name: "alpha".into(),
                },
                &ctx(),
            )
            .await
            .unwrap();
        let page = service.list(T, first_page(), None).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "alpha");
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let service = new_service();
        let error = service.get(T, Uuid::now_v7()).await.unwrap_err();
        assert!(matches!(error, AppError::NotFound));
    }

    #[tokio::test]
    async fn soft_delete_hides_from_list_and_get() {
        let service = new_service();
        let widget = service
            .create(T, CreateWidget { name: "x".into() }, &ctx())
            .await
            .unwrap();
        service.delete(T, widget.id, &ctx()).await.unwrap();
        // 软删后 get 404、list 不含、再删幂等 NotFound
        assert!(matches!(
            service.get(T, widget.id).await,
            Err(AppError::NotFound)
        ));
        assert_eq!(
            service
                .list(T, first_page(), None)
                .await
                .unwrap()
                .items
                .len(),
            0
        );
        assert!(matches!(
            service.delete(T, widget.id, &ctx()).await,
            Err(AppError::NotFound)
        ));
    }

    /// 富化:created_by 解析到用户 → 带 brief;脏值('system')→ 降级 null。一次 batch、不跨 join。
    #[tokio::test]
    async fn list_enriched_attaches_user_and_degrades_dirty() {
        let repo = Arc::new(InMemoryWidgetRepo::new());
        let user_id = Uuid::now_v7();
        // 直接 repo.create 精确控 created_by(service.create 的 by 来自 ctx,这里要指定具体值)
        repo.create(T, "known".into(), Some(user_id.to_string()))
            .await
            .unwrap();
        repo.create(T, "orphan".into(), Some("system".into()))
            .await
            .unwrap();
        let directory = Arc::new(StaticUserDirectory(HashMap::from([(
            user_id,
            UserBrief {
                id: user_id,
                username: "alice".into(),
                email: None,
            },
        )])));
        let service = WidgetService::new(repo, directory, Arc::new(MemoryEventBus::new()));
        let page = service
            .list_enriched(
                T,
                first_page(),
                None,
                WidgetSortField::default(),
                SortOrder::default(),
            )
            .await
            .unwrap();
        let by = |name: &str| page.items.iter().find(|v| v.name == name).unwrap();
        assert_eq!(
            by("known").created_by_user.as_ref().unwrap().username,
            "alice"
        );
        assert!(by("orphan").created_by_user.is_none()); // 'system' 脏值 → 降级 null
    }

    /// create 成功后发布 Created 事件;订阅方收到的 widget 与返回值一致。
    #[tokio::test]
    async fn create_publishes_created_event() {
        use crate::features::widget::memory_event_bus::MemoryEventBus;
        use crate::features::widget::ports::EventBus;
        use crate::features::widget::widget_event::WidgetEvent;
        let bus = Arc::new(MemoryEventBus::new());
        let service = WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            bus.clone(),
        );
        let mut subscription = bus.subscribe().await.unwrap();
        let created = service
            .create(T, CreateWidget { name: "evt".into() }, &ctx())
            .await
            .unwrap();
        let got = time::timeout(Duration::from_secs(1), subscription.recv())
            .await
            .expect("1s 内应收到事件")
            .expect("总线不应关闭");
        match got {
            WidgetEvent::Created { tenant_id, widget } => {
                assert_eq!(widget.id, created.id);
                assert_eq!(tenant_id, T, "事件带写入时的租户");
            }
            other => panic!("期待 Created,得到 {other:?}"),
        }
    }

    /// 删除事件带租户 + created_by(删后行不可读,订阅侧只能靠事件里的这两样判定可见性)。
    #[tokio::test]
    async fn delete_publishes_tenant_and_owner() {
        let bus = Arc::new(MemoryEventBus::new());
        let service = WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            bus.clone(),
        );
        let ctx = AuditContext::new_with_user("u1".into(), Some(T));
        let widget = service
            .create(T, CreateWidget { name: "d".into() }, &ctx)
            .await
            .unwrap();
        let mut subscription = bus.subscribe().await.unwrap();
        service.delete(T, widget.id, &ctx).await.unwrap();
        let got = time::timeout(Duration::from_secs(1), subscription.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got,
            WidgetEvent::Deleted {
                tenant_id: T,
                id: widget.id,
                created_by: Some("u1".into()),
            }
        );
    }

    /// 计数只数本租户(别的租户的同名行不算)。
    #[tokio::test]
    async fn count_is_per_tenant() {
        let repo = Arc::new(InMemoryWidgetRepo::new());
        let other = TenantId::try_new(Uuid::now_v7()).unwrap();
        repo.create(T, "a".into(), None).await.unwrap();
        repo.create(other, "a".into(), None).await.unwrap();
        repo.create(other, "b".into(), None).await.unwrap();
        let service = WidgetService::new(
            repo,
            Arc::new(StaticUserDirectory::new()),
            Arc::new(MemoryEventBus::new()),
        );
        assert_eq!(service.count(T, None).await.unwrap(), 1);
        assert_eq!(service.count(other, None).await.unwrap(), 2);
    }
}

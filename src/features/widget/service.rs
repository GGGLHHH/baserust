use std::collections::HashSet;
use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::port::UserDirectory;
use super::repo::WidgetRepo;
use super::types::{CreateWidget, UpdateWidget, Widget};
use super::view::WidgetView;
use crate::infra::audit::AuditContext;
use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageQuery};

/// 业务逻辑层。范式:
/// - 持 `Arc<dyn WidgetRepo>` 端口,不关心底层是内存还是 Postgres。
/// - 在此做输入校验、编排;写操作从 `AuditContext` 取审计主体下传给 repo。
/// - `Clone` 廉价(只 clone Arc),可直接放进 `AppState`。
#[derive(Clone)]
pub struct WidgetService {
    repo: Arc<dyn WidgetRepo>,
    /// 跨模块富化端口(按 id 批量取用户)。widget **不知道**背后是 idm 还是 HTTP —— app 装配时注入。
    users: Arc<dyn UserDirectory>,
}

impl WidgetService {
    pub fn new(repo: Arc<dyn WidgetRepo>, users: Arc<dyn UserDirectory>) -> Self {
        Self { repo, users }
    }

    /// 分页列表(纯,不富化)。`PageQuery::resolve` 兼做互斥校验/clamp/默认,失败映射 AppError。
    pub async fn list(&self, query: PageQuery) -> Result<Page<Widget>, AppError> {
        let params = query.resolve()?;
        self.repo.list(&params).await
    }

    /// 富化列表:list 后收集 distinct created_by → **一次** batch → 内存拼成 `WidgetView`。
    /// 防 N+1 的纪律在此:一次 `batch_by_ids`、不是每行一次;脏值('system'/NULL/非 UUID)与
    /// 已删用户优雅降级成 `created_by_user: null`,绝不报错、绝不跨 schema join。
    pub async fn list_enriched(&self, query: PageQuery) -> Result<Page<WidgetView>, AppError> {
        let page = self.list(query).await?;
        // 收集 distinct + parse 过滤:'system'/NULL/历史脏值 parse 失败的不当 user 查。
        let ids: Vec<Uuid> = page
            .items
            .iter()
            .filter_map(|w| w.created_by.as_deref())
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let dir = self.users.batch_by_ids(&ids).await?;
        Ok(page.map_items(|w| WidgetView::enrich(w, &dir)))
    }

    pub async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        self.repo.get(id).await
    }

    pub async fn create(
        &self,
        input: CreateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        input.validate()?;
        self.repo.create(input.name, ctx.audit_id()).await
    }

    pub async fn update(
        &self,
        id: Uuid,
        input: UpdateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        input.validate()?;
        self.repo.update(id, input.name, ctx.audit_id()).await
    }

    /// 软删除(非物理 DELETE)。
    pub async fn delete(&self, id: Uuid, ctx: &AuditContext) -> Result<(), AppError> {
        self.repo.soft_delete(id, ctx.audit_id()).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::features::widget::repo::InMemoryWidgetRepo;
    use crate::features::widget::{StaticUserDirectory, UserBrief};

    fn ctx() -> AuditContext {
        AuditContext::anonymous(None)
    }
    fn first_page() -> PageQuery {
        PageQuery {
            page: None,
            cursor: None,
            size: None,
            with_total: None,
        }
    }
    /// 测试用 service:内存 repo + 空富化目录(不富化的用例够用)。
    fn new_svc() -> WidgetService {
        WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
        )
    }

    #[tokio::test]
    async fn create_rejects_empty_name() {
        let svc = new_svc();
        let err = svc
            .create(
                CreateWidget {
                    name: String::new(),
                },
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn create_then_list_roundtrips() {
        let svc = new_svc();
        svc.create(
            CreateWidget {
                name: "alpha".into(),
            },
            &ctx(),
        )
        .await
        .unwrap();
        let page = svc.list(first_page()).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "alpha");
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let svc = new_svc();
        let err = svc.get(Uuid::now_v7()).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    #[tokio::test]
    async fn soft_delete_hides_from_list_and_get() {
        let svc = new_svc();
        let w = svc
            .create(CreateWidget { name: "x".into() }, &ctx())
            .await
            .unwrap();
        svc.delete(w.id, &ctx()).await.unwrap();
        // 软删后 get 404、list 不含、再删幂等 NotFound
        assert!(matches!(svc.get(w.id).await, Err(AppError::NotFound)));
        assert_eq!(svc.list(first_page()).await.unwrap().items.len(), 0);
        assert!(matches!(
            svc.delete(w.id, &ctx()).await,
            Err(AppError::NotFound)
        ));
    }

    /// 富化:created_by 解析到用户 → 带 brief;脏值('system')→ 降级 null。一次 batch、不跨 join。
    #[tokio::test]
    async fn list_enriched_attaches_user_and_degrades_dirty() {
        let repo = Arc::new(InMemoryWidgetRepo::new());
        let uid = Uuid::now_v7();
        // 直接 repo.create 精确控 created_by(service.create 的 by 来自 ctx,这里要指定具体值)
        repo.create("known".into(), Some(uid.to_string()))
            .await
            .unwrap();
        repo.create("orphan".into(), Some("system".into()))
            .await
            .unwrap();
        let dir = Arc::new(StaticUserDirectory(HashMap::from([(
            uid,
            UserBrief {
                id: uid,
                username: "alice".into(),
                email: None,
            },
        )])));
        let svc = WidgetService::new(repo, dir);
        let page = svc.list_enriched(first_page()).await.unwrap();
        let by = |n: &str| page.items.iter().find(|v| v.name == n).unwrap();
        assert_eq!(
            by("known").created_by_user.as_ref().unwrap().username,
            "alice"
        );
        assert!(by("orphan").created_by_user.is_none()); // 'system' 脏值 → 降级 null
    }
}

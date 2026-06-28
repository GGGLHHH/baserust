use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::repo::WidgetRepo;
use super::types::{CreateWidget, UpdateWidget, Widget};
use crate::audit::AuditContext;
use crate::error::AppError;
use crate::pagination::{Page, PageQuery};

/// 业务逻辑层。范式:
/// - 持 `Arc<dyn WidgetRepo>` 端口,不关心底层是内存还是 Postgres。
/// - 在此做输入校验、编排;写操作从 `AuditContext` 取审计主体下传给 repo。
/// - `Clone` 廉价(只 clone Arc),可直接放进 `AppState`。
#[derive(Clone)]
pub struct WidgetService {
    repo: Arc<dyn WidgetRepo>,
}

impl WidgetService {
    pub fn new(repo: Arc<dyn WidgetRepo>) -> Self {
        Self { repo }
    }

    /// 分页列表。`PageQuery::resolve` 兼做互斥校验/clamp/默认,失败映射 AppError。
    pub async fn list(&self, query: PageQuery) -> Result<Page<Widget>, AppError> {
        let params = query.resolve()?;
        self.repo.list(&params).await
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
    use super::*;
    use crate::widget::repo::InMemoryWidgetRepo;

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

    #[tokio::test]
    async fn create_rejects_empty_name() {
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
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
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
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
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
        let err = svc.get(Uuid::now_v7()).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    #[tokio::test]
    async fn soft_delete_hides_from_list_and_get() {
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
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
}

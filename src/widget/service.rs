use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::repo::WidgetRepo;
use super::types::{CreateWidget, Widget};
use crate::error::AppError;

/// 业务逻辑层。范式:
/// - 持 `Arc<dyn WidgetRepo>` 端口,不关心底层是内存还是 Postgres。
/// - 在此做输入校验、编排、业务规则;handler 保持薄。
/// - `Clone` 廉价(只 clone Arc),可直接放进 `AppState`。
#[derive(Clone)]
pub struct WidgetService {
    repo: Arc<dyn WidgetRepo>,
}

impl WidgetService {
    pub fn new(repo: Arc<dyn WidgetRepo>) -> Self {
        Self { repo }
    }

    pub async fn list(&self) -> Result<Vec<Widget>, AppError> {
        self.repo.list().await
    }

    pub async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        self.repo.get(id).await
    }

    pub async fn create(&self, input: CreateWidget) -> Result<Widget, AppError> {
        // 输入校验在业务边界做(garde 声明式规则);失败经 From<Report> 变 422
        input.validate()?;
        self.repo.create(input.name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widget::repo::InMemoryWidgetRepo;

    #[tokio::test]
    async fn create_rejects_empty_name() {
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
        let err = svc
            .create(CreateWidget {
                name: String::new(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn create_then_list_roundtrips() {
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
        svc.create(CreateWidget {
            name: "alpha".into(),
        })
        .await
        .unwrap();
        let all = svc.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "alpha");
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let svc = WidgetService::new(Arc::new(InMemoryWidgetRepo::new()));
        let err = svc.get(Uuid::now_v7()).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }
}

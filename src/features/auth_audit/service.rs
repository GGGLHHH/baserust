//! 薄 service:query DTO → 域内查询的组装 + stats 时间窗缺省/clamp。
//! handler 只做鉴权 + 接线判 404(`AppState.auth_audit = None` = 未接审计后端)。

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::repo::AuthEventRepo;
use super::types::{AuthEventFilter, AuthEventRow, AuthStats, StatsQuery};
use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};

#[derive(Clone)]
pub struct AuthAuditService {
    repo: Arc<dyn AuthEventRepo>,
}

impl AuthAuditService {
    pub fn new(repo: Arc<dyn AuthEventRepo>) -> Self {
        Self { repo }
    }

    /// 某用户的认证事件历史。
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
        filter: AuthEventFilter,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        self.repo
            .list(&filter.into_query(Some(user_id)), page)
            .await
    }

    /// 全局认证审计流。
    pub async fn list(
        &self,
        filter: AuthEventFilter,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        self.repo.list(&filter.into_query(None), page).await
    }

    /// 仪表盘统计。缺省最近 24h;clamp 92d(防 generate_series 巨量小时桶,
    /// ≥ 90d 留存期不截真实数据);from >= to 退化成 1h 窗口而非报错。
    pub async fn stats(&self, q: StatsQuery) -> Result<AuthStats, AppError> {
        let now = OffsetDateTime::now_utc();
        let to = q.to.unwrap_or(now);
        let from = q.from.unwrap_or(now - time::Duration::hours(24));
        let from = from.max(to - time::Duration::days(92));
        let from = if from < to {
            from
        } else {
            to - time::Duration::hours(1)
        };
        self.repo.stats(from, to).await
    }
}

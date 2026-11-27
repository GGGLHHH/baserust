//! 薄用例层:列表查询透传 + stats 时间窗缺省/clamp。
//! HTTP 适配只做鉴权 + 接线判 404(`AppState.auth_audit = None` = 未接审计后端)+ 线格式互转。

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::auth_event_repo::AuthEventRepo;
use super::model::{AuthEventQuery, AuthEventRow, AuthStats};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{Page, PageParams};
use crate::kernel::time_range::{RequestedTimeRange, TimeRange};

/// 认证审计的查询用例(列表 / 某用户的历史 / 仪表盘统计)。`Clone` 廉价(只 clone `Arc`)。
#[derive(Clone)]
pub struct AuthAuditService {
    repo: Arc<dyn AuthEventRepo>,
}

impl AuthAuditService {
    pub fn new(repo: Arc<dyn AuthEventRepo>) -> Self {
        Self { repo }
    }

    /// 某用户的认证事件历史(`query.user_id` 被覆盖为该用户)。
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
        mut query: AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        query.user_id = Some(user_id);
        self.repo.list(&query, page).await
    }

    /// 全局认证审计流。
    pub async fn list(
        &self,
        query: AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        self.repo.list(&query, page).await
    }

    /// 仪表盘统计。缺省最近 24h;clamp 92d(防 generate_series 巨量小时桶,
    /// ≥ 90d 留存期不截真实数据);from >= to 退化成 1h 窗口而非报错。
    pub async fn stats(&self, requested: RequestedTimeRange) -> Result<AuthStats, AppError> {
        let now = OffsetDateTime::now_utc();
        let to = requested.to.unwrap_or(now);
        let from = requested.from.unwrap_or(now - Duration::hours(24));
        let from = from.max(to - Duration::days(92));
        let from = if from < to {
            from
        } else {
            to - Duration::hours(1)
        };
        self.repo.stats(TimeRange { from, to }).await
    }
}

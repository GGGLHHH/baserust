//! auth_audit 的**端口**:投影读模型的仓储(实现:`in_memory_auth_event_repo` / `adapters::pg_auth_event_repo`)。

use async_trait::async_trait;
use time::OffsetDateTime;

use super::model::{AuthEventQuery, AuthEventRow, AuthStats, NewAuthEvent};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{Page, PageParams};
use crate::kernel::time_range::TimeRange;

/// 认证事件读模型的仓储端口(projector 写、admin 查询 / 统计读、保留期 job 删)。
#[async_trait]
pub trait AuthEventRepo: Send + Sync {
    /// 幂等落库:同 event_seq 重投不重复(ON CONFLICT DO NOTHING)。
    /// 返回是否**真插入**(false = 重投被幂等吞掉)—— projector 据此决定要不要 SSE 发布。
    async fn insert(&self, event: &NewAuthEvent) -> Result<bool, AppError>;
    /// keyset(id v7)+ 过滤列表。
    async fn list(
        &self,
        query: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError>;
    /// 保留:删 occurred_at < cutoff 的行,返回删除数。
    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError>;
    /// 仪表盘聚合:`[from, to)` 区间的时间序列 + group-by 计数(admin `/auth-events/stats` 用)。
    async fn stats(&self, range: TimeRange) -> Result<AuthStats, AppError>;
}

//! auth_audit 的**端口**:投影读模型的仓储(实现:`adapters::memory` / `adapters::postgres`)。

use async_trait::async_trait;
use time::OffsetDateTime;

use super::model::{AuthEventQuery, AuthEventRow, AuthStats, NewAuthEvent};
use crate::kernel::error::AppError;
use crate::kernel::pagination::{Page, PageParams};

#[async_trait]
pub trait AuthEventRepo: Send + Sync {
    /// 幂等落库:同 event_seq 重投不重复(ON CONFLICT DO NOTHING)。
    /// 返回是否**真插入**(false = 重投被幂等吞掉)—— projector 据此决定要不要 SSE 发布。
    async fn insert(&self, ev: &NewAuthEvent) -> Result<bool, AppError>;
    /// keyset(id v7)+ 过滤列表。
    async fn list(
        &self,
        q: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError>;
    /// 保留:删 occurred_at < cutoff 的行,返回删除数。
    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError>;
    /// 仪表盘聚合:`[from, to)` 区间的时间序列 + group-by 计数(admin `/auth-events/stats` 用)。
    async fn stats(&self, from: OffsetDateTime, to: OffsetDateTime) -> Result<AuthStats, AppError>;
}

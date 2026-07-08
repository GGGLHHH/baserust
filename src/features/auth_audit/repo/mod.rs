mod memory;
mod postgres;

pub use memory::InMemoryAuthEventRepo;
pub use postgres::PgAuthEventRepo;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::types::{AuthEventQuery, AuthEventRow, NewAuthEvent};
use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};

#[async_trait]
pub trait AuthEventRepo: Send + Sync {
    /// 幂等落库:同 event_seq 重投不重复(ON CONFLICT DO NOTHING)。
    async fn insert(&self, ev: &NewAuthEvent) -> Result<(), AppError>;
    /// keyset(id v7)+ 过滤列表。
    async fn list(
        &self,
        q: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError>;
    /// 保留:删 occurred_at < cutoff 的行,返回删除数。
    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError>;
}

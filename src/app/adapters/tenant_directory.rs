//! `auth::TenantDirectory` 的进程内适配器:转调 tenants 的仓储。
//!
//! 组合根是唯一同时认识两边的地方 —— auth 声明端口、tenants 有数据、这里做翻译。
//! 只做 map + 转调,零业务决策(那归 auth 的 handler)。

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::auth::{TenantBrief, TenantDirectory};
use crate::features::tenants::TenantRepo;
use crate::infra::error::AppError;

pub struct InProcessTenantDirectory {
    tenants: Arc<dyn TenantRepo>,
}

impl InProcessTenantDirectory {
    pub fn new(tenants: Arc<dyn TenantRepo>) -> Self {
        Self { tenants }
    }
}

#[async_trait]
impl TenantDirectory for InProcessTenantDirectory {
    async fn memberships_of(&self, user_id: Uuid) -> Result<Vec<TenantBrief>, AppError> {
        // `memberships` 的契约已保证:过滤停用/软删租户 + 按 seq 升序 —— 正是端口要的两条。
        Ok(self
            .tenants
            .memberships(user_id)
            .await?
            .into_iter()
            .map(|m| TenantBrief {
                id: m.tenant_id,
                name: m.name,
                display_name: m.display_name,
            })
            .collect())
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        self.tenants.set_active(user_id, tenant_id).await
    }
}

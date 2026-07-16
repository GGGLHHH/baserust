//! 内存实现 —— 脚手架默认,无需数据库即可跑通全链路。
//! 镜像 PG 的「memberships 过滤 suspended/软删 + granted_at 升序」语义(conformance 对拍钉住)。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

#[derive(Clone)]
struct TenantRow {
    name: String,
    display_name: String,
    status: TenantStatus,
    deleted_at: Option<OffsetDateTime>,
}

#[derive(Clone)]
struct MemberRow {
    role: TenantRole,
    granted_at: OffsetDateTime,
}

/// 一把锁覆盖三张表 —— 与 PG 侧同一个原子段口径(镜像 widget 的 MemStore 手法)。
#[derive(Default)]
struct MemStore {
    tenants: HashMap<Uuid, TenantRow>,
    /// (user_id, tenant_id) -> MemberRow
    members: HashMap<(Uuid, Uuid), MemberRow>,
    active: HashMap<Uuid, Uuid>,
}

pub struct InMemoryTenantRepo {
    store: Mutex<MemStore>,
}

impl InMemoryTenantRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(MemStore::default()),
        }
    }
}

impl Default for InMemoryTenantRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStore {
    /// 镜像 PG 的 `join tenants where deleted_at is null and status = 'active'`。
    /// 这是契约,不是优化 —— 见 repo/mod.rs 的 `memberships` doc。
    fn alive_membership(&self, user_id: Uuid, tenant_id: Uuid) -> Option<Membership> {
        let m = self.members.get(&(user_id, tenant_id))?;
        let t = self.tenants.get(&tenant_id)?;
        if t.deleted_at.is_some() || t.status != TenantStatus::Active {
            return None;
        }
        Some(Membership {
            tenant_id,
            name: t.name.clone(),
            display_name: t.display_name.clone(),
            role: m.role,
        })
    }
}

#[async_trait]
impl TenantRepo for InMemoryTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut rows: Vec<(OffsetDateTime, Membership)> = store
            .members
            .iter()
            .filter(|((u, _), _)| *u == user_id)
            .filter_map(|((u, t), m)| store.alive_membership(*u, *t).map(|ms| (m.granted_at, ms)))
            .collect();
        // granted_at 升序;同刻用 tenant_id 兜底,保证确定性(镜像 PG 的 ORDER BY granted_at, tenant_id)
        rows.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.tenant_id.cmp(&b.1.tenant_id))
        });
        Ok(rows.into_iter().map(|(_, m)| m).collect())
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        Ok(store.alive_membership(user_id, tenant_id))
    }

    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .active
            .get(&user_id)
            .copied())
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .active
            .insert(user_id, tenant_id);
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        _by: Option<String>,
    ) -> Result<(), AppError> {
        self.store.lock().expect("锁未中毒").tenants.insert(
            id,
            TenantRow {
                name: name.to_string(),
                display_name: display_name.to_string(),
                status,
                deleted_at: None,
            },
        );
        Ok(())
    }

    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        _by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 替换语义:granted_at **保留**(镜像 PG 的 on conflict do update 不碰 granted_at)——
        // 否则 memberships 的升序会因改个角色就跳位,.or(ms.first()) 的回退目标跟着变。
        let granted_at = store
            .members
            .get(&(user_id, tenant_id))
            .map(|m| m.granted_at)
            .unwrap_or_else(OffsetDateTime::now_utc);
        store
            .members
            .insert((user_id, tenant_id), MemberRow { role, granted_at });
        Ok(())
    }
}

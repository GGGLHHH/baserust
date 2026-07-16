//! Postgres 实现。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,无需 AssertSqlSafe)。
//! **连的是 idm role**(search_path=idm),表名无 schema 前缀靠 role 配置落位。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

pub struct PgTenantRepo {
    pool: PgPool,
}

impl PgTenantRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// **契约写死在 SQL 里**:下面两条读路径都必须 join tenants + 过滤软删/停用
// (见 repo/mod.rs 的 `memberships` doc)。这是 base_select() 的同位物 ——
// 只有两条读路径,各自内联比抽一个常量更短;第三条读路径出现时再抽。

const MEMBERSHIPS_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role \
     from tenant_members m join tenants t on t.id = m.tenant_id \
     where m.user_id = $1 and t.deleted_at is null and t.status = 'active' \
     order by m.granted_at, m.tenant_id";

const MEMBERSHIP_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role \
     from tenant_members m join tenants t on t.id = m.tenant_id \
     where m.user_id = $1 and m.tenant_id = $2 \
       and t.deleted_at is null and t.status = 'active'";

const ACTIVE_SQL: &str = "select tenant_id from user_active_tenant where user_id = $1";

/// `updated_at` **不在 do update 集里** —— 归 `user_active_tenant_set_updated_at` 触发器
/// (与 profile/repo/postgres.rs 的 UPSERT_SQL 同口径:全仓凡有 updated_at 的表都靠触发器)。
const SET_ACTIVE_SQL: &str = "insert into user_active_tenant (user_id, tenant_id) \
     values ($1, $2) \
     on conflict (user_id) do update set \
       tenant_id = excluded.tenant_id";

/// `deleted_at` **不在 do update 集里** —— 见 repo/mod.rs 的 `upsert_tenant` doc:
/// 软删是 spec §4.4 当作安全控制的机制,seed 每次启动都跑,不能让 upsert 静默把它
/// 改回 null、无声撤销运维手工做的停用决定。内存实现镜像了这条(memory.rs::upsert_tenant
/// 保留既有 deleted_at),conformance 用 `pg_upsert_tenant_does_not_revive_soft_deleted` 钉住。
const UPSERT_TENANT_SQL: &str = "insert into tenants \
     (id, name, display_name, status, created_by, updated_by) \
     values ($1, $2, $3, $4, $5, $5) \
     on conflict (id) do update set \
       name = excluded.name, \
       display_name = excluded.display_name, \
       status = excluded.status, \
       updated_by = excluded.updated_by";

/// `granted_at` **不在 do update 集里** —— 改角色不该让成员"重新加入"(会打乱
/// memberships 的升序,进而改变 TenantRoleRepo 的 .or(ms.first()) 回退目标)。
/// 内存实现镜像了这条(memory.rs::upsert_member 保留 granted_at),conformance 钉住。
const UPSERT_MEMBER_SQL: &str = "insert into tenant_members \
     (user_id, tenant_id, role, granted_by) \
     values ($1, $2, $3, $4) \
     on conflict (user_id, tenant_id) do update set \
       role = excluded.role, \
       granted_by = excluded.granted_by";

/// DB 的 role 裸值 → 枚举。**未知值 = 坏数据**(DB 有 check 约束,理论到不了这);
/// 到了就是 Internal,不猜、不降级 —— fail-closed(镜像 infra::error 里 content status
/// 解析失败的同款处理:脏值嵌进 anyhow 消息,只进日志,响应体只给通用 500)。
fn parse_role(s: &str) -> Result<TenantRole, AppError> {
    TenantRole::parse_db(s).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "tenant_members.role 出现闭集外的值,check 约束被绕过?: {s}"
        ))
    })
}

#[async_trait]
impl TenantRepo for PgTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(MEMBERSHIPS_SQL)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        rows.into_iter()
            .map(|(tenant_id, name, display_name, role)| {
                Ok(Membership {
                    tenant_id,
                    name,
                    display_name,
                    role: parse_role(&role)?,
                })
            })
            .collect()
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        let row: Option<(Uuid, String, String, String)> = sqlx::query_as(MEMBERSHIP_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        row.map(|(tenant_id, name, display_name, role)| {
            Ok(Membership {
                tenant_id,
                name,
                display_name,
                role: parse_role(&role)?,
            })
        })
        .transpose()
    }

    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        let row: Option<(Uuid,)> = sqlx::query_as(ACTIVE_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(row.map(|(id,)| id))
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        sqlx::query(SET_ACTIVE_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError> {
        sqlx::query(UPSERT_TENANT_SQL)
            .bind(id)
            .bind(name)
            .bind(display_name)
            .bind(status.as_db())
            .bind(by)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError> {
        sqlx::query(UPSERT_MEMBER_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .bind(role.as_db())
            .bind(by)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }
}

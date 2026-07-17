//! Postgres 实现。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,无需 AssertSqlSafe)。
//! **连的是 idm role**(search_path=idm),表名无 schema 前缀靠 role 配置落位。
//!
//! 行解码走 `sqlx::FromRow`(`Membership`)+ `sqlx::Type`(`TenantRole`),照 profile/auth_audit
//! 的既有范式 —— 不手拆元组、不手写 parse_*:闭集外的 role 值由 sqlx 的 decode 错误
//! fail-closed 成 `Internal`(脏值只进日志,响应体只给通用 500,见 infra/error.rs)。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{
    Membership, Tenant, TenantMemberFact, TenantRole, TenantStatus,
};
use crate::infra::error::AppError;

/// 唯一约束违例(23505)→ `Conflict`(409),其余 → `Internal`(500)。
/// 镜像 `widget/repo/postgres.rs::map_db_err` —— 建租户重名不该漏成 500。
fn map_db_err(e: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &e {
        if db.code().as_deref() == Some("23505") {
            return AppError::Conflict("tenant name already exists".to_owned());
        }
    }
    AppError::Internal(e.into())
}

pub struct PgTenantRepo {
    pool: PgPool,
}

impl PgTenantRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// **契约写死在 SQL 里**:下面两条读路径都必须 join tenants + 过滤软删/停用
// (见 repo/mod.rs 的 `memberships` doc)。这是 base_select() 的同位物。
// 两条各自内联那段 where(而非抽公共常量):Rust 的 `concat!` 不收 const 标识符,
// 抽出来要绕 macro_rules,而 conformance 对**两条路径**在**两个过滤维度**上都有对称断言
// (status 见共享契约、deleted_at 见 pg_memberships_filters_soft_deleted_tenant)——
// 「改一条漏改另一条」会被测试直接抓到,不是靠肉眼。第三条读路径出现时再抽。

/// `is_active` 由 left join 算出,**不是**单独查一次拼的 —— 两次读非同一快照,
/// 并发 set_active 时铸币路径会读到不一致的组合。见 repo/mod.rs 的 memberships doc。
/// `order by m.seq`:v7 严格全序,单列即可,不需要 tiebreak。
const MEMBERSHIPS_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role, \
       (a.tenant_id is not null) as is_active \
     from tenant_members m \
     join tenants t on t.id = m.tenant_id \
     left join user_active_tenant a \
       on a.user_id = m.user_id and a.tenant_id = m.tenant_id \
     where m.user_id = $1 and t.deleted_at is null and t.status = 'active' \
     order by m.seq";

const MEMBERSHIP_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role, \
       (a.tenant_id is not null) as is_active \
     from tenant_members m \
     join tenants t on t.id = m.tenant_id \
     left join user_active_tenant a \
       on a.user_id = m.user_id and a.tenant_id = m.tenant_id \
     where m.user_id = $1 and m.tenant_id = $2 \
       and t.deleted_at is null and t.status = 'active'";

/// `updated_at` 归 `user_active_tenant_set_updated_at` 触发器(与 profile 的 UPSERT_SQL 同口径:
/// 全仓凡有 updated_at 的表都靠触发器)。
/// **`where ... is distinct from ...` 守卫**:值没变就不 UPDATE ⇒ 触发器不触发 ⇒ updated_at
/// 的语义是「最近一次真正切换」而非「最近一次调用」。没有这个守卫,PG 的 BEFORE UPDATE
/// 触发器会无条件触发(它不比较 NEW/OLD),前端每次请求兜底调一遍就把它污染成「最近一次请求」。
const SET_ACTIVE_SQL: &str = "insert into user_active_tenant (user_id, tenant_id) \
     values ($1, $2) \
     on conflict (user_id) do update set \
       tenant_id = excluded.tenant_id \
     where user_active_tenant.tenant_id is distinct from excluded.tenant_id";

/// `deleted_at` **不在 do update 集里** —— 见 repo/mod.rs 的 `upsert_tenant` doc:
/// 软删是 spec §4.4 当作安全控制的机制,seed 每次启动都跑,不能让 upsert 静默把它
/// 改回 null、无声撤销运维手工做的停用决定。
/// `created_by` 同样不在集里(建时落 $5、替时保留);`updated_by` 每次按 $5 覆盖(含 NULL)。
const UPSERT_TENANT_SQL: &str = "insert into tenants \
     (id, name, display_name, status, created_by, updated_by) \
     values ($1, $2, $3, $4, $5, $5) \
     on conflict (id) do update set \
       name = excluded.name, \
       display_name = excluded.display_name, \
       status = excluded.status, \
       updated_by = excluded.updated_by";

/// **`do update` 只改 role** —— `seq` / `granted_at` / `granted_by` 三者都冻结:
/// 它们共同描述「这个人何时、被谁加进来」这一次事件,改角色不让它重新发生。
/// 见 repo/mod.rs 的 upsert_member doc(含曾经让 granted_by 随写覆盖导致的伪造审计记录)。
const UPSERT_MEMBER_SQL: &str = "insert into tenant_members \
     (user_id, tenant_id, role, seq, granted_by) \
     values ($1, $2, $3, $4, $5) \
     on conflict (user_id, tenant_id) do update set \
       role = excluded.role";

// ── P6 平台管理 ──

/// 存活行,最近建的在前。列不含 deleted_at(`Tenant` DTO 不暴露)。
const LIST_TENANTS_SQL: &str = "select id, name, display_name, status, created_at, updated_at \
     from tenants where deleted_at is null order by created_at desc";

const GET_TENANT_SQL: &str = "select id, name, display_name, status, created_at, updated_at \
     from tenants where id = $1 and deleted_at is null";

/// **INSERT**(非 upsert):重名 → 23505 → `map_db_err` → Conflict(409)。status 建时恒 active。
const CREATE_TENANT_SQL: &str = "insert into tenants \
     (id, name, display_name, status, created_by, updated_by) \
     values ($1, $2, $3, 'active', $4, $4) \
     returning id, name, display_name, status, created_at, updated_at";

/// 全量替换 display_name + status(name 不改);只动存活行。updated_at 归触发器。
const UPDATE_TENANT_SQL: &str =
    "update tenants set display_name = $2, status = $3, updated_by = $4 \
     where id = $1 and deleted_at is null \
     returning id, name, display_name, status, created_at, updated_at";

/// 某租户成员的原始事实(无 username —— 那由 service 富化)。按加入顺序。
const MEMBERS_OF_SQL: &str = "select user_id, role, granted_at \
     from tenant_members where tenant_id = $1 order by seq";

const REMOVE_MEMBER_SQL: &str = "delete from tenant_members where user_id = $1 and tenant_id = $2";

#[async_trait]
impl TenantRepo for PgTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        sqlx::query_as::<_, Membership>(MEMBERSHIPS_SQL)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        sqlx::query_as::<_, Membership>(MEMBERSHIP_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
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
            .bind(status)
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
        // seq 只在 INSERT 生效(conflict 分支不碰它)—— 与内存侧同语义。
        sqlx::query(UPSERT_MEMBER_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .bind(role)
            .bind(Uuid::now_v7())
            .bind(by)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, AppError> {
        sqlx::query_as::<_, Tenant>(LIST_TENANTS_SQL)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn get_tenant(&self, id: Uuid) -> Result<Option<Tenant>, AppError> {
        sqlx::query_as::<_, Tenant>(GET_TENANT_SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn create_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        sqlx::query_as::<_, Tenant>(CREATE_TENANT_SQL)
            .bind(id)
            .bind(name)
            .bind(display_name)
            .bind(by)
            .fetch_one(&self.pool)
            .await
            .map_err(map_db_err) // 重名 → 23505 → Conflict(409)
    }

    async fn update_tenant(
        &self,
        id: Uuid,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        sqlx::query_as::<_, Tenant>(UPDATE_TENANT_SQL)
            .bind(id)
            .bind(display_name)
            .bind(status)
            .bind(by)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)
    }

    async fn members_of(&self, tenant_id: Uuid) -> Result<Vec<TenantMemberFact>, AppError> {
        sqlx::query_as::<_, TenantMemberFact>(MEMBERS_OF_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn remove_member(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        let res = sqlx::query(REMOVE_MEMBER_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

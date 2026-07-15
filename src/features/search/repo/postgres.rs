//! Postgres 实现 —— 每个 `apply_*` = **一条守卫 upsert**(`ON CONFLICT ... WHERE`):冲突行只有
//! 落后于新 `seq` 才更新;新行(该 user_id 未见过)直接 insert(partial row,另一源列留空/默认)。
//! 固定语句 → const SQL(镜像 profile 仓储:无动态 filter/分页,不需要 sea-query)。
//! `query`(P4 动态读)例外 —— filter/排序/分页可变,走 sea-query(镜像 widget 的动态 list)。

use async_trait::async_trait;
use sea_query::extension::postgres::{PgBinOper, PgExpr};
use sea_query::{
    ArrayType, Cond, Expr, ExprTrait, Func, Iden, NullOrdering, Order, PostgresQueryBuilder, Query,
    SelectStatement, Value,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort, SearchIndexRepo};
use crate::infra::error::AppError;
use crate::infra::pagination::PageParams;
use crate::infra::sort::SortOrder;

pub struct PgSearchIndexRepo {
    pool: PgPool,
}

impl PgSearchIndexRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// sea-query 列标识符(动态 `query` 专用 —— `apply_*`/`get`/`rebuild_upsert` 是固定 SQL,不需要它)。
/// 表名不带 schema 前缀 —— search role 的 `search_path` 已隔离。
#[derive(Iden)]
enum AdminUserIndex {
    Table,
    UserId,
    Username,
    Email,
    EmailVerified,
    DisplayName,
    Roles,
    CreatedAt,
    Deleted,
    IdmSeq,
    ProfileSeq,
}

const QUERY_COLS: [AdminUserIndex; 10] = [
    AdminUserIndex::UserId,
    AdminUserIndex::Username,
    AdminUserIndex::Email,
    AdminUserIndex::EmailVerified,
    AdminUserIndex::DisplayName,
    AdminUserIndex::Roles,
    AdminUserIndex::CreatedAt,
    AdminUserIndex::Deleted,
    AdminUserIndex::IdmSeq,
    AdminUserIndex::ProfileSeq,
];

/// `query` 的固定起手式:半行(username 未落地)与软删行永不出现。
fn base_select() -> SelectStatement {
    let mut q = Query::select();
    q.from(AdminUserIndex::Table)
        .and_where(Expr::col(AdminUserIndex::Username).is_not_null())
        .and_where(Expr::col(AdminUserIndex::Deleted).eq(false));
    q
}

/// `roles_any`/`roles_none` 数组重叠(`&&`)判定用的 text[] 参数值(需 `postgres-array` 特性)。
fn roles_array(roles: &[String]) -> Value {
    Value::Array(
        ArrayType::String,
        Some(Box::new(roles.iter().cloned().map(Value::from).collect())),
    )
}

/// 转义 LIKE 元字符(`\ % _`)+ 包 `%...%`,口径逐字对齐 idm `PgUserRepo::list`(与内存 `contains`
/// parity)。`q`/`username` 两个独立子串过滤共用这一套转义,后者按 ILIKE 默认转义字符(反斜杠)
/// 生效——等价于显式 `ESCAPE '\'`,不需要重复声明。
fn ilike_contains(term: &str) -> String {
    let esc = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{esc}%")
}

/// 动态 filter 套到 select 上。主查询与 `COUNT` 查询共用,保证 total 与 rows 同一过滤口径。
fn apply_query_filters(q: &mut SelectStatement, filter: &IndexQuery) {
    if let Some(term) = filter.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let pattern = ilike_contains(term);
        q.cond_where(
            Cond::any()
                .add(Expr::col(AdminUserIndex::Username).ilike(pattern.clone()))
                .add(Expr::col(AdminUserIndex::DisplayName).ilike(pattern)),
        );
    }
    // username:仅 username 的子串,与上面的 q(username OR display_name)是独立分支,AND 组合。
    if let Some(term) = filter
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        q.and_where(Expr::col(AdminUserIndex::Username).ilike(ilike_contains(term)));
    }
    if !filter.roles_any.is_empty() {
        q.and_where(Expr::col(AdminUserIndex::Roles).binary(
            PgBinOper::Overlap,
            Expr::val(roles_array(&filter.roles_any)),
        ));
    }
    if !filter.roles_none.is_empty() {
        q.and_where(
            Expr::col(AdminUserIndex::Roles)
                .binary(
                    PgBinOper::Overlap,
                    Expr::val(roles_array(&filter.roles_none)),
                )
                .not(),
        );
    }
    if let Some(from) = filter.created_from {
        q.and_where(Expr::col(AdminUserIndex::CreatedAt).gte(from));
    }
    if let Some(to) = filter.created_to {
        q.and_where(Expr::col(AdminUserIndex::CreatedAt).lte(to));
    }
}

/// 排序主键表达式:字符串列加 `COLLATE "C"` 强制字节序,与内存 `str Ord` parity(否则 PG 按列
/// collation 可能大小写混排漂移);`created_at` 是时间戳,无 collation。
fn sort_expr(sort: IndexSort) -> Expr {
    match sort {
        IndexSort::CreatedAt => Expr::col(AdminUserIndex::CreatedAt),
        IndexSort::Username => Expr::cust(r#""admin_user_index"."username" COLLATE "C""#),
        IndexSort::DisplayName => Expr::cust(r#""admin_user_index"."display_name" COLLATE "C""#),
        IndexSort::Email => Expr::cust(r#""admin_user_index"."email" COLLATE "C""#),
    }
}

const GET_SQL: &str = "select user_id, username, email, email_verified, display_name, \
     roles, created_at, deleted, idm_seq, profile_seq \
     from admin_user_index where user_id = $1";

/// `user.created`:idm 列一次填全(含 `deleted=false` 基线)+ `idm_seq`。守卫同其余 idm 方法。
const APPLY_USER_CREATED_SQL: &str = "insert into admin_user_index \
     (user_id, username, email, email_verified, roles, created_at, deleted, idm_seq) \
     values ($1, $2, $3, $4, $5, $6, false, $7) \
     on conflict (user_id) do update set \
       username = excluded.username, \
       email = excluded.email, \
       email_verified = excluded.email_verified, \
       roles = excluded.roles, \
       created_at = excluded.created_at, \
       deleted = false, \
       idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where admin_user_index.idm_seq is null or admin_user_index.idm_seq < excluded.idm_seq";

/// `user.updated`:只动 username/email/email_verified + `idm_seq`(**不碰** roles/created_at/deleted)。
const APPLY_USER_UPDATED_SQL: &str = "insert into admin_user_index \
     (user_id, username, email, email_verified, idm_seq) \
     values ($1, $2, $3, $4, $5) \
     on conflict (user_id) do update set \
       username = excluded.username, email = excluded.email, \
       email_verified = excluded.email_verified, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where admin_user_index.idm_seq is null or admin_user_index.idm_seq < excluded.idm_seq";

/// `roles.set`:只动 roles + `idm_seq`。
const APPLY_ROLES_SET_SQL: &str = "insert into admin_user_index (user_id, roles, idm_seq) \
     values ($1, $2, $3) \
     on conflict (user_id) do update set \
       roles = excluded.roles, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where admin_user_index.idm_seq is null or admin_user_index.idm_seq < excluded.idm_seq";

/// `user.deleted`:只动 `deleted=true` + `idm_seq`。
const APPLY_USER_DELETED_SQL: &str = "insert into admin_user_index (user_id, deleted, idm_seq) \
     values ($1, true, $2) \
     on conflict (user_id) do update set \
       deleted = true, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where admin_user_index.idm_seq is null or admin_user_index.idm_seq < excluded.idm_seq";

/// `profile.updated`:只动 display_name + `profile_seq`(独立水位,和 idm 列不相交)。
const APPLY_PROFILE_UPDATED_SQL: &str =
    "insert into admin_user_index (user_id, display_name, profile_seq) \
     values ($1, $2, $3) \
     on conflict (user_id) do update set \
       display_name = excluded.display_name, profile_seq = excluded.profile_seq, \
       updated_at = (now() at time zone 'utc') \
     where admin_user_index.profile_seq is null or admin_user_index.profile_seq < excluded.profile_seq";

/// 重建 bin 用:把不在快照(`$1` = 存活 id 数组)里的行扫成已删。
/// `<> all($1)` 对空数组恒真 → 源里没存活用户就全扫(合法语义,见 trait 注)。
/// `idm_seq <= $2` 守卫:比快照新的行(rebuild 期间刚投影进来)不动;`is null` 也扫(没水位 =
/// 早于任何快照)。已 `deleted` 的排除掉,返回行数才等于"这次真扫了几行"。
const MARK_DELETED_EXCEPT_SQL: &str = "update admin_user_index set \
       deleted = true, idm_seq = $2, updated_at = (now() at time zone 'utc') \
     where user_id <> all($1) and deleted = false \
       and (idm_seq is null or idm_seq <= $2)";

/// 重建 bin 用:全列 upsert,**无 WHERE 守卫**——无条件覆写(快照重建语义,非事件回放)。
const REBUILD_UPSERT_SQL: &str = "insert into admin_user_index \
     (user_id, username, email, email_verified, display_name, roles, created_at, deleted, \
      idm_seq, profile_seq) \
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     on conflict (user_id) do update set \
       username = excluded.username, \
       email = excluded.email, \
       email_verified = excluded.email_verified, \
       display_name = excluded.display_name, \
       roles = excluded.roles, \
       created_at = excluded.created_at, \
       deleted = excluded.deleted, \
       idm_seq = excluded.idm_seq, \
       profile_seq = excluded.profile_seq, \
       updated_at = (now() at time zone 'utc')";

#[async_trait]
impl SearchIndexRepo for PgSearchIndexRepo {
    #[allow(clippy::too_many_arguments)] // 领域事件字段展开,拆参数对象不值当(仅此一处超阈)
    async fn apply_user_created(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        roles: &[String],
        created_at: OffsetDateTime,
        seq: i64,
    ) -> Result<(), AppError> {
        sqlx::query(APPLY_USER_CREATED_SQL)
            .bind(user_id)
            .bind(username)
            .bind(email)
            .bind(email_verified)
            .bind(roles)
            .bind(created_at)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn apply_user_updated(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        seq: i64,
    ) -> Result<(), AppError> {
        sqlx::query(APPLY_USER_UPDATED_SQL)
            .bind(user_id)
            .bind(username)
            .bind(email)
            .bind(email_verified)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        sqlx::query(APPLY_ROLES_SET_SQL)
            .bind(user_id)
            .bind(roles)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn apply_user_deleted(&self, user_id: Uuid, seq: i64) -> Result<(), AppError> {
        sqlx::query(APPLY_USER_DELETED_SQL)
            .bind(user_id)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        seq: i64,
    ) -> Result<(), AppError> {
        sqlx::query(APPLY_PROFILE_UPDATED_SQL)
            .bind(user_id)
            .bind(display_name)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn rebuild_upsert(&self, row: AdminUserIndexRow) -> Result<(), AppError> {
        sqlx::query(REBUILD_UPSERT_SQL)
            .bind(row.user_id)
            .bind(row.username)
            .bind(row.email)
            .bind(row.email_verified)
            .bind(row.display_name)
            .bind(row.roles)
            .bind(row.created_at)
            .bind(row.deleted)
            .bind(row.idm_seq)
            .bind(row.profile_seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn mark_deleted_except(&self, alive: &[Uuid], p_idm: i64) -> Result<usize, AppError> {
        let r = sqlx::query(MARK_DELETED_EXCEPT_SQL)
            .bind(alive)
            .bind(p_idm)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(r.rows_affected() as usize)
    }

    async fn get(&self, user_id: Uuid) -> Result<Option<AdminUserIndexRow>, AppError> {
        sqlx::query_as::<_, AdminUserIndexRow>(GET_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }

    async fn query(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError> {
        let sq_order: Order = order.into();
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                // SELECT cols FROM admin_user_index WHERE <基线 + 动态 filter>
                //   ORDER BY <sort> COLLATE?/NULLS LAST, user_id <order> LIMIT size OFFSET (page-1)*size
                let mut q = base_select();
                q.columns(QUERY_COLS);
                apply_query_filters(&mut q, filter);
                q.order_by_expr_with_nulls(sort_expr(sort), sq_order.clone(), NullOrdering::Last)
                    .order_by(AdminUserIndex::UserId, sq_order)
                    .limit(*size)
                    .offset((page.saturating_sub(1)) * size);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows = sqlx::query_as_with::<sqlx::Postgres, AdminUserIndexRow, _>(
                    AssertSqlSafe(sql),
                    values,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

                let total = if *with_total {
                    // COUNT(user_id) 同 filter,去 limit/offset/order,保证与 rows 同口径。
                    let mut c = base_select();
                    apply_query_filters(&mut c, filter);
                    c.expr(Func::count(Expr::col(AdminUserIndex::UserId)));
                    let (csql, cvalues) = c.build_sqlx(PostgresQueryBuilder);
                    let n: i64 = sqlx::query_scalar_with::<sqlx::Postgres, i64, _>(
                        AssertSqlSafe(csql),
                        cvalues,
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;
                    Some(n as u64)
                } else {
                    None
                };
                Ok(IndexQueryResult {
                    rows,
                    total,
                    next_after: None,
                })
            }
            PageParams::Cursor { after, limit } => {
                // keyset 恒按 user_id(忽略 sort —— 换排序键会破翻页正确性),但方向跟 order 走
                // (镜像 idm `PgUserRepo::list`)——只有默认 created_at 排序时 handler 才放行 cursor,
                // 这时 order 才是唯一有意义的方向信号,keyset 必须跟它一致,不能悄悄扣死升序。
                // 取 limit+1 判 has_more。
                let mut q = base_select();
                q.columns(QUERY_COLS);
                apply_query_filters(&mut q, filter);
                if let Some(after) = after {
                    let cond = match order {
                        SortOrder::Asc => Expr::col(AdminUserIndex::UserId).gt(*after),
                        SortOrder::Desc => Expr::col(AdminUserIndex::UserId).lt(*after),
                    };
                    q.and_where(cond);
                }
                q.order_by(AdminUserIndex::UserId, sq_order)
                    .limit(*limit + 1);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let mut rows = sqlx::query_as_with::<sqlx::Postgres, AdminUserIndexRow, _>(
                    AssertSqlSafe(sql),
                    values,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

                let has_more = rows.len() as u64 > *limit;
                let next_after = if has_more {
                    rows.truncate(*limit as usize);
                    rows.last().map(|r| r.user_id)
                } else {
                    None
                };
                Ok(IndexQueryResult {
                    rows,
                    total: None,
                    next_after,
                })
            }
        }
    }
}

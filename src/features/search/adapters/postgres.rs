//! search 仓储端口的 **Postgres 适配器**。两张表:账号目录 `account_index`(全局)、租户成员索引
//! `admin_user_index`(主键 `(tenant_id, user_id)`,FORCE RLS)。
//!
//! - 每个 `apply_*` = 守卫 upsert(`ON CONFLICT ... WHERE`):冲突行只有落后于新 `seq` 才更新。账号事件在
//!   **一个事务**里先写账号目录、再 `update` 该用户在所有租户里的成员行(各行各自的水位守卫);成员事件
//!   `insert … select … from account_index`(新行的账号列从账号目录抄)。
//! - **写侧必须用 search 的 system 池**(BYPASSRLS,投影器 / rebuild):账号事件要改所有租户的行,运行时账号
//!   受 RLS 约束改不到别的租户。成员事件和读方法照样在租户事务里跑(`infra::pg::tenant_tx`,SQL 也写
//!   `tenant_id = $1`),RLS 是第二道防线。
//! - `query`(某租户成员列表)/ `query_accounts`(平台账号列表,账号目录)动态 filter / 排序 / 分页走 sea-query,
//!   两表共用一套构造(`run_query`);其余是固定 SQL。

use async_trait::async_trait;
use sea_query::extension::postgres::{PgBinOper, PgExpr};
use sea_query::{
    ArrayType, Cond, Expr, ExprTrait, Func, Iden, NullOrdering, Order, PostgresQueryBuilder, Query,
    SelectStatement, Value,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::search::model::{
    AccountIndexRow, AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort,
};
use crate::features::search::ports::SearchIndexRepo;
use crate::infra::pg::{order as pg_order, tenant_tx};
use crate::kernel::error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

pub struct PgSearchIndexRepo {
    pool: PgPool,
}

impl PgSearchIndexRepo {
    /// 写侧(投影器 / rebuild)传 search 的 **system 池**;只读(请求路径的成员列表)传运行时池。
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn tx(&self) -> Result<Transaction<'static, Postgres>, AppError> {
        self.pool.begin().await.map_err(internal)
    }

    async fn tenant_tx(
        &self,
        tenant: TenantId,
    ) -> Result<Transaction<'static, Postgres>, AppError> {
        tenant_tx(&self.pool, tenant).await.map_err(internal)
    }
}

fn internal(e: sqlx::Error) -> AppError {
    AppError::Internal(e.into())
}

/// `account_index` 的一行(数据库形状)。只在本适配器内存在,出门即转成领域行。
#[derive(sqlx::FromRow)]
struct AccountRecord {
    user_id: Uuid,
    username: Option<String>,
    email: Option<String>,
    email_verified: bool,
    display_name: Option<String>,
    roles: Vec<String>,
    created_at: Option<OffsetDateTime>,
    deleted: bool,
    idm_seq: Option<i64>,
    profile_seq: Option<i64>,
}

impl From<AccountRecord> for AccountIndexRow {
    fn from(r: AccountRecord) -> Self {
        Self {
            user_id: r.user_id,
            username: r.username,
            email: r.email,
            email_verified: r.email_verified,
            display_name: r.display_name,
            roles: r.roles,
            created_at: r.created_at,
            deleted: r.deleted,
            idm_seq: r.idm_seq,
            profile_seq: r.profile_seq,
        }
    }
}

/// `admin_user_index` 的一行(数据库形状)。
#[derive(sqlx::FromRow)]
struct MemberRecord {
    tenant_id: Uuid,
    user_id: Uuid,
    username: Option<String>,
    email: Option<String>,
    email_verified: bool,
    display_name: Option<String>,
    created_at: Option<OffsetDateTime>,
    deleted: bool,
    idm_seq: Option<i64>,
    profile_seq: Option<i64>,
    roles: Vec<String>,
    status: Option<String>,
    removed: bool,
    member_seq: Option<i64>,
}

impl TryFrom<MemberRecord> for AdminUserIndexRow {
    type Error = AppError;
    fn try_from(r: MemberRecord) -> Result<Self, AppError> {
        Ok(Self {
            // CHECK 约束保证非 nil;真出现了是数据完整性故障 → 500。
            tenant_id: TenantId::new(r.tenant_id).map_err(|e| {
                AppError::Internal(anyhow::anyhow!("admin_user_index.tenant_id: {e}"))
            })?,
            user_id: r.user_id,
            username: r.username,
            email: r.email,
            email_verified: r.email_verified,
            display_name: r.display_name,
            created_at: r.created_at,
            deleted: r.deleted,
            idm_seq: r.idm_seq,
            profile_seq: r.profile_seq,
            roles: r.roles,
            status: r.status,
            removed: r.removed,
            member_seq: r.member_seq,
        })
    }
}

fn decode_members(rows: Vec<MemberRecord>) -> Result<Vec<AdminUserIndexRow>, AppError> {
    rows.into_iter().map(AdminUserIndexRow::try_from).collect()
}

/// sea-query 列标识符(动态 `query` / `query_accounts` 专用)。表名不带 schema 前缀 —— search 账号的
/// `search_path` 已隔离。两张表同名的列(username / roles / created_at …)共用这些标识(不带表名前缀)。
#[derive(Iden, Clone, Copy)]
enum AdminUserIndex {
    Table,
    TenantId,
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
    Status,
    Removed,
    MemberSeq,
}

#[derive(Iden)]
enum AccountIndex {
    Table,
}

/// 动态查询查哪张表:某租户的成员索引,或全局账号目录。
#[derive(Clone, Copy)]
enum Target {
    Members(TenantId),
    Accounts,
}

impl Target {
    fn table(self) -> &'static str {
        match self {
            Target::Members(_) => "admin_user_index",
            Target::Accounts => "account_index",
        }
    }
}

/// 账号目录的列(列名与成员索引同名)。
const ACCOUNT_QUERY_COLS: [AdminUserIndex; 10] = [
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

const QUERY_COLS: [AdminUserIndex; 14] = [
    AdminUserIndex::TenantId,
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
    AdminUserIndex::Status,
    AdminUserIndex::Removed,
    AdminUserIndex::MemberSeq,
];

/// 动态查询的固定起手式:半行(username 未落地)、已删账号永不出现;成员索引再加「只看本租户」
/// (RLS 之外再写一遍,走索引)+「已移出的成员不出现」。
fn base_select(target: Target) -> SelectStatement {
    let mut q = Query::select();
    match target {
        Target::Members(tenant) => {
            q.from(AdminUserIndex::Table)
                .and_where(Expr::col(AdminUserIndex::TenantId).eq(tenant.as_uuid()))
                .and_where(Expr::col(AdminUserIndex::Removed).eq(false));
        }
        Target::Accounts => {
            q.from(AccountIndex::Table);
        }
    }
    q.and_where(Expr::col(AdminUserIndex::Username).is_not_null())
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
fn sort_expr(target: Target, sort: IndexSort) -> Expr {
    let collated = |col: &str| Expr::cust(format!(r#""{}"."{col}" COLLATE "C""#, target.table()));
    match sort {
        IndexSort::CreatedAt => Expr::col(AdminUserIndex::CreatedAt),
        IndexSort::Username => collated("username"),
        IndexSort::DisplayName => collated("display_name"),
        IndexSort::Email => collated("email"),
    }
}

/// 动态 filter + 排序 + 分页的执行(两张表共用;`conn` 由调用方给 —— 成员索引是租户事务,账号目录是池连接)。
/// offset:按 `sort` 排(NULLS LAST)+ user_id 兜底,带 total 时同口径 COUNT;cursor:恒按 user_id keyset,
/// 方向随 `order`(镜像 idm `PgUserRepo::list`;只有默认 created_at 排序时 handler 才放行 cursor),取 limit+1 判 has_more。
#[allow(clippy::too_many_arguments)] // 查询参数逐个透传,拆结构体不值当
async fn run_query<R>(
    conn: &mut sqlx::PgConnection,
    target: Target,
    cols: &[AdminUserIndex],
    filter: &IndexQuery,
    sort: IndexSort,
    order: SortOrder,
    page: &PageParams,
    key: fn(&R) -> Uuid,
) -> Result<IndexQueryResult<R>, AppError>
where
    R: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
{
    let sq_order: Order = pg_order(order);
    let mut q = base_select(target);
    q.columns(cols.iter().copied());
    apply_query_filters(&mut q, filter);
    match page {
        PageParams::Offset {
            page,
            size,
            with_total,
        } => {
            q.order_by_expr_with_nulls(
                sort_expr(target, sort),
                sq_order.clone(),
                NullOrdering::Last,
            )
            .order_by(AdminUserIndex::UserId, sq_order)
            .limit(*size)
            .offset((page.saturating_sub(1)) * size);
            let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
            let rows = sqlx::query_as_with::<sqlx::Postgres, R, _>(AssertSqlSafe(sql), values)
                .fetch_all(&mut *conn)
                .await
                .map_err(internal)?;
            let total = if *with_total {
                // COUNT(user_id) 同 filter,去 limit/offset/order,保证与 rows 同口径。
                let mut c = base_select(target);
                apply_query_filters(&mut c, filter);
                c.expr(Func::count(Expr::col(AdminUserIndex::UserId)));
                let (csql, cvalues) = c.build_sqlx(PostgresQueryBuilder);
                let n: i64 =
                    sqlx::query_scalar_with::<sqlx::Postgres, i64, _>(AssertSqlSafe(csql), cvalues)
                        .fetch_one(&mut *conn)
                        .await
                        .map_err(internal)?;
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
            let mut rows = sqlx::query_as_with::<sqlx::Postgres, R, _>(AssertSqlSafe(sql), values)
                .fetch_all(&mut *conn)
                .await
                .map_err(internal)?;
            let has_more = rows.len() as u64 > *limit;
            let next_after = if has_more {
                rows.truncate(*limit as usize);
                rows.last().map(key)
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

const ACCOUNT_COLS: &str =
    "user_id, username, email, email_verified, display_name, roles, created_at, \
     deleted, idm_seq, profile_seq";
const MEMBER_COLS: &str = "tenant_id, user_id, username, email, email_verified, display_name, \
     created_at, deleted, idm_seq, profile_seq, roles, status, removed, member_seq";

/// 成员行时间戳(各 SQL 共用)。
const NOW_UTC: &str = "(now() at time zone 'utc')";

// ── 账号目录(account_index):守卫 upsert,同多租户之前的 admin_user_index ──

/// `user.created`:idm 列一次填全(含 `deleted=false` 基线)+ `idm_seq`。
const ACCOUNT_USER_CREATED_SQL: &str = "insert into account_index \
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
     where account_index.idm_seq is null or account_index.idm_seq < excluded.idm_seq";

/// `user.updated`:只动 username/email/email_verified + `idm_seq`(**不碰** roles/created_at/deleted)。
const ACCOUNT_USER_UPDATED_SQL: &str = "insert into account_index \
     (user_id, username, email, email_verified, idm_seq) \
     values ($1, $2, $3, $4, $5) \
     on conflict (user_id) do update set \
       username = excluded.username, email = excluded.email, \
       email_verified = excluded.email_verified, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where account_index.idm_seq is null or account_index.idm_seq < excluded.idm_seq";

/// `user.roles_set`(平台角色):只动 roles + `idm_seq`。
const ACCOUNT_ROLES_SET_SQL: &str = "insert into account_index (user_id, roles, idm_seq) \
     values ($1, $2, $3) \
     on conflict (user_id) do update set \
       roles = excluded.roles, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where account_index.idm_seq is null or account_index.idm_seq < excluded.idm_seq";

/// `user.deleted`:只动 `deleted=true` + `idm_seq`。
const ACCOUNT_USER_DELETED_SQL: &str = "insert into account_index (user_id, deleted, idm_seq) \
     values ($1, true, $2) \
     on conflict (user_id) do update set \
       deleted = true, idm_seq = excluded.idm_seq, \
       updated_at = (now() at time zone 'utc') \
     where account_index.idm_seq is null or account_index.idm_seq < excluded.idm_seq";

/// `profile.updated`:只动 display_name + `profile_seq`(独立水位,和 idm 列不相交)。
const ACCOUNT_PROFILE_UPDATED_SQL: &str =
    "insert into account_index (user_id, display_name, profile_seq) \
     values ($1, $2, $3) \
     on conflict (user_id) do update set \
       display_name = excluded.display_name, profile_seq = excluded.profile_seq, \
       updated_at = (now() at time zone 'utc') \
     where account_index.profile_seq is null or account_index.profile_seq < excluded.profile_seq";

/// 重建 bin 用:全列 upsert,**无 WHERE 守卫**——无条件覆写(快照重建语义,非事件回放)。
const ACCOUNT_REBUILD_SQL: &str = "insert into account_index \
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

// ── 账号事件同步到该用户的**全部**成员行(每行各自的水位守卫;只有已存在的行,不建新行)──

const MEMBERS_USER_CREATED_SQL: &str = "update admin_user_index set \
       username = $2, email = $3, email_verified = $4, created_at = $5, deleted = false, \
       idm_seq = $6, updated_at = (now() at time zone 'utc') \
     where user_id = $1 and (idm_seq is null or idm_seq < $6)";

const MEMBERS_USER_UPDATED_SQL: &str = "update admin_user_index set \
       username = $2, email = $3, email_verified = $4, \
       idm_seq = $5, updated_at = (now() at time zone 'utc') \
     where user_id = $1 and (idm_seq is null or idm_seq < $5)";

const MEMBERS_USER_DELETED_SQL: &str = "update admin_user_index set \
       deleted = true, idm_seq = $2, updated_at = (now() at time zone 'utc') \
     where user_id = $1 and (idm_seq is null or idm_seq < $2)";

const MEMBERS_PROFILE_UPDATED_SQL: &str = "update admin_user_index set \
       display_name = $2, profile_seq = $3, updated_at = (now() at time zone 'utc') \
     where user_id = $1 and (profile_seq is null or profile_seq < $3)";

// ── 成员事件:没有行就新建(账号列从账号目录抄),有行就按 member_seq 守卫只改本事件的列 ──
// `from (select 1) one left join account_index`:账号目录还没有这个账号时也照样插一行(账号列留空)。

/// 新成员行的账号列(从账号目录抄),拼在各成员 SQL 的 select 里。参数 $1 = tenant_id、$2 = user_id。
const MEMBER_INSERT_HEAD: &str = "insert into admin_user_index \
     (tenant_id, user_id, username, email, email_verified, display_name, created_at, deleted, \
      idm_seq, profile_seq, status, roles, removed, member_seq) \
     select $1, $2, a.username, a.email, coalesce(a.email_verified, false), a.display_name, \
      a.created_at, coalesce(a.deleted, false), a.idm_seq, a.profile_seq, ";
const MEMBER_INSERT_TAIL: &str =
    " from (select 1) one left join account_index a on a.user_id = $2 \
     on conflict (tenant_id, user_id) do update set ";
const MEMBER_GUARD: &str = " where admin_user_index.member_seq is null \
     or admin_user_index.member_seq < excluded.member_seq";

/// 拼一条成员事件 SQL:`values` = status, roles, removed, member_seq 四列的取值表达式;`set` = 冲突时
/// 只改的那几列(本事件拥有的列)。
fn member_sql(values: &str, set: &str) -> String {
    format!(
        "{MEMBER_INSERT_HEAD}{values}{MEMBER_INSERT_TAIL}{set}, \
         member_seq = excluded.member_seq, updated_at = {NOW_UTC}{MEMBER_GUARD}"
    )
}

/// 重建 bin 用:成员行全列 upsert,无守卫。
const MEMBER_REBUILD_SQL: &str = "insert into admin_user_index \
     (tenant_id, user_id, username, email, email_verified, display_name, created_at, deleted, \
      idm_seq, profile_seq, roles, status, removed, member_seq) \
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
     on conflict (tenant_id, user_id) do update set \
       username = excluded.username, email = excluded.email, \
       email_verified = excluded.email_verified, display_name = excluded.display_name, \
       created_at = excluded.created_at, deleted = excluded.deleted, \
       idm_seq = excluded.idm_seq, profile_seq = excluded.profile_seq, \
       roles = excluded.roles, status = excluded.status, removed = excluded.removed, \
       member_seq = excluded.member_seq, updated_at = (now() at time zone 'utc')";

/// `tenant.deleted`:该租户全部成员行标记移出(水位落后的行)。
const TENANT_DELETED_SQL: &str = "update admin_user_index set \
       removed = true, member_seq = $2, updated_at = (now() at time zone 'utc') \
     where tenant_id = $1 and (member_seq is null or member_seq < $2)";

#[async_trait]
impl SearchIndexRepo for PgSearchIndexRepo {
    #[allow(clippy::too_many_arguments)] // 领域事件字段展开,拆参数对象不值当(仅此一处超阈)
    #[tracing::instrument(name = "pg.search_index.apply_user_created", skip_all)]
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
        let mut tx = self.tx().await?;
        sqlx::query(ACCOUNT_USER_CREATED_SQL)
            .bind(user_id)
            .bind(username)
            .bind(email)
            .bind(email_verified)
            .bind(roles)
            .bind(created_at)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query(MEMBERS_USER_CREATED_SQL)
            .bind(user_id)
            .bind(username)
            .bind(email)
            .bind(email_verified)
            .bind(created_at)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_user_updated", skip_all)]
    async fn apply_user_updated(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        seq: i64,
    ) -> Result<(), AppError> {
        let mut tx = self.tx().await?;
        for sql in [ACCOUNT_USER_UPDATED_SQL, MEMBERS_USER_UPDATED_SQL] {
            sqlx::query(sql)
                .bind(user_id)
                .bind(username)
                .bind(email)
                .bind(email_verified)
                .bind(seq)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_roles_set", skip_all)]
    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        // 平台角色只在账号目录;成员行的 roles 是租户角色,不动。
        sqlx::query(ACCOUNT_ROLES_SET_SQL)
            .bind(user_id)
            .bind(roles)
            .bind(seq)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.search_index.apply_user_deleted", skip_all)]
    async fn apply_user_deleted(&self, user_id: Uuid, seq: i64) -> Result<(), AppError> {
        let mut tx = self.tx().await?;
        for sql in [ACCOUNT_USER_DELETED_SQL, MEMBERS_USER_DELETED_SQL] {
            sqlx::query(sql)
                .bind(user_id)
                .bind(seq)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_profile_updated", skip_all)]
    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        seq: i64,
    ) -> Result<(), AppError> {
        let mut tx = self.tx().await?;
        for sql in [ACCOUNT_PROFILE_UPDATED_SQL, MEMBERS_PROFILE_UPDATED_SQL] {
            sqlx::query(sql)
                .bind(user_id)
                .bind(display_name)
                .bind(seq)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_member_added", skip_all)]
    async fn apply_member_added(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        let sql = member_sql(
            "$3, $4, false, $5",
            "status = excluded.status, roles = excluded.roles, removed = false",
        );
        let mut tx = self.tenant_tx(tenant).await?;
        sqlx::query(AssertSqlSafe(sql))
            .bind(tenant.as_uuid())
            .bind(user_id)
            .bind(status)
            .bind(roles)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_member_updated", skip_all)]
    async fn apply_member_updated(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        seq: i64,
    ) -> Result<(), AppError> {
        let sql = member_sql("$3, '{}', false, $4", "status = excluded.status");
        let mut tx = self.tenant_tx(tenant).await?;
        sqlx::query(AssertSqlSafe(sql))
            .bind(tenant.as_uuid())
            .bind(user_id)
            .bind(status)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_member_roles_set", skip_all)]
    async fn apply_member_roles_set(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        let sql = member_sql("null, $3, false, $4", "roles = excluded.roles");
        let mut tx = self.tenant_tx(tenant).await?;
        sqlx::query(AssertSqlSafe(sql))
            .bind(tenant.as_uuid())
            .bind(user_id)
            .bind(roles)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_member_removed", skip_all)]
    async fn apply_member_removed(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        seq: i64,
    ) -> Result<(), AppError> {
        let sql = member_sql("null, '{}', true, $3", "removed = true");
        let mut tx = self.tenant_tx(tenant).await?;
        sqlx::query(AssertSqlSafe(sql))
            .bind(tenant.as_uuid())
            .bind(user_id)
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.apply_tenant_deleted", skip_all)]
    async fn apply_tenant_deleted(&self, tenant: TenantId, seq: i64) -> Result<(), AppError> {
        let mut tx = self.tenant_tx(tenant).await?;
        sqlx::query(TENANT_DELETED_SQL)
            .bind(tenant.as_uuid())
            .bind(seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    // span 名沿用多租户之前的 `rebuild_upsert`(账号目录就是原表;历史按 span 名存,改名会断开)。
    #[tracing::instrument(name = "pg.search_index.rebuild_upsert", skip_all)]
    async fn rebuild_account(&self, row: AccountIndexRow) -> Result<(), AppError> {
        sqlx::query(ACCOUNT_REBUILD_SQL)
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
            .map_err(internal)?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.search_index.rebuild_member", skip_all)]
    async fn rebuild_member(&self, row: AdminUserIndexRow) -> Result<(), AppError> {
        let mut tx = self.tenant_tx(row.tenant_id).await?;
        sqlx::query(MEMBER_REBUILD_SQL)
            .bind(row.tenant_id.as_uuid())
            .bind(row.user_id)
            .bind(row.username)
            .bind(row.email)
            .bind(row.email_verified)
            .bind(row.display_name)
            .bind(row.created_at)
            .bind(row.deleted)
            .bind(row.idm_seq)
            .bind(row.profile_seq)
            .bind(row.roles)
            .bind(row.status)
            .bind(row.removed)
            .bind(row.member_seq)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    // span 名沿用原来的 `get`(同上)。
    #[tracing::instrument(name = "pg.search_index.get", skip_all)]
    async fn get_account(&self, user_id: Uuid) -> Result<Option<AccountIndexRow>, AppError> {
        let sql = format!("select {ACCOUNT_COLS} from account_index where user_id = $1");
        sqlx::query_as::<_, AccountRecord>(AssertSqlSafe(sql))
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map(|r| r.map(AccountIndexRow::from))
            .map_err(internal)
    }

    #[tracing::instrument(name = "pg.search_index.get_member", skip_all)]
    async fn get_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
    ) -> Result<Option<AdminUserIndexRow>, AppError> {
        let sql = format!(
            "select {MEMBER_COLS} from admin_user_index where tenant_id = $1 and user_id = $2"
        );
        let mut tx = self.tenant_tx(tenant).await?;
        let row = sqlx::query_as::<_, MemberRecord>(AssertSqlSafe(sql))
            .bind(tenant.as_uuid())
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        row.map(AdminUserIndexRow::try_from).transpose()
    }

    #[tracing::instrument(name = "pg.search_index.query", skip_all)]
    async fn query(
        &self,
        tenant: TenantId,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError> {
        // 读在租户事务里(运行时账号受 RLS 约束,只看得见本租户);SQL 里也写了 tenant_id = $1。
        let mut tx = self.tenant_tx(tenant).await?;
        let raw = run_query::<MemberRecord>(
            &mut tx,
            Target::Members(tenant),
            &QUERY_COLS,
            filter,
            sort,
            order,
            page,
            |r| r.user_id,
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(IndexQueryResult {
            rows: decode_members(raw.rows)?,
            total: raw.total,
            next_after: raw.next_after,
        })
    }

    #[tracing::instrument(name = "pg.search_index.query_accounts", skip_all)]
    async fn query_accounts(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult<AccountIndexRow>, AppError> {
        // 账号目录是全局表(不开 RLS),运行时池直接读。
        let mut conn = self.pool.acquire().await.map_err(internal)?;
        let raw = run_query::<AccountRecord>(
            &mut conn,
            Target::Accounts,
            &ACCOUNT_QUERY_COLS,
            filter,
            sort,
            order,
            page,
            |r| r.user_id,
        )
        .await?;
        Ok(IndexQueryResult {
            rows: raw.rows.into_iter().map(AccountIndexRow::from).collect(),
            total: raw.total,
            next_after: raw.next_after,
        })
    }
}

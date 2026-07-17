//! widget 仓储的 Postgres 实现 —— sea-query 构建 + sqlx 执行。设了 APP_DB_HOST 才注入(app role 连接)。

use async_trait::async_trait;
use sea_query::{Expr, ExprTrait, Func, Order, PostgresQueryBuilder, Query, SelectStatement};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{WidgetRepo, WidgetTags, Widgets, COLS};
use crate::features::widget::types::{Widget, WidgetSortField};
use crate::infra::authz::TenantId;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};
use crate::infra::sort::SortOrder;

/// 排序主键表达式:字符串列(`name`)加 `COLLATE "C"` 强制字节序,与内存 `str::cmp` parity —— 否则 PG
/// 按列默认 collation(官方镜像多为 en_US.utf8 之类 locale)会大小写/locale 混排,与内存分叉,而
/// widget_repo_conformance 只测默认排序,漂移静默(镜像 search::sort_expr 已确立的口径)。`created_at`
/// 是时间戳,无 collation,直接列。
fn sort_expr(sort: WidgetSortField) -> Expr {
    match sort {
        WidgetSortField::Name => Expr::cust(r#""widgets"."name" COLLATE "C""#),
        other => Expr::col(other.column()),
    }
}

pub struct PgWidgetRepo {
    pool: PgPool,
}

impl PgWidgetRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 所有读的唯一起手式:固定 FROM + **租户闸** + `deleted_at IS NULL`
    /// (两个收口都在这,防各方法漏写过滤)。
    ///
    /// **租户在这里,不在各方法里** —— 这不是洁癖:owner 谓词在本文件写了**三遍**
    /// (行查询 / COUNT / cursor),漏一处就是 total 与 items 不一致。租户漏一处是**跨公司泄露**。
    /// 收在起手式里,漏不掉。
    ///
    /// 返回 owned SelectStatement,调用方 `let mut q = Self::base_select(t); q.columns(...)...`。
    fn base_select(tenant: TenantId) -> SelectStatement {
        let mut q = Query::select();
        q.from(Widgets::Table)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.get()))
            .and_where(Expr::col(Widgets::DeletedAt).is_null());
        q
    }
}

#[async_trait]
impl WidgetRepo for PgWidgetRepo {
    async fn list(
        &self,
        tenant: TenantId,
        page: &PageParams,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError> {
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                // SELECT cols FROM widgets WHERE deleted_at IS NULL [AND created_by = owner]
                //   ORDER BY <sort_by> <order>, id <order> LIMIT size OFFSET (page-1)*size
                // id 作 tiebreaker(同 name/created_at 值时定序);方向随主键一致。
                let mut q = Self::base_select(tenant);
                q.columns(COLS);
                if let Some(o) = owner {
                    q.and_where(Expr::col(Widgets::CreatedBy).eq(o)); // ownership 过滤
                }
                q.order_by_expr(sort_expr(sort_by), order.into())
                    .order_by(Widgets::Id, order.into())
                    .limit(*size)
                    .offset((page.saturating_sub(1)) * size);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows =
                    sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?;

                let total = if *with_total {
                    // COUNT(id) 同 filter(含 owner)、去 limit/offset(id 非空 PK,等价 COUNT(*))
                    let mut c = Self::base_select(tenant);
                    c.expr(Func::count(Expr::col(Widgets::Id)));
                    if let Some(o) = owner {
                        c.and_where(Expr::col(Widgets::CreatedBy).eq(o));
                    }
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
                Ok(Page::offset(rows, *page, *size, total))
            }
            PageParams::Cursor { after, limit } => {
                // keyset on id(v7 单列严格全序):取 limit+1 判 has_more
                let mut q = Self::base_select(tenant);
                q.columns(COLS);
                if let Some(o) = owner {
                    q.and_where(Expr::col(Widgets::CreatedBy).eq(o)); // ownership 过滤
                }
                if let Some(after) = after {
                    // v7 id 单列严格全序:id < cursor 配 ORDER BY id DESC 即正确翻页
                    q.and_where(Expr::col(Widgets::Id).lt(*after));
                }
                q.order_by(Widgets::Id, Order::Desc).limit(*limit + 1);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let mut rows =
                    sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?;

                let has_more = rows.len() as u64 > *limit;
                let next_cursor = if has_more {
                    rows.truncate(*limit as usize);
                    rows.last().map(|w| encode_cursor(w.id))
                } else {
                    None
                };
                Ok(Page::cursor(rows, *limit, next_cursor))
            }
        }
    }

    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError> {
        let mut q = Self::base_select(tenant);
        q.columns(COLS).and_where(Expr::col(Widgets::Id).eq(id));
        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)
    }

    async fn create(
        &self,
        tenant: TenantId,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let id = Uuid::now_v7();
        // created_at/updated_at 不入列 → 走 DB default;created_by=updated_by=by。
        // **tenant_id 显式入列**:它没有 DB default(migration 0005 特意不给)——
        // 漏写 = PG 报 not-null 违约,而不是静默落进错租户。
        let (sql, values) = Query::insert()
            .into_table(Widgets::Table)
            .columns([
                Widgets::Id,
                Widgets::TenantId,
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                tenant.get().into(),
                name.into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns(COLS))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_one(&self.pool)
            .await
            .map_err(map_db_err) // 重名 → 23505 → Conflict(409)
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: Uuid,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        // updated_at 由触发器自动盖;只能改**本租户的**存活行 —— 租户进 WHERE 而不是
        // 「先 get 出来再判」:后者一定会有人忘,且多一次往返。别租户的 id → 0 行 → NotFound。
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::Name, name)
            .value(Widgets::UpdatedBy, by)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.get()))
            .and_where(Expr::col(Widgets::Id).eq(id))
            .and_where(Expr::col(Widgets::DeletedAt).is_null())
            .returning(Query::returning().columns(COLS))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_db_err)? // 改名撞已有名 → 23505 → Conflict(409)
            .ok_or(AppError::NotFound)
    }

    async fn soft_delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        // 软删 = 盖 deleted_at(+ updated_by;updated_at 触发器自动);幂等:已删行不再命中。
        // 租户进 WHERE:别租户的 id → 0 行 → NotFound(同 update)。
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::DeletedAt, OffsetDateTime::now_utc())
            .value(Widgets::UpdatedBy, by)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.get()))
            .and_where(Expr::col(Widgets::Id).eq(id))
            .and_where(Expr::col(Widgets::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<sqlx::Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    // ── 父子双表事务范式:整个原子操作 = 一个方法;`Transaction` 只活在方法体,不进 trait 签名。──
    async fn create_with_tags(
        &self,
        tenant: TenantId,
        name: String,
        labels: Vec<String>,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        // 事务边界归实现体。任一步 `?` 提前返回 → tx drop → 自动 ROLLBACK(全有或全无)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // 父:建 widget(撞存活名 → 23505 → Conflict)。执行器从 `&self.pool` 换成 `&mut *tx`。
        let widget_id = Uuid::now_v7();
        let (sql, vals) = Query::insert()
            .into_table(Widgets::Table)
            .columns([
                Widgets::Id,
                Widgets::TenantId,
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([
                widget_id.into(),
                tenant.get().into(),
                name.into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns(COLS))
            .build_sqlx(PostgresQueryBuilder);
        let widget = sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), vals)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_db_err)?;

        // 子:逐个建 tag。批内/已有重复 label → (widget_id,label) 唯一违例 → 23505 → Conflict → 回滚父行。
        for label in labels {
            let (sql, vals) = Query::insert()
                .into_table(WidgetTags::Table)
                .columns([WidgetTags::Id, WidgetTags::WidgetId, WidgetTags::Label])
                .values_panic([Uuid::now_v7().into(), widget_id.into(), label.into()])
                .build_sqlx(PostgresQueryBuilder);
            sqlx::query_with::<sqlx::Postgres, _>(AssertSqlSafe(sql), vals)
                .execute(&mut *tx)
                .await
                .map_err(map_db_err)?;
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(widget)
    }

    /// **子表没有租户列**,所以经父表 join 收口:知道别租户的 widget id 也读不到它的标签。
    ///
    /// 为什么不给 `widget_tags` 加 tenant 列(反范式冗余一份):子表恒经父表可达,
    /// join 在**同一个 schema 内**(禁的是跨 schema join,这个不跨),一次查询搞定;
    /// 冗余一份反而多一个会漂移的真相。父表的 `widgets_tenant_alive_idx` 直接吃这个 join。
    async fn tags_of(&self, tenant: TenantId, widget_id: Uuid) -> Result<Vec<String>, AppError> {
        let (sql, vals) = Query::select()
            .column((WidgetTags::Table, WidgetTags::Label))
            .from(WidgetTags::Table)
            .inner_join(
                Widgets::Table,
                Expr::col((Widgets::Table, Widgets::Id))
                    .equals((WidgetTags::Table, WidgetTags::WidgetId)),
            )
            .and_where(Expr::col((WidgetTags::Table, WidgetTags::WidgetId)).eq(widget_id))
            .and_where(Expr::col((Widgets::Table, Widgets::TenantId)).eq(tenant.get()))
            .and_where(Expr::col((Widgets::Table, Widgets::DeletedAt)).is_null())
            .order_by((WidgetTags::Table, WidgetTags::Label), Order::Asc)
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<sqlx::Postgres, String, _>(AssertSqlSafe(sql), vals)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))
    }
}

/// sqlx 错误下钻:**unique 违例(SQLSTATE 23505)→ `Conflict`(409)**;其余 → `Internal`(500,
/// 原始细节只进日志)。写操作(create/update)专用 —— 把 DB 约束违例翻成对客户端有意义的 409 而非裸 500。
/// 范式:照抄者给某列加 unique 后,记得把对应写路径的 `map_err` 换成这个,别让约束违例漏成 500。
/// 文案**通用**(本表只 name 一个唯一索引);要按列给具体文案,用 `db.constraint()` 分辨命中的是哪个索引。
fn map_db_err(e: sqlx::Error) -> AppError {
    if e.as_database_error()
        .is_some_and(|db| db.is_unique_violation())
    {
        AppError::Conflict("resource already exists".to_owned())
    } else {
        AppError::Internal(e.into())
    }
}

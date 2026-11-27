//! widget 仓储端口的 **Postgres 适配器** —— sea-query 构建 + sqlx 执行。设了 APP_DB_HOST 才注入(app role 连接)。
//!
//! 数据库的形状只活在这个文件:表/列标识符、`WidgetRow`(`FromRow`)、排序字段到列的映射、
//! 约束违例到领域错误的翻译。出这个文件的一律是领域模型 `Widget`。
//!
//! **租户(spec §4.4)**:每个方法都在自己的事务里跑 —— `infra::pg::tenant_transaction` 开事务并设事务级
//! `app.tenant_id`(RLS 策略读它,第二道防线),业务 SQL 再**同时**写 `tenant_id = $1`(第一道,走
//! `(tenant_id, …)` 索引)。读方法也一样。连的是运行时账号(非 owner、NOBYPASSRLS),漏写条件也串不了租户。

use async_trait::async_trait;
use sea_query::{
    Condition, Expr, ExprTrait, Func, Iden, Order, PostgresQueryBuilder, Query, SelectStatement,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, FromRow, PgConnection, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::widget::model::{Widget, WidgetSortField};
use crate::features::widget::ports::WidgetRepo;
use crate::infra::pg;
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{OffsetPosition, Page, PageParams};
use crate::kernel::sort_order::SortOrder;
use crate::kernel::tenant_id::TenantId;

/// sea-query 表/列标识符。`#[derive(Iden)]` 按 snake_case 渲染:`Widgets::Table` -> "widgets" 等。
#[derive(Iden)]
enum Widgets {
    Table,
    TenantId,
    Id,
    Name,
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    DeletedAt,
}

/// 读列(**不含 deleted_at**:领域模型不含它)。列名按 name 映射到 [`WidgetRow`] 的 FromRow 字段。
const COLUMNS: [Widgets; 6] = [
    Widgets::Id,
    Widgets::Name,
    Widgets::CreatedBy,
    Widgets::CreatedAt,
    Widgets::UpdatedBy,
    Widgets::UpdatedAt,
];

/// 子表 `widget_tags` 的 sea-query 标识符(父子双表事务样板用)。
#[derive(Iden)]
enum WidgetTags {
    Table,
    TenantId,
    Id,
    WidgetId,
    Label,
}

/// 一行 `widgets`(读列)。只在本适配器内存在,出门即转成领域模型 [`Widget`]。
#[derive(FromRow)]
struct WidgetRow {
    id: Uuid,
    name: String,
    created_by: Option<String>,
    created_at: OffsetDateTime,
    updated_by: Option<String>,
    updated_at: OffsetDateTime,
}

impl From<WidgetRow> for Widget {
    fn from(row: WidgetRow) -> Self {
        Widget {
            id: row.id,
            name: row.name,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

/// 可排序字段 → 列标识符(白名单在领域,列名在这)。
fn column(sort: WidgetSortField) -> Widgets {
    match sort {
        WidgetSortField::CreatedAt => Widgets::CreatedAt,
        WidgetSortField::Name => Widgets::Name,
    }
}

/// 排序主键表达式:字符串列(`name`)加 `COLLATE "C"` 强制字节序,与内存 `str::cmp` parity —— 否则 PG
/// 按列默认 collation(官方镜像多为 en_US.utf8 之类 locale)会大小写/locale 混排,与内存分叉,而
/// widget_repo_conformance 只测默认排序,漂移静默(镜像 search::sort_expr 已确立的口径)。`created_at`
/// 是时间戳,无 collation,直接列。
fn sort_expr(sort: WidgetSortField) -> Expr {
    match sort {
        WidgetSortField::Name => Expr::cust(r#""widgets"."name" COLLATE "C""#),
        other => Expr::col(column(other)),
    }
}

/// 方向敏感的 keyset 比较(`expression` 按 `order` 排在 `value` 之后):asc 取 `>`、desc 取 `<`。
/// **严格**不等 —— 排除锚点行自身。
fn strictly_after(expression: Expr, order: SortOrder, value: Expr) -> Expr {
    match order {
        SortOrder::Asc => expression.gt(value),
        SortOrder::Desc => expression.lt(value),
    }
}

/// offset 分页的取数窗口(`PageParams::Offset` 的字段)。
struct OffsetWindow {
    page: u64,
    size: u64,
    with_total: bool,
}

/// cursor 分页的取数窗口(`PageParams::Cursor` 的字段)。
struct CursorWindow {
    after: Option<Uuid>,
    limit: u64,
}

/// `(key, id)` 字典序 keyset 谓词,展开成 `key <> a.key OR (key = a.key AND id <> a.id)`
/// (`<>` 随 order 取 `<`/`>`)。不用行值比较 `(a,b) < (c,d)`:左侧文本键是带 `COLLATE` 的自定义
/// 表达式,展开形式在任何后端都稳,PG 照样能用 `(name COLLATE "C", id)` 复合索引。
///
/// **比较必须复用 `sort_expr`** —— 与 ORDER BY 同一个 collation。两者分叉不会报错,会**漏行**。
fn keyset_after(key: WidgetSortField, order: SortOrder, anchor: &Widget) -> Condition {
    let (primary, key_equal) = match key {
        WidgetSortField::Name => (
            strictly_after(sort_expr(key), order, Expr::val(anchor.name.clone())),
            sort_expr(key).eq(anchor.name.clone()),
        ),
        WidgetSortField::CreatedAt => (
            strictly_after(sort_expr(key), order, Expr::val(anchor.created_at)),
            sort_expr(key).eq(anchor.created_at),
        ),
    };
    Condition::any()
        .add(primary)
        .add(Condition::all().add(key_equal).add(strictly_after(
            Expr::col(Widgets::Id),
            order,
            Expr::val(anchor.id),
        )))
}

/// widget 仓储的 Postgres 实现(运行时账号的连接池;每个方法一个租户事务)。
pub struct PgWidgetRepo {
    pool: PgPool,
}

/// sqlx 错误 → `Internal`(500,原始细节只进日志)。
fn internal(error: sqlx::Error) -> AppError {
    AppError::Internal(error.into())
}

impl PgWidgetRepo {
    /// 用 app schema 的运行时连接池(非 owner、受 RLS 约束)构造。
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 本方法的租户事务(`set_config('app.tenant_id', …, true)`)。每个仓储方法一个,读也一样。
    async fn begin(&self, tenant: TenantId) -> Result<Transaction<'static, Postgres>, AppError> {
        pg::tenant_transaction(&self.pool, tenant)
            .await
            .map_err(internal)
    }

    /// 所有读的唯一起手式:固定 FROM + `tenant_id = $1` + `deleted_at IS NULL`(租户与软删除收口,
    /// 防各方法漏写过滤)。返回 owned SelectStatement,调用方 `let mut query = Self::base_select(tenant); query.columns(...)...`。
    fn base_select(tenant: TenantId) -> SelectStatement {
        let mut query = Query::select();
        query
            .from(Widgets::Table)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.as_uuid()))
            .and_where(Expr::col(Widgets::DeletedAt).is_null());
        query
    }

    /// 取 cursor 锚点行,只为读它的排序键值。**不走 `base_select`** —— 不过滤软删:
    /// 翻页途中锚点行被软删,后续页仍要翻得下去(软删行还在表里)。**仍按租户过滤**。
    /// 查不到 = cursor 不是本租户本表发出的 → 400,与 `decode_cursor` 解码失败同口径。
    async fn anchor(
        connection: &mut PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Widget, AppError> {
        let mut query = Query::select();
        query
            .columns(COLUMNS)
            .from(Widgets::Table)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.as_uuid()))
            .and_where(Expr::col(Widgets::Id).eq(id));
        let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
        let row: Option<WidgetRow> = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_optional(connection)
            .await
            .map_err(internal)?;
        row.map(Widget::from)
            .ok_or_else(|| AppError::BadRequest("Invalid cursor".to_owned()))
    }

    /// 本租户一页 offset 列表(+ 可选 total),跑在调用方的租户事务上。
    async fn list_offset(
        connection: &mut PgConnection,
        tenant: TenantId,
        window: OffsetWindow,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError> {
        // SELECT cols FROM widgets WHERE tenant_id = $t AND deleted_at IS NULL [AND created_by = owner]
        //   ORDER BY <sort_by> <order>, id <order> LIMIT size OFFSET (page-1)*size
        // id 作 tiebreaker(同 name/created_at 值时定序);方向随主键一致。
        let OffsetWindow {
            page,
            size,
            with_total,
        } = window;
        let mut query = Self::base_select(tenant);
        query.columns(COLUMNS);
        if let Some(created_by) = owner {
            query.and_where(Expr::col(Widgets::CreatedBy).eq(created_by)); // ownership 过滤
        }
        query
            .order_by_expr(sort_expr(sort_by), pg::order(order))
            .order_by(Widgets::Id, pg::order(order))
            .limit(size)
            .offset((page.saturating_sub(1)) * size);
        let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
        let records: Vec<WidgetRow> = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_all(&mut *connection)
            .await
            .map_err(internal)?;
        let rows: Vec<Widget> = records.into_iter().map(Widget::from).collect();

        let total = if with_total {
            // COUNT(id) 同 filter(含租户、owner)、去 limit/offset(id 非空 PK,等价 COUNT(*))
            let mut count_query = Self::base_select(tenant);
            count_query.expr(Func::count(Expr::col(Widgets::Id)));
            if let Some(created_by) = owner {
                count_query.and_where(Expr::col(Widgets::CreatedBy).eq(created_by));
            }
            let (count_sql, count_values) = count_query.build_sqlx(PostgresQueryBuilder);
            let count: i64 = sqlx::query_scalar_with(AssertSqlSafe(count_sql), count_values)
                .fetch_one(&mut *connection)
                .await
                .map_err(internal)?;
            Some(count as u64)
        } else {
            None
        };
        Ok(Page::new_with_offset(
            rows,
            OffsetPosition { page, size },
            total,
        ))
    }

    /// 本租户一页 cursor(keyset)列表,跑在调用方的租户事务上(锚点读同一事务)。
    async fn list_cursor(
        connection: &mut PgConnection,
        tenant: TenantId,
        window: CursorWindow,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError> {
        // ── keyset:**ORDER BY 与谓词必须同一把键**,否则翻页跳行 ──
        // (反面教材见 `search/rebuild.rs` 的注释:ORDER BY created_at 配 id 谓词会漏人。)
        // `created_at` 序复用 v7 id 单列(零额外查询);其余键用 `(key, id)` 复合,
        // 键值从锚点行读 —— 所以 **cursor payload 仍只是 16 字节 id,换排序键不动它的格式**。
        // 取 limit+1 判 has_more。
        let CursorWindow { after, limit } = window;
        let mut query = Self::base_select(tenant);
        query.columns(COLUMNS);
        if let Some(created_by) = owner {
            query.and_where(Expr::col(Widgets::CreatedBy).eq(created_by)); // ownership 过滤
        }
        if let Some(after) = after {
            match sort_by {
                // v7 id 单列严格全序:直接和 cursor 比,不必读锚点行。
                WidgetSortField::CreatedAt => {
                    query.and_where(strictly_after(
                        Expr::col(Widgets::Id),
                        order,
                        Expr::val(after),
                    ));
                }
                key => {
                    let anchor = Self::anchor(&mut *connection, tenant, after).await?;
                    query.cond_where(keyset_after(key, order, &anchor));
                }
            }
        }
        match sort_by {
            WidgetSortField::CreatedAt => {
                query.order_by(Widgets::Id, pg::order(order));
            }
            key => {
                query
                    .order_by_expr(sort_expr(key), pg::order(order))
                    .order_by(Widgets::Id, pg::order(order));
            }
        }
        query.limit(limit + 1);
        let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
        let records: Vec<WidgetRow> = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_all(&mut *connection)
            .await
            .map_err(internal)?;
        let mut rows: Vec<Widget> = records.into_iter().map(Widget::from).collect();

        let has_more = rows.len() as u64 > limit;
        let next_after = if has_more {
            rows.truncate(limit as usize);
            rows.last().map(|w| w.id)
        } else {
            None
        };
        Ok(Page::new_with_cursor(rows, limit, next_after))
    }
}

#[async_trait]
impl WidgetRepo for PgWidgetRepo {
    #[tracing::instrument(name = "pg.widgets.list", skip_all)]
    async fn list(
        &self,
        tenant: TenantId,
        page: &PageParams,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError> {
        let mut transaction = self.begin(tenant).await?;
        let out = match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let window = OffsetWindow {
                    page: *page,
                    size: *size,
                    with_total: *with_total,
                };
                Self::list_offset(&mut transaction, tenant, window, owner, sort_by, order).await?
            }
            PageParams::Cursor { after, limit } => {
                let window = CursorWindow {
                    after: *after,
                    limit: *limit,
                };
                Self::list_cursor(&mut transaction, tenant, window, owner, sort_by, order).await?
            }
        };
        transaction.commit().await.map_err(internal)?;
        Ok(out)
    }

    #[tracing::instrument(name = "pg.widgets.get", skip_all)]
    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError> {
        let mut transaction = self.begin(tenant).await?;
        let mut query = Self::base_select(tenant);
        query
            .columns(COLUMNS)
            .and_where(Expr::col(Widgets::Id).eq(id));
        let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
        let row: Option<WidgetRow> = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(internal)?;
        transaction.commit().await.map_err(internal)?;
        row.map(Widget::from).ok_or(AppError::NotFound)
    }

    #[tracing::instrument(name = "pg.widgets.create", skip_all)]
    async fn create(
        &self,
        tenant: TenantId,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let mut transaction = self.begin(tenant).await?;
        let id = Uuid::now_v7();
        // created_at/updated_at 不入列 → 走 DB default;created_by=updated_by=by
        let (sql, values) = Query::insert()
            .into_table(Widgets::Table)
            .columns([
                Widgets::TenantId,
                Widgets::Id,
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([
                tenant.as_uuid().into(),
                id.into(),
                name.into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns(COLUMNS))
            .build_sqlx(PostgresQueryBuilder);
        let row: WidgetRow = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_db_err)?; // 本租户内重名 → 23505 → Conflict(409)
        transaction.commit().await.map_err(internal)?;
        Ok(Widget::from(row))
    }

    #[tracing::instrument(name = "pg.widgets.update", skip_all)]
    async fn update(
        &self,
        tenant: TenantId,
        id: Uuid,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        let mut transaction = self.begin(tenant).await?;
        // updated_at 由触发器自动盖;只能改本租户的存活行
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::Name, name)
            .value(Widgets::UpdatedBy, by)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.as_uuid()))
            .and_where(Expr::col(Widgets::Id).eq(id))
            .and_where(Expr::col(Widgets::DeletedAt).is_null())
            .returning(Query::returning().columns(COLUMNS))
            .build_sqlx(PostgresQueryBuilder);
        let row: Option<WidgetRow> = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_db_err)?; // 改名撞本租户已有名 → 23505 → Conflict(409)
        transaction.commit().await.map_err(internal)?;
        row.map(Widget::from).ok_or(AppError::NotFound)
    }

    #[tracing::instrument(name = "pg.widgets.soft_delete", skip_all)]
    async fn soft_delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let mut transaction = self.begin(tenant).await?;
        // 软删 = 盖 deleted_at(+ updated_by;updated_at 触发器自动);幂等:已删行不再命中
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::DeletedAt, OffsetDateTime::now_utc())
            .value(Widgets::UpdatedBy, by)
            .and_where(Expr::col(Widgets::TenantId).eq(tenant.as_uuid()))
            .and_where(Expr::col(Widgets::Id).eq(id))
            .and_where(Expr::col(Widgets::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let result = sqlx::query_with(AssertSqlSafe(sql), values)
            .execute(&mut *transaction)
            .await
            .map_err(internal)?;
        transaction.commit().await.map_err(internal)?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    // ── 父子双表事务范式:整个原子操作 = 一个方法;`Transaction` 只活在方法体,不进 trait 签名。──
    #[tracing::instrument(name = "pg.widgets.create_with_tags", skip_all)]
    async fn create_with_tags(
        &self,
        tenant: TenantId,
        name: String,
        labels: Vec<String>,
        by: Option<String>,
    ) -> Result<Widget, AppError> {
        // 事务边界归实现体(租户事务:同一个 tx 里父子两表都受 RLS 约束)。
        // 任一步 `?` 提前返回 → tx drop → 自动 ROLLBACK(全有或全无)。
        let mut transaction = self.begin(tenant).await?;

        // 父:建 widget(撞本租户存活名 → 23505 → Conflict)。执行器从 `&self.pool` 换成 `&mut *transaction`。
        let widget_id = Uuid::now_v7();
        let (sql, values) = Query::insert()
            .into_table(Widgets::Table)
            .columns([
                Widgets::TenantId,
                Widgets::Id,
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([
                tenant.as_uuid().into(),
                widget_id.into(),
                name.into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns(COLUMNS))
            .build_sqlx(PostgresQueryBuilder);
        let row: WidgetRow = sqlx::query_as_with(AssertSqlSafe(sql), values)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_db_err)?;
        let widget = Widget::from(row);

        // 子:逐个建 tag(与父同租户)。批内/已有重复 label → (widget_id,label) 唯一违例 → 23505 → Conflict → 回滚父行。
        for label in labels {
            let (sql, values) = Query::insert()
                .into_table(WidgetTags::Table)
                .columns([
                    WidgetTags::TenantId,
                    WidgetTags::Id,
                    WidgetTags::WidgetId,
                    WidgetTags::Label,
                ])
                .values_panic([
                    tenant.as_uuid().into(),
                    Uuid::now_v7().into(),
                    widget_id.into(),
                    label.into(),
                ])
                .build_sqlx(PostgresQueryBuilder);
            sqlx::query_with(AssertSqlSafe(sql), values)
                .execute(&mut *transaction)
                .await
                .map_err(map_db_err)?;
        }

        transaction.commit().await.map_err(internal)?;
        Ok(widget)
    }

    #[tracing::instrument(name = "pg.widgets.tags_of", skip_all)]
    async fn tags_of(&self, tenant: TenantId, widget_id: Uuid) -> Result<Vec<String>, AppError> {
        let mut transaction = self.begin(tenant).await?;
        let (sql, values) = Query::select()
            .column(WidgetTags::Label)
            .from(WidgetTags::Table)
            .and_where(Expr::col(WidgetTags::TenantId).eq(tenant.as_uuid()))
            .and_where(Expr::col(WidgetTags::WidgetId).eq(widget_id))
            .order_by(WidgetTags::Label, Order::Asc)
            .build_sqlx(PostgresQueryBuilder);
        let labels: Vec<String> = sqlx::query_scalar_with(AssertSqlSafe(sql), values)
            .fetch_all(&mut *transaction)
            .await
            .map_err(internal)?;
        transaction.commit().await.map_err(internal)?;
        Ok(labels)
    }
}

/// sqlx 错误下钻:**unique 违例(SQLSTATE 23505)→ `Conflict`(409)**;其余 → `Internal`(500,
/// 原始细节只进日志)。写操作(create/update)专用 —— 把 DB 约束违例翻成对客户端有意义的 409 而非裸 500。
/// 范式:照抄者给某列加 unique 后,记得把对应写路径的 `map_err` 换成这个,别让约束违例漏成 500。
/// 文案**通用**(本表只 name 一个唯一索引);要按列给具体文案,用 `db.constraint()` 分辨命中的是哪个索引。
fn map_db_err(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|db| db.is_unique_violation())
    {
        AppError::Conflict("resource already exists".to_owned())
    } else {
        AppError::Internal(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// keyset 谓词与 ORDER BY **必须用同一个 collation**:分叉不会报错,只会静默漏行。
    /// 行为对拍归 PG conformance(要 DB);这条无 DB 也能钉住 SQL 形状,守住那个静默失败。
    #[test]
    fn name_keyset_predicate_and_order_share_collation() {
        let now = OffsetDateTime::now_utc();
        let anchor = Widget {
            id: Uuid::now_v7(),
            name: "m".to_owned(),
            created_by: None,
            created_at: now,
            updated_by: None,
            updated_at: now,
        };
        let mut query = Query::select();
        query
            .column(Widgets::Id)
            .from(Widgets::Table)
            .cond_where(keyset_after(
                WidgetSortField::Name,
                SortOrder::Desc,
                &anchor,
            ))
            .order_by_expr(sort_expr(WidgetSortField::Name), Order::Desc)
            .order_by(Widgets::Id, Order::Desc);
        let sql = query.to_string(PostgresQueryBuilder);

        // 谓词两处(`name <> a.name`、`name = a.name`)+ ORDER BY 一处,一个都不能少。
        assert_eq!(
            sql.matches(r#"COLLATE "C""#).count(),
            3,
            "谓词与 ORDER BY 的 collation 必须一致: {sql}"
        );
        // tiebreaker 方向随主键(desc → `<`),否则同名行会翻重或翻漏。
        assert!(
            sql.contains(r#""id" < "#),
            "tiebreaker 方向应随 order: {sql}"
        );
    }
}

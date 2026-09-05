//! widget 仓储的 Postgres 实现 —— sea-query 构建 + sqlx 执行。设了 APP_DB_HOST 才注入(app role 连接)。

use async_trait::async_trait;
use sea_query::{
    Condition, Expr, ExprTrait, Func, Order, PostgresQueryBuilder, Query, SelectStatement,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{WidgetRepo, WidgetTags, Widgets, COLS};
use crate::features::widget::types::{Widget, WidgetSortField};
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

/// 方向敏感的 keyset 比较:asc 取 `>`、desc 取 `<`。**严格**不等 —— 排除锚点行自身。
fn cmp_dir(e: Expr, order: SortOrder, v: impl Into<Expr>) -> Expr {
    match order {
        SortOrder::Asc => e.gt(v),
        SortOrder::Desc => e.lt(v),
    }
}

/// `(key, id)` 字典序 keyset 谓词,展开成 `key <> a.key OR (key = a.key AND id <> a.id)`
/// (`<>` 随 order 取 `<`/`>`)。不用行值比较 `(a,b) < (c,d)`:左侧文本键是带 `COLLATE` 的自定义
/// 表达式,展开形式在任何后端都稳,PG 照样能用 `(name COLLATE "C", id)` 复合索引。
///
/// **比较必须复用 `sort_expr`** —— 与 ORDER BY 同一个 collation。两者分叉不会报错,会**漏行**。
fn keyset_after(key: WidgetSortField, order: SortOrder, anchor: &Widget) -> Condition {
    let (primary, eq) = match key {
        WidgetSortField::Name => (
            cmp_dir(sort_expr(key), order, anchor.name.clone()),
            sort_expr(key).eq(anchor.name.clone()),
        ),
        WidgetSortField::CreatedAt => (
            cmp_dir(sort_expr(key), order, anchor.created_at),
            sort_expr(key).eq(anchor.created_at),
        ),
    };
    Condition::any()
        .add(primary)
        .add(
            Condition::all()
                .add(eq)
                .add(cmp_dir(Expr::col(Widgets::Id), order, anchor.id)),
        )
}

pub struct PgWidgetRepo {
    pool: PgPool,
}

impl PgWidgetRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 所有读的唯一起手式:固定 FROM + `deleted_at IS NULL`(软删除收口,防各方法漏写过滤)。
    /// 返回 owned SelectStatement,调用方 `let mut q = Self::base_select(); q.columns(...)...`。
    fn base_select() -> SelectStatement {
        let mut q = Query::select();
        q.from(Widgets::Table)
            .and_where(Expr::col(Widgets::DeletedAt).is_null());
        q
    }

    /// 取 cursor 锚点行,只为读它的排序键值。**不走 `base_select`** —— 不过滤软删:
    /// 翻页途中锚点行被软删,后续页仍要翻得下去(软删行还在表里)。
    /// 查不到 = cursor 不是本表发出的 → 400,与 `decode_cursor` 解码失败同口径。
    async fn anchor(&self, id: Uuid) -> Result<Widget, AppError> {
        let mut q = Query::select();
        q.columns(COLS)
            .from(Widgets::Table)
            .and_where(Expr::col(Widgets::Id).eq(id));
        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or_else(|| AppError::BadRequest("Invalid cursor".to_owned()))
    }
}

#[async_trait]
impl WidgetRepo for PgWidgetRepo {
    async fn list(
        &self,
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
                let mut q = Self::base_select();
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
                    let mut c = Self::base_select();
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
                // ── keyset:**ORDER BY 与谓词必须同一把键**,否则翻页跳行 ──
                // (反面教材见 `search/rebuild.rs` 的注释:ORDER BY created_at 配 id 谓词会漏人。)
                // `created_at` 序复用 v7 id 单列(零额外查询);其余键用 `(key, id)` 复合,
                // 键值从锚点行读 —— 所以 **cursor payload 仍只是 16 字节 id,换排序键不动它的格式**。
                // 取 limit+1 判 has_more。
                let mut q = Self::base_select();
                q.columns(COLS);
                if let Some(o) = owner {
                    q.and_where(Expr::col(Widgets::CreatedBy).eq(o)); // ownership 过滤
                }
                if let Some(after) = after {
                    match sort_by {
                        // v7 id 单列严格全序:直接和 cursor 比,不必读锚点行。
                        WidgetSortField::CreatedAt => {
                            q.and_where(cmp_dir(Expr::col(Widgets::Id), order, *after));
                        }
                        key => {
                            q.cond_where(keyset_after(key, order, &self.anchor(*after).await?));
                        }
                    }
                }
                match sort_by {
                    WidgetSortField::CreatedAt => {
                        q.order_by(Widgets::Id, order.into());
                    }
                    key => {
                        q.order_by_expr(sort_expr(key), order.into())
                            .order_by(Widgets::Id, order.into());
                    }
                }
                q.limit(*limit + 1);
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

    async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        let mut q = Self::base_select();
        q.columns(COLS).and_where(Expr::col(Widgets::Id).eq(id));
        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)
    }

    async fn create(&self, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let id = Uuid::now_v7();
        // created_at/updated_at 不入列 → 走 DB default;created_by=updated_by=by
        let (sql, values) = Query::insert()
            .into_table(Widgets::Table)
            .columns([
                Widgets::Id,
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([id.into(), name.into(), by.clone().into(), by.into()])
            .returning(Query::returning().columns(COLS))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
            .fetch_one(&self.pool)
            .await
            .map_err(map_db_err) // 重名 → 23505 → Conflict(409)
    }

    async fn update(&self, id: Uuid, name: String, by: Option<String>) -> Result<Widget, AppError> {
        // updated_at 由触发器自动盖;只能改存活行
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::Name, name)
            .value(Widgets::UpdatedBy, by)
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

    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), AppError> {
        // 软删 = 盖 deleted_at(+ updated_by;updated_at 触发器自动);幂等:已删行不再命中
        let (sql, values) = Query::update()
            .table(Widgets::Table)
            .value(Widgets::DeletedAt, OffsetDateTime::now_utc())
            .value(Widgets::UpdatedBy, by)
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
                Widgets::Name,
                Widgets::CreatedBy,
                Widgets::UpdatedBy,
            ])
            .values_panic([widget_id.into(), name.into(), by.clone().into(), by.into()])
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

    async fn tags_of(&self, widget_id: Uuid) -> Result<Vec<String>, AppError> {
        let (sql, vals) = Query::select()
            .column(WidgetTags::Label)
            .from(WidgetTags::Table)
            .and_where(Expr::col(WidgetTags::WidgetId).eq(widget_id))
            .order_by(WidgetTags::Label, Order::Asc)
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
        let mut q = Query::select();
        q.column(Widgets::Id)
            .from(Widgets::Table)
            .cond_where(keyset_after(
                WidgetSortField::Name,
                SortOrder::Desc,
                &anchor,
            ))
            .order_by_expr(sort_expr(WidgetSortField::Name), Order::Desc)
            .order_by(Widgets::Id, Order::Desc);
        let sql = q.to_string(PostgresQueryBuilder);

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

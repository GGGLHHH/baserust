//! widget 仓储的 Postgres 实现 —— sea-query 构建 + sqlx 执行。设了 APP_DB_HOST 才注入(app role 连接)。

use async_trait::async_trait;
use sea_query::{Expr, ExprTrait, Func, Order, PostgresQueryBuilder, Query, SelectStatement};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{WidgetRepo, Widgets, COLS};
use crate::features::widget::types::Widget;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};

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
}

#[async_trait]
impl WidgetRepo for PgWidgetRepo {
    async fn list(&self, page: &PageParams, owner: Option<&str>) -> Result<Page<Widget>, AppError> {
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                // SELECT cols FROM widgets WHERE deleted_at IS NULL [AND created_by = owner]
                //   ORDER BY id DESC LIMIT size OFFSET (page-1)*size
                let mut q = Self::base_select();
                q.columns(COLS);
                if let Some(o) = owner {
                    q.and_where(Expr::col(Widgets::CreatedBy).eq(o)); // ownership 过滤
                }
                q.order_by(Widgets::Id, Order::Desc)
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
                // keyset on id(v7 单列严格全序):取 limit+1 判 has_more
                let mut q = Self::base_select();
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
            .map_err(|e| AppError::Internal(e.into()))
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
            .map_err(|e| AppError::Internal(e.into()))?
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
}

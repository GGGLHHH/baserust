use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sea_query::{Expr, ExprTrait, Func, Iden, Order, PostgresQueryBuilder, Query, SelectStatement};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::types::Widget;
use crate::error::AppError;
use crate::pagination::{encode_cursor, Page, PageParams};

/// sea-query 表/列标识符。`#[derive(Iden)]` 按 snake_case 渲染:`Widgets::Table` -> "widgets" 等。
#[derive(Iden)]
enum Widgets {
    Table,
    Id,
    Name,
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    DeletedAt,
}

/// 读列(**不含 deleted_at**:DTO 不暴露)。列名按 name 映射到 `Widget` 的 FromRow 字段。
const COLS: [Widgets; 6] = [
    Widgets::Id,
    Widgets::Name,
    Widgets::CreatedBy,
    Widgets::CreatedAt,
    Widgets::UpdatedBy,
    Widgets::UpdatedAt,
];

/// 仓储端口。范式:trait 定义数据访问契约,service 依赖 trait 而非实现(内存 ↔ Postgres 可拔插)。
/// 写操作的 `by` = 审计主体(created_by/updated_by),来自 `AuditContext`;时间由 DB default/触发器管。
#[async_trait]
pub trait WidgetRepo: Send + Sync {
    /// 列表分页(offset 跳页 / cursor keyset 双模式,由 `PageParams` 选)。只返回存活行。
    async fn list(&self, page: &PageParams) -> Result<Page<Widget>, AppError>;
    /// 按 id 取存活行;不存在/已软删 → NotFound。
    async fn get(&self, id: Uuid) -> Result<Widget, AppError>;
    /// 创建;created_by/updated_by 都填 `by`,created_at/updated_at 由 DB default。
    async fn create(&self, name: String, by: Option<String>) -> Result<Widget, AppError>;
    /// 改名;updated_by 填 `by`,updated_at 由触发器自动盖。已软删 → NotFound。
    async fn update(&self, id: Uuid, name: String, by: Option<String>) -> Result<Widget, AppError>;
    /// 软删除(盖 deleted_at,非物理 DELETE);幂等(已删再删 → NotFound)。
    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), AppError>;
}

// ============ 内存实现 ============

/// 内存内部行:比 `Widget` 多 `deleted_at`(DTO 不暴露,但软删除要它)。
#[derive(Clone)]
struct Row {
    id: Uuid,
    name: String,
    created_by: Option<String>,
    created_at: OffsetDateTime,
    updated_by: Option<String>,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

impl Row {
    fn to_widget(&self) -> Widget {
        Widget {
            id: self.id,
            name: self.name.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at,
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// 内存实现 —— 脚手架默认,无需数据库即可跑通全链路 + 写单测。镜像 PG 的软删过滤与排序保 parity。
pub struct InMemoryWidgetRepo {
    store: Mutex<HashMap<Uuid, Row>>,
}

impl InMemoryWidgetRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWidgetRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WidgetRepo for InMemoryWidgetRepo {
    async fn list(&self, page: &PageParams) -> Result<Page<Widget>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        // 镜像 PG:存活过滤 + ORDER BY created_at DESC, id DESC
        let mut alive: Vec<Row> = store
            .values()
            .filter(|r| r.deleted_at.is_none())
            .cloned()
            .collect();
        // ORDER BY id DESC(v7 id 即创建序倒序,最新在前)
        alive.sort_by(|a, b| b.id.cmp(&a.id));

        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let total = if *with_total {
                    Some(alive.len() as u64)
                } else {
                    None
                };
                let start = ((page.saturating_sub(1)) * size) as usize;
                let items: Vec<Widget> = alive
                    .iter()
                    .skip(start)
                    .take(*size as usize)
                    .map(Row::to_widget)
                    .collect();
                Ok(Page::offset(items, *page, *size, total))
            }
            PageParams::Cursor { after, limit } => {
                let mut items: Vec<Widget> = alive
                    .iter()
                    .filter(|r| match after {
                        Some(after) => r.id < *after, // id < cursor 配 ORDER BY id DESC
                        None => true,
                    })
                    .take((*limit + 1) as usize)
                    .map(Row::to_widget)
                    .collect();
                let has_more = items.len() as u64 > *limit;
                let next_cursor = if has_more {
                    items.truncate(*limit as usize);
                    items.last().map(|w| encode_cursor(w.id))
                } else {
                    None
                };
                Ok(Page::cursor(items, *limit, next_cursor))
            }
        }
    }

    async fn get(&self, id: Uuid) -> Result<Widget, AppError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(Row::to_widget)
            .ok_or(AppError::NotFound)
    }

    async fn create(&self, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let now = OffsetDateTime::now_utc();
        let row = Row {
            id: Uuid::now_v7(),
            name,
            created_by: by.clone(),
            created_at: now,
            updated_by: by,
            updated_at: now,
            deleted_at: None,
        };
        self.store
            .lock()
            .expect("锁未中毒")
            .insert(row.id, row.clone());
        Ok(row.to_widget())
    }

    async fn update(&self, id: Uuid, name: String, by: Option<String>) -> Result<Widget, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                r.name = name;
                r.updated_by = by;
                r.updated_at = OffsetDateTime::now_utc();
                Ok(r.to_widget())
            }
            _ => Err(AppError::NotFound),
        }
    }

    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                let now = OffsetDateTime::now_utc();
                r.deleted_at = Some(now);
                r.updated_by = by;
                r.updated_at = now;
                Ok(())
            }
            _ => Err(AppError::NotFound),
        }
    }
}

// ============ Postgres 实现 ============

/// Postgres 实现 —— sea-query 构建 + sqlx 执行。设了 APP_DB_HOST 才注入(用 app role 连接)。
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
    async fn list(&self, page: &PageParams) -> Result<Page<Widget>, AppError> {
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                // SELECT cols FROM widgets WHERE deleted_at IS NULL
                //   ORDER BY created_at DESC, id DESC LIMIT size OFFSET (page-1)*size
                let mut q = Self::base_select();
                q.columns(COLS)
                    .order_by(Widgets::Id, Order::Desc)
                    .limit(*size)
                    .offset((page.saturating_sub(1)) * size);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows =
                    sqlx::query_as_with::<sqlx::Postgres, Widget, _>(AssertSqlSafe(sql), values)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?;

                let total = if *with_total {
                    // COUNT(id) 同 filter、去 limit/offset(id 非空 PK,等价 COUNT(*))
                    let mut c = Self::base_select();
                    c.expr(Func::count(Expr::col(Widgets::Id)));
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
                // keyset on (created_at, id):取 limit+1 判 has_more
                let mut q = Self::base_select();
                q.columns(COLS);
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

//! auth_audit 仓储端口的 **Postgres 适配器**。数据库形状(列、`AuthEventRecord` 行、闭集文本列的解码)
//! 只活在这个文件;出门一律是领域读模型 `AuthEventRow`。
//!
//! `auth_event` 是**平台级**表(多租户 spec §6.1:认证审计只给平台管理员看,能看到无租户的行),不开 RLS;
//! 组合根用 search 的 **system 池**装配它(投影器写、保留期删、admin 读)。行上记 `tenant_id` 备以后的
//! 租户级登录日志用。

use async_trait::async_trait;
use sea_query::{Expr, ExprTrait, Iden, Order, PostgresQueryBuilder, Query, SelectStatement};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, FromRow, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::auth_audit::auth_event_repo::AuthEventRepo;
use crate::features::auth_audit::model::{
    AuthEventQuery, AuthEventRow, AuthEventType, AuthKpi, AuthStats, FailureReason, IpStat,
    NewAuthEvent, ReasonCount, StatBucket, TypeCount,
};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{OffsetPosition, Page, PageParams};
use crate::kernel::time_range::TimeRange;

// 只列出动态 filter/order 实际引用到的列(insert/FROM 走固定 SQL 字符串,不经这个 Iden;无 Table 变体)。
#[derive(Iden)]
enum AuthEvent {
    Id,
    EventType,
    OccurredAt,
    UserId,
    Outcome,
}

/// `auth_event` 读列的一行。闭集列是 text,在 [`TryFrom`] 里解析成领域枚举 —— 存了闭集外的值
/// 是数据完整性故障(唯一写者是本仓 emit/投影),解码失败 → `Internal`(500,原始值只进日志)。
#[derive(FromRow)]
struct AuthEventRecord {
    id: Uuid,
    event_type: String,
    occurred_at: OffsetDateTime,
    channel: String,
    user_id: Option<Uuid>,
    identifier_attempted: Option<String>,
    session_id: Option<Uuid>,
    actor: Option<String>,
    outcome: String,
    failure_reason: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    country: Option<String>,
    city: Option<String>,
    os: Option<String>,
    browser: Option<String>,
    tenant_id: Option<Uuid>,
}

/// 闭集文本列解码失败 → Internal(数据完整性故障)。
fn bad_closed_value(error: String) -> AppError {
    AppError::Internal(anyhow::anyhow!("auth_event 闭集列解码失败: {error}"))
}

impl TryFrom<AuthEventRecord> for AuthEventRow {
    type Error = AppError;
    fn try_from(record: AuthEventRecord) -> Result<Self, AppError> {
        Ok(Self {
            id: record.id,
            event_type: record.event_type.parse().map_err(bad_closed_value)?,
            occurred_at: record.occurred_at,
            channel: record.channel.parse().map_err(bad_closed_value)?,
            user_id: record.user_id,
            identifier_attempted: record.identifier_attempted,
            session_id: record.session_id,
            actor: record.actor,
            outcome: record.outcome.parse().map_err(bad_closed_value)?,
            failure_reason: record
                .failure_reason
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(bad_closed_value)?,
            ip: record.ip,
            user_agent: record.user_agent,
            country: record.country,
            city: record.city,
            os: record.os,
            browser: record.browser,
            tenant_id: record.tenant_id,
        })
    }
}

fn decode_rows(rows: Vec<AuthEventRecord>) -> Result<Vec<AuthEventRow>, AppError> {
    rows.into_iter().map(AuthEventRow::try_from).collect()
}

/// [`AuthEventRepo`] 的 Postgres 实现。`pool` 应是 search 的 **system 池**(`auth_event` 是平台级表,不走 RLS)。
pub struct PgAuthEventRepo {
    pool: PgPool,
}

impl PgAuthEventRepo {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// 转义 LIKE 元字符(`\ % _`)+ 包 `%...%`(镜像 search repo 的 `ilike_contains`,与内存 `contains` parity)。
fn ilike_contains(term: &str) -> String {
    let escaped = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

fn apply_filters(query: &mut SelectStatement, filter: &AuthEventQuery) {
    if let Some(user_id) = filter.user_id {
        query.and_where(Expr::col(AuthEvent::UserId).eq(user_id));
    }
    if let Some(event_type) = filter.event_type {
        query.and_where(Expr::col(AuthEvent::EventType).eq(event_type.as_str()));
    }
    if let Some(outcome) = &filter.outcome {
        query.and_where(Expr::col(AuthEvent::Outcome).eq(outcome.as_str()));
    }
    // 联合模糊搜:actor + identifier_attempted + ip(文本),大小写不敏感子串。ip 是 inet,cast 成 text 再 ILIKE。
    if let Some(term) = filter
        .query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let pattern = ilike_contains(term);
        query.and_where(Expr::cust_with_values(
            r#"("actor" ILIKE $1 OR "identifier_attempted" ILIKE $2 OR "ip"::text ILIKE $3)"#,
            [pattern.clone(), pattern.clone(), pattern],
        ));
    }
    if let Some(ip) = &filter.ip {
        // 已在提取器校验为合法 IpAddr;绑其规范文本,`::inet` cast 恒合法(不会 500)。
        query.and_where(Expr::cust_with_values(
            r#""ip" = $1::inet"#,
            [ip.to_string()],
        ));
    }
    if let Some(from) = filter.from {
        query.and_where(Expr::col(AuthEvent::OccurredAt).gte(from));
    }
    if let Some(to) = filter.to {
        query.and_where(Expr::col(AuthEvent::OccurredAt).lt(to));
    }
}

#[async_trait]
impl AuthEventRepo for PgAuthEventRepo {
    #[tracing::instrument(name = "pg.auth_events.insert", skip_all)]
    async fn insert(&self, event: &NewAuthEvent) -> Result<bool, AppError> {
        // 显式列 INSERT + ON CONFLICT (event_seq) DO NOTHING(幂等)。富化列不写 → DB 默认 null。
        // ip 用 ::inet cast(sea-query 无 inet 类型,用文本 cast 交给 sqlx bind)。
        let sql = r#"insert into auth_event
            (id, event_type, occurred_at, channel, auth_method, user_id, identifier_attempted,
             session_id, actor, outcome, failure_reason, ip, forwarded_chain, user_agent, request_id, event_seq,
             tenant_id)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::inet,$13,$14,$15,$16,$17)
            on conflict (event_seq) do nothing"#;
        let result = sqlx::query(sql)
            .bind(event.id)
            .bind(&event.event_type)
            .bind(event.occurred_at)
            .bind(&event.channel)
            .bind(&event.auth_method)
            .bind(event.user_id)
            .bind(&event.identifier_attempted)
            .bind(event.session_id)
            .bind(&event.actor)
            .bind(&event.outcome)
            .bind(&event.failure_reason)
            .bind(event.ip.map(|ip| ip.to_string()))
            .bind(&event.forwarded_chain)
            .bind(&event.user_agent)
            .bind(&event.request_id)
            .bind(event.event_sequence)
            .bind(event.tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(result.rows_affected() > 0)
    }

    #[tracing::instrument(name = "pg.auth_events.list", skip_all)]
    async fn list(
        &self,
        filter: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        // SELECT list 固定(含 Phase 1 恒 null 的 country/city/os/browser),与 AuthEventRow 列序一致。
        const SELECT_COLUMNS: &str = r#"id, event_type, occurred_at, channel, user_id, identifier_attempted,
            session_id, actor, outcome, failure_reason, host(ip) as ip, user_agent,
            country, city, os, browser, tenant_id from auth_event"#;
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let mut query = Query::select();
                query.expr(Expr::cust(SELECT_COLUMNS));
                apply_filters(&mut query, filter);
                query
                    .order_by(AuthEvent::Id, Order::Desc)
                    .limit(size)
                    .offset((page.saturating_sub(1)) * size);
                let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
                let records: Vec<AuthEventRecord> = sqlx::query_as_with(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;
                let rows = decode_rows(records)?;
                let total = if with_total {
                    let mut count_query = Query::select();
                    count_query.expr(Expr::cust("count(*) from auth_event"));
                    apply_filters(&mut count_query, filter);
                    let (count_sql, count_values) = count_query.build_sqlx(PostgresQueryBuilder);
                    let count: i64 =
                        sqlx::query_scalar_with(AssertSqlSafe(count_sql), count_values)
                            .fetch_one(&self.pool)
                            .await
                            .map_err(|e| AppError::Internal(e.into()))?;
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
            PageParams::Cursor { after, limit } => {
                let mut query = Query::select();
                query.expr(Expr::cust(SELECT_COLUMNS));
                apply_filters(&mut query, filter);
                if let Some(after) = after {
                    query.and_where(Expr::col(AuthEvent::Id).lt(after)); // id v7 DESC keyset
                }
                query.order_by(AuthEvent::Id, Order::Desc).limit(limit + 1);
                let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
                let records: Vec<AuthEventRecord> = sqlx::query_as_with(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;
                let mut rows = decode_rows(records)?;
                let has_more = rows.len() as u64 > limit;
                let next = if has_more {
                    rows.truncate(limit as usize);
                    rows.last().map(|row| row.id)
                } else {
                    None
                };
                Ok(Page::new_with_cursor(rows, limit, next))
            }
        }
    }

    #[tracing::instrument(name = "pg.auth_events.delete_older_than", skip_all)]
    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let result = sqlx::query("delete from auth_event where occurred_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(result.rows_affected())
    }

    // 五条固定聚合查询,行形状写死 → 元组就够(不值当为此上 sea-query);元组在原地按名解构,不跨函数传。
    #[tracing::instrument(name = "pg.auth_events.stats", skip_all)]
    async fn stats(&self, range: TimeRange) -> Result<AuthStats, AppError> {
        let TimeRange { from, to } = range;
        let activity: Vec<(OffsetDateTime, i64, i64)> = sqlx::query_as(
            r#"SELECT g.t, coalesce(s.success,0) AS success, coalesce(s.failure,0) AS failure
               FROM generate_series(date_trunc('hour',$1::timestamptz), date_trunc('hour',$2::timestamptz), interval '1 hour') AS g(t)
               LEFT JOIN (
                 SELECT date_trunc('hour',occurred_at) AS t,
                        count(*) FILTER (WHERE outcome='success') AS success,
                        count(*) FILTER (WHERE outcome='failure') AS failure
                 FROM auth_event WHERE occurred_at >= $1 AND occurred_at < $2 GROUP BY 1
               ) s ON s.t = g.t
               ORDER BY g.t"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let activity: Vec<StatBucket> = activity
            .into_iter()
            .map(|(bucket_start, success, failure)| StatBucket {
                bucket_start,
                success,
                failure,
            })
            .collect();

        let reasons: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT failure_reason AS key, count(*) AS count FROM auth_event
               WHERE outcome='failure' AND failure_reason IS NOT NULL AND occurred_at >= $1 AND occurred_at < $2
               GROUP BY 1 ORDER BY 2 DESC"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let reasons: Vec<ReasonCount> = reasons
            .into_iter()
            .map(|(key, count)| {
                let key: FailureReason = key.parse().map_err(bad_closed_value)?;
                Ok(ReasonCount { key, count })
            })
            .collect::<Result<_, AppError>>()?;

        let types: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT event_type AS key, count(*) AS count FROM auth_event
               WHERE occurred_at >= $1 AND occurred_at < $2 GROUP BY 1 ORDER BY 2 DESC"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let types: Vec<TypeCount> = types
            .into_iter()
            .map(|(key, count)| {
                let key: AuthEventType = key.parse().map_err(bad_closed_value)?;
                Ok(TypeCount { key, count })
            })
            .collect::<Result<_, AppError>>()?;

        let top_ips: Vec<(String, i64, i64)> = sqlx::query_as(
            r#"SELECT host(ip) AS ip, count(*) AS total, count(*) FILTER (WHERE outcome='failure') AS failures
               FROM auth_event WHERE ip IS NOT NULL AND occurred_at >= $1 AND occurred_at < $2
               GROUP BY ip ORDER BY failures DESC, total DESC LIMIT 6"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let top_ips: Vec<IpStat> = top_ips
            .into_iter()
            .map(|(ip, total, failures)| IpStat {
                ip,
                failures,
                total,
            })
            .collect();

        // kpi + 环比:previous_from 是与 [from,to) 等长的前一个窗口起点,一条查询里用 FILTER 同时数
        // 当前/上个窗口(FROM 的时间范围要撑到 previous_from,否则 FILTER 看不到上个窗口的行)。
        let previous_from = from - (to - from);
        let (current_total, current_failed, current_ips, previous_total, previous_failed): (
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            r#"SELECT
                    count(*) FILTER (WHERE occurred_at >= $1) AS cur_total,
                    count(*) FILTER (WHERE occurred_at >= $1 AND outcome='failure') AS cur_failed,
                    count(DISTINCT ip) FILTER (WHERE occurred_at >= $1) AS cur_ips,
                    count(*) FILTER (WHERE occurred_at < $1) AS prev_total,
                    count(*) FILTER (WHERE occurred_at < $1 AND outcome='failure') AS prev_failed
                   FROM auth_event WHERE occurred_at >= $3 AND occurred_at < $2"#,
        )
        .bind(from)
        .bind(to)
        .bind(previous_from)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let success_rate = if current_total > 0 {
            (current_total - current_failed) as f64 / current_total as f64
        } else {
            1.0
        };
        let total_delta = if previous_total > 0 {
            (current_total - previous_total) as f64 / previous_total as f64
        } else {
            0.0
        };
        let failed_delta = if previous_failed > 0 {
            (current_failed - previous_failed) as f64 / previous_failed as f64
        } else {
            0.0
        };
        let kpi = AuthKpi {
            total_events: current_total,
            failed_count: current_failed,
            unique_ips: current_ips,
            success_rate,
            total_delta,
            failed_delta,
        };

        Ok(AuthStats {
            activity,
            reasons,
            types,
            top_ips,
            kpi,
        })
    }
}

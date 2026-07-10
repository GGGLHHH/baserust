use async_trait::async_trait;
use sea_query::{Expr, ExprTrait, Iden, Order, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, PgPool};
use time::OffsetDateTime;

use super::super::types::{
    AuthEventQuery, AuthEventRow, AuthEventType, AuthKpi, AuthStats, FailureReason, IpStat,
    NewAuthEvent, ReasonCount, StatBucket, TypeCount,
};
use super::AuthEventRepo;
use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};

// 只列出动态 filter/order 实际引用到的列(insert/FROM 走固定 SQL 字符串,不经这个 Iden;无 Table 变体)。
#[derive(Iden)]
enum AuthEvent {
    Id,
    EventType,
    OccurredAt,
    UserId,
    Outcome,
}

pub struct PgAuthEventRepo {
    pool: PgPool,
}
impl PgAuthEventRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn apply_filters(q: &mut sea_query::SelectStatement, f: &AuthEventQuery) {
    if let Some(u) = f.user_id {
        q.and_where(Expr::col(AuthEvent::UserId).eq(u));
    }
    if let Some(t) = f.event_type {
        q.and_where(Expr::col(AuthEvent::EventType).eq(t.as_str()));
    }
    if let Some(o) = &f.outcome {
        q.and_where(Expr::col(AuthEvent::Outcome).eq(o.as_str()));
    }
    if let Some(ip) = &f.ip {
        q.and_where(Expr::cust_with_values(r#""ip" = $1::inet"#, [ip.clone()]));
    }
    if let Some(from) = f.from {
        q.and_where(Expr::col(AuthEvent::OccurredAt).gte(from));
    }
    if let Some(to) = f.to {
        q.and_where(Expr::col(AuthEvent::OccurredAt).lt(to));
    }
}

#[async_trait]
impl AuthEventRepo for PgAuthEventRepo {
    async fn insert(&self, ev: &NewAuthEvent) -> Result<bool, AppError> {
        // 显式列 INSERT + ON CONFLICT (event_seq) DO NOTHING(幂等)。富化列不写 → DB 默认 null。
        // ip 用 ::inet cast(sea-query 无 inet 类型,用文本 cast 交给 sqlx bind)。
        let sql = r#"insert into auth_event
            (id, event_type, occurred_at, channel, auth_method, user_id, identifier_attempted,
             session_id, actor, outcome, failure_reason, ip, forwarded_chain, user_agent, request_id, event_seq)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::inet,$13,$14,$15,$16)
            on conflict (event_seq) do nothing"#;
        let res = sqlx::query(sql)
            .bind(ev.id)
            .bind(&ev.event_type)
            .bind(ev.occurred_at)
            .bind(&ev.channel)
            .bind(&ev.auth_method)
            .bind(ev.user_id)
            .bind(&ev.identifier_attempted)
            .bind(ev.session_id)
            .bind(&ev.actor)
            .bind(&ev.outcome)
            .bind(&ev.failure_reason)
            .bind(ev.ip.map(|i| i.to_string()))
            .bind(&ev.forwarded_chain)
            .bind(&ev.user_agent)
            .bind(&ev.request_id)
            .bind(ev.event_seq)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(res.rows_affected() > 0)
    }

    async fn list(
        &self,
        f: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        // SELECT list 固定(含 Phase 1 恒 null 的 country/city/os/browser),与 AuthEventRow 列序一致。
        const SEL: &str = r#"id, event_type, occurred_at, channel, user_id, identifier_attempted,
            session_id, actor, outcome, failure_reason, host(ip) as ip, user_agent,
            country, city, os, browser from auth_event"#;
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let mut q = Query::select();
                q.expr(Expr::cust(SEL));
                apply_filters(&mut q, f);
                q.order_by(AuthEvent::Id, Order::Desc)
                    .limit(size)
                    .offset((page.saturating_sub(1)) * size);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows = sqlx::query_as_with::<_, AuthEventRow, _>(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;
                let total = if with_total {
                    let mut c = Query::select();
                    c.expr(Expr::cust("count(*) from auth_event"));
                    apply_filters(&mut c, f);
                    let (csql, cvalues) = c.build_sqlx(PostgresQueryBuilder);
                    let n: i64 = sqlx::query_scalar_with::<_, i64, _>(AssertSqlSafe(csql), cvalues)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?;
                    Some(n as u64)
                } else {
                    None
                };
                Ok(Page::offset(rows, page, size, total))
            }
            PageParams::Cursor { after, limit } => {
                let mut q = Query::select();
                q.expr(Expr::cust(SEL));
                apply_filters(&mut q, f);
                if let Some(after) = after {
                    q.and_where(Expr::col(AuthEvent::Id).lt(after)); // id v7 DESC keyset
                }
                q.order_by(AuthEvent::Id, Order::Desc).limit(limit + 1);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let mut rows =
                    sqlx::query_as_with::<_, AuthEventRow, _>(AssertSqlSafe(sql), values)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?;
                let has_more = rows.len() as u64 > limit;
                let next = if has_more {
                    rows.truncate(limit as usize);
                    rows.last().map(|r| encode_cursor(r.id))
                } else {
                    None
                };
                Ok(Page::cursor(rows, limit, next))
            }
        }
    }

    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let r = sqlx::query("delete from auth_event where occurred_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(r.rows_affected())
    }

    // 五条固定聚合查询,行形状写死 → 元组 + turbofish 就够(不值当为此上 sea-query)。
    async fn stats(&self, from: OffsetDateTime, to: OffsetDateTime) -> Result<AuthStats, AppError> {
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
        let activity = activity
            .into_iter()
            .map(|(t, success, failure)| StatBucket {
                t,
                success,
                failure,
            })
            .collect();

        let reasons: Vec<(FailureReason, i64)> = sqlx::query_as(
            r#"SELECT failure_reason AS key, count(*) AS count FROM auth_event
               WHERE outcome='failure' AND failure_reason IS NOT NULL AND occurred_at >= $1 AND occurred_at < $2
               GROUP BY 1 ORDER BY 2 DESC"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let reasons = reasons
            .into_iter()
            .map(|(key, count)| ReasonCount { key, count })
            .collect();

        let types: Vec<(AuthEventType, i64)> = sqlx::query_as(
            r#"SELECT event_type AS key, count(*) AS count FROM auth_event
               WHERE occurred_at >= $1 AND occurred_at < $2 GROUP BY 1 ORDER BY 2 DESC"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        let types = types
            .into_iter()
            .map(|(key, count)| TypeCount { key, count })
            .collect();

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
        let top_ips = top_ips
            .into_iter()
            .map(|(ip, total, failures)| IpStat {
                ip,
                failures,
                total,
            })
            .collect();

        // kpi + 环比:prev_from 是与 [from,to) 等长的前一个窗口起点,一条查询里用 FILTER 同时数
        // 当前/上个窗口(FROM 的时间范围要撑到 prev_from,否则 FILTER 看不到上个窗口的行)。
        let prev_from = from - (to - from);
        let (cur_total, cur_failed, cur_ips, prev_total, prev_failed): (i64, i64, i64, i64, i64) =
            sqlx::query_as(
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
            .bind(prev_from)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        let success_rate = if cur_total > 0 {
            (cur_total - cur_failed) as f64 / cur_total as f64
        } else {
            1.0
        };
        let total_delta = if prev_total > 0 {
            (cur_total - prev_total) as f64 / prev_total as f64
        } else {
            0.0
        };
        let failed_delta = if prev_failed > 0 {
            (cur_failed - prev_failed) as f64 / prev_failed as f64
        } else {
            0.0
        };
        let kpi = AuthKpi {
            total_events: cur_total,
            failed_count: cur_failed,
            unique_ips: cur_ips,
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

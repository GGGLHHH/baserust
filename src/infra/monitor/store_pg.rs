//! [`OpsStore`] 的 Postgres 实现(ops schema,role=ops;表见 `migrations/ops`)。
//! 落一分钟 = 一个事务:写分钟表 + 累加进小时表与小时明细(upsert 相加,直方图用 `add_buckets`)。

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use super::hist::Hist;
use super::store::Service;
use super::store::{
    hour_start, DbOpTotals, LogEntry, LogQuery, MinuteRecord, OpsStore, PeriodTotals, PurgeCounts,
    Retention, RouteTotals, SeriesRow, Severity, StoredLog, Tier,
};

pub struct PgOpsStore {
    pool: PgPool,
}

impl PgOpsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const TOTAL_COLS: &str =
    "requests, errors_4xx, errors_5xx, latency_buckets, db_calls, db_latency_buckets, \
     outbox_published, outbox_failures, projector_processed, projector_failed, in_flight_max, \
     pool_in_use_max, pool_max, sse_max, projector_pending_max, rss_bytes_max, cpu_percent_max";

fn i(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn u(v: i64) -> u64 {
    v.max(0) as u64
}

/// 汇总行的 upsert:计数相加、读数取大。`table` 只会是常量表名。
fn upsert_totals_sql(table: &str) -> String {
    format!(
        "insert into {table} (instance, bucket, {TOTAL_COLS}) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
         on conflict (instance, bucket) do update set \
           requests = {table}.requests + excluded.requests, \
           errors_4xx = {table}.errors_4xx + excluded.errors_4xx, \
           errors_5xx = {table}.errors_5xx + excluded.errors_5xx, \
           latency_buckets = add_buckets({table}.latency_buckets, excluded.latency_buckets), \
           db_calls = {table}.db_calls + excluded.db_calls, \
           db_latency_buckets = add_buckets({table}.db_latency_buckets, excluded.db_latency_buckets), \
           outbox_published = {table}.outbox_published + excluded.outbox_published, \
           outbox_failures = {table}.outbox_failures + excluded.outbox_failures, \
           projector_processed = {table}.projector_processed + excluded.projector_processed, \
           projector_failed = {table}.projector_failed + excluded.projector_failed, \
           in_flight_max = greatest({table}.in_flight_max, excluded.in_flight_max), \
           pool_in_use_max = greatest({table}.pool_in_use_max, excluded.pool_in_use_max), \
           pool_max = greatest({table}.pool_max, excluded.pool_max), \
           sse_max = greatest({table}.sse_max, excluded.sse_max), \
           projector_pending_max = greatest({table}.projector_pending_max, excluded.projector_pending_max), \
           rss_bytes_max = greatest({table}.rss_bytes_max, excluded.rss_bytes_max), \
           cpu_percent_max = greatest({table}.cpu_percent_max, excluded.cpu_percent_max)"
    )
}

async fn upsert_totals(
    tx: &mut sqlx::PgConnection,
    table: &str,
    instance: &str,
    bucket: OffsetDateTime,
    t: &PeriodTotals,
) -> sqlx::Result<()> {
    // 表名只来自本文件的常量(metric_minute / metric_hour),其余全是绑定参数。
    sqlx::query(sqlx::AssertSqlSafe(upsert_totals_sql(table)))
        .bind(instance)
        .bind(bucket)
        .bind(i(t.requests))
        .bind(i(t.errors_4xx))
        .bind(i(t.errors_5xx))
        .bind(t.latency.counts())
        .bind(i(t.db_calls))
        .bind(t.db_latency.counts())
        .bind(i(t.outbox_published))
        .bind(i(t.outbox_failures))
        .bind(i(t.projector_processed))
        .bind(i(t.projector_failed))
        .bind(i(t.in_flight_max))
        .bind(i(t.pool_in_use_max))
        .bind(i(t.pool_max))
        .bind(i(t.sse_max))
        .bind(i(t.projector_pending_max))
        .bind(t.rss_bytes_max.map(i))
        .bind(t.cpu_percent_max)
        .execute(tx)
        .await
        .map(|_| ())
}

fn totals_from_row(row: &sqlx::postgres::PgRow) -> sqlx::Result<PeriodTotals> {
    Ok(PeriodTotals {
        requests: u(row.try_get("requests")?),
        errors_4xx: u(row.try_get("errors_4xx")?),
        errors_5xx: u(row.try_get("errors_5xx")?),
        latency: Hist::from_counts(&row.try_get::<Vec<i64>, _>("latency_buckets")?),
        db_calls: u(row.try_get("db_calls")?),
        db_latency: Hist::from_counts(&row.try_get::<Vec<i64>, _>("db_latency_buckets")?),
        outbox_published: u(row.try_get("outbox_published")?),
        outbox_failures: u(row.try_get("outbox_failures")?),
        projector_processed: u(row.try_get("projector_processed")?),
        projector_failed: u(row.try_get("projector_failed")?),
        in_flight_max: u(row.try_get("in_flight_max")?),
        pool_in_use_max: u(row.try_get("pool_in_use_max")?),
        pool_max: u(row.try_get("pool_max")?),
        sse_max: u(row.try_get("sse_max")?),
        projector_pending_max: u(row.try_get("projector_pending_max")?),
        rss_bytes_max: row.try_get::<Option<i64>, _>("rss_bytes_max")?.map(u),
        cpu_percent_max: row.try_get("cpu_percent_max")?,
    })
}

/// LIKE 元字符转义 + 包 `%...%`(与内存实现的 `contains` 同口径)。
fn ilike_contains(term: &str) -> String {
    let escaped = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

#[async_trait]
impl OpsStore for PgOpsStore {
    async fn record_minute(&self, rec: &MinuteRecord) -> anyhow::Result<()> {
        let hour = hour_start(rec.bucket);
        let mut tx = self.pool.begin().await?;
        upsert_totals(
            &mut tx,
            "metric_minute",
            &rec.instance,
            rec.bucket,
            &rec.totals,
        )
        .await?;
        upsert_totals(&mut tx, "metric_hour", &rec.instance, hour, &rec.totals).await?;
        for r in &rec.routes {
            sqlx::query(
                "insert into route_hour (instance, bucket, method, route, requests, errors_4xx, errors_5xx, latency_buckets) \
                 values ($1, $2, $3, $4, $5, $6, $7, $8) \
                 on conflict (instance, bucket, method, route) do update set \
                   requests = route_hour.requests + excluded.requests, \
                   errors_4xx = route_hour.errors_4xx + excluded.errors_4xx, \
                   errors_5xx = route_hour.errors_5xx + excluded.errors_5xx, \
                   latency_buckets = add_buckets(route_hour.latency_buckets, excluded.latency_buckets)",
            )
            .bind(&rec.instance)
            .bind(hour)
            .bind(&r.method)
            .bind(&r.route)
            .bind(i(r.requests))
            .bind(i(r.errors_4xx))
            .bind(i(r.errors_5xx))
            .bind(r.latency.counts())
            .execute(&mut *tx)
            .await?;
        }
        for d in &rec.db_ops {
            sqlx::query(
                "insert into db_op_hour (instance, bucket, operation, calls, latency_buckets) \
                 values ($1, $2, $3, $4, $5) \
                 on conflict (instance, bucket, operation) do update set \
                   calls = db_op_hour.calls + excluded.calls, \
                   latency_buckets = add_buckets(db_op_hour.latency_buckets, excluded.latency_buckets)",
            )
            .bind(&rec.instance)
            .bind(hour)
            .bind(&d.operation)
            .bind(i(d.latency.total()))
            .bind(d.latency.counts())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn insert_logs(&self, logs: &[LogEntry]) -> anyhow::Result<()> {
        if logs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for e in logs {
            sqlx::query(
                "insert into log_record (ts, instance, service, severity, target, body, request_id, method, route, status, duration_ms, attributes) \
                 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)",
            )
            .bind(e.ts)
            .bind(&e.instance)
            .bind(e.service.as_str())
            .bind(e.severity.as_str())
            .bind(&e.target)
            .bind(&e.body)
            .bind(&e.request_id)
            .bind(&e.method)
            .bind(&e.route)
            .bind(e.status.map(i32::from))
            .bind(e.duration_ms)
            .bind(serde_json::Value::Object(e.attributes.clone()).to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn series(
        &self,
        tier: Tier,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<SeriesRow>> {
        let table = match tier {
            Tier::Minute => "metric_minute",
            Tier::Hour => "metric_hour",
        };
        // 表名来自上面的 match(常量),时间是绑定参数。
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "select instance, bucket, {TOTAL_COLS} from {table} \
             where bucket >= $1 and bucket < $2 order by bucket, instance"
        )))
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(SeriesRow {
                    instance: row.try_get("instance")?,
                    bucket: row.try_get("bucket")?,
                    totals: totals_from_row(row)?,
                })
            })
            .collect::<sqlx::Result<_>>()
            .map_err(Into::into)
    }

    async fn route_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, RouteTotals)>> {
        let rows = sqlx::query(
            "select instance, method, route, requests, errors_4xx, errors_5xx, latency_buckets \
             from route_hour where bucket >= $1 and bucket < $2",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut acc: std::collections::BTreeMap<(String, String, String), RouteTotals> =
            Default::default();
        for row in &rows {
            let instance: String = row.try_get("instance")?;
            let method: String = row.try_get("method")?;
            let route: String = row.try_get("route")?;
            let r = acc
                .entry((instance, method.clone(), route.clone()))
                .or_insert_with(|| RouteTotals {
                    method,
                    route,
                    ..Default::default()
                });
            r.requests += u(row.try_get("requests")?);
            r.errors_4xx += u(row.try_get("errors_4xx")?);
            r.errors_5xx += u(row.try_get("errors_5xx")?);
            r.latency.add(&Hist::from_counts(
                &row.try_get::<Vec<i64>, _>("latency_buckets")?,
            ));
        }
        Ok(acc.into_iter().map(|((i, _, _), r)| (i, r)).collect())
    }

    async fn db_op_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, DbOpTotals)>> {
        let rows = sqlx::query(
            "select instance, operation, latency_buckets from db_op_hour \
             where bucket >= $1 and bucket < $2",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut acc: std::collections::BTreeMap<(String, String), DbOpTotals> = Default::default();
        for row in &rows {
            let instance: String = row.try_get("instance")?;
            let operation: String = row.try_get("operation")?;
            acc.entry((instance, operation.clone()))
                .or_insert_with(|| DbOpTotals {
                    operation,
                    ..Default::default()
                })
                .latency
                .add(&Hist::from_counts(
                    &row.try_get::<Vec<i64>, _>("latency_buckets")?,
                ));
        }
        Ok(acc.into_iter().map(|((i, _), d)| (i, d)).collect())
    }

    async fn logs(&self, q: &LogQuery) -> anyhow::Result<(Vec<StoredLog>, u64)> {
        // 条件全部参数化;未给的条件用 `$n is null` 短路,一条 SQL 覆盖所有组合。
        let min_sev: Option<Vec<String>> = q.min_severity.map(|m| match m {
            Severity::Warn => vec!["WARN".to_owned(), "ERROR".to_owned()],
            Severity::Error => vec!["ERROR".to_owned()],
        });
        let pattern = q.q.as_deref().map(ilike_contains);
        let filter = "($1::timestamptz is null or ts >= $1) \
             and ($2::timestamptz is null or ts < $2) \
             and ($3::text[] is null or severity = any($3)) \
             and ($4::text is null or instance = $4) \
             and ($5::text is null or request_id = $5) \
             and ($6::text is null or body ilike $6 or target ilike $6 or route ilike $6) \
             and ($7::text is null or service = $7)";
        // filter 是常量,用户输入全部走绑定参数。
        let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "select count(*) from log_record where {filter}"
        )))
        .bind(q.from)
        .bind(q.to)
        .bind(&min_sev)
        .bind(&q.instance)
        .bind(&q.request_id)
        .bind(&pattern)
        .bind(q.service.map(|s| s.as_str()))
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "select id, ts, instance, service, severity, target, body, request_id, method, route, status, duration_ms, attributes::text as attributes \
             from log_record where {filter} order by ts desc, id desc limit $8 offset $9"
        )))
        .bind(q.from)
        .bind(q.to)
        .bind(&min_sev)
        .bind(&q.instance)
        .bind(&q.request_id)
        .bind(&pattern)
        .bind(q.service.map(|s| s.as_str()))
        .bind(i(q.size))
        .bind(i(q.offset()))
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .iter()
            .map(|row| -> anyhow::Result<StoredLog> {
                let sev: String = row.try_get("severity")?;
                let attrs: String = row.try_get("attributes")?;
                let service: String = row.try_get("service")?;
                Ok(StoredLog {
                    id: row.try_get("id")?,
                    entry: LogEntry {
                        ts: row.try_get("ts")?,
                        instance: row.try_get("instance")?,
                        service: Service::parse(&service).unwrap_or(Service::App),
                        severity: Severity::parse(&sev).unwrap_or(Severity::Warn),
                        target: row.try_get("target")?,
                        body: row.try_get("body")?,
                        request_id: row.try_get("request_id")?,
                        method: row.try_get("method")?,
                        route: row.try_get("route")?,
                        status: row
                            .try_get::<Option<i32>, _>("status")?
                            .and_then(|s| u16::try_from(s).ok()),
                        duration_ms: row.try_get("duration_ms")?,
                        attributes: serde_json::from_str(&attrs).unwrap_or_default(),
                    },
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok((items, u(total)))
    }

    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts> {
        let del = |sql: &'static str, cutoff: OffsetDateTime| {
            let pool = self.pool.clone();
            async move {
                sqlx::query(sql)
                    .bind(cutoff)
                    .execute(&pool)
                    .await
                    .map(|r| r.rows_affected())
            }
        };
        let minutes = del(
            "delete from metric_minute where bucket < $1",
            now - Retention::MINUTE,
        )
        .await?;
        let hours = del(
            "delete from metric_hour where bucket < $1",
            now - Retention::HOUR,
        )
        .await?;
        let routes = del(
            "delete from route_hour where bucket < $1",
            now - Retention::DETAIL,
        )
        .await?;
        let dbs = del(
            "delete from db_op_hour where bucket < $1",
            now - Retention::DETAIL,
        )
        .await?;
        let logs = del(
            "delete from log_record where ts < $1",
            now - Retention::LOGS,
        )
        .await?;
        Ok(PurgeCounts {
            minutes,
            hours,
            details: routes + dbs,
            logs,
        })
    }

    fn persistent(&self) -> bool {
        true
    }
}

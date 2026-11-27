//! [`OpsStore`] 的 Postgres 实现(ops schema,role=ops;表见 `migrations/ops`)。
//! 落一分钟 = 一个事务:写分钟表 + 累加进小时表与小时明细(upsert 相加,直方图用 `add_buckets`)。

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Row};
use time::OffsetDateTime;

use super::histogram::Histogram;
use super::store::{
    hour_start, DbOperationTotals, InstanceDbOperationTotals, InstanceRouteTotals, LogEntry,
    LogPage, LogQuery, MinuteRecord, OpsStore, PeriodTotals, PurgeCounts, Retention, RouteTotals,
    SeriesRow, Service, Severity, StoredLog, Tier,
};
use crate::kernel::time_range::TimeRange;

/// ops schema 上的 [`OpsStore`]。
pub struct PgOpsStore {
    pool: PgPool,
}

impl PgOpsStore {
    /// `pool` 连的是 ops 账号(search_path 落在 ops schema)。
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const TOTAL_COLUMNS: &str =
    "requests, errors_4xx, errors_5xx, latency_buckets, db_calls, db_latency_buckets, \
     outbox_published, outbox_failures, projector_processed, projector_failed, in_flight_max, \
     pool_in_use_max, pool_max, sse_max, projector_pending_max, rss_bytes_max, cpu_percent_max";

/// 计数 → PG bigint(超出范围饱和到 `i64::MAX`)。
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// PG bigint → 计数(负数当 0)。
fn non_negative_u64(value: i64) -> u64 {
    value.max(0) as u64
}

/// 汇总行的 upsert:计数相加、读数取大。`table` 只会是常量表名。
fn upsert_totals_sql(table: &str) -> String {
    format!(
        "insert into {table} (instance, bucket, {TOTAL_COLUMNS}) \
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
    connection: &mut PgConnection,
    table: &str,
    instance: &str,
    bucket: OffsetDateTime,
    totals: &PeriodTotals,
) -> sqlx::Result<()> {
    // 表名只来自本文件的常量(metric_minute / metric_hour),其余全是绑定参数。
    sqlx::query(AssertSqlSafe(upsert_totals_sql(table)))
        .bind(instance)
        .bind(bucket)
        .bind(saturating_i64(totals.requests))
        .bind(saturating_i64(totals.errors_4xx))
        .bind(saturating_i64(totals.errors_5xx))
        .bind(totals.latency.counts())
        .bind(saturating_i64(totals.db_calls))
        .bind(totals.db_latency.counts())
        .bind(saturating_i64(totals.outbox_published))
        .bind(saturating_i64(totals.outbox_failures))
        .bind(saturating_i64(totals.projector_processed))
        .bind(saturating_i64(totals.projector_failed))
        .bind(saturating_i64(totals.in_flight_max))
        .bind(saturating_i64(totals.pool_in_use_max))
        .bind(saturating_i64(totals.pool_max))
        .bind(saturating_i64(totals.sse_max))
        .bind(saturating_i64(totals.projector_pending_max))
        .bind(totals.rss_bytes_max.map(saturating_i64))
        .bind(totals.cpu_percent_max)
        .execute(connection)
        .await
        .map(|_| ())
}

fn totals_from_row(row: &PgRow) -> sqlx::Result<PeriodTotals> {
    let latency_buckets: Vec<i64> = row.try_get("latency_buckets")?;
    let db_latency_buckets: Vec<i64> = row.try_get("db_latency_buckets")?;
    let rss_bytes_max: Option<i64> = row.try_get("rss_bytes_max")?;
    Ok(PeriodTotals {
        requests: non_negative_u64(row.try_get("requests")?),
        errors_4xx: non_negative_u64(row.try_get("errors_4xx")?),
        errors_5xx: non_negative_u64(row.try_get("errors_5xx")?),
        latency: Histogram::from_counts(&latency_buckets),
        db_calls: non_negative_u64(row.try_get("db_calls")?),
        db_latency: Histogram::from_counts(&db_latency_buckets),
        outbox_published: non_negative_u64(row.try_get("outbox_published")?),
        outbox_failures: non_negative_u64(row.try_get("outbox_failures")?),
        projector_processed: non_negative_u64(row.try_get("projector_processed")?),
        projector_failed: non_negative_u64(row.try_get("projector_failed")?),
        in_flight_max: non_negative_u64(row.try_get("in_flight_max")?),
        pool_in_use_max: non_negative_u64(row.try_get("pool_in_use_max")?),
        pool_max: non_negative_u64(row.try_get("pool_max")?),
        sse_max: non_negative_u64(row.try_get("sse_max")?),
        projector_pending_max: non_negative_u64(row.try_get("projector_pending_max")?),
        rss_bytes_max: rss_bytes_max.map(non_negative_u64),
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
    async fn record_minute(&self, record: &MinuteRecord) -> anyhow::Result<()> {
        let hour = hour_start(record.bucket);
        let mut transaction = self.pool.begin().await?;
        upsert_totals(
            &mut transaction,
            "metric_minute",
            &record.instance,
            record.bucket,
            &record.totals,
        )
        .await?;
        upsert_totals(
            &mut transaction,
            "metric_hour",
            &record.instance,
            hour,
            &record.totals,
        )
        .await?;
        for route in &record.routes {
            sqlx::query(
                "insert into route_hour (instance, bucket, method, route, requests, errors_4xx, errors_5xx, latency_buckets) \
                 values ($1, $2, $3, $4, $5, $6, $7, $8) \
                 on conflict (instance, bucket, method, route) do update set \
                   requests = route_hour.requests + excluded.requests, \
                   errors_4xx = route_hour.errors_4xx + excluded.errors_4xx, \
                   errors_5xx = route_hour.errors_5xx + excluded.errors_5xx, \
                   latency_buckets = add_buckets(route_hour.latency_buckets, excluded.latency_buckets)",
            )
            .bind(&record.instance)
            .bind(hour)
            .bind(&route.method)
            .bind(&route.route)
            .bind(saturating_i64(route.requests))
            .bind(saturating_i64(route.errors_4xx))
            .bind(saturating_i64(route.errors_5xx))
            .bind(route.latency.counts())
            .execute(&mut *transaction)
            .await?;
        }
        for operation in &record.db_operations {
            sqlx::query(
                "insert into db_op_hour (instance, bucket, operation, calls, latency_buckets) \
                 values ($1, $2, $3, $4, $5) \
                 on conflict (instance, bucket, operation) do update set \
                   calls = db_op_hour.calls + excluded.calls, \
                   latency_buckets = add_buckets(db_op_hour.latency_buckets, excluded.latency_buckets)",
            )
            .bind(&record.instance)
            .bind(hour)
            .bind(&operation.operation)
            .bind(saturating_i64(operation.latency.total()))
            .bind(operation.latency.counts())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn insert_logs(&self, logs: &[LogEntry]) -> anyhow::Result<()> {
        if logs.is_empty() {
            return Ok(());
        }
        let mut transaction = self.pool.begin().await?;
        for entry in logs {
            sqlx::query(
                "insert into log_record (ts, instance, service, severity, target, body, request_id, method, route, status, duration_ms, attributes) \
                 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)",
            )
            .bind(entry.timestamp)
            .bind(&entry.instance)
            .bind(entry.service.as_str())
            .bind(entry.severity.as_str())
            .bind(&entry.target)
            .bind(&entry.body)
            .bind(&entry.request_id)
            .bind(&entry.method)
            .bind(&entry.route)
            .bind(entry.status.map(i32::from))
            .bind(entry.duration_ms)
            .bind(Value::Object(entry.attributes.clone()).to_string())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn series(&self, tier: Tier, range: TimeRange) -> anyhow::Result<Vec<SeriesRow>> {
        let TimeRange { from, to } = range;
        let table = match tier {
            Tier::Minute => "metric_minute",
            Tier::Hour => "metric_hour",
        };
        // 表名来自上面的 match(常量),时间是绑定参数。
        let rows = sqlx::query(AssertSqlSafe(format!(
            "select instance, bucket, {TOTAL_COLUMNS} from {table} \
             where bucket >= $1 and bucket < $2 order by bucket, instance"
        )))
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let series: sqlx::Result<Vec<SeriesRow>> = rows
            .iter()
            .map(|row| {
                Ok(SeriesRow {
                    instance: row.try_get("instance")?,
                    bucket: row.try_get("bucket")?,
                    totals: totals_from_row(row)?,
                })
            })
            .collect();
        Ok(series?)
    }

    async fn route_totals(&self, range: TimeRange) -> anyhow::Result<Vec<InstanceRouteTotals>> {
        let TimeRange { from, to } = range;
        let rows = sqlx::query(
            "select instance, method, route, requests, errors_4xx, errors_5xx, latency_buckets \
             from route_hour where bucket >= $1 and bucket < $2",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut by_route: BTreeMap<(String, String, String), RouteTotals> = BTreeMap::new();
        for row in &rows {
            let instance: String = row.try_get("instance")?;
            let method: String = row.try_get("method")?;
            let route: String = row.try_get("route")?;
            let latency_buckets: Vec<i64> = row.try_get("latency_buckets")?;
            let totals = by_route
                .entry((instance, method.clone(), route.clone()))
                .or_insert_with(|| RouteTotals {
                    method,
                    route,
                    ..Default::default()
                });
            totals.requests += non_negative_u64(row.try_get("requests")?);
            totals.errors_4xx += non_negative_u64(row.try_get("errors_4xx")?);
            totals.errors_5xx += non_negative_u64(row.try_get("errors_5xx")?);
            totals
                .latency
                .add(&Histogram::from_counts(&latency_buckets));
        }
        Ok(by_route
            .into_iter()
            .map(|((instance, _, _), totals)| InstanceRouteTotals { instance, totals })
            .collect())
    }

    async fn db_operation_totals(
        &self,
        range: TimeRange,
    ) -> anyhow::Result<Vec<InstanceDbOperationTotals>> {
        let TimeRange { from, to } = range;
        let rows = sqlx::query(
            "select instance, operation, latency_buckets from db_op_hour \
             where bucket >= $1 and bucket < $2",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut by_operation: BTreeMap<(String, String), DbOperationTotals> = BTreeMap::new();
        for row in &rows {
            let instance: String = row.try_get("instance")?;
            let operation: String = row.try_get("operation")?;
            let latency_buckets: Vec<i64> = row.try_get("latency_buckets")?;
            by_operation
                .entry((instance, operation.clone()))
                .or_insert_with(|| DbOperationTotals {
                    operation,
                    ..Default::default()
                })
                .latency
                .add(&Histogram::from_counts(&latency_buckets));
        }
        Ok(by_operation
            .into_iter()
            .map(|((instance, _), totals)| InstanceDbOperationTotals { instance, totals })
            .collect())
    }

    async fn logs(&self, query: &LogQuery) -> anyhow::Result<LogPage> {
        // 条件全部参数化;未给的条件用 `$n is null` 短路,一条 SQL 覆盖所有组合。
        let severities: Option<Vec<String>> =
            query.min_severity.map(|min_severity| match min_severity {
                Severity::Warn => vec!["WARN".to_owned(), "ERROR".to_owned()],
                Severity::Error => vec!["ERROR".to_owned()],
            });
        let pattern = query.query.as_deref().map(ilike_contains);
        let filter = "($1::timestamptz is null or ts >= $1) \
             and ($2::timestamptz is null or ts < $2) \
             and ($3::text[] is null or severity = any($3)) \
             and ($4::text is null or instance = $4) \
             and ($5::text is null or request_id = $5) \
             and ($6::text is null or body ilike $6 or target ilike $6 or route ilike $6) \
             and ($7::text is null or service = $7)";
        // filter 是常量,用户输入全部走绑定参数。
        let total: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "select count(*) from log_record where {filter}"
        )))
        .bind(query.from)
        .bind(query.to)
        .bind(&severities)
        .bind(&query.instance)
        .bind(&query.request_id)
        .bind(&pattern)
        .bind(query.service.map(Service::as_str))
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query(AssertSqlSafe(format!(
            "select id, ts, instance, service, severity, target, body, request_id, method, route, status, duration_ms, attributes::text as attributes \
             from log_record where {filter} order by ts desc, id desc limit $8 offset $9"
        )))
        .bind(query.from)
        .bind(query.to)
        .bind(&severities)
        .bind(&query.instance)
        .bind(&query.request_id)
        .bind(&pattern)
        .bind(query.service.map(Service::as_str))
        .bind(saturating_i64(query.size))
        .bind(saturating_i64(query.offset()))
        .fetch_all(&self.pool)
        .await?;
        let items: anyhow::Result<Vec<StoredLog>> = rows
            .iter()
            .map(|row| -> anyhow::Result<StoredLog> {
                let severity: String = row.try_get("severity")?;
                let attributes: String = row.try_get("attributes")?;
                let service: String = row.try_get("service")?;
                let status: Option<i32> = row.try_get("status")?;
                Ok(StoredLog {
                    id: row.try_get("id")?,
                    entry: LogEntry {
                        timestamp: row.try_get("ts")?,
                        instance: row.try_get("instance")?,
                        service: service.parse().unwrap_or(Service::App),
                        severity: severity.parse().unwrap_or(Severity::Warn),
                        target: row.try_get("target")?,
                        body: row.try_get("body")?,
                        request_id: row.try_get("request_id")?,
                        method: row.try_get("method")?,
                        route: row.try_get("route")?,
                        status: status.and_then(|status| u16::try_from(status).ok()),
                        duration_ms: row.try_get("duration_ms")?,
                        attributes: serde_json::from_str(&attributes).unwrap_or_default(),
                    },
                })
            })
            .collect();
        Ok(LogPage {
            logs: items?,
            total: non_negative_u64(total),
        })
    }

    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts> {
        let delete_before = |sql: &'static str, cutoff: OffsetDateTime| {
            let pool = self.pool.clone();
            async move {
                sqlx::query(sql)
                    .bind(cutoff)
                    .execute(&pool)
                    .await
                    .map(|result| result.rows_affected())
            }
        };
        let minutes = delete_before(
            "delete from metric_minute where bucket < $1",
            now - Retention::MINUTE,
        )
        .await?;
        let hours = delete_before(
            "delete from metric_hour where bucket < $1",
            now - Retention::HOUR,
        )
        .await?;
        let routes = delete_before(
            "delete from route_hour where bucket < $1",
            now - Retention::DETAIL,
        )
        .await?;
        let db_operations = delete_before(
            "delete from db_op_hour where bucket < $1",
            now - Retention::DETAIL,
        )
        .await?;
        let logs = delete_before(
            "delete from log_record where ts < $1",
            now - Retention::LOGS,
        )
        .await?;
        Ok(PurgeCounts {
            minutes,
            hours,
            details: routes + db_operations,
            logs,
        })
    }

    fn persistent(&self) -> bool {
        true
    }
}

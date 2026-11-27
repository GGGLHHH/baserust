//! 后台「系统监控」页的 HTTP 入口 + 采样任务。放组合根:要探针(各 schema 连接池 / NATS)、
//! 挂载范围(本进程是 app / idm / 合体)和 idm 的内网地址。数据本身在 [`crate::infra::monitor`]。
//!
//! 拓扑:开发单进程 `Both` → 一个实例(combined);生产分进程 → 浏览器只打到 app(nginx 把
//! `/api/v1/admin/monitoring` 转给 app),app 再经 `IDM_INTERNAL_URL` 拉 idm 的 `/internal/monitoring`
//! 并进同一份响应。`/internal/*` 不在 nginx 的转发范围(只转 `/api/`、`/health`),外部到不了。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use reqwest::Client;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::watch;
use tokio::time::{self as tokio_time, Instant as TokioInstant};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;
use crate::app::probes::Probes;
use crate::app::Mount;
use crate::infra::authorization::TokenScope;
use crate::infra::config::Config;
use crate::infra::http::audit::CurrentUser;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Query};
use crate::infra::http::pagination::Page;
use crate::infra::monitor::report::{
    DbOperationStats, DependencyCheck, HistoryInstance, HistoryPoint, HistoryQuery, HistoryRange,
    HistoryReport, InstanceReport, InstanceRole, LogRecordView, LogsQuery, MonitoringReport,
    RouteStats, TrafficSummary,
};
use crate::infra::monitor::store::{
    self, InstanceDbOperationTotals, InstanceRouteTotals, LogEntry, LogPage, LogQuery,
    MemoryOpsStore, OpsStore, PeriodTotals, Retention, Severity, StoredLog,
};
use crate::infra::monitor::{self, logs, SAMPLE_INTERVAL};
use crate::infra::telemetry::MetricsSampler;
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::Permission;
use crate::kernel::pagination::{OffsetPosition, Page as CorePage};
use crate::kernel::time_range::TimeRange;

/// 拉 idm 报告的超时(它要先做一轮依赖检查,依赖检查本身每项 2s 封顶)。
const REMOTE_TIMEOUT: Duration = Duration::from_secs(4);

/// 挂载范围 → 监控里的进程身份(指标、日志都按它区分 app / idm)。
impl From<Mount> for InstanceRole {
    fn from(mount: Mount) -> Self {
        match mount {
            Mount::App => InstanceRole::App,
            Mount::Idm => InstanceRole::Idm,
            Mount::Both => InstanceRole::Combined,
        }
    }
}

/// 本进程在监控页上的身份 + 要汇总的远端进程 + 历史 / 日志的存储。
#[derive(Clone)]
pub struct MonitoringSetup {
    role: InstanceRole,
    remote_idm: Option<RemoteInstance>,
    store: Arc<dyn OpsStore>,
}

impl Default for MonitoringSetup {
    /// 单进程合体、无远端、内存存储(测试 / 内存模式)。
    fn default() -> Self {
        Self {
            role: InstanceRole::Combined,
            remote_idm: None,
            store: Arc::new(MemoryOpsStore::new()),
        }
    }
}

impl MonitoringSetup {
    /// 按挂载范围定进程身份;`App` 进程配了 `IDM_INTERNAL_URL` 时汇总远端 idm。存储先用内存,
    /// 配了 ops 数据库再经 [`Self::with_store`] 换掉。
    #[must_use]
    pub fn new(config: &Config, mount: Mount) -> Self {
        let role = InstanceRole::from(mount);
        let remote_idm = match (mount, &config.idm_internal_url) {
            (Mount::App, Some(url)) => Some(RemoteInstance {
                role: InstanceRole::Idm,
                url: format!("{}/internal/monitoring", url.trim_end_matches('/')),
                client: Client::new(),
            }),
            _ => None,
        };
        Self {
            role,
            remote_idm,
            store: Arc::new(MemoryOpsStore::new()),
        }
    }

    /// 换存储(配了 ops 数据库时用 PG 实现)。
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn OpsStore>) -> Self {
        self.store = store;
        self
    }

    /// 本进程在监控页上的身份。
    #[must_use]
    pub fn role(&self) -> InstanceRole {
        self.role
    }

    /// 历史 / 日志存储(内存或 ops 库)。
    #[must_use]
    pub fn store(&self) -> &dyn OpsStore {
        self.store.as_ref()
    }
}

#[derive(Clone)]
struct RemoteInstance {
    role: InstanceRole,
    url: String,
    client: Client,
}

impl RemoteInstance {
    /// 拉不到就给一条"不可达"的实例(页面照常出,只标红这一个进程);原始错误只进日志。
    async fn fetch(&self) -> InstanceReport {
        let result = self
            .client
            .get(&self.url)
            .timeout(REMOTE_TIMEOUT)
            .send()
            .await;
        let reason = match result {
            Ok(response) if response.status().is_success() => {
                let parsed: reqwest::Result<InstanceReport> = response.json().await;
                match parsed {
                    Ok(report) => return report,
                    Err(error) => {
                        tracing::warn!(url = %self.url, error = %error, "监控:idm 报告解析失败");
                        "响应无法解析".to_owned()
                    }
                }
            }
            Ok(response) => {
                tracing::warn!(url = %self.url, status = %response.status(), "监控:idm 报告返回错误状态");
                format!("返回 HTTP {}", response.status().as_u16())
            }
            Err(error) => {
                tracing::warn!(url = %self.url, error = %error, "监控:拉取 idm 报告失败");
                if error.is_timeout() {
                    "超时".to_owned()
                } else if error.is_connect() {
                    "连接失败".to_owned()
                } else {
                    "请求失败".to_owned()
                }
            }
        };
        InstanceReport::new_unreachable(self.role, reason)
    }
}

/// admin 组(组闸 + 端点内 `ops:read`,superadmin 独占)。只在挂了 app 的进程上(App / Both)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_monitoring))
        .routes(routes!(get_monitoring_history))
        .routes(routes!(list_monitoring_logs))
}

/// idm 进程的内部端点(不进 OpenAPI、不鉴权:只在容器网络里可达)。
pub fn internal_router() -> Router<AppState> {
    Router::new().route("/internal/monitoring", get(internal_monitoring))
}

/// 系统监控:每个进程的依赖健康、请求量 / 错误 / 耗时、数据库操作耗时、连接池、后台任务(outbox / projector)、
/// SSE 在线数、进程资源,以及最近一段时间(默认 1 小时,15 秒一个点)的历史曲线。数据只在进程内存里,重启清空。
#[utoipa::path(
    get,
    path = "/monitoring",
    tag = "monitoring",
    responses(
        (status = 200, description = "各进程的监控数据(生产分进程时含 app 与 idm)", body = MonitoringReport),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 ops:read 权限(superadmin 独占)", body = ErrorBody)
    )
)]
pub async fn get_monitoring(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Json<MonitoringReport>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::OpsRead)?;
    let local = local_report(&state);
    let instances = match &state.monitoring.remote_idm {
        Some(remote) => {
            let (local, remote) = tokio::join!(local, remote.fetch());
            vec![local, remote]
        }
        None => vec![local.await],
    };
    Ok(Json(MonitoringReport {
        generated_at: OffsetDateTime::now_utc(),
        instances,
    }))
}

// `axum::Json` 带路径写:本文件的 `Json` 是 handler 用的 `infra::http::extract::Json`。
async fn internal_monitoring(State(state): State<AppState>) -> axum::Json<InstanceReport> {
    axum::Json(local_report(&state).await)
}

async fn local_report(state: &AppState) -> InstanceReport {
    // 先读连接池占用、再做依赖检查:检查本身会借连接(`select 1`),反过来读会把它们算进"使用中"。
    let pools = state.probes.pool_stats();
    let checks: Vec<DependencyCheck> = state
        .probes
        .check()
        .await
        .into_iter()
        .map(|result| DependencyCheck {
            name: result.name,
            ok: result.ok,
            latency_ms: result.latency_ms,
            error: result.error,
        })
        .collect();
    monitor::global().report(state.monitoring.role, checks, pools)
}

/// `/metrics` 端点开没开([`run_sampler`] 据此决定要不要顺带刷新进程资源 / 连接池指标)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsEndpoint {
    Enabled,
    Disabled,
}

/// 采样任务:每 [`SAMPLE_INTERVAL`] 存一份监控快照;开了 `/metrics` 时顺带刷新进程资源 / 连接池指标。
/// 随服务优雅退出而停。
pub async fn run_sampler(
    probes: Probes,
    metrics: MetricsEndpoint,
    mut shutdown: watch::Receiver<bool>,
) {
    let metrics = (metrics == MetricsEndpoint::Enabled).then(MetricsSampler::new);
    // 第一拍放在一个间隔之后:启动瞬间的快照和基线几乎一样,只会多出一个空点。
    let mut tick = tokio_time::interval_at(TokioInstant::now() + SAMPLE_INTERVAL, SAMPLE_INTERVAL);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(metrics) = &metrics {
                    metrics.collect();
                    probes.record_pool_metrics();
                }
                monitor::global().sample(&probes.pool_stats());
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

/// 历史趋势:按时间范围(24 小时 ~ 1 年)给出各进程的曲线、范围合计,以及接口 / 数据库操作的明细。
/// 数据来自 ops 数据库(分钟级留 15 天、小时级留 13 个月、明细留 30 天);没配时只有进程内存里最近一段。
#[utoipa::path(
    get,
    path = "/monitoring/history",
    tag = "monitoring",
    params(HistoryQuery),
    responses(
        (status = 200, body = HistoryReport),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 ops:read 权限(superadmin 独占)", body = ErrorBody)
    )
)]
pub async fn get_monitoring_history(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryReport>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::OpsRead)?;
    let report = build_history(
        &*state.monitoring.store,
        query.range,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(|error| {
        tracing::error!(target: logs::STORE_TARGET, error = %error, "监控:读取历史失败");
        AppError::Internal(anyhow::anyhow!("读取监控历史失败"))
    })?;
    Ok(Json(report))
}

/// 日志:WARN 及以上的日志、失败请求(5xx)和慢请求(≥1 秒),按时间倒序分页。保留 15 天。
#[utoipa::path(
    get,
    path = "/monitoring/logs",
    tag = "monitoring",
    params(LogsQuery),
    responses(
        (status = 200, body = Page<LogRecordView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 ops:read 权限(superadmin 独占)", body = ErrorBody),
        (status = 422, description = "参数不合法(size 超出 1~200 / from 晚于 to)", body = ErrorBody)
    )
)]
pub async fn list_monitoring_logs(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Page<LogRecordView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::OpsRead)?;
    if !(1..=200).contains(&query.size) || query.page == 0 {
        return Err(AppError::Validation("size 需在 1~200 之间,page 从 1 开始".to_owned()).into());
    }
    if let (Some(from), Some(to)) = (query.from, query.to) {
        if from > to {
            return Err(AppError::Validation("from 不能晚于 to".to_owned()).into());
        }
    }
    let log_query = LogQuery {
        from: query.from,
        to: query.to,
        min_severity: query.level,
        instance: query.instance.map(|i| i.as_str().to_owned()),
        service: query.service,
        query: query.query.filter(|s| !s.trim().is_empty()),
        request_id: query.request_id.filter(|s| !s.trim().is_empty()),
        page: query.page,
        size: query.size,
    };
    let LogPage { logs: items, total } =
        state
            .monitoring
            .store
            .logs(&log_query)
            .await
            .map_err(|error| {
                tracing::error!(target: logs::STORE_TARGET, error = %error, "监控:查询日志失败");
                AppError::Internal(anyhow::anyhow!("查询日志失败"))
            })?;
    let position = OffsetPosition {
        page: log_query.page,
        size: log_query.size,
    };
    let page = CorePage::new_with_offset(
        items.into_iter().map(log_view).collect(),
        position,
        Some(total),
    );
    Ok(Json(Page::from_core(page, |v| v)))
}

fn log_view(stored: StoredLog) -> LogRecordView {
    let entry = stored.entry;
    LogRecordView {
        id: stored.id,
        timestamp: entry.timestamp,
        instance: entry.instance.parse().unwrap_or(InstanceRole::Combined),
        service: entry.service,
        severity: entry.severity,
        target: entry.target,
        body: entry.body,
        request_id: entry.request_id,
        method: entry.method,
        route: entry.route,
        status: entry.status,
        duration_ms: entry.duration_ms,
        attributes: entry.attributes,
    }
}

fn traffic_of(totals: &PeriodTotals) -> TrafficSummary {
    TrafficSummary {
        requests: totals.requests,
        errors_4xx: totals.errors_4xx,
        errors_5xx: totals.errors_5xx,
        p50_ms: totals.latency.quantile(0.5),
        p95_ms: totals.latency.quantile(0.95),
        p99_ms: totals.latency.quantile(0.99),
    }
}

fn point_of(at: OffsetDateTime, totals: &PeriodTotals) -> HistoryPoint {
    HistoryPoint {
        at,
        requests: totals.requests,
        errors_4xx: totals.errors_4xx,
        errors_5xx: totals.errors_5xx,
        p95_ms: totals.latency.quantile(0.95),
        in_flight: totals.in_flight_max as i64,
        db_calls: totals.db_calls,
        db_p95_ms: totals.db_latency.quantile(0.95),
        pool_in_use: totals.pool_in_use_max,
        pool_max: totals.pool_max,
        sse_connections: totals.sse_max as i64,
        outbox_published: totals.outbox_published,
        projector_processed: totals.projector_processed,
        projector_pending: totals.projector_pending_max,
        rss_bytes: totals.rss_bytes_max,
        cpu_percent: totals.cpu_percent_max,
    }
}

/// 读存储、按范围的步长重新分桶,组装历史报告。
pub async fn build_history(
    store: &dyn OpsStore,
    range: HistoryRange,
    now: OffsetDateTime,
) -> anyhow::Result<HistoryReport> {
    let step = range.step();
    let step_seconds = step.whole_seconds().max(1);
    // 起点对齐到步长,让每个点的时间整齐(如 5 分钟一格)。
    let raw_from = now - range.duration();
    let from_seconds =
        raw_from.unix_timestamp() - raw_from.unix_timestamp().rem_euclid(step_seconds);
    let from = OffsetDateTime::from_unix_timestamp(from_seconds)?;
    let to = now;
    let details_from = from.max(now - Retention::DETAIL);

    let rows = store.series(range.tier(), TimeRange { from, to }).await?;
    let mut per_instance: BTreeMap<String, BTreeMap<i64, PeriodTotals>> = BTreeMap::new();
    for row in rows {
        let bin = (row.bucket.unix_timestamp() - from_seconds).div_euclid(step_seconds);
        per_instance
            .entry(row.instance)
            .or_default()
            .entry(bin)
            .or_default()
            .merge(&row.totals);
    }
    let mut routes: BTreeMap<String, Vec<RouteStats>> = BTreeMap::new();
    for InstanceRouteTotals {
        instance,
        totals: route_totals,
    } in store
        .route_totals(TimeRange {
            from: details_from,
            to,
        })
        .await?
    {
        routes.entry(instance).or_default().push(RouteStats {
            method: route_totals.method,
            route: route_totals.route,
            requests: route_totals.requests,
            errors_4xx: route_totals.errors_4xx,
            errors_5xx: route_totals.errors_5xx,
            p50_ms: route_totals.latency.quantile(0.5),
            p95_ms: route_totals.latency.quantile(0.95),
        });
    }
    let mut db_operations: BTreeMap<String, Vec<DbOperationStats>> = BTreeMap::new();
    for InstanceDbOperationTotals {
        instance,
        totals: operation_totals,
    } in store
        .db_operation_totals(TimeRange {
            from: details_from,
            to,
        })
        .await?
    {
        db_operations
            .entry(instance)
            .or_default()
            .push(DbOperationStats {
                name: operation_totals.operation,
                calls: operation_totals.latency.total(),
                p50_ms: operation_totals.latency.quantile(0.5),
                p95_ms: operation_totals.latency.quantile(0.95),
            });
    }

    let mut names: Vec<String> = per_instance.keys().cloned().collect();
    let detail_names = routes.keys().chain(db_operations.keys());
    for detail_name in detail_names {
        if !names.contains(detail_name) {
            names.push(detail_name.clone());
        }
    }
    let mut instances = Vec::new();
    for name in names {
        let Ok(role) = name.parse::<InstanceRole>() else {
            continue;
        };
        let bins = per_instance.remove(&name).unwrap_or_default();
        let mut total = PeriodTotals::default();
        let mut points = Vec::with_capacity(bins.len());
        for (bin, totals) in &bins {
            total.merge(totals);
            let at = OffsetDateTime::from_unix_timestamp(from_seconds + bin * step_seconds)
                .unwrap_or(from);
            points.push(point_of(at, totals));
        }
        let mut instance_routes = routes.remove(&name).unwrap_or_default();
        instance_routes.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.route.cmp(&b.route)));
        let mut instance_db_operations = db_operations.remove(&name).unwrap_or_default();
        instance_db_operations.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.name.cmp(&b.name)));
        instances.push(HistoryInstance {
            role,
            traffic: traffic_of(&total),
            points,
            routes: instance_routes,
            db_operations: instance_db_operations,
        });
    }
    instances.sort_by_key(|i| i.role.as_str());
    Ok(HistoryReport {
        range,
        from,
        to,
        step_seconds: step_seconds as u64,
        persistent: store.persistent(),
        details_from,
        instances,
    })
}

// ── 后台任务(随服务优雅退出而停)──

/// 等到 `duration` 或收到退出信号;收到退出返回 `false`。
async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio_time::sleep(duration) => true,
        changed = shutdown.changed() => !(changed.is_err() || *shutdown.borrow()),
    }
}

/// 每分钟落盘:整分后 2 秒,把上一分钟的增量写进存储。
pub async fn run_minute_flusher(
    setup: MonitoringSetup,
    probes: Probes,
    mut shutdown: watch::Receiver<bool>,
) {
    let instance = setup.role.as_str();
    loop {
        let now = OffsetDateTime::now_utc();
        let next = store::minute_start(now) + TimeDuration::minutes(1) + TimeDuration::seconds(2);
        let wait = (next - now).unsigned_abs();
        if !sleep_or_shutdown(wait, &mut shutdown).await {
            break;
        }
        let bucket = store::minute_start(OffsetDateTime::now_utc()) - TimeDuration::minutes(1);
        let record = monitor::global().take_minute(instance, bucket, &probes.pool_stats());
        if let Err(error) = setup.store.record_minute(&record).await {
            tracing::warn!(target: logs::STORE_TARGET, error = %error, "监控:写分钟数据失败(这一分钟丢失)");
        }
    }
}

/// 日志写入:从采集队列批量取(最多 500 条 / 1 秒一批)写进存储;队列满丢弃的条数也记一条。
pub async fn run_log_writer(setup: MonitoringSetup, mut shutdown: watch::Receiver<bool>) {
    let Some(mut receiver) = logs::take_receiver() else {
        return;
    };
    let mut batch: Vec<LogEntry> = Vec::with_capacity(500);
    loop {
        let stop = tokio::select! {
            n = receiver.recv_many(&mut batch, 500) => n == 0,
            changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        };
        // 再等一小会儿凑批(突发时一次写多条)。
        if !stop && batch.len() < 500 {
            let _ = tokio_time::timeout(Duration::from_secs(1), async {
                while batch.len() < 500 {
                    let room = 500 - batch.len();
                    if receiver.recv_many(&mut batch, room).await == 0 {
                        break;
                    }
                }
            })
            .await;
        }
        let dropped = logs::take_dropped();
        if dropped > 0 {
            batch.push(LogEntry {
                timestamp: OffsetDateTime::now_utc(),
                instance: setup.role.as_str().to_owned(),
                service: store::classify_service(store::LogOrigin {
                    instance: setup.role.as_str(),
                    target: logs::STORE_TARGET,
                    route: None,
                }),
                severity: Severity::Warn,
                target: logs::STORE_TARGET.to_owned(),
                body: format!("日志过多,采集队列已满,丢弃了 {dropped} 条"),
                request_id: None,
                method: None,
                route: None,
                status: None,
                duration_ms: None,
                attributes: Default::default(),
            });
        }
        if !batch.is_empty() {
            if let Err(error) = setup.store.insert_logs(&batch).await {
                tracing::warn!(target: logs::STORE_TARGET, error = %error, count = batch.len(), "监控:写日志失败(这批丢失)");
            }
            batch.clear();
        }
        if stop {
            break;
        }
    }
}

/// 保留期清理:启动后 1 分钟跑一次,之后每小时一次。
pub async fn run_retention(setup: MonitoringSetup, mut shutdown: watch::Receiver<bool>) {
    let mut wait = Duration::from_secs(60);
    loop {
        if !sleep_or_shutdown(wait, &mut shutdown).await {
            break;
        }
        wait = Duration::from_secs(3600);
        match setup.store.purge(OffsetDateTime::now_utc()).await {
            // 日志字段名 `n` 不随变量改名,保持日志输出与改名前一致。
            Ok(purged) => tracing::debug!(n = ?purged, "监控:保留期清理完成"),
            Err(error) => {
                tracing::warn!(target: logs::STORE_TARGET, error = %error, "监控:保留期清理失败");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::monitor::histogram::Histogram;
    use crate::infra::monitor::store::{MinuteRecord, RouteTotals};

    fn minute_record(
        instance: &str,
        bucket: OffsetDateTime,
        requests: u64,
        ms: f64,
    ) -> MinuteRecord {
        let mut latency = Histogram::default();
        for _ in 0..requests {
            latency.record(ms);
        }
        MinuteRecord {
            instance: instance.to_owned(),
            bucket,
            totals: PeriodTotals {
                requests,
                latency,
                ..Default::default()
            },
            routes: vec![RouteTotals {
                method: "GET".into(),
                route: "/a".into(),
                requests,
                latency,
                ..Default::default()
            }],
            db_operations: vec![],
        }
    }

    #[tokio::test]
    async fn history_rebins_minutes_into_steps_per_instance() {
        let ops_store = MemoryOpsStore::new();
        let now = OffsetDateTime::now_utc();
        let base = store::minute_start(now) - TimeDuration::minutes(30);
        for minute_offset in 0..10 {
            let bucket = base + TimeDuration::minutes(minute_offset);
            ops_store
                .record_minute(&minute_record("app", bucket, 2, 5.0))
                .await
                .unwrap();
            ops_store
                .record_minute(&minute_record("idm", bucket, 1, 50.0))
                .await
                .unwrap();
        }
        let history = build_history(&ops_store, HistoryRange::Day, now)
            .await
            .unwrap();
        assert_eq!(history.step_seconds, 300);
        assert!(!history.persistent);
        let roles: Vec<_> = history.instances.iter().map(|i| i.role).collect();
        assert_eq!(roles, [InstanceRole::App, InstanceRole::Idm]);
        let app = &history.instances[0];
        assert_eq!(app.traffic.requests, 20);
        assert_eq!(app.points.iter().map(|p| p.requests).sum::<u64>(), 20);
        assert!(
            app.points.len() >= 2 && app.points.len() <= 3,
            "10 分钟 → 2~3 个 5 分钟点"
        );
        assert_eq!(app.routes[0].requests, 20);
        assert!(history.instances[1].traffic.p95_ms.unwrap() > app.traffic.p95_ms.unwrap());
    }
}

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
use time::OffsetDateTime;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::probes::Probes;
use crate::app::state::AppState;
use crate::app::Mount;
use crate::infra::authz::TokenScope;
use crate::infra::config::Config;
use crate::infra::http::audit::CurrentUser;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Query};
use crate::infra::http::pagination::Page;
use crate::infra::monitor::logs;
use crate::infra::monitor::report::{
    DbOperationStats, DependencyCheck, HistoryInstance, HistoryPoint, HistoryQuery, HistoryRange,
    HistoryReport, InstanceReport, InstanceRole, LogRecordView, LogsQuery, MonitoringReport,
    RouteStats, TrafficSummary,
};
use crate::infra::monitor::store::{
    minute_start, LogEntry, LogQuery, MemoryOpsStore, OpsStore, PeriodTotals, Retention, StoredLog,
};
use crate::infra::monitor::{self, SAMPLE_INTERVAL};
use crate::infra::telemetry::MetricsSampler;
use crate::kernel::authz::Perm;
use crate::kernel::error::AppError;

/// 拉 idm 报告的超时(它要先做一轮依赖检查,依赖检查本身每项 2s 封顶)。
const REMOTE_TIMEOUT: Duration = Duration::from_secs(4);

/// 挂载范围 → 监控里的进程身份(指标、日志都按它区分 app / idm)。
pub fn role_for_mount(mount: Mount) -> InstanceRole {
    match mount {
        Mount::App => InstanceRole::App,
        Mount::Idm => InstanceRole::Idm,
        Mount::Both => InstanceRole::Combined,
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
    pub fn new(config: &Config, mount: Mount) -> Self {
        let role = role_for_mount(mount);
        let remote_idm = match (mount, &config.idm_internal_url) {
            (Mount::App, Some(url)) => Some(RemoteInstance {
                role: InstanceRole::Idm,
                url: format!("{}/internal/monitoring", url.trim_end_matches('/')),
                client: reqwest::Client::new(),
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
    pub fn with_store(mut self, store: Arc<dyn OpsStore>) -> Self {
        self.store = store;
        self
    }

    pub fn role(&self) -> InstanceRole {
        self.role
    }

    pub fn store(&self) -> Arc<dyn OpsStore> {
        self.store.clone()
    }
}

#[derive(Clone)]
struct RemoteInstance {
    role: InstanceRole,
    url: String,
    client: reqwest::Client,
}

impl RemoteInstance {
    /// 拉不到就给一条"不可达"的实例(页面照常出,只标红这一个进程);原始错误只进日志。
    async fn fetch(&self) -> InstanceReport {
        let res = self
            .client
            .get(&self.url)
            .timeout(REMOTE_TIMEOUT)
            .send()
            .await;
        let reason = match res {
            Ok(resp) if resp.status().is_success() => match resp.json::<InstanceReport>().await {
                Ok(report) => return report,
                Err(e) => {
                    tracing::warn!(url = %self.url, error = %e, "监控:idm 报告解析失败");
                    "响应无法解析".to_owned()
                }
            },
            Ok(resp) => {
                tracing::warn!(url = %self.url, status = %resp.status(), "监控:idm 报告返回错误状态");
                format!("返回 HTTP {}", resp.status().as_u16())
            }
            Err(e) => {
                tracing::warn!(url = %self.url, error = %e, "监控:拉取 idm 报告失败");
                if e.is_timeout() {
                    "超时".to_owned()
                } else if e.is_connect() {
                    "连接失败".to_owned()
                } else {
                    "请求失败".to_owned()
                }
            }
        };
        InstanceReport::unreachable(self.role, reason)
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
        .require_scoped(&user.0, &scope.0, Perm::OpsRead)?;
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

async fn internal_monitoring(State(state): State<AppState>) -> axum::Json<InstanceReport> {
    axum::Json(local_report(&state).await)
}

async fn local_report(state: &AppState) -> InstanceReport {
    // 先读连接池占用、再做依赖检查:检查本身会借连接(`select 1`),反过来读会把它们算进"使用中"。
    let pools = state.probes.pool_stats();
    let checks = state
        .probes
        .check()
        .await
        .into_iter()
        .map(|r| DependencyCheck {
            name: r.name,
            ok: r.ok,
            latency_ms: r.latency_ms,
            error: r.error,
        })
        .collect();
    monitor::global().report(state.monitoring.role, checks, pools)
}

/// 采样任务:每 [`SAMPLE_INTERVAL`] 存一份监控快照;开了 `/metrics` 时顺带刷新进程资源 / 连接池指标。
/// 随服务优雅退出而停。
pub async fn run_sampler(
    probes: Probes,
    metrics_enabled: bool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let metrics = metrics_enabled.then(MetricsSampler::new);
    // 第一拍放在一个间隔之后:启动瞬间的快照和基线几乎一样,只会多出一个空点。
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + SAMPLE_INTERVAL,
        SAMPLE_INTERVAL,
    );
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
        .require_scoped(&user.0, &scope.0, Perm::OpsRead)?;
    let report = build_history(
        &*state.monitoring.store,
        query.range,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(|e| {
        tracing::error!(target: logs::STORE_TARGET, error = %e, "监控:读取历史失败");
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
        .require_scoped(&user.0, &scope.0, Perm::OpsRead)?;
    if !(1..=200).contains(&query.size) || query.page == 0 {
        return Err(AppError::Validation("size 需在 1~200 之间,page 从 1 开始".to_owned()).into());
    }
    if let (Some(f), Some(t)) = (query.from, query.to) {
        if f > t {
            return Err(AppError::Validation("from 不能晚于 to".to_owned()).into());
        }
    }
    let q = LogQuery {
        from: query.from,
        to: query.to,
        min_severity: query.level,
        instance: query.instance.map(|i| i.as_str().to_owned()),
        service: query.service,
        q: query.q.filter(|s| !s.trim().is_empty()),
        request_id: query.request_id.filter(|s| !s.trim().is_empty()),
        page: query.page,
        size: query.size,
    };
    let (items, total) = state.monitoring.store.logs(&q).await.map_err(|e| {
        tracing::error!(target: logs::STORE_TARGET, error = %e, "监控:查询日志失败");
        AppError::Internal(anyhow::anyhow!("查询日志失败"))
    })?;
    let page = crate::kernel::pagination::Page::offset(
        items.into_iter().map(log_view).collect(),
        q.page,
        q.size,
        Some(total),
    );
    Ok(Json(Page::from_core(page, |v| v)))
}

fn log_view(s: StoredLog) -> LogRecordView {
    let e = s.entry;
    LogRecordView {
        id: s.id,
        ts: e.ts,
        instance: InstanceRole::parse(&e.instance).unwrap_or(InstanceRole::Combined),
        service: e.service,
        severity: e.severity,
        target: e.target,
        body: e.body,
        request_id: e.request_id,
        method: e.method,
        route: e.route,
        status: e.status,
        duration_ms: e.duration_ms,
        attributes: e.attributes,
    }
}

fn traffic_of(t: &PeriodTotals) -> TrafficSummary {
    TrafficSummary {
        requests: t.requests,
        errors_4xx: t.errors_4xx,
        errors_5xx: t.errors_5xx,
        p50_ms: t.latency.quantile(0.5),
        p95_ms: t.latency.quantile(0.95),
        p99_ms: t.latency.quantile(0.99),
    }
}

fn point_of(at: OffsetDateTime, t: &PeriodTotals) -> HistoryPoint {
    HistoryPoint {
        at,
        requests: t.requests,
        errors_4xx: t.errors_4xx,
        errors_5xx: t.errors_5xx,
        p95_ms: t.latency.quantile(0.95),
        in_flight: t.in_flight_max as i64,
        db_calls: t.db_calls,
        db_p95_ms: t.db_latency.quantile(0.95),
        pool_in_use: t.pool_in_use_max,
        pool_max: t.pool_max,
        sse_connections: t.sse_max as i64,
        outbox_published: t.outbox_published,
        projector_processed: t.projector_processed,
        projector_pending: t.projector_pending_max,
        rss_bytes: t.rss_bytes_max,
        cpu_percent: t.cpu_percent_max,
    }
}

/// 读存储、按范围的步长重新分桶,组装历史报告。
pub async fn build_history(
    store: &dyn OpsStore,
    range: HistoryRange,
    now: OffsetDateTime,
) -> anyhow::Result<HistoryReport> {
    let step = range.step();
    let step_secs = step.whole_seconds().max(1);
    // 起点对齐到步长,让每个点的时间整齐(如 5 分钟一格)。
    let raw_from = now - range.duration();
    let from_secs = raw_from.unix_timestamp() - raw_from.unix_timestamp().rem_euclid(step_secs);
    let from = OffsetDateTime::from_unix_timestamp(from_secs)?;
    let to = now;
    let details_from = from.max(now - Retention::DETAIL);

    let rows = store.series(range.tier(), from, to).await?;
    let mut per_instance: BTreeMap<String, BTreeMap<i64, PeriodTotals>> = BTreeMap::new();
    for row in rows {
        let bin = (row.bucket.unix_timestamp() - from_secs).div_euclid(step_secs);
        per_instance
            .entry(row.instance)
            .or_default()
            .entry(bin)
            .or_default()
            .merge(&row.totals);
    }
    let mut routes: BTreeMap<String, Vec<RouteStats>> = BTreeMap::new();
    for (instance, r) in store.route_totals(details_from, to).await? {
        routes.entry(instance).or_default().push(RouteStats {
            method: r.method,
            route: r.route,
            requests: r.requests,
            errors_4xx: r.errors_4xx,
            errors_5xx: r.errors_5xx,
            p50_ms: r.latency.quantile(0.5),
            p95_ms: r.latency.quantile(0.95),
        });
    }
    let mut db_ops: BTreeMap<String, Vec<DbOperationStats>> = BTreeMap::new();
    for (instance, d) in store.db_op_totals(details_from, to).await? {
        db_ops.entry(instance).or_default().push(DbOperationStats {
            name: d.operation,
            calls: d.latency.total(),
            p50_ms: d.latency.quantile(0.5),
            p95_ms: d.latency.quantile(0.95),
        });
    }

    let mut names: Vec<String> = per_instance.keys().cloned().collect();
    for k in routes.keys().chain(db_ops.keys()) {
        if !names.contains(k) {
            names.push(k.clone());
        }
    }
    let mut instances = Vec::new();
    for name in names {
        let Some(role) = InstanceRole::parse(&name) else {
            continue;
        };
        let bins = per_instance.remove(&name).unwrap_or_default();
        let mut total = PeriodTotals::default();
        let points = bins
            .iter()
            .map(|(bin, t)| {
                total.merge(t);
                let at = OffsetDateTime::from_unix_timestamp(from_secs + bin * step_secs)
                    .unwrap_or(from);
                point_of(at, t)
            })
            .collect();
        let mut r = routes.remove(&name).unwrap_or_default();
        r.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.route.cmp(&b.route)));
        let mut d = db_ops.remove(&name).unwrap_or_default();
        d.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.name.cmp(&b.name)));
        instances.push(HistoryInstance {
            role,
            traffic: traffic_of(&total),
            points,
            routes: r,
            db_operations: d,
        });
    }
    instances.sort_by_key(|i| i.role.as_str());
    Ok(HistoryReport {
        range,
        from,
        to,
        step_secs: step_secs as u64,
        persistent: store.persistent(),
        details_from,
        instances,
    })
}

// ── 后台任务(随服务优雅退出而停)──

/// 等到 `dur` 或收到退出信号;收到退出返回 `false`。
async fn sleep_or_shutdown(
    dur: std::time::Duration,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => true,
        changed = shutdown.changed() => !(changed.is_err() || *shutdown.borrow()),
    }
}

/// 每分钟落盘:整分后 2 秒,把上一分钟的增量写进存储。
pub async fn run_minute_flusher(
    setup: MonitoringSetup,
    probes: Probes,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let instance = setup.role.as_str();
    loop {
        let now = OffsetDateTime::now_utc();
        let next = minute_start(now) + time::Duration::minutes(1) + time::Duration::seconds(2);
        let wait = (next - now).unsigned_abs();
        if !sleep_or_shutdown(wait, &mut shutdown).await {
            break;
        }
        let bucket = minute_start(OffsetDateTime::now_utc()) - time::Duration::minutes(1);
        let rec = monitor::global().take_minute(instance, bucket, &probes.pool_stats());
        if let Err(e) = setup.store.record_minute(&rec).await {
            tracing::warn!(target: logs::STORE_TARGET, error = %e, "监控:写分钟数据失败(这一分钟丢失)");
        }
    }
}

/// 日志写入:从采集队列批量取(最多 500 条 / 1 秒一批)写进存储;队列满丢弃的条数也记一条。
pub async fn run_log_writer(
    setup: MonitoringSetup,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let Some(mut rx) = logs::take_receiver() else {
        return;
    };
    let mut batch: Vec<LogEntry> = Vec::with_capacity(500);
    loop {
        let stop = tokio::select! {
            n = rx.recv_many(&mut batch, 500) => n == 0,
            changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        };
        // 再等一小会儿凑批(突发时一次写多条)。
        if !stop && batch.len() < 500 {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while batch.len() < 500 {
                    let room = 500 - batch.len();
                    if rx.recv_many(&mut batch, room).await == 0 {
                        break;
                    }
                }
            })
            .await;
        }
        let dropped = logs::take_dropped();
        if dropped > 0 {
            batch.push(LogEntry {
                ts: OffsetDateTime::now_utc(),
                instance: setup.role.as_str().to_owned(),
                service: crate::infra::monitor::store::classify_service(
                    setup.role.as_str(),
                    logs::STORE_TARGET,
                    None,
                ),
                severity: crate::infra::monitor::store::Severity::Warn,
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
            if let Err(e) = setup.store.insert_logs(&batch).await {
                tracing::warn!(target: logs::STORE_TARGET, error = %e, count = batch.len(), "监控:写日志失败(这批丢失)");
            }
            batch.clear();
        }
        if stop {
            break;
        }
    }
}

/// 保留期清理:启动后 1 分钟跑一次,之后每小时一次。
pub async fn run_retention(
    setup: MonitoringSetup,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = std::time::Duration::from_secs(60);
    loop {
        if !sleep_or_shutdown(wait, &mut shutdown).await {
            break;
        }
        wait = std::time::Duration::from_secs(3600);
        match setup.store.purge(OffsetDateTime::now_utc()).await {
            Ok(n) => tracing::debug!(?n, "监控:保留期清理完成"),
            Err(e) => tracing::warn!(target: logs::STORE_TARGET, error = %e, "监控:保留期清理失败"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::monitor::hist::Hist;
    use crate::infra::monitor::store::{MinuteRecord, RouteTotals};

    fn rec(instance: &str, bucket: OffsetDateTime, requests: u64, ms: f64) -> MinuteRecord {
        let mut latency = Hist::default();
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
            db_ops: vec![],
        }
    }

    #[tokio::test]
    async fn history_rebins_minutes_into_steps_per_instance() {
        let store = MemoryOpsStore::new();
        let now = OffsetDateTime::now_utc();
        let base = minute_start(now) - time::Duration::minutes(30);
        for k in 0..10 {
            let t = base + time::Duration::minutes(k);
            store.record_minute(&rec("app", t, 2, 5.0)).await.unwrap();
            store.record_minute(&rec("idm", t, 1, 50.0)).await.unwrap();
        }
        let h = build_history(&store, HistoryRange::Day, now).await.unwrap();
        assert_eq!(h.step_secs, 300);
        assert!(!h.persistent);
        let roles: Vec<_> = h.instances.iter().map(|i| i.role).collect();
        assert_eq!(roles, [InstanceRole::App, InstanceRole::Idm]);
        let app = &h.instances[0];
        assert_eq!(app.traffic.requests, 20);
        assert_eq!(app.points.iter().map(|p| p.requests).sum::<u64>(), 20);
        assert!(
            app.points.len() >= 2 && app.points.len() <= 3,
            "10 分钟 → 2~3 个 5 分钟点"
        );
        assert_eq!(app.routes[0].requests, 20);
        assert!(h.instances[1].traffic.p95_ms.unwrap() > app.traffic.p95_ms.unwrap());
    }
}

//! **进程内监控**:后台「系统监控」页的数据源(`GET /api/v1/admin/monitoring`)。不依赖任何外部组件。
//!
//! - **请求**:中间件 [`track_requests`] 按路由模板记请求数 / 4xx / 5xx / 延迟直方图;
//! - **数据库**:[`DbTimingLayer`](tracing layer)给仓储方法上的 `pg.*` span 计时;
//! - **后台任务**:outbox relay、projector、SSE 连接经 `infra::telemetry` 的埋点函数写进来;
//! - **进程**:内存 / CPU / 线程 / 文件句柄(`metrics-process` 的采集函数)。
//!
//! 全部是累计值。采样任务每 [`SAMPLE_INTERVAL`] 存一份**累计快照**,环形保留 [`RETENTION`];
//! 窗口统计 = 当前累计 − 最老快照,历史曲线 = 相邻快照之差。进程重启即清空(只做"现在怎么样",
//! 不做长期留存)。进程全局单例([`global`]):埋点处(中间件、tracing layer、后台循环)拿不到 AppState。

pub mod hist;
mod layer;
pub mod logs;
pub mod report;
pub mod store;
pub mod store_pg;

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use time::OffsetDateTime;

pub use hist::Hist;
pub use layer::DbTimingLayer;
use report::{
    DbOperationStats, DependencyCheck, HistoryPoint, InstanceReport, InstanceRole, OutboxStatus,
    PoolStatus, ProcessStatus, ProjectorStatus, RouteStats, SseStatus, TrafficSummary,
};

/// 采样间隔(历史曲线的分辨率)。
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(15);
/// 内存里保留多久。
pub const RETENTION: Duration = Duration::from_secs(3600);
/// 环形缓冲容量:保留期内的快照数 + 1 个基线。
const CAPACITY: usize = (RETENTION.as_secs() / SAMPLE_INTERVAL.as_secs()) as usize + 1;

/// 不计入请求统计的路径:探针 / 指标抓取 / 监控页自己的轮询(否则监控页开着就成了流量主力)。
const UNTRACKED_PATHS: [&str; 5] = [
    "/health",
    "/livez",
    "/readyz",
    "/metrics",
    "/internal/monitoring",
];
/// 监控接口自己(实时 / 历史 / 日志)也不计入。
const UNTRACKED_PREFIX: &str = "/api/v1/admin/monitoring";

fn is_untracked(path: &str) -> bool {
    UNTRACKED_PATHS.contains(&path) || path.starts_with(UNTRACKED_PREFIX)
}

/// 没匹配上任何路由的请求(404 扫描等)统一记成这个,防止任意 URL 把统计表撑爆。
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// 进程全局单例。
pub fn global() -> &'static Monitor {
    static MONITOR: LazyLock<Monitor> = LazyLock::new(Monitor::new);
    &MONITOR
}

/// 请求统计中间件(挂在 `build_router` 的中间件栈里,panic 兜底之外,保证 500 也被记到)。
pub async fn track_requests(req: Request, next: Next) -> Response {
    if is_untracked(req.uri().path()) {
        return next.run(req).await;
    }
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_owned());
    let method = req.method().as_str().to_owned();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let monitor = global();
    let _in_flight = monitor.request_started();
    let started = Instant::now();
    let res = next.run(req).await;
    let status = res.status().as_u16();
    let elapsed = started.elapsed();
    monitor.record_request(&method, &route, status, elapsed);
    logs::record_access(request_id, &method, &route, status, elapsed);
    res
}

type RouteKey = (String, String);

#[derive(Clone, Copy, Debug, Default)]
struct RouteAcc {
    requests: u64,
    errors_4xx: u64,
    errors_5xx: u64,
    latency: Hist,
}

impl RouteAcc {
    fn since(&self, earlier: &RouteAcc) -> RouteAcc {
        RouteAcc {
            requests: self.requests.saturating_sub(earlier.requests),
            errors_4xx: self.errors_4xx.saturating_sub(earlier.errors_4xx),
            errors_5xx: self.errors_5xx.saturating_sub(earlier.errors_5xx),
            latency: self.latency.since(&earlier.latency),
        }
    }

    fn add(&mut self, other: &RouteAcc) {
        self.requests += other.requests;
        self.errors_4xx += other.errors_4xx;
        self.errors_5xx += other.errors_5xx;
        self.latency.add(&other.latency);
    }
}

/// 快照时刻的读数(非累计量)。
#[derive(Clone, Copy, Debug, Default)]
struct Gauges {
    in_flight: i64,
    sse: i64,
    pool_in_use: u64,
    pool_max: u64,
    projector_pending: u64,
    rss_bytes: Option<u64>,
    cpu_percent: Option<f64>,
}

/// 一份累计快照。
#[derive(Clone, Debug)]
struct Snapshot {
    at: OffsetDateTime,
    routes: BTreeMap<RouteKey, RouteAcc>,
    db_ops: BTreeMap<&'static str, Hist>,
    /// outbox / projector 的计数,键见 [`counter_key`]。
    counters: BTreeMap<String, u64>,
    gauges: Gauges,
}

#[derive(Default)]
struct OutboxMeta {
    last_poll_at: Option<OffsetDateTime>,
    last_batch: u64,
}

#[derive(Default)]
struct ProjectorMeta {
    last_lag_ms: Option<f64>,
    pending: Option<u64>,
    ack_pending: Option<u64>,
}

#[derive(Default)]
struct Live {
    routes: BTreeMap<RouteKey, RouteAcc>,
    db_ops: BTreeMap<&'static str, Hist>,
    counters: BTreeMap<String, u64>,
    sse: BTreeMap<&'static str, i64>,
    outbox: BTreeMap<&'static str, OutboxMeta>,
    projectors: BTreeMap<String, ProjectorMeta>,
}

#[derive(Default)]
struct CpuTracker {
    last: Option<(Instant, f64)>,
    percent: Option<f64>,
}

pub struct Monitor {
    started_at: OffsetDateTime,
    in_flight: AtomicI64,
    live: Mutex<Live>,
    ring: Mutex<VecDeque<Snapshot>>,
    cpu: Mutex<CpuTracker>,
    /// 每分钟落盘用:上次落盘时的累计快照 + 这一分钟内各次采样读数的最大值。
    minute: Mutex<MinuteState>,
}

struct MinuteState {
    baseline: Snapshot,
    peak: GaugePeak,
}

/// 一分钟内各次采样的读数最大值。
#[derive(Default)]
struct GaugePeak {
    in_flight: u64,
    pool_in_use: u64,
    pool_max: u64,
    sse: u64,
    projector_pending: u64,
    rss_bytes: Option<u64>,
    cpu_percent: Option<f64>,
}

impl GaugePeak {
    fn observe(&mut self, g: &Gauges) {
        self.in_flight = self.in_flight.max(g.in_flight.max(0) as u64);
        self.pool_in_use = self.pool_in_use.max(g.pool_in_use);
        self.pool_max = self.pool_max.max(g.pool_max);
        self.sse = self.sse.max(g.sse.max(0) as u64);
        self.projector_pending = self.projector_pending.max(g.projector_pending);
        if let Some(r) = g.rss_bytes {
            self.rss_bytes = Some(self.rss_bytes.map_or(r, |x| x.max(r)));
        }
        if let Some(c) = g.cpu_percent {
            self.cpu_percent = Some(self.cpu_percent.map_or(c, |x| x.max(c)));
        }
    }
}

/// 锁中毒(持锁时 panic)不该让监控永久失效:数据仍可用,取出来继续。
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn counter_key(kind: &str, name: &str, field: &str) -> String {
    format!("{kind}:{name}:{field}")
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// 在途请求计数守卫:请求结束(含客户端断开导致 future 被丢弃)时减一。
pub struct InFlightGuard<'a>(&'a AtomicI64);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Monitor {
    fn new() -> Self {
        let started_at = OffsetDateTime::now_utc();
        let zero = Snapshot {
            at: started_at,
            routes: BTreeMap::new(),
            db_ops: BTreeMap::new(),
            counters: BTreeMap::new(),
            gauges: Gauges::default(),
        };
        let mut ring = VecDeque::with_capacity(CAPACITY + 1);
        // 基线:全零快照。进程刚起、还没淘汰过快照时,窗口 = 自启动以来。
        ring.push_back(zero.clone());
        Self {
            started_at,
            in_flight: AtomicI64::new(0),
            live: Mutex::new(Live::default()),
            ring: Mutex::new(ring),
            cpu: Mutex::new(CpuTracker::default()),
            minute: Mutex::new(MinuteState {
                baseline: zero,
                peak: GaugePeak::default(),
            }),
        }
    }

    // ── 埋点 ──

    pub fn request_started(&self) -> InFlightGuard<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard(&self.in_flight)
    }

    pub fn record_request(&self, method: &str, route: &str, status: u16, elapsed: Duration) {
        let mut live = lock(&self.live);
        let key = (method.to_owned(), route.to_owned());
        let acc = live.routes.entry(key).or_default();
        acc.requests += 1;
        match status {
            400..=499 => acc.errors_4xx += 1,
            500..=599 => acc.errors_5xx += 1,
            _ => {}
        }
        acc.latency.record(ms(elapsed));
    }

    pub fn record_db(&self, operation: &'static str, elapsed: Duration) {
        lock(&self.live)
            .db_ops
            .entry(operation)
            .or_default()
            .record(ms(elapsed));
    }

    pub fn sse_opened(&self, stream: &'static str) {
        *lock(&self.live).sse.entry(stream).or_default() += 1;
    }

    pub fn sse_closed(&self, stream: &'static str) {
        *lock(&self.live).sse.entry(stream).or_default() -= 1;
    }

    /// relay 启动时登记(从没发布过也在页面上占一行)。
    pub fn outbox_registered(&self, source: &'static str) {
        let mut live = lock(&self.live);
        live.outbox.entry(source).or_default();
        for field in ["published", "failures"] {
            live.counters
                .entry(counter_key("outbox", source, field))
                .or_default();
        }
    }

    pub fn outbox_polled(&self, source: &'static str, batch: usize) {
        let mut live = lock(&self.live);
        let meta = live.outbox.entry(source).or_default();
        meta.last_poll_at = Some(OffsetDateTime::now_utc());
        meta.last_batch = batch as u64;
    }

    pub fn outbox_published(&self, source: &'static str, n: usize) {
        *lock(&self.live)
            .counters
            .entry(counter_key("outbox", source, "published"))
            .or_default() += n as u64;
    }

    pub fn outbox_failed(&self, source: &'static str) {
        *lock(&self.live)
            .counters
            .entry(counter_key("outbox", source, "failures"))
            .or_default() += 1;
    }

    /// projector 处理完一条消息。`result`:`ok` 计成功;`shutdown`(关停中断)不计;其余计失败。
    pub fn projector_result(&self, projector: &str, result: &str, lag: Option<Duration>) {
        let field = match result {
            "ok" => "processed",
            "shutdown" => return,
            _ => "failed",
        };
        let mut live = lock(&self.live);
        let meta = live.projectors.entry(projector.to_owned()).or_default();
        if let Some(lag) = lag {
            meta.last_lag_ms = Some(ms(lag));
        }
        *live
            .counters
            .entry(counter_key("projector", projector, field))
            .or_default() += 1;
    }

    /// projector 定时上报消费者积压(也起登记作用:没消息时页面上也有这一行)。
    pub fn projector_pending(&self, projector: &str, pending: u64, ack_pending: u64) {
        let mut live = lock(&self.live);
        let meta = live.projectors.entry(projector.to_owned()).or_default();
        meta.pending = Some(pending);
        meta.ack_pending = Some(ack_pending);
        for field in ["processed", "failed"] {
            live.counters
                .entry(counter_key("projector", projector, field))
                .or_default();
        }
    }

    // ── 采样 / 报告 ──

    /// 采一次进程资源;`update_cpu` 时用与上次采样的差算 CPU 占用(只由采样任务调用,报告请求不扰动它)。
    fn process_status(&self, update_cpu: bool) -> ProcessStatus {
        let m = metrics_process::collector::collect();
        let mut cpu = lock(&self.cpu);
        if update_cpu {
            if let Some(total) = m.cpu_seconds_total {
                let now = Instant::now();
                if let Some((then, prev)) = cpu.last {
                    let wall = now.duration_since(then).as_secs_f64();
                    if wall > 0.0 {
                        cpu.percent = Some(((total - prev) / wall * 100.0).max(0.0));
                    }
                }
                cpu.last = Some((now, total));
            }
        }
        ProcessStatus {
            rss_bytes: m.resident_memory_bytes,
            cpu_percent: cpu.percent,
            threads: m.threads,
            open_fds: m.open_fds,
        }
    }

    fn snapshot(
        &self,
        at: OffsetDateTime,
        pools: &[PoolStatus],
        process: &ProcessStatus,
    ) -> Snapshot {
        let live = lock(&self.live);
        let projector_pending = live.projectors.values().filter_map(|p| p.pending).sum();
        Snapshot {
            at,
            routes: live.routes.clone(),
            db_ops: live.db_ops.clone(),
            counters: live.counters.clone(),
            gauges: Gauges {
                in_flight: self.in_flight.load(Ordering::Relaxed),
                sse: live.sse.values().sum(),
                pool_in_use: pools.iter().map(|p| u64::from(p.in_use)).sum(),
                pool_max: pools.iter().map(|p| u64::from(p.max)).sum(),
                projector_pending,
                rss_bytes: process.rss_bytes,
                cpu_percent: process.cpu_percent,
            },
        }
    }

    /// 存一份累计快照(采样任务每 [`SAMPLE_INTERVAL`] 调一次)。
    pub fn sample(&self, pools: &[PoolStatus]) {
        let process = self.process_status(true);
        let snap = self.snapshot(OffsetDateTime::now_utc(), pools, &process);
        lock(&self.minute).peak.observe(&snap.gauges);
        let mut ring = lock(&self.ring);
        ring.push_back(snap);
        while ring.len() > CAPACITY {
            ring.pop_front();
        }
    }

    /// 取出自上次以来的增量,作为 `bucket` 这一分钟的落盘记录(落盘任务每分钟调一次)。
    pub fn take_minute(
        &self,
        instance: &str,
        bucket: OffsetDateTime,
        pools: &[PoolStatus],
    ) -> store::MinuteRecord {
        let process = self.process_status(false);
        let current = self.snapshot(OffsetDateTime::now_utc(), pools, &process);
        let mut minute = lock(&self.minute);
        minute.peak.observe(&current.gauges);
        let delta = Delta::between(&current, &minute.baseline);
        let peak = std::mem::take(&mut minute.peak);
        minute.baseline = current;
        drop(minute);

        let total = delta.route_total();
        let db = delta.db_total();
        store::MinuteRecord {
            instance: instance.to_owned(),
            bucket,
            totals: store::PeriodTotals {
                requests: total.requests,
                errors_4xx: total.errors_4xx,
                errors_5xx: total.errors_5xx,
                latency: total.latency,
                db_calls: db.total(),
                db_latency: db,
                outbox_published: delta.counter_sum("outbox", "published"),
                outbox_failures: delta.counter_sum("outbox", "failures"),
                projector_processed: delta.counter_sum("projector", "processed"),
                projector_failed: delta.counter_sum("projector", "failed"),
                in_flight_max: peak.in_flight,
                pool_in_use_max: peak.pool_in_use,
                pool_max: peak.pool_max,
                sse_max: peak.sse,
                projector_pending_max: peak.projector_pending,
                rss_bytes_max: peak.rss_bytes,
                cpu_percent_max: peak.cpu_percent,
            },
            routes: delta
                .routes
                .iter()
                .filter(|(_, acc)| acc.requests > 0)
                .map(|((method, route), acc)| store::RouteTotals {
                    method: method.clone(),
                    route: route.clone(),
                    requests: acc.requests,
                    errors_4xx: acc.errors_4xx,
                    errors_5xx: acc.errors_5xx,
                    latency: acc.latency,
                })
                .collect(),
            db_ops: delta
                .db_ops
                .iter()
                .filter(|(_, h)| h.total() > 0)
                .map(|(op, h)| store::DbOpTotals {
                    operation: (*op).to_owned(),
                    latency: *h,
                })
                .collect(),
        }
    }

    /// 本进程的监控报告。`checks` / `pools` 由调用方(组合根,持有探针)现查现给。
    pub fn report(
        &self,
        role: InstanceRole,
        checks: Vec<DependencyCheck>,
        pools: Vec<PoolStatus>,
    ) -> InstanceReport {
        let now = OffsetDateTime::now_utc();
        let process = self.process_status(false);
        let current = self.snapshot(now, &pools, &process);

        let ring = lock(&self.ring);
        let baseline = ring.front().expect("环形缓冲至少有基线快照");
        let window = Delta::between(&current, baseline);
        let history: Vec<HistoryPoint> = ring
            .iter()
            .zip(ring.iter().skip(1))
            .map(|(prev, cur)| Delta::between(cur, prev).history_point(cur))
            .collect();
        let window_secs = (now - baseline.at).whole_seconds().max(0) as u64;
        drop(ring);

        let live = lock(&self.live);
        let outbox = live
            .outbox
            .iter()
            .map(|(source, meta)| OutboxStatus {
                source: (*source).to_owned(),
                published: window.counter("outbox", source, "published"),
                failures: window.counter("outbox", source, "failures"),
                last_batch: meta.last_batch,
                last_poll_at: meta.last_poll_at,
            })
            .collect();
        let projectors = live
            .projectors
            .iter()
            .map(|(name, meta)| ProjectorStatus {
                name: name.clone(),
                processed: window.counter("projector", name, "processed"),
                failed: window.counter("projector", name, "failed"),
                last_lag_ms: meta.last_lag_ms,
                pending: meta.pending,
                ack_pending: meta.ack_pending,
            })
            .collect();
        let sse = live
            .sse
            .iter()
            .map(|(stream, n)| SseStatus {
                stream: (*stream).to_owned(),
                connections: *n,
            })
            .collect();
        drop(live);

        let total = window.route_total();
        let mut routes: Vec<RouteStats> = window
            .routes
            .iter()
            .filter(|(_, acc)| acc.requests > 0)
            .map(|((method, route), acc)| RouteStats {
                method: method.clone(),
                route: route.clone(),
                requests: acc.requests,
                errors_4xx: acc.errors_4xx,
                errors_5xx: acc.errors_5xx,
                p50_ms: acc.latency.quantile(0.5),
                p95_ms: acc.latency.quantile(0.95),
            })
            .collect();
        routes.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.route.cmp(&b.route)));
        let mut db_operations: Vec<DbOperationStats> = window
            .db_ops
            .iter()
            .filter(|(_, h)| h.total() > 0)
            .map(|(name, h)| DbOperationStats {
                name: (*name).to_owned(),
                calls: h.total(),
                p50_ms: h.quantile(0.5),
                p95_ms: h.quantile(0.95),
            })
            .collect();
        db_operations.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.name.cmp(&b.name)));

        InstanceReport {
            role,
            reachable: true,
            error: None,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at: Some(self.started_at),
            uptime_secs: (now - self.started_at).whole_seconds().max(0) as u64,
            window_secs,
            sample_interval_secs: SAMPLE_INTERVAL.as_secs(),
            checks,
            process,
            in_flight: current.gauges.in_flight,
            pools,
            sse,
            traffic: TrafficSummary {
                requests: total.requests,
                errors_4xx: total.errors_4xx,
                errors_5xx: total.errors_5xx,
                p50_ms: total.latency.quantile(0.5),
                p95_ms: total.latency.quantile(0.95),
                p99_ms: total.latency.quantile(0.99),
            },
            routes,
            db_operations,
            outbox,
            projectors,
            history,
        }
    }
}

/// 两份累计快照之差。
struct Delta {
    routes: BTreeMap<RouteKey, RouteAcc>,
    db_ops: BTreeMap<&'static str, Hist>,
    counters: BTreeMap<String, u64>,
}

impl Delta {
    fn between(cur: &Snapshot, earlier: &Snapshot) -> Delta {
        let routes = cur
            .routes
            .iter()
            .map(|(k, acc)| {
                let d = earlier.routes.get(k).map_or(*acc, |e| acc.since(e));
                (k.clone(), d)
            })
            .collect();
        let db_ops = cur
            .db_ops
            .iter()
            .map(|(k, h)| (*k, earlier.db_ops.get(k).map_or(*h, |e| h.since(e))))
            .collect();
        let counters = cur
            .counters
            .iter()
            .map(|(k, v)| {
                let e = earlier.counters.get(k).copied().unwrap_or(0);
                (k.clone(), v.saturating_sub(e))
            })
            .collect();
        Delta {
            routes,
            db_ops,
            counters,
        }
    }

    fn counter(&self, kind: &str, name: &str, field: &str) -> u64 {
        self.counters
            .get(&counter_key(kind, name, field))
            .copied()
            .unwrap_or(0)
    }

    fn counter_sum(&self, kind: &str, field: &str) -> u64 {
        let prefix = format!("{kind}:");
        let suffix = format!(":{field}");
        self.counters
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix) && k.ends_with(&suffix))
            .map(|(_, v)| *v)
            .sum()
    }

    fn route_total(&self) -> RouteAcc {
        let mut total = RouteAcc::default();
        for acc in self.routes.values() {
            total.add(acc);
        }
        total
    }

    fn db_total(&self) -> Hist {
        let mut total = Hist::default();
        for h in self.db_ops.values() {
            total.add(h);
        }
        total
    }

    fn history_point(&self, at: &Snapshot) -> HistoryPoint {
        let total = self.route_total();
        let db = self.db_total();
        let g = at.gauges;
        HistoryPoint {
            at: at.at,
            requests: total.requests,
            errors_4xx: total.errors_4xx,
            errors_5xx: total.errors_5xx,
            p95_ms: total.latency.quantile(0.95),
            in_flight: g.in_flight,
            db_calls: db.total(),
            db_p95_ms: db.quantile(0.95),
            pool_in_use: g.pool_in_use,
            pool_max: g.pool_max,
            sse_connections: g.sse,
            outbox_published: self.counter_sum("outbox", "published"),
            projector_processed: self.counter_sum("projector", "processed"),
            projector_pending: g.projector_pending,
            rss_bytes: g.rss_bytes,
            cpu_percent: g.cpu_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(in_use: u32, max: u32) -> PoolStatus {
        PoolStatus {
            name: "app".into(),
            size: in_use,
            idle: 0,
            in_use,
            max,
        }
    }

    #[test]
    fn report_counts_requests_by_route_and_status() {
        let m = Monitor::new();
        m.record_request("GET", "/a", 200, Duration::from_millis(3));
        m.record_request("GET", "/a", 404, Duration::from_millis(3));
        m.record_request("POST", "/b", 500, Duration::from_millis(30));
        let r = m.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(r.traffic.requests, 3);
        assert_eq!(r.traffic.errors_4xx, 1);
        assert_eq!(r.traffic.errors_5xx, 1);
        assert_eq!(r.routes[0].route, "/a", "按请求数降序");
        assert_eq!(r.routes[0].requests, 2);
        assert!(r.history.is_empty(), "还没采样就没有历史点");
    }

    #[test]
    fn history_points_are_per_interval_deltas() {
        let m = Monitor::new();
        m.record_request("GET", "/a", 200, Duration::from_millis(1));
        m.sample(&[pool(1, 10)]);
        m.record_request("GET", "/a", 200, Duration::from_millis(1));
        m.record_request("GET", "/a", 200, Duration::from_millis(1));
        m.sample(&[pool(2, 10)]);
        let r = m.report(InstanceRole::Combined, vec![], vec![]);
        let reqs: Vec<u64> = r.history.iter().map(|p| p.requests).collect();
        assert_eq!(reqs, vec![1, 2]);
        assert_eq!(r.history[1].pool_in_use, 2);
        assert_eq!(r.traffic.requests, 3, "窗口内全部请求");
    }

    #[test]
    fn window_drops_evicted_samples() {
        let m = Monitor::new();
        m.record_request("GET", "/old", 200, Duration::from_millis(1));
        for _ in 0..CAPACITY {
            m.sample(&[]);
        }
        m.record_request("GET", "/new", 200, Duration::from_millis(1));
        let r = m.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(r.traffic.requests, 1, "最老的请求已滑出窗口");
        assert_eq!(r.routes.len(), 1);
        assert_eq!(r.routes[0].route, "/new");
        assert_eq!(r.history.len(), CAPACITY - 1);
    }

    #[test]
    fn background_tasks_are_listed_even_when_idle() {
        let m = Monitor::new();
        m.outbox_registered("idm");
        m.projector_pending("search", 5, 1);
        m.outbox_published("idm", 3);
        m.projector_result("search", "ok", Some(Duration::from_millis(40)));
        m.projector_result("search", "poison", None);
        m.projector_result("search", "shutdown", None);
        let r = m.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(r.outbox.len(), 1);
        assert_eq!(r.outbox[0].published, 3);
        let p = &r.projectors[0];
        assert_eq!((p.processed, p.failed, p.pending), (1, 1, Some(5)));
        assert_eq!(p.last_lag_ms, Some(40.0));
    }

    #[test]
    fn take_minute_returns_increments_since_last_take() {
        let m = Monitor::new();
        m.record_request("GET", "/a", 200, Duration::from_millis(2));
        m.record_request("GET", "/a", 503, Duration::from_millis(2));
        m.record_db("pg.widgets.list", Duration::from_millis(3));
        m.sample(&[pool(3, 10)]);
        let t = OffsetDateTime::now_utc();
        let first = m.take_minute("combined", t, &[pool(1, 10)]);
        assert_eq!(first.totals.requests, 2);
        assert_eq!(first.totals.errors_5xx, 1);
        assert_eq!(first.totals.db_calls, 1);
        assert_eq!(first.totals.pool_in_use_max, 3, "取这一分钟内的最大值");
        assert_eq!(first.routes.len(), 1);
        assert_eq!(first.db_ops[0].operation, "pg.widgets.list");

        m.record_request("GET", "/b", 200, Duration::from_millis(2));
        let second = m.take_minute("combined", t, &[]);
        assert_eq!(second.totals.requests, 1, "只含上次之后的增量");
        assert_eq!(second.routes[0].route, "/b");
        assert_eq!(second.totals.pool_in_use_max, 0, "峰值每分钟重置");
    }

    #[test]
    fn sse_and_in_flight_are_gauges() {
        let m = Monitor::new();
        m.sse_opened("widgets");
        m.sse_opened("widgets");
        m.sse_closed("widgets");
        let guard = m.request_started();
        let r = m.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(r.sse[0].connections, 1);
        assert_eq!(r.in_flight, 1);
        drop(guard);
        assert_eq!(
            m.report(InstanceRole::Combined, vec![], vec![]).in_flight,
            0
        );
    }
}

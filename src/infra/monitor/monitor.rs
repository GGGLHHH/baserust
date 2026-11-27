//! 进程内监控的本体 [`Monitor`]:累计计数、环形快照、窗口 / 历史 / 每分钟落盘的增量计算,
//! 以及请求统计中间件 [`track_requests`]。模块总览见上一级 [`crate::infra::monitor`]。

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use std::{cmp, mem};

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics_process::collector;
use time::OffsetDateTime;

use super::histogram::Histogram;
use super::logs;
use super::report::{
    DbOperationStats, DependencyCheck, HistoryPoint, InstanceReport, InstanceRole, OutboxStatus,
    PoolStatus, ProcessStatus, ProjectorStatus, RouteStats, SseStatus, TrafficSummary,
};
use super::store::{DbOperationTotals, MinuteRecord, PeriodTotals, RouteTotals};

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
#[must_use]
pub fn global() -> &'static Monitor {
    static MONITOR: LazyLock<Monitor> = LazyLock::new(Monitor::new);
    &MONITOR
}

/// 请求统计中间件(挂在 `build_router` 的中间件栈里,panic 兜底之外,保证 500 也被记到)。
pub async fn track_requests(request: Request, next: Next) -> Response {
    if is_untracked(request.uri().path()) {
        return next.run(request).await;
    }
    let route = request.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_ROUTE.to_owned(),
        |matched| matched.as_str().to_owned(),
    );
    let method = request.method().as_str().to_owned();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let monitor = global();
    let _in_flight = monitor.request_started();
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let elapsed = started.elapsed();
    let outcome = RequestOutcome {
        method: &method,
        route: &route,
        status,
        elapsed,
    };
    monitor.record_request(outcome);
    logs::record_access(request_id, outcome);
    response
}

/// 请求统计的键:方法 + 路由模板。字段顺序决定排序(先方法、再路由)。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    method: String,
    route: String,
}

/// 单个路由的累计计数。
#[derive(Clone, Copy, Debug, Default)]
struct RouteAccumulator {
    requests: u64,
    errors_4xx: u64,
    errors_5xx: u64,
    latency: Histogram,
}

impl RouteAccumulator {
    fn since(&self, earlier: &RouteAccumulator) -> RouteAccumulator {
        RouteAccumulator {
            requests: self.requests.saturating_sub(earlier.requests),
            errors_4xx: self.errors_4xx.saturating_sub(earlier.errors_4xx),
            errors_5xx: self.errors_5xx.saturating_sub(earlier.errors_5xx),
            latency: self.latency.since(&earlier.latency),
        }
    }

    fn add(&mut self, other: &RouteAccumulator) {
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

/// live 累计量的「代」。live 锁中毒时累计量整份从零重来,就换一代(代号 +1)。
/// 不同代的两份快照不能相减:新一代是从零重新累计的。
#[derive(Clone, Copy, Debug)]
struct LiveGeneration {
    number: u64,
    started_at: OffsetDateTime,
}

/// 一份累计快照。
#[derive(Clone, Debug)]
struct Snapshot {
    at: OffsetDateTime,
    /// 取自哪一代 live。
    generation: LiveGeneration,
    routes: BTreeMap<RouteKey, RouteAccumulator>,
    db_ops: BTreeMap<&'static str, Histogram>,
    /// outbox / projector 的计数,键见 [`counter_key`]。
    counters: BTreeMap<String, u64>,
    gauges: Gauges,
}

impl Snapshot {
    /// 某一代 live 起点的全零快照(这一代的基线)。
    fn zero(generation: LiveGeneration) -> Snapshot {
        Snapshot {
            at: generation.started_at,
            generation,
            routes: BTreeMap::new(),
            db_ops: BTreeMap::new(),
            counters: BTreeMap::new(),
            gauges: Gauges::default(),
        }
    }
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

/// 埋点写入的累计量与后台任务的登记信息。
struct Live {
    generation: LiveGeneration,
    routes: BTreeMap<RouteKey, RouteAccumulator>,
    db_ops: BTreeMap<&'static str, Histogram>,
    counters: BTreeMap<String, u64>,
    outbox: BTreeMap<&'static str, OutboxMeta>,
    projectors: BTreeMap<String, ProjectorMeta>,
}

impl Live {
    fn new(generation: LiveGeneration) -> Live {
        Live {
            generation,
            routes: BTreeMap::new(),
            db_ops: BTreeMap::new(),
            counters: BTreeMap::new(),
            outbox: BTreeMap::new(),
            projectors: BTreeMap::new(),
        }
    }
}

/// 一次 CPU 采样:时刻 + 进程累计 CPU 秒数。
#[derive(Clone, Copy)]
struct CpuSample {
    at: Instant,
    cpu_seconds_total: f64,
}

#[derive(Default)]
struct CpuTracker {
    last: Option<CpuSample>,
    percent: Option<f64>,
}

/// 采进程资源时要不要顺带刷新 CPU 占用。
#[derive(Clone, Copy, PartialEq, Eq)]
enum CpuUsage {
    /// 用与上次采样的差重算(只有采样任务这么做)。
    Refresh,
    /// 沿用上次算好的值(报告请求不扰动采样节奏)。
    KeepLast,
}

/// 一次请求的结果([`Monitor::record_request`] / [`super::logs::record_access`] 的入参)。
#[derive(Clone, Copy, Debug)]
pub struct RequestOutcome<'request> {
    pub method: &'request str,
    /// 路由模板(没匹配上 = [`UNMATCHED_ROUTE`])。
    pub route: &'request str,
    pub status: u16,
    pub elapsed: Duration,
}

/// projector 处理一条消息的结果([`Monitor::projector_result`] / `telemetry::record_projector_message` 的入参)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectorOutcome {
    /// 投影成功。
    Ok,
    /// 毒消息(永不可投):跳过并 ack。
    Poison,
    /// 重试超限,按毒消息跳过(投影缺口靠 rebuild 回填)。
    Dropped,
    /// 暂时故障,不 ack、等重投。
    Transient,
    /// 关停中断:不 ack、不计数。
    Shutdown,
}

impl ProjectorOutcome {
    /// `/metrics` 计数器的 `result` 标签值(线上名字,改它会断外部看板)。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectorOutcome::Ok => "ok",
            ProjectorOutcome::Poison => "poison",
            ProjectorOutcome::Dropped => "dropped",
            ProjectorOutcome::Transient => "transient",
            ProjectorOutcome::Shutdown => "shutdown",
        }
    }
}

/// JetStream 消费者的积压([`Monitor::projector_pending`] 的入参):两个计数按名字区分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerBacklog {
    /// 还没投递的消息数。
    pub pending: u64,
    /// 已投递、还没 ack 的消息数。
    pub ack_pending: u64,
}

/// 进程内监控的全部状态(见 [`global`])。
///
/// # 锁中毒
///
/// 每把锁都按 `lock_or_reset` 上写的统一策略处理(丢弃中毒状态、换新、清标记,不 panic),
/// 但「换新」时要保证数据不因此出错:
///
/// - `ring` / `minute` 中毒:用调用方刚取的 live 快照当新基线,窗口 / 这一分钟的增量从此刻重算。
///   不能用全零基线 —— 那会把 live 自启动以来的累计量当成窗口量,或当成这一分钟的量落进 ops 库;
/// - `live` 中毒:累计量从零重来并换一代(`LiveGeneration`)。`ring` / `minute` 下次被用到时
///   发现基线还是旧代,就换成新一代的零基线;取于换代之前的过时快照直接作废,不拿它算增量。
///   换代靠代号惰性传递,不在持 live 锁时去拿 ring / minute 锁(那是反向嵌套,会死锁)。
///   本类现在没有任何嵌套加锁,以后要嵌套只许 ring → live、minute → live 这个方向;
/// - SSE 连接数是「当前状态」,不是累计量,单独一把锁,`live` 中毒牵连不到它。它的临界区只有一次
///   整数加减,本就不会中毒;万一中毒被清空,[`Monitor::sse_closed`] 最低减到 0,不会变成负数
///   (代价只是中毒前就开着的连接断开之前少算几条);
/// - 在途请求数是原子量,不受任何锁影响;outbox / projector 的登记信息随 `live` 一起清掉,
///   下一次轮询 / 积压上报时自动补回。
pub struct Monitor {
    started_at: OffsetDateTime,
    in_flight: AtomicI64,
    /// `live` 已经换过几代(锁中毒重置的次数),只在持 `live` 锁时递增。
    live_resets: AtomicU64,
    live: Mutex<Live>,
    /// 各 SSE 流当前的连接数。
    sse: Mutex<BTreeMap<&'static str, i64>>,
    ring: Mutex<VecDeque<Snapshot>>,
    cpu: Mutex<CpuTracker>,
    /// 每分钟落盘用:上次落盘时的累计快照 + 这一分钟内各次采样读数的最大值。
    minute: Mutex<MinuteState>,
}

struct MinuteState {
    baseline: Snapshot,
    peak: GaugePeak,
}

impl MinuteState {
    fn new(baseline: Snapshot) -> MinuteState {
        MinuteState {
            baseline,
            peak: GaugePeak::default(),
        }
    }
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
    fn observe(&mut self, gauges: &Gauges) {
        self.in_flight = self.in_flight.max(gauges.in_flight.max(0) as u64);
        self.pool_in_use = self.pool_in_use.max(gauges.pool_in_use);
        self.pool_max = self.pool_max.max(gauges.pool_max);
        self.sse = self.sse.max(gauges.sse.max(0) as u64);
        self.projector_pending = self.projector_pending.max(gauges.projector_pending);
        if let Some(rss) = gauges.rss_bytes {
            self.rss_bytes = Some(self.rss_bytes.map_or(rss, |peak| peak.max(rss)));
        }
        if let Some(cpu) = gauges.cpu_percent {
            self.cpu_percent = Some(self.cpu_percent.map_or(cpu, |peak| peak.max(cpu)));
        }
    }
}

/// 取锁,锁中毒时按下面的**锁中毒策略**换成新状态。永不 panic、永不报错。
///
/// # 锁中毒策略
///
/// 本项目统一的做法:保护**可以丢弃**的进程内状态的 `Mutex` 都照此处理(监控各锁、内存版监控存储、
/// 前端错误上报的限流器、日志队列的接收端;新加的同类锁也一样)。中毒(之前有人持锁时 panic)时:
///
/// - **绝不读**中毒锁里的数据:它可能只改了一半;
/// - 整份换成 `fresh()` 给的新状态,再 `clear_poison`,之后照常工作;
/// - 不 panic、不永久报错:这些锁在请求路径或后台循环上(`track_requests` 还在 `CatchPanicLayer`
///   之外,在那 panic 会直接断开连接),为一份可丢的状态让服务出错或功能永久失效不值得。
///
/// 丢掉状态后哪些量会跟着出错、怎么补偿,由各调用处自己写清(例如 [`Monitor`] 的「锁中毒」一节)。
/// 状态不能丢的锁不适用这条策略:例如核心 crate 内存仓储里的业务数据,中毒时 `expect` panic,
/// 请求经 `CatchPanicLayer` 变成 500,同样不读中毒数据。
pub(crate) fn lock_or_reset<T>(mutex: &Mutex<T>, fresh: impl FnOnce() -> T) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = fresh();
            mutex.clear_poison();
            guard
        }
    }
}

fn counter_key(kind: &str, name: &str, field: &str) -> String {
    format!("{kind}:{name}:{field}")
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// 在途请求计数守卫:请求结束(含客户端断开导致 future 被丢弃)时减一。
#[must_use = "守卫一丢弃在途计数就减回去,要持有到请求结束"]
pub struct InFlightGuard<'monitor>(&'monitor AtomicI64);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 只含一个基线快照的环形缓冲。进程刚起时基线是全零快照,窗口 = 自启动以来。
fn fresh_ring(baseline: Snapshot) -> VecDeque<Snapshot> {
    let mut ring = VecDeque::with_capacity(CAPACITY + 1);
    ring.push_back(baseline);
    ring
}

/// 一份新取的快照与环形缓冲 / 每分钟基线的关系(见 [`Monitor`] 的「锁中毒」一节)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alignment {
    /// 同一代 live,可以直接相减。
    SameGeneration,
    /// 基线所在的锁中毒过,刚按这份快照重建了基线:这份快照就是基线,增量为零。
    Rebased,
    /// 快照取于 live 换代之前,而基线已经是新一代:快照作废,不拿它算增量。
    Stale,
}

/// 让基线跟上 `current` 的代。基线是旧代(或没有基线)→ 换成新一代的零基线并返回 `true`。
fn generation_alignment(baseline: Option<&Snapshot>, current: &Snapshot) -> (Alignment, bool) {
    let baseline_generation = baseline.map(|snapshot| snapshot.generation.number);
    match baseline_generation.cmp(&Some(current.generation.number)) {
        cmp::Ordering::Less => (Alignment::SameGeneration, true),
        cmp::Ordering::Equal => (Alignment::SameGeneration, false),
        cmp::Ordering::Greater => (Alignment::Stale, false),
    }
}

impl Monitor {
    fn new() -> Self {
        let started_at = OffsetDateTime::now_utc();
        let generation = LiveGeneration {
            number: 0,
            started_at,
        };
        Self {
            started_at,
            in_flight: AtomicI64::new(0),
            live_resets: AtomicU64::new(0),
            live: Mutex::new(Live::new(generation)),
            sse: Mutex::new(BTreeMap::new()),
            ring: Mutex::new(fresh_ring(Snapshot::zero(generation))),
            cpu: Mutex::new(CpuTracker::default()),
            minute: Mutex::new(MinuteState::new(Snapshot::zero(generation))),
        }
    }

    /// 中毒 → 累计量从零重来并换一代。换代发生在持 `live` 锁时,而快照也在持锁时读代号,
    /// 所以代号单调、快照的代与它的计数一致。
    fn live(&self) -> MutexGuard<'_, Live> {
        lock_or_reset(&self.live, || {
            let number = self.live_resets.fetch_add(1, Ordering::Relaxed) + 1;
            Live::new(LiveGeneration {
                number,
                started_at: OffsetDateTime::now_utc(),
            })
        })
    }

    /// 中毒 → 清空(见 [`Monitor::sse_closed`] 怎么防负数)。
    fn sse(&self) -> MutexGuard<'_, BTreeMap<&'static str, i64>> {
        lock_or_reset(&self.sse, BTreeMap::new)
    }

    /// 取环形缓冲,并让它与 `current`(调用方刚取的 live 快照)对齐:
    /// 中毒 → 以 `current` 为基线重建;基线是旧代 → 换成新一代的零基线。
    fn ring_for(&self, current: &Snapshot) -> (MutexGuard<'_, VecDeque<Snapshot>>, Alignment) {
        let mut rebased = false;
        let mut ring = lock_or_reset(&self.ring, || {
            rebased = true;
            fresh_ring(current.clone())
        });
        if rebased {
            return (ring, Alignment::Rebased);
        }
        let (alignment, new_generation) = generation_alignment(ring.front(), current);
        if new_generation {
            *ring = fresh_ring(Snapshot::zero(current.generation));
        }
        (ring, alignment)
    }

    fn cpu(&self) -> MutexGuard<'_, CpuTracker> {
        lock_or_reset(&self.cpu, CpuTracker::default)
    }

    /// 取每分钟状态,对齐规则同 [`Monitor::ring_for`]。
    fn minute_for(&self, current: &Snapshot) -> (MutexGuard<'_, MinuteState>, Alignment) {
        let mut rebased = false;
        let mut minute = lock_or_reset(&self.minute, || {
            rebased = true;
            MinuteState::new(current.clone())
        });
        if rebased {
            return (minute, Alignment::Rebased);
        }
        let (alignment, new_generation) = generation_alignment(Some(&minute.baseline), current);
        if new_generation {
            minute.baseline = Snapshot::zero(current.generation);
        }
        (minute, alignment)
    }

    // ── 埋点 ──

    /// 请求开始:在途数 +1,返回的守卫丢弃时 -1。
    pub fn request_started(&self) -> InFlightGuard<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard(&self.in_flight)
    }

    /// 请求结束:按 `(method, route)` 记一次,4xx / 5xx 分开计,耗时进直方图。
    pub fn record_request(&self, outcome: RequestOutcome<'_>) {
        let RequestOutcome {
            method,
            route,
            status,
            elapsed,
        } = outcome;
        let mut live = self.live();
        let key = RouteKey {
            method: method.to_owned(),
            route: route.to_owned(),
        };
        let accumulator = live.routes.entry(key).or_default();
        accumulator.requests += 1;
        match status {
            400..=499 => accumulator.errors_4xx += 1,
            500..=599 => accumulator.errors_5xx += 1,
            _ => {}
        }
        accumulator.latency.record(millis(elapsed));
    }

    /// 一次数据库操作(`pg.*` span)的耗时。
    pub fn record_db(&self, operation: &'static str, elapsed: Duration) {
        self.live()
            .db_ops
            .entry(operation)
            .or_default()
            .record(millis(elapsed));
    }

    /// `stream` 上新开一条 SSE 连接。
    pub fn sse_opened(&self, stream: &'static str) {
        *self.sse().entry(stream).or_default() += 1;
    }

    /// `stream` 上断开一条 SSE 连接。最低减到 0:计数锁万一中毒被清空,
    /// 中毒前就开着的连接断开时也不会把计数减成负数。
    pub fn sse_closed(&self, stream: &'static str) {
        if let Some(connections) = self.sse().get_mut(stream) {
            *connections = connections.saturating_sub(1).max(0);
        }
    }

    /// relay 启动时登记(从没发布过也在页面上占一行)。
    pub fn outbox_registered(&self, source: &'static str) {
        let mut live = self.live();
        live.outbox.entry(source).or_default();
        for field in ["published", "failures"] {
            live.counters
                .entry(counter_key("outbox", source, field))
                .or_default();
        }
    }

    /// relay 一轮轮询成功,本轮取到 `batch` 条。
    pub fn outbox_polled(&self, source: &'static str, batch: usize) {
        let mut live = self.live();
        let meta = live.outbox.entry(source).or_default();
        meta.last_poll_at = Some(OffsetDateTime::now_utc());
        meta.last_batch = batch as u64;
    }

    /// relay 成功发布了 `count` 条。
    pub fn outbox_published(&self, source: &'static str, count: usize) {
        *self
            .live()
            .counters
            .entry(counter_key("outbox", source, "published"))
            .or_default() += count as u64;
    }

    /// relay 一次发布失败。
    pub fn outbox_failed(&self, source: &'static str) {
        *self
            .live()
            .counters
            .entry(counter_key("outbox", source, "failures"))
            .or_default() += 1;
    }

    /// projector 处理完一条消息。`Ok` 计成功;`Shutdown`(关停中断)不计;其余计失败。
    pub fn projector_result(
        &self,
        projector: &str,
        outcome: ProjectorOutcome,
        lag: Option<Duration>,
    ) {
        let field = match outcome {
            ProjectorOutcome::Ok => "processed",
            ProjectorOutcome::Shutdown => return,
            ProjectorOutcome::Poison | ProjectorOutcome::Dropped | ProjectorOutcome::Transient => {
                "failed"
            }
        };
        let mut live = self.live();
        let meta = live.projectors.entry(projector.to_owned()).or_default();
        if let Some(lag) = lag {
            meta.last_lag_ms = Some(millis(lag));
        }
        *live
            .counters
            .entry(counter_key("projector", projector, field))
            .or_default() += 1;
    }

    /// projector 定时上报消费者积压(也起登记作用:没消息时页面上也有这一行)。
    pub fn projector_pending(&self, projector: &str, backlog: ConsumerBacklog) {
        let mut live = self.live();
        let meta = live.projectors.entry(projector.to_owned()).or_default();
        meta.pending = Some(backlog.pending);
        meta.ack_pending = Some(backlog.ack_pending);
        for field in ["processed", "failed"] {
            live.counters
                .entry(counter_key("projector", projector, field))
                .or_default();
        }
    }

    // ── 采样 / 报告 ──

    /// 采一次进程资源;[`CpuUsage::Refresh`] 时用与上次采样的差算 CPU 占用。
    fn process_status(&self, cpu_usage: CpuUsage) -> ProcessStatus {
        let metrics = collector::collect();
        let mut cpu = self.cpu();
        if cpu_usage == CpuUsage::Refresh {
            if let Some(total) = metrics.cpu_seconds_total {
                let now = Instant::now();
                if let Some(previous) = cpu.last {
                    let wall = now.duration_since(previous.at).as_secs_f64();
                    if wall > 0.0 {
                        let busy = total - previous.cpu_seconds_total;
                        cpu.percent = Some((busy / wall * 100.0).max(0.0));
                    }
                }
                cpu.last = Some(CpuSample {
                    at: now,
                    cpu_seconds_total: total,
                });
            }
        }
        ProcessStatus {
            rss_bytes: metrics.resident_memory_bytes,
            cpu_percent: cpu.percent,
            threads: metrics.threads,
            open_file_descriptors: metrics.open_fds,
        }
    }

    fn snapshot(
        &self,
        at: OffsetDateTime,
        pools: &[PoolStatus],
        process: &ProcessStatus,
    ) -> Snapshot {
        let live = self.live();
        let projector_pending = live
            .projectors
            .values()
            .filter_map(|projector| projector.pending)
            .sum();
        let generation = live.generation;
        let routes = live.routes.clone();
        let db_operations = live.db_ops.clone();
        let counters = live.counters.clone();
        drop(live);
        Snapshot {
            at,
            generation,
            routes,
            db_ops: db_operations,
            counters,
            gauges: Gauges {
                in_flight: self.in_flight.load(Ordering::Relaxed),
                sse: self.sse().values().sum(),
                pool_in_use: pools.iter().map(|pool| u64::from(pool.in_use)).sum(),
                pool_max: pools.iter().map(|pool| u64::from(pool.max)).sum(),
                projector_pending,
                rss_bytes: process.rss_bytes,
                cpu_percent: process.cpu_percent,
            },
        }
    }

    /// 存一份累计快照(采样任务每 [`SAMPLE_INTERVAL`] 调一次)。
    pub fn sample(&self, pools: &[PoolStatus]) {
        let process = self.process_status(CpuUsage::Refresh);
        let snapshot = self.snapshot(OffsetDateTime::now_utc(), pools, &process);
        self.minute_for(&snapshot).0.peak.observe(&snapshot.gauges);
        let (mut ring, alignment) = self.ring_for(&snapshot);
        // Rebased:这份快照已经是基线;Stale:过时快照,不进缓冲。
        if alignment == Alignment::SameGeneration {
            ring.push_back(snapshot);
            while ring.len() > CAPACITY {
                ring.pop_front();
            }
        }
    }

    /// 取出自上次以来的增量,作为 `bucket` 这一分钟的落盘记录(落盘任务每分钟调一次)。
    pub fn take_minute(
        &self,
        instance: &str,
        bucket: OffsetDateTime,
        pools: &[PoolStatus],
    ) -> MinuteRecord {
        let process = self.process_status(CpuUsage::KeepLast);
        let current = self.snapshot(OffsetDateTime::now_utc(), pools, &process);
        let (mut minute, alignment) = self.minute_for(&current);
        minute.peak.observe(&current.gauges);
        let peak = mem::take(&mut minute.peak);
        let delta = if alignment == Alignment::Stale {
            // 过时快照:这一分钟记空、基线不动,这段增量留到下一分钟。
            Delta::empty()
        } else {
            let delta = Delta::between(&current, &minute.baseline);
            minute.baseline = current;
            delta
        };
        drop(minute);

        let total = delta.route_total();
        let db = delta.db_total();
        let routes: Vec<RouteTotals> = delta
            .routes
            .iter()
            .filter(|(_, accumulator)| accumulator.requests > 0)
            .map(|(key, accumulator)| RouteTotals {
                method: key.method.clone(),
                route: key.route.clone(),
                requests: accumulator.requests,
                errors_4xx: accumulator.errors_4xx,
                errors_5xx: accumulator.errors_5xx,
                latency: accumulator.latency,
            })
            .collect();
        let db_operations: Vec<DbOperationTotals> = delta
            .db_ops
            .iter()
            .filter(|(_, histogram)| histogram.total() > 0)
            .map(|(operation, histogram)| DbOperationTotals {
                operation: (*operation).to_owned(),
                latency: *histogram,
            })
            .collect();
        MinuteRecord {
            instance: instance.to_owned(),
            bucket,
            totals: PeriodTotals {
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
            routes,
            db_operations,
        }
    }

    /// 本进程的监控报告。`checks` / `pools` 由调用方(组合根,持有探针)现查现给。
    ///
    /// # Panics
    ///
    /// 环形缓冲为空时 panic。它在构造、中毒重建、换代时都放进一个基线快照,
    /// 淘汰时也只削到容量,不会变空 —— 走到这里是本模块的 bug。
    #[must_use]
    pub fn report(
        &self,
        role: InstanceRole,
        checks: Vec<DependencyCheck>,
        pools: Vec<PoolStatus>,
    ) -> InstanceReport {
        let now = OffsetDateTime::now_utc();
        let process = self.process_status(CpuUsage::KeepLast);
        let current = self.snapshot(now, &pools, &process);

        let (ring, alignment) = self.ring_for(&current);
        let baseline = ring.front().expect("环形缓冲至少有基线快照");
        let window = if alignment == Alignment::Stale {
            Delta::empty()
        } else {
            Delta::between(&current, baseline)
        };
        let history: Vec<HistoryPoint> = ring
            .iter()
            .zip(ring.iter().skip(1))
            .map(|(earlier, later)| Delta::between(later, earlier).history_point(later))
            .collect();
        let window_seconds = (now - baseline.at).whole_seconds().max(0) as u64;
        drop(ring);

        let live = self.live();
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
        drop(live);
        let sse = self
            .sse()
            .iter()
            .map(|(stream, connections)| SseStatus {
                stream: (*stream).to_owned(),
                connections: *connections,
            })
            .collect();

        let total = window.route_total();
        let mut routes: Vec<RouteStats> = window
            .routes
            .iter()
            .filter(|(_, accumulator)| accumulator.requests > 0)
            .map(|(key, accumulator)| RouteStats {
                method: key.method.clone(),
                route: key.route.clone(),
                requests: accumulator.requests,
                errors_4xx: accumulator.errors_4xx,
                errors_5xx: accumulator.errors_5xx,
                p50_ms: accumulator.latency.quantile(0.5),
                p95_ms: accumulator.latency.quantile(0.95),
            })
            .collect();
        routes.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.route.cmp(&b.route)));
        let mut db_operations: Vec<DbOperationStats> = window
            .db_ops
            .iter()
            .filter(|(_, histogram)| histogram.total() > 0)
            .map(|(name, histogram)| DbOperationStats {
                name: (*name).to_owned(),
                calls: histogram.total(),
                p50_ms: histogram.quantile(0.5),
                p95_ms: histogram.quantile(0.95),
            })
            .collect();
        db_operations.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.name.cmp(&b.name)));

        InstanceReport {
            role,
            reachable: true,
            error: None,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at: Some(self.started_at),
            uptime_seconds: (now - self.started_at).whole_seconds().max(0) as u64,
            window_seconds,
            sample_interval_seconds: SAMPLE_INTERVAL.as_secs(),
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
    routes: BTreeMap<RouteKey, RouteAccumulator>,
    db_ops: BTreeMap<&'static str, Histogram>,
    counters: BTreeMap<String, u64>,
}

impl Delta {
    /// 零增量。
    fn empty() -> Delta {
        Delta {
            routes: BTreeMap::new(),
            db_ops: BTreeMap::new(),
            counters: BTreeMap::new(),
        }
    }

    fn between(current: &Snapshot, earlier: &Snapshot) -> Delta {
        let mut routes = BTreeMap::new();
        for (key, accumulator) in &current.routes {
            let delta = earlier
                .routes
                .get(key)
                .map_or(*accumulator, |before| accumulator.since(before));
            routes.insert(key.clone(), delta);
        }
        let mut db_operations = BTreeMap::new();
        for (&operation, histogram) in &current.db_ops {
            let delta = earlier
                .db_ops
                .get(operation)
                .map_or(*histogram, |before| histogram.since(before));
            db_operations.insert(operation, delta);
        }
        let mut counters = BTreeMap::new();
        for (key, value) in &current.counters {
            let before = earlier.counters.get(key).copied().unwrap_or(0);
            counters.insert(key.clone(), value.saturating_sub(before));
        }
        Delta {
            routes,
            db_ops: db_operations,
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
            .filter(|(key, _)| key.starts_with(&prefix) && key.ends_with(&suffix))
            .map(|(_, value)| *value)
            .sum()
    }

    fn route_total(&self) -> RouteAccumulator {
        let mut total = RouteAccumulator::default();
        for accumulator in self.routes.values() {
            total.add(accumulator);
        }
        total
    }

    fn db_total(&self) -> Histogram {
        let mut total = Histogram::default();
        for histogram in self.db_ops.values() {
            total.add(histogram);
        }
        total
    }

    fn history_point(&self, snapshot: &Snapshot) -> HistoryPoint {
        let total = self.route_total();
        let db = self.db_total();
        let gauges = snapshot.gauges;
        HistoryPoint {
            at: snapshot.at,
            requests: total.requests,
            errors_4xx: total.errors_4xx,
            errors_5xx: total.errors_5xx,
            p95_ms: total.latency.quantile(0.95),
            in_flight: gauges.in_flight,
            db_calls: db.total(),
            db_p95_ms: db.quantile(0.95),
            pool_in_use: gauges.pool_in_use,
            pool_max: gauges.pool_max,
            sse_connections: gauges.sse,
            outbox_published: self.counter_sum("outbox", "published"),
            projector_processed: self.counter_sum("projector", "processed"),
            projector_pending: gauges.projector_pending,
            rss_bytes: gauges.rss_bytes,
            cpu_percent: gauges.cpu_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

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

    /// `/metrics` 的 `result` 标签是线上名字(外部看板按它聚合):改成枚举后取值不能变。
    #[test]
    fn projector_outcome_labels_keep_wire_names() {
        let labels: Vec<&str> = [
            ProjectorOutcome::Ok,
            ProjectorOutcome::Poison,
            ProjectorOutcome::Dropped,
            ProjectorOutcome::Transient,
            ProjectorOutcome::Shutdown,
        ]
        .into_iter()
        .map(ProjectorOutcome::as_str)
        .collect();
        assert_eq!(labels, ["ok", "poison", "dropped", "transient", "shutdown"]);
    }

    #[test]
    fn report_counts_requests_by_route_and_status() {
        let monitor = Monitor::new();
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 200,
            elapsed: Duration::from_millis(3),
        });
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 404,
            elapsed: Duration::from_millis(3),
        });
        monitor.record_request(RequestOutcome {
            method: "POST",
            route: "/b",
            status: 500,
            elapsed: Duration::from_millis(30),
        });
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.traffic.requests, 3);
        assert_eq!(report.traffic.errors_4xx, 1);
        assert_eq!(report.traffic.errors_5xx, 1);
        assert_eq!(report.routes[0].route, "/a", "按请求数降序");
        assert_eq!(report.routes[0].requests, 2);
        assert!(report.history.is_empty(), "还没采样就没有历史点");
    }

    #[test]
    fn history_points_are_per_interval_deltas() {
        let monitor = Monitor::new();
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 200,
            elapsed: Duration::from_millis(1),
        });
        monitor.sample(&[pool(1, 10)]);
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 200,
            elapsed: Duration::from_millis(1),
        });
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 200,
            elapsed: Duration::from_millis(1),
        });
        monitor.sample(&[pool(2, 10)]);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        let per_interval: Vec<u64> = report.history.iter().map(|p| p.requests).collect();
        assert_eq!(per_interval, vec![1, 2]);
        assert_eq!(report.history[1].pool_in_use, 2);
        assert_eq!(report.traffic.requests, 3, "窗口内全部请求");
    }

    #[test]
    fn window_drops_evicted_samples() {
        let monitor = Monitor::new();
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/old",
            status: 200,
            elapsed: Duration::from_millis(1),
        });
        for _ in 0..CAPACITY {
            monitor.sample(&[]);
        }
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/new",
            status: 200,
            elapsed: Duration::from_millis(1),
        });
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.traffic.requests, 1, "最老的请求已滑出窗口");
        assert_eq!(report.routes.len(), 1);
        assert_eq!(report.routes[0].route, "/new");
        assert_eq!(report.history.len(), CAPACITY - 1);
    }

    #[test]
    fn background_tasks_are_listed_even_when_idle() {
        let monitor = Monitor::new();
        monitor.outbox_registered("idm");
        monitor.projector_pending(
            "search",
            ConsumerBacklog {
                pending: 5,
                ack_pending: 1,
            },
        );
        monitor.outbox_published("idm", 3);
        monitor.projector_result(
            "search",
            ProjectorOutcome::Ok,
            Some(Duration::from_millis(40)),
        );
        monitor.projector_result("search", ProjectorOutcome::Poison, None);
        monitor.projector_result("search", ProjectorOutcome::Shutdown, None);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.outbox.len(), 1);
        assert_eq!(report.outbox[0].published, 3);
        let projector = &report.projectors[0];
        assert_eq!(
            (projector.processed, projector.failed, projector.pending),
            (1, 1, Some(5))
        );
        assert_eq!(projector.last_lag_ms, Some(40.0));
    }

    #[test]
    fn take_minute_returns_increments_since_last_take() {
        let monitor = Monitor::new();
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 200,
            elapsed: Duration::from_millis(2),
        });
        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/a",
            status: 503,
            elapsed: Duration::from_millis(2),
        });
        monitor.record_db("pg.widgets.list", Duration::from_millis(3));
        monitor.sample(&[pool(3, 10)]);
        let bucket = OffsetDateTime::now_utc();
        let first = monitor.take_minute("combined", bucket, &[pool(1, 10)]);
        assert_eq!(first.totals.requests, 2);
        assert_eq!(first.totals.errors_5xx, 1);
        assert_eq!(first.totals.db_calls, 1);
        assert_eq!(first.totals.pool_in_use_max, 3, "取这一分钟内的最大值");
        assert_eq!(first.routes.len(), 1);
        assert_eq!(first.db_operations[0].operation, "pg.widgets.list");

        monitor.record_request(RequestOutcome {
            method: "GET",
            route: "/b",
            status: 200,
            elapsed: Duration::from_millis(2),
        });
        let second = monitor.take_minute("combined", bucket, &[]);
        assert_eq!(second.totals.requests, 1, "只含上次之后的增量");
        assert_eq!(second.routes[0].route, "/b");
        assert_eq!(second.totals.pool_in_use_max, 0, "峰值每分钟重置");
    }

    #[test]
    fn sse_and_in_flight_are_gauges() {
        let monitor = Monitor::new();
        monitor.sse_opened("widgets");
        monitor.sse_opened("widgets");
        monitor.sse_closed("widgets");
        let guard = monitor.request_started();
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.sse[0].connections, 1);
        assert_eq!(report.in_flight, 1);
        drop(guard);
        assert_eq!(
            monitor
                .report(InstanceRole::Combined, vec![], vec![])
                .in_flight,
            0
        );
    }

    /// 让 `mutex` 中毒:另起一个线程持锁时 panic。
    fn poison<T: Send>(mutex: &Mutex<T>) {
        thread::scope(|scope| {
            let result = scope
                .spawn(|| {
                    let _guard = mutex.lock();
                    panic!("测试:持锁时 panic,让锁中毒");
                })
                .join();
            assert!(result.is_err());
        });
        assert!(mutex.is_poisoned());
    }

    fn requests(monitor: &Monitor, count: usize) {
        for _ in 0..count {
            monitor.record_request(RequestOutcome {
                method: "GET",
                route: "/a",
                status: 200,
                elapsed: Duration::from_millis(1),
            });
        }
    }

    fn sse_connections(report: &InstanceReport) -> Vec<i64> {
        report.sse.iter().map(|status| status.connections).collect()
    }

    #[test]
    fn ring_poison_rebases_on_current_counts_instead_of_zero() {
        let monitor = Monitor::new();
        requests(&monitor, 5);
        monitor.sample(&[]);
        poison(&monitor.ring);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.traffic.requests, 0, "不把启动以来的累计量当成窗口量");
        assert!(!monitor.ring.is_poisoned());

        requests(&monitor, 1);
        monitor.sample(&[]);
        requests(&monitor, 1);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.traffic.requests, 2, "重建之后照常累计");
        let history: Vec<u64> = report.history.iter().map(|point| point.requests).collect();
        assert_eq!(history, vec![1]);
    }

    #[test]
    fn ring_poison_during_sample_does_not_duplicate_the_snapshot() {
        let monitor = Monitor::new();
        requests(&monitor, 3);
        poison(&monitor.ring);
        monitor.sample(&[]);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert!(report.history.is_empty(), "这份快照成了基线,不再重复进缓冲");
        assert_eq!(report.traffic.requests, 0);
    }

    #[test]
    fn minute_poison_does_not_flush_cumulative_totals() {
        let monitor = Monitor::new();
        let bucket = OffsetDateTime::now_utc();
        requests(&monitor, 10);
        assert_eq!(
            monitor.take_minute("combined", bucket, &[]).totals.requests,
            10
        );
        requests(&monitor, 3);
        poison(&monitor.minute);
        let spiked = monitor.take_minute("combined", bucket, &[]);
        assert_eq!(
            spiked.totals.requests, 0,
            "丢掉这一段,而不是把累计 13 条写成一分钟的量"
        );
        assert!(!monitor.minute.is_poisoned());

        requests(&monitor, 2);
        assert_eq!(
            monitor.take_minute("combined", bucket, &[]).totals.requests,
            2
        );
    }

    #[test]
    fn live_poison_restarts_counting_without_spikes_and_keeps_sse() {
        let monitor = Monitor::new();
        let bucket = OffsetDateTime::now_utc();
        monitor.sse_opened("widgets");
        monitor.sse_opened("widgets");
        requests(&monitor, 5);
        monitor.sample(&[]);
        assert_eq!(
            monitor.take_minute("combined", bucket, &[]).totals.requests,
            5
        );
        requests(&monitor, 3);

        poison(&monitor.live);
        requests(&monitor, 1);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert!(!monitor.live.is_poisoned());
        assert_eq!(
            report.traffic.requests, 1,
            "窗口从换代起算,不含旧代、也不被旧基线减成 0"
        );
        assert_eq!(
            sse_connections(&report),
            vec![2],
            "SSE 连接数是当前状态,不清零"
        );

        monitor.sample(&[]);
        requests(&monitor, 1);
        let minute = monitor.take_minute("combined", bucket, &[]);
        assert_eq!(minute.totals.requests, 2, "这一分钟只含新一代的增量");
        assert_eq!(
            monitor
                .report(InstanceRole::Combined, vec![], vec![])
                .traffic
                .requests,
            2
        );

        for _ in 0..3 {
            monitor.sse_closed("widgets");
        }
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(sse_connections(&report), vec![0], "多断开的不会减成负数");
    }

    #[test]
    fn snapshot_taken_before_live_reset_is_discarded() {
        let monitor = Monitor::new();
        requests(&monitor, 5);
        let process = monitor.process_status(CpuUsage::KeepLast);
        let stale = monitor.snapshot(OffsetDateTime::now_utc(), &[], &process);
        poison(&monitor.live);
        requests(&monitor, 1);
        monitor.sample(&[]);
        let bucket = OffsetDateTime::now_utc();
        assert_eq!(
            monitor.take_minute("combined", bucket, &[]).totals.requests,
            1
        );

        assert_eq!(monitor.ring_for(&stale).1, Alignment::Stale);
        assert_eq!(monitor.minute_for(&stale).1, Alignment::Stale);
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(report.traffic.requests, 1);
        assert_eq!(report.history.len(), 1, "过时快照没有进缓冲");
    }

    #[test]
    fn sse_poison_never_goes_negative() {
        let monitor = Monitor::new();
        monitor.sse_opened("widgets");
        monitor.sse_opened("widgets");
        poison(&monitor.sse);
        for _ in 0..3 {
            monitor.sse_closed("widgets");
        }
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert!(sse_connections(&report)
            .iter()
            .all(|&connections| connections >= 0));
        monitor.sse_opened("widgets");
        monitor.sse_closed("widgets");
        monitor.sse_closed("widgets");
        let report = monitor.report(InstanceRole::Combined, vec![], vec![]);
        assert_eq!(sse_connections(&report), vec![0]);
    }
}

//! 监控数据的持久化端口:分钟级 / 小时级指标、接口与数据库操作的小时明细、日志。
//!
//! 实现两份:[`MemoryOpsStore`](默认:不配 `OPS_DB_HOST` 时用,也是测试的假实现,只留最近一段)、
//! [`super::pg_ops_store::PgOpsStore`](ops schema)。保留期见 [`Retention`]。

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use utoipa::ToSchema;

use super::histogram::Histogram;
use super::lock_or_reset;
use crate::kernel::time_range::TimeRange;

/// 分层保留期(参照 CloudWatch 的降采样:细粒度短留、粗粒度长留)。
pub struct Retention;

impl Retention {
    /// 分钟级指标。
    pub const MINUTE: Duration = Duration::days(15);
    /// 小时级指标(约 13 个月,够做同比)。
    pub const HOUR: Duration = Duration::days(395);
    /// 接口 / 数据库操作的小时明细。
    pub const DETAIL: Duration = Duration::days(30);
    /// 日志。
    pub const LOGS: Duration = Duration::days(15);
}

/// 一个时间段(一分钟 / 一小时)的进程级汇总:计数类为增量,读数类为段内最大值。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PeriodTotals {
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub latency: Histogram,
    pub db_calls: u64,
    pub db_latency: Histogram,
    pub outbox_published: u64,
    pub outbox_failures: u64,
    pub projector_processed: u64,
    pub projector_failed: u64,
    pub in_flight_max: u64,
    pub pool_in_use_max: u64,
    pub pool_max: u64,
    pub sse_max: u64,
    pub projector_pending_max: u64,
    pub rss_bytes_max: Option<u64>,
    pub cpu_percent_max: Option<f64>,
}

/// 两个可缺读数取大;一边缺就用另一边。
fn max_option<T: PartialOrd + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if right > left { right } else { left }),
        (left, None) => left,
        (None, right) => right,
    }
}

impl PeriodTotals {
    /// 合并另一段:计数相加、读数取大。
    pub fn merge(&mut self, other: &PeriodTotals) {
        self.requests += other.requests;
        self.errors_4xx += other.errors_4xx;
        self.errors_5xx += other.errors_5xx;
        self.latency.add(&other.latency);
        self.db_calls += other.db_calls;
        self.db_latency.add(&other.db_latency);
        self.outbox_published += other.outbox_published;
        self.outbox_failures += other.outbox_failures;
        self.projector_processed += other.projector_processed;
        self.projector_failed += other.projector_failed;
        self.in_flight_max = self.in_flight_max.max(other.in_flight_max);
        self.pool_in_use_max = self.pool_in_use_max.max(other.pool_in_use_max);
        self.pool_max = self.pool_max.max(other.pool_max);
        self.sse_max = self.sse_max.max(other.sse_max);
        self.projector_pending_max = self.projector_pending_max.max(other.projector_pending_max);
        self.rss_bytes_max = max_option(self.rss_bytes_max, other.rss_bytes_max);
        self.cpu_percent_max = max_option(self.cpu_percent_max, other.cpu_percent_max);
    }
}

/// 某接口在一段时间内的统计。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteTotals {
    pub method: String,
    pub route: String,
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub latency: Histogram,
}

/// 某数据库操作在一段时间内的统计(调用次数 = 直方图总数)。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DbOperationTotals {
    pub operation: String,
    pub latency: Histogram,
}

/// 某进程的一条接口合计([`OpsStore::route_totals`] 的结果行)。
#[derive(Clone, Debug, PartialEq)]
pub struct InstanceRouteTotals {
    pub instance: String,
    pub totals: RouteTotals,
}

/// 某进程的一条数据库操作合计([`OpsStore::db_operation_totals`] 的结果行)。
#[derive(Clone, Debug, PartialEq)]
pub struct InstanceDbOperationTotals {
    pub instance: String,
    pub totals: DbOperationTotals,
}

/// 日志分页查询的结果([`OpsStore::logs`])。
#[derive(Clone, Debug)]
pub struct LogPage {
    /// 本页。
    pub logs: Vec<StoredLog>,
    /// 符合条件的总数。
    pub total: u64,
}

/// 一分钟的落盘记录。
#[derive(Clone, Debug)]
pub struct MinuteRecord {
    pub instance: String,
    /// 整分起点(UTC)。
    pub bucket: OffsetDateTime,
    pub totals: PeriodTotals,
    pub routes: Vec<RouteTotals>,
    pub db_operations: Vec<DbOperationTotals>,
}

/// 一个时间段的汇总行(查询结果)。
#[derive(Clone, Debug)]
pub struct SeriesRow {
    pub instance: String,
    pub bucket: OffsetDateTime,
    pub totals: PeriodTotals,
}

/// 读哪一层。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Minute,
    Hour,
}

/// 标签串(存储 / 线格式里的 `WARN`、`app`…)不是任何已知取值:[`FromStr`] 的错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownLabel {
    /// 标签种类(如 `severity`),只用于错误消息。
    pub kind: &'static str,
}

impl fmt::Display for UnknownLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "未知的 {} 取值", self.kind)
    }
}

impl Error for UnknownLabel {}

/// 日志级别(只存 WARN 及以上)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Warn,
    Error,
}

impl Severity {
    /// 存储里的级别串(`WARN` / `ERROR`,与 serde 同名)。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

impl FromStr for Severity {
    type Err = UnknownLabel;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "WARN" => Ok(Severity::Warn),
            "ERROR" => Ok(Severity::Error),
            _ => Err(UnknownLabel { kind: "severity" }),
        }
    }
}

/// 日志归属的服务:app(业务)/ idm(认证)/ web(前端,浏览器上报的错误)。app / idm 分进程部署时
/// 就是进程身份;单进程开发时按 [`classify_service`] 推断,口径与 nginx 的分流规则一致。
/// web 只来自前端上报接口(`app::client_errors`),不经推断。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    App,
    Idm,
    Web,
}

impl Service {
    /// 存储里的服务名(与 serde 同名)。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Service::App => "app",
            Service::Idm => "idm",
            Service::Web => "web",
        }
    }
}

impl FromStr for Service {
    type Err = UnknownLabel;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "app" => Ok(Service::App),
            "idm" => Ok(Service::Idm),
            "web" => Ok(Service::Web),
            _ => Err(UnknownLabel { kind: "service" }),
        }
    }
}

/// 归 idm 的接口前缀:与 nginx.conf 把请求转给 idm 容器的规则相同(`^/api/v1/((public|frontend|admin)/auth|admin/platform)/`)。
const IDM_ROUTE_PREFIXES: [&str; 4] = [
    "/api/v1/public/auth/",
    "/api/v1/frontend/auth/",
    "/api/v1/admin/auth/",
    "/api/v1/admin/platform/",
];

/// 归 idm 的代码模块(生产上它们只装在 idm 进程里):认证、后台用户管理、认证审计、搜索投影,以及 idm 领域库。
const IDM_TARGETS: [&str; 6] = [
    "idm",
    "baserust::features::auth",
    "baserust::features::users",
    "baserust::features::tenants",
    "baserust::features::auth_audit",
    "baserust::features::search",
];

/// 一条日志从哪来([`classify_service`] 的入参):三个字符串按名字区分,不靠参数位置。
#[derive(Clone, Copy, Debug)]
pub struct LogOrigin<'origin> {
    /// 进程身份(`app` / `idm` / 合体进程的名字)。
    pub instance: &'origin str,
    /// 产生日志的模块(tracing target)。
    pub target: &'origin str,
    /// 请求的路由模板;不在请求里 = `None`。
    pub route: Option<&'origin str>,
}

/// 判定一条日志属于哪个服务:进程身份明确(app / idm)就用它;单进程时有接口路径按分流规则,
/// 否则按产生日志的模块,都不像 idm 的归 app。
#[must_use]
pub fn classify_service(origin: LogOrigin<'_>) -> Service {
    let LogOrigin {
        instance,
        target,
        route,
    } = origin;
    match instance {
        "app" => return Service::App,
        "idm" => return Service::Idm,
        _ => {}
    }
    if let Some(route) = route {
        return if IDM_ROUTE_PREFIXES
            .iter()
            .any(|prefix| route.starts_with(prefix))
        {
            Service::Idm
        } else {
            Service::App
        };
    }
    let idm_module = IDM_TARGETS.iter().any(|module| {
        target == *module
            || target
                .strip_prefix(module)
                .is_some_and(|rest| rest.starts_with("::"))
    });
    if idm_module {
        Service::Idm
    } else {
        Service::App
    }
}

/// 一条日志(字段对齐 OpenTelemetry 日志数据模型;请求上下文单独成字段便于筛选)。
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    pub timestamp: OffsetDateTime,
    pub instance: String,
    pub service: Service,
    pub severity: Severity,
    pub target: String,
    pub body: String,
    pub request_id: Option<String>,
    pub method: Option<String>,
    pub route: Option<String>,
    pub status: Option<u16>,
    pub duration_ms: Option<f64>,
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

/// 已存储的日志(带 id)。
#[derive(Clone, Debug, PartialEq)]
pub struct StoredLog {
    pub id: i64,
    pub entry: LogEntry,
}

/// 日志查询条件(都可选;结果按时间倒序)。
#[derive(Clone, Debug, Default)]
pub struct LogQuery {
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    /// 最低级别:`Warn` = WARN + ERROR,`Error` = 只 ERROR。
    pub min_severity: Option<Severity>,
    pub instance: Option<String>,
    pub service: Option<Service>,
    /// 消息 / 模块 / 接口的子串(不区分大小写)。
    pub query: Option<String>,
    pub request_id: Option<String>,
    pub page: u64,
    pub size: u64,
}

impl LogQuery {
    /// 本页第一条的偏移(`page` 从 1 开始)。
    #[must_use]
    pub fn offset(&self) -> u64 {
        // 饱和乘:page 极大时不在 debug 构建里溢出 panic(结果只是查不到数据)。
        self.page.saturating_sub(1).saturating_mul(self.size)
    }

    /// 内存实现与测试用的匹配逻辑(PG 实现用 SQL 表达同一口径)。
    #[must_use]
    pub fn matches(&self, entry: &LogEntry) -> bool {
        if self.from.is_some_and(|from| entry.timestamp < from)
            || self.to.is_some_and(|to| entry.timestamp >= to)
        {
            return false;
        }
        if self
            .min_severity
            .is_some_and(|min_severity| entry.severity < min_severity)
        {
            return false;
        }
        if self
            .instance
            .as_ref()
            .is_some_and(|instance| &entry.instance != instance)
        {
            return false;
        }
        if self.service.is_some_and(|service| entry.service != service) {
            return false;
        }
        if self
            .request_id
            .as_ref()
            .is_some_and(|request_id| entry.request_id.as_ref() != Some(request_id))
        {
            return false;
        }
        if let Some(term) = &self.query {
            let term = term.to_lowercase();
            let hit = entry.body.to_lowercase().contains(&term)
                || entry.target.to_lowercase().contains(&term)
                || entry
                    .route
                    .as_ref()
                    .is_some_and(|route| route.to_lowercase().contains(&term));
            if !hit {
                return false;
            }
        }
        true
    }
}

/// 一次保留期清理删掉的行数。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeCounts {
    pub minutes: u64,
    pub hours: u64,
    pub details: u64,
    pub logs: u64,
}

/// 监控数据存储端口。
#[async_trait]
pub trait OpsStore: Send + Sync {
    /// 落一分钟:写分钟表,同时把它累加进所在小时的汇总与明细。
    async fn record_minute(&self, record: &MinuteRecord) -> anyhow::Result<()>;
    /// 批量写日志(写入任务攒一批调一次)。
    async fn insert_logs(&self, logs: &[LogEntry]) -> anyhow::Result<()>;
    /// `[from, to)` 内的汇总行,按时间升序。
    async fn series(&self, tier: Tier, range: TimeRange) -> anyhow::Result<Vec<SeriesRow>>;
    /// `[from, to)` 内各进程、各接口的合计。
    async fn route_totals(&self, range: TimeRange) -> anyhow::Result<Vec<InstanceRouteTotals>>;
    /// `[from, to)` 内各进程、各数据库操作的合计。
    async fn db_operation_totals(
        &self,
        range: TimeRange,
    ) -> anyhow::Result<Vec<InstanceDbOperationTotals>>;
    /// 分页查日志,返回本页与总数。
    async fn logs(&self, query: &LogQuery) -> anyhow::Result<LogPage>;
    /// 删掉超过保留期的数据。
    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts>;
    /// 是否真的持久化(内存实现 = false,页面据此提示"只有最近一段")。
    fn persistent(&self) -> bool;
}

/// 截到整点。
#[must_use]
pub fn hour_start(time: OffsetDateTime) -> OffsetDateTime {
    time.replace_minute(0)
        .and_then(|truncated| truncated.replace_second(0))
        .and_then(|truncated| truncated.replace_nanosecond(0))
        .unwrap_or(time)
}

/// 截到整分。
#[must_use]
pub fn minute_start(time: OffsetDateTime) -> OffsetDateTime {
    time.replace_second(0)
        .and_then(|truncated| truncated.replace_nanosecond(0))
        .unwrap_or(time)
}

/// 内存实现:只留最近 [`MemoryOpsStore::MINUTES`] 分钟的指标和最近 [`MemoryOpsStore::LOGS`] 条日志。
pub struct MemoryOpsStore {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    minutes: VecDeque<MinuteRecord>,
    logs: VecDeque<StoredLog>,
    next_log_id: i64,
}

impl MemoryInner {
    /// 空存储,日志 id 从 1 开始。
    fn new() -> Self {
        Self {
            next_log_id: 1,
            ..Default::default()
        }
    }
}

impl Default for MemoryOpsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryOpsStore {
    /// 最多留 24 小时的分钟记录。
    pub const MINUTES: usize = 24 * 60;
    /// 最多留这么多条日志。
    pub const LOGS: usize = 2000;

    /// 空存储,日志 id 从 1 开始。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MemoryInner::new()),
        }
    }

    /// 中毒 → 按 [`lock_or_reset`] 的锁中毒策略清空重来(内存版只是最近一段的缓存,丢了可以接受)。
    fn lock(&self) -> MutexGuard<'_, MemoryInner> {
        lock_or_reset(&self.inner, MemoryInner::new)
    }
}

#[async_trait]
impl OpsStore for MemoryOpsStore {
    async fn record_minute(&self, record: &MinuteRecord) -> anyhow::Result<()> {
        let mut inner = self.lock();
        inner.minutes.push_back(record.clone());
        while inner.minutes.len() > Self::MINUTES {
            inner.minutes.pop_front();
        }
        Ok(())
    }

    async fn insert_logs(&self, logs: &[LogEntry]) -> anyhow::Result<()> {
        let mut inner = self.lock();
        for entry in logs {
            let id = inner.next_log_id;
            inner.next_log_id += 1;
            inner.logs.push_back(StoredLog {
                id,
                entry: entry.clone(),
            });
        }
        while inner.logs.len() > Self::LOGS {
            inner.logs.pop_front();
        }
        Ok(())
    }

    async fn series(&self, tier: Tier, range: TimeRange) -> anyhow::Result<Vec<SeriesRow>> {
        let TimeRange { from, to } = range;
        let inner = self.lock();
        let mut out: BTreeMap<(OffsetDateTime, String), PeriodTotals> = BTreeMap::new();
        let in_range = inner
            .minutes
            .iter()
            .filter(|minute| minute.bucket >= from && minute.bucket < to);
        for minute in in_range {
            let bucket = match tier {
                Tier::Minute => minute.bucket,
                Tier::Hour => hour_start(minute.bucket),
            };
            out.entry((bucket, minute.instance.clone()))
                .or_default()
                .merge(&minute.totals);
        }
        Ok(out
            .into_iter()
            .map(|((bucket, instance), totals)| SeriesRow {
                instance,
                bucket,
                totals,
            })
            .collect())
    }

    async fn route_totals(&self, range: TimeRange) -> anyhow::Result<Vec<InstanceRouteTotals>> {
        let TimeRange { from, to } = range;
        let inner = self.lock();
        let mut out: BTreeMap<(String, String, String), RouteTotals> = BTreeMap::new();
        let in_range = inner
            .minutes
            .iter()
            .filter(|minute| minute.bucket >= from && minute.bucket < to);
        for minute in in_range {
            for route in &minute.routes {
                let key = (
                    minute.instance.clone(),
                    route.method.clone(),
                    route.route.clone(),
                );
                let totals = out.entry(key).or_insert_with(|| RouteTotals {
                    method: route.method.clone(),
                    route: route.route.clone(),
                    ..Default::default()
                });
                totals.requests += route.requests;
                totals.errors_4xx += route.errors_4xx;
                totals.errors_5xx += route.errors_5xx;
                totals.latency.add(&route.latency);
            }
        }
        Ok(out
            .into_iter()
            .map(|((instance, _, _), totals)| InstanceRouteTotals { instance, totals })
            .collect())
    }

    async fn db_operation_totals(
        &self,
        range: TimeRange,
    ) -> anyhow::Result<Vec<InstanceDbOperationTotals>> {
        let TimeRange { from, to } = range;
        let inner = self.lock();
        let mut out: BTreeMap<(String, String), DbOperationTotals> = BTreeMap::new();
        let in_range = inner
            .minutes
            .iter()
            .filter(|minute| minute.bucket >= from && minute.bucket < to);
        for minute in in_range {
            for operation in &minute.db_operations {
                out.entry((minute.instance.clone(), operation.operation.clone()))
                    .or_insert_with(|| DbOperationTotals {
                        operation: operation.operation.clone(),
                        ..Default::default()
                    })
                    .latency
                    .add(&operation.latency);
            }
        }
        Ok(out
            .into_iter()
            .map(|((instance, _), totals)| InstanceDbOperationTotals { instance, totals })
            .collect())
    }

    async fn logs(&self, query: &LogQuery) -> anyhow::Result<LogPage> {
        let inner = self.lock();
        let mut hits: Vec<&StoredLog> = inner
            .logs
            .iter()
            .filter(|log| query.matches(&log.entry))
            .collect();
        hits.sort_by(|left, right| {
            right
                .entry
                .timestamp
                .cmp(&left.entry.timestamp)
                .then(right.id.cmp(&left.id))
        });
        let total = hits.len() as u64;
        let page: Vec<StoredLog> = hits
            .into_iter()
            .skip(usize::try_from(query.offset()).unwrap_or(usize::MAX))
            .take(usize::try_from(query.size).unwrap_or(usize::MAX))
            .cloned()
            .collect();
        Ok(LogPage { logs: page, total })
    }

    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts> {
        let mut inner = self.lock();
        let minutes_before = inner.minutes.len();
        inner
            .minutes
            .retain(|minute| minute.bucket >= now - Retention::MINUTE);
        let logs_before = inner.logs.len();
        inner
            .logs
            .retain(|log| log.entry.timestamp >= now - Retention::LOGS);
        Ok(PurgeCounts {
            minutes: (minutes_before - inner.minutes.len()) as u64,
            logs: (logs_before - inner.logs.len()) as u64,
            ..Default::default()
        })
    }

    fn persistent(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn process_identity_wins() {
        assert_eq!(
            classify_service(LogOrigin {
                instance: "idm",
                target: "baserust::features::widget",
                route: Some("/api/v1/frontend/widgets")
            }),
            Service::Idm
        );
        assert_eq!(
            classify_service(LogOrigin {
                instance: "app",
                target: "idm::session",
                route: None
            }),
            Service::App
        );
    }

    #[test]
    fn combined_follows_nginx_routing_then_module() {
        let classify = |target: &str, route: Option<&str>| {
            classify_service(LogOrigin {
                instance: "combined",
                target,
                route,
            })
        };
        assert_eq!(
            classify(
                "baserust::infra::http::error",
                Some("/api/v1/public/auth/login")
            ),
            Service::Idm
        );
        assert_eq!(
            classify(
                "baserust::infra::http::error",
                Some("/api/v1/admin/auth/users/{id}")
            ),
            Service::Idm
        );
        assert_eq!(
            classify(
                "baserust::infra::http::error",
                Some("/api/v1/admin/platform/tenants/{id}")
            ),
            Service::Idm,
            "平台租户管理归 idm(nginx 同样转给 idm)"
        );
        assert_eq!(
            classify("baserust::features::tenants::adapters::http", None),
            Service::Idm
        );
        assert_eq!(
            classify(
                "baserust::infra::http::error",
                Some("/api/v1/admin/widgets")
            ),
            Service::App
        );
        assert_eq!(classify("http.access", Some("unmatched")), Service::App);
        assert_eq!(
            classify(
                "baserust::features::auth_audit::adapters::auth_event_projector",
                None
            ),
            Service::Idm
        );
        assert_eq!(
            classify("baserust::features::auth::adapters::emit", None),
            Service::Idm
        );
        assert_eq!(classify("idm::service", None), Service::Idm);
        assert_eq!(
            classify("baserust::features::authz_like", None),
            Service::App,
            "前缀要按模块边界匹配"
        );
        assert_eq!(classify("baserust::infra::outbox", None), Service::App);
    }

    #[test]
    fn offset_saturates_on_huge_page() {
        let query = LogQuery {
            page: u64::MAX,
            size: 100,
            ..Default::default()
        };
        assert_eq!(query.offset(), u64::MAX);
    }

    #[tokio::test]
    async fn memory_logs_with_huge_page_is_empty_instead_of_panicking() {
        let store = MemoryOpsStore::new();
        let query = LogQuery {
            page: u64::MAX,
            size: u64::MAX,
            ..Default::default()
        };
        let LogPage { logs: page, total } = store.logs(&query).await.unwrap();
        assert!(page.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn memory_store_resets_after_poison() {
        let store = MemoryOpsStore::new();
        thread::scope(|scope| {
            let result = scope
                .spawn(|| {
                    let _guard = store.inner.lock();
                    panic!("测试:持锁时 panic,让锁中毒");
                })
                .join();
            assert!(result.is_err());
        });
        assert!(store.inner.is_poisoned());
        let query = LogQuery {
            page: 1,
            size: 10,
            ..Default::default()
        };
        assert!(
            store.logs(&query).await.is_ok(),
            "中毒后清空重来,不永久报错"
        );
        assert!(!store.inner.is_poisoned());
    }
}

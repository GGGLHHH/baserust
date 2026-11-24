//! 监控数据的持久化端口:分钟级 / 小时级指标、接口与数据库操作的小时明细、日志。
//!
//! 实现两份:[`MemoryOpsStore`](默认:不配 `OPS_DB_HOST` 时用,也是测试的假实现,只留最近一段)、
//! [`super::store_pg::PgOpsStore`](ops schema)。保留期见 [`Retention`]。

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use utoipa::ToSchema;

use super::hist::Hist;

/// 分层保留期(参照 CloudWatch 的降采样:细粒度短留、粗粒度长留)。
pub struct Retention;

impl Retention {
    pub const MINUTE: Duration = Duration::days(15);
    pub const HOUR: Duration = Duration::days(395);
    pub const DETAIL: Duration = Duration::days(30);
    pub const LOGS: Duration = Duration::days(15);
}

/// 一个时间段(一分钟 / 一小时)的进程级汇总:计数类为增量,读数类为段内最大值。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PeriodTotals {
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub latency: Hist,
    pub db_calls: u64,
    pub db_latency: Hist,
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

fn max_opt<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y > x { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

impl PeriodTotals {
    /// 合并另一段:计数相加、读数取大。
    pub fn merge(&mut self, o: &PeriodTotals) {
        self.requests += o.requests;
        self.errors_4xx += o.errors_4xx;
        self.errors_5xx += o.errors_5xx;
        self.latency.add(&o.latency);
        self.db_calls += o.db_calls;
        self.db_latency.add(&o.db_latency);
        self.outbox_published += o.outbox_published;
        self.outbox_failures += o.outbox_failures;
        self.projector_processed += o.projector_processed;
        self.projector_failed += o.projector_failed;
        self.in_flight_max = self.in_flight_max.max(o.in_flight_max);
        self.pool_in_use_max = self.pool_in_use_max.max(o.pool_in_use_max);
        self.pool_max = self.pool_max.max(o.pool_max);
        self.sse_max = self.sse_max.max(o.sse_max);
        self.projector_pending_max = self.projector_pending_max.max(o.projector_pending_max);
        self.rss_bytes_max = max_opt(self.rss_bytes_max, o.rss_bytes_max);
        self.cpu_percent_max = max_opt(self.cpu_percent_max, o.cpu_percent_max);
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
    pub latency: Hist,
}

/// 某数据库操作在一段时间内的统计(调用次数 = 直方图总数)。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DbOpTotals {
    pub operation: String,
    pub latency: Hist,
}

/// 一分钟的落盘记录。
#[derive(Clone, Debug)]
pub struct MinuteRecord {
    pub instance: String,
    /// 整分起点(UTC)。
    pub bucket: OffsetDateTime,
    pub totals: PeriodTotals,
    pub routes: Vec<RouteTotals>,
    pub db_ops: Vec<DbOpTotals>,
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

/// 日志级别(只存 WARN 及以上)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "WARN" => Some(Severity::Warn),
            "ERROR" => Some(Severity::Error),
            _ => None,
        }
    }
}

/// 日志归属的服务:app(业务)/ idm(认证)。分进程部署时就是进程身份;单进程开发时按
/// [`classify_service`] 推断,口径与 nginx 的分流规则一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    App,
    Idm,
}

impl Service {
    pub fn as_str(self) -> &'static str {
        match self {
            Service::App => "app",
            Service::Idm => "idm",
        }
    }

    pub fn parse(s: &str) -> Option<Service> {
        match s {
            "app" => Some(Service::App),
            "idm" => Some(Service::Idm),
            _ => None,
        }
    }
}

/// 归 idm 的接口前缀:与 nginx.conf 把请求转给 idm 容器的规则相同(`^/api/v1/(public|frontend|admin)/auth/`)。
const IDM_ROUTE_PREFIXES: [&str; 3] = [
    "/api/v1/public/auth/",
    "/api/v1/frontend/auth/",
    "/api/v1/admin/auth/",
];

/// 归 idm 的代码模块(生产上它们只装在 idm 进程里):认证、后台用户管理、认证审计、搜索投影,以及 idm 领域库。
const IDM_TARGETS: [&str; 5] = [
    "idm",
    "baserust::features::auth",
    "baserust::features::users",
    "baserust::features::auth_audit",
    "baserust::features::search",
];

/// 判定一条日志属于哪个服务:进程身份明确(app / idm)就用它;单进程时有接口路径按分流规则,
/// 否则按产生日志的模块,都不像 idm 的归 app。
pub fn classify_service(instance: &str, target: &str, route: Option<&str>) -> Service {
    match instance {
        "app" => return Service::App,
        "idm" => return Service::Idm,
        _ => {}
    }
    if let Some(route) = route {
        return if IDM_ROUTE_PREFIXES.iter().any(|p| route.starts_with(p)) {
            Service::Idm
        } else {
            Service::App
        };
    }
    let idm_module = IDM_TARGETS.iter().any(|m| {
        target == *m
            || target
                .strip_prefix(m)
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
    pub ts: OffsetDateTime,
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
    pub q: Option<String>,
    pub request_id: Option<String>,
    pub page: u64,
    pub size: u64,
}

impl LogQuery {
    pub fn offset(&self) -> u64 {
        self.page.saturating_sub(1) * self.size
    }

    /// 内存实现与测试用的匹配逻辑(PG 实现用 SQL 表达同一口径)。
    pub fn matches(&self, e: &LogEntry) -> bool {
        if self.from.is_some_and(|f| e.ts < f) || self.to.is_some_and(|t| e.ts >= t) {
            return false;
        }
        if self.min_severity.is_some_and(|m| e.severity < m) {
            return false;
        }
        if self.instance.as_ref().is_some_and(|i| &e.instance != i) {
            return false;
        }
        if self.service.is_some_and(|s| e.service != s) {
            return false;
        }
        if self
            .request_id
            .as_ref()
            .is_some_and(|r| e.request_id.as_ref() != Some(r))
        {
            return false;
        }
        if let Some(q) = &self.q {
            let q = q.to_lowercase();
            let hit = e.body.to_lowercase().contains(&q)
                || e.target.to_lowercase().contains(&q)
                || e.route
                    .as_ref()
                    .is_some_and(|r| r.to_lowercase().contains(&q));
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
    async fn record_minute(&self, rec: &MinuteRecord) -> anyhow::Result<()>;
    async fn insert_logs(&self, logs: &[LogEntry]) -> anyhow::Result<()>;
    /// `[from, to)` 内的汇总行,按时间升序。
    async fn series(
        &self,
        tier: Tier,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<SeriesRow>>;
    /// `[from, to)` 内各进程、各接口的合计。
    async fn route_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, RouteTotals)>>;
    /// `[from, to)` 内各进程、各数据库操作的合计。
    async fn db_op_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, DbOpTotals)>>;
    /// 分页查日志,返回(本页, 总数)。
    async fn logs(&self, q: &LogQuery) -> anyhow::Result<(Vec<StoredLog>, u64)>;
    /// 删掉超过保留期的数据。
    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts>;
    /// 是否真的持久化(内存实现 = false,页面据此提示"只有最近一段")。
    fn persistent(&self) -> bool;
}

/// 截到整点。
pub fn hour_start(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_minute(0)
        .and_then(|t| t.replace_second(0))
        .and_then(|t| t.replace_nanosecond(0))
        .unwrap_or(t)
}

/// 截到整分。
pub fn minute_start(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_second(0)
        .and_then(|t| t.replace_nanosecond(0))
        .unwrap_or(t)
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

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MemoryInner {
                next_log_id: 1,
                ..Default::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl OpsStore for MemoryOpsStore {
    async fn record_minute(&self, rec: &MinuteRecord) -> anyhow::Result<()> {
        let mut inner = self.lock();
        inner.minutes.push_back(rec.clone());
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

    async fn series(
        &self,
        tier: Tier,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<SeriesRow>> {
        let inner = self.lock();
        let mut out: BTreeMap<(OffsetDateTime, String), PeriodTotals> = BTreeMap::new();
        for m in inner
            .minutes
            .iter()
            .filter(|m| m.bucket >= from && m.bucket < to)
        {
            let bucket = match tier {
                Tier::Minute => m.bucket,
                Tier::Hour => hour_start(m.bucket),
            };
            out.entry((bucket, m.instance.clone()))
                .or_default()
                .merge(&m.totals);
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

    async fn route_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, RouteTotals)>> {
        let inner = self.lock();
        let mut out: BTreeMap<(String, String, String), RouteTotals> = BTreeMap::new();
        for m in inner
            .minutes
            .iter()
            .filter(|m| m.bucket >= from && m.bucket < to)
        {
            for r in &m.routes {
                let acc = out
                    .entry((m.instance.clone(), r.method.clone(), r.route.clone()))
                    .or_insert_with(|| RouteTotals {
                        method: r.method.clone(),
                        route: r.route.clone(),
                        ..Default::default()
                    });
                acc.requests += r.requests;
                acc.errors_4xx += r.errors_4xx;
                acc.errors_5xx += r.errors_5xx;
                acc.latency.add(&r.latency);
            }
        }
        Ok(out.into_iter().map(|((i, _, _), r)| (i, r)).collect())
    }

    async fn db_op_totals(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> anyhow::Result<Vec<(String, DbOpTotals)>> {
        let inner = self.lock();
        let mut out: BTreeMap<(String, String), DbOpTotals> = BTreeMap::new();
        for m in inner
            .minutes
            .iter()
            .filter(|m| m.bucket >= from && m.bucket < to)
        {
            for d in &m.db_ops {
                out.entry((m.instance.clone(), d.operation.clone()))
                    .or_insert_with(|| DbOpTotals {
                        operation: d.operation.clone(),
                        ..Default::default()
                    })
                    .latency
                    .add(&d.latency);
            }
        }
        Ok(out.into_iter().map(|((i, _), d)| (i, d)).collect())
    }

    async fn logs(&self, q: &LogQuery) -> anyhow::Result<(Vec<StoredLog>, u64)> {
        let inner = self.lock();
        let mut hits: Vec<&StoredLog> = inner.logs.iter().filter(|l| q.matches(&l.entry)).collect();
        hits.sort_by(|a, b| b.entry.ts.cmp(&a.entry.ts).then(b.id.cmp(&a.id)));
        let total = hits.len() as u64;
        let page = hits
            .into_iter()
            .skip(q.offset() as usize)
            .take(q.size as usize)
            .cloned()
            .collect();
        Ok((page, total))
    }

    async fn purge(&self, now: OffsetDateTime) -> anyhow::Result<PurgeCounts> {
        let mut inner = self.lock();
        let before_m = inner.minutes.len();
        inner
            .minutes
            .retain(|m| m.bucket >= now - Retention::MINUTE);
        let before_l = inner.logs.len();
        inner.logs.retain(|l| l.entry.ts >= now - Retention::LOGS);
        Ok(PurgeCounts {
            minutes: (before_m - inner.minutes.len()) as u64,
            logs: (before_l - inner.logs.len()) as u64,
            ..Default::default()
        })
    }

    fn persistent(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_wins() {
        assert_eq!(
            classify_service(
                "idm",
                "baserust::features::widget",
                Some("/api/v1/frontend/widgets")
            ),
            Service::Idm
        );
        assert_eq!(classify_service("app", "idm::session", None), Service::App);
    }

    #[test]
    fn combined_follows_nginx_routing_then_module() {
        let c = |t: &str, r: Option<&str>| classify_service("combined", t, r);
        assert_eq!(
            c(
                "baserust::infra::http::error",
                Some("/api/v1/public/auth/login")
            ),
            Service::Idm
        );
        assert_eq!(
            c(
                "baserust::infra::http::error",
                Some("/api/v1/admin/auth/users/{id}")
            ),
            Service::Idm
        );
        assert_eq!(
            c(
                "baserust::infra::http::error",
                Some("/api/v1/admin/widgets")
            ),
            Service::App
        );
        assert_eq!(c("http.access", Some("unmatched")), Service::App);
        assert_eq!(
            c("baserust::features::auth_audit::adapters::projector", None),
            Service::Idm
        );
        assert_eq!(
            c("baserust::features::auth::adapters::emit", None),
            Service::Idm
        );
        assert_eq!(c("idm::service", None), Service::Idm);
        assert_eq!(
            c("baserust::features::authz_like", None),
            Service::App,
            "前缀要按模块边界匹配"
        );
        assert_eq!(c("baserust::infra::outbox", None), Service::App);
    }
}

//! 监控报告的线格式(`GET /api/v1/admin/monitoring` 的响应体;idm 进程的 `/internal/monitoring` 也回 [`InstanceReport`])。
//! 同时 `Deserialize`:app 进程拉 idm 的报告后原样并进自己的响应。

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use utoipa::{IntoParams, ToSchema};

use super::store::{Service, Severity, Tier};

impl InstanceRole {
    /// 存储里的实例名。
    pub fn as_str(self) -> &'static str {
        match self {
            InstanceRole::App => "app",
            InstanceRole::Idm => "idm",
            InstanceRole::Combined => "combined",
        }
    }

    pub fn parse(s: &str) -> Option<InstanceRole> {
        match s {
            "app" => Some(InstanceRole::App),
            "idm" => Some(InstanceRole::Idm),
            "combined" => Some(InstanceRole::Combined),
            _ => None,
        }
    }
}

/// 实例角色。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstanceRole {
    /// 业务进程(生产分进程拓扑)。
    App,
    /// 认证进程(生产分进程拓扑)。
    Idm,
    /// 单进程同时挂 app + idm(本地开发)。
    Combined,
}

/// 整体报告:每个进程一份。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct MonitoringReport {
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub instances: Vec<InstanceReport>,
}

/// 单个进程的监控数据。计数类字段(请求数、发布数…)都是**统计窗口内**的值:
/// 窗口 = 进程内存里保留的最近一段(默认 1 小时),进程刚启动时从启动算起。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InstanceReport {
    pub role: InstanceRole,
    /// 拉取这个进程的报告是否成功(app 汇总 idm 时可能失败)。失败时其余字段为空值。
    pub reachable: bool,
    /// 拉取失败的原因。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub version: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    pub uptime_secs: u64,
    /// 统计窗口长度(秒)。
    pub window_secs: u64,
    /// 历史曲线的采样间隔(秒)。
    pub sample_interval_secs: u64,
    /// 依赖检查(与 `/readyz` 同源)。
    pub checks: Vec<DependencyCheck>,
    pub process: ProcessStatus,
    /// 正在处理的请求数。
    pub in_flight: i64,
    pub pools: Vec<PoolStatus>,
    pub sse: Vec<SseStatus>,
    pub traffic: TrafficSummary,
    /// 按接口(路由模板)统计,按请求数降序。
    pub routes: Vec<RouteStats>,
    /// 按数据库操作(仓储方法)统计,按调用次数降序。
    pub db_operations: Vec<DbOperationStats>,
    pub outbox: Vec<OutboxStatus>,
    pub projectors: Vec<ProjectorStatus>,
    /// 历史曲线(每个点是一个采样间隔内的增量或当时的读数),时间升序。
    pub history: Vec<HistoryPoint>,
}

impl InstanceReport {
    /// 拉不到报告的进程:只带角色和原因。
    pub fn unreachable(role: InstanceRole, error: String) -> Self {
        Self {
            role,
            reachable: false,
            error: Some(error),
            version: String::new(),
            started_at: None,
            uptime_secs: 0,
            window_secs: 0,
            sample_interval_secs: 0,
            checks: Vec::new(),
            process: ProcessStatus::default(),
            in_flight: 0,
            pools: Vec::new(),
            sse: Vec::new(),
            traffic: TrafficSummary::default(),
            routes: Vec::new(),
            db_operations: Vec::new(),
            outbox: Vec::new(),
            projectors: Vec::new(),
            history: Vec::new(),
        }
    }
}

/// 单项依赖检查。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct DependencyCheck {
    /// `db_app` / `db_idm` / `db_content` / `db_search` / `nats`。
    pub name: String,
    pub ok: bool,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 进程资源(取不到的平台上为空)。
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ProcessStatus {
    /// 常驻内存(字节)。
    pub rss_bytes: Option<u64>,
    /// CPU 占用(百分比,按单核计,多核可超过 100)。最近一个采样间隔的均值。
    pub cpu_percent: Option<f64>,
    pub threads: Option<u64>,
    pub open_fds: Option<u64>,
}

/// 数据库连接池。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct PoolStatus {
    /// schema 名(app / idm / content / search)。
    pub name: String,
    pub size: u32,
    pub idle: u32,
    pub in_use: u32,
    pub max: u32,
}

/// SSE 推送流的在线连接数。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SseStatus {
    pub stream: String,
    pub connections: i64,
}

/// 窗口内的请求汇总。
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct TrafficSummary {
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

/// 单个接口的统计。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct RouteStats {
    pub method: String,
    /// 路由模板(如 `/api/v1/frontend/widgets/{id}`);没匹配上任何路由的请求记为 `unmatched`。
    pub route: String,
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// 单个数据库操作的统计(来自仓储方法上的 `pg.*` span)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct DbOperationStats {
    /// 如 `pg.widgets.list`。
    pub name: String,
    pub calls: u64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// outbox relay(把发件箱里的事件发到 JetStream)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct OutboxStatus {
    /// 来源 schema(idm / app)。
    pub source: String,
    pub published: u64,
    pub failures: u64,
    /// 最近一轮取到的条数(持续等于批大小 = 有积压)。
    pub last_batch: u64,
    /// 最近一次轮询成功的时间;长时间不动 = relay 卡住。
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_poll_at: Option<OffsetDateTime>,
}

/// projector(消费 JetStream 事件写读模型)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProjectorStatus {
    pub name: String,
    pub processed: u64,
    pub failed: u64,
    /// 最近一条消息从发布到处理完的延迟(毫秒)。
    pub last_lag_ms: Option<f64>,
    /// 还没投递给它的消息数(积压)。
    pub pending: Option<u64>,
    /// 已投递、还没确认的消息数。
    pub ack_pending: Option<u64>,
}

/// 历史曲线上的一个点。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct HistoryPoint {
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub requests: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub p95_ms: Option<f64>,
    pub in_flight: i64,
    pub db_calls: u64,
    pub db_p95_ms: Option<f64>,
    pub pool_in_use: u64,
    pub pool_max: u64,
    pub sse_connections: i64,
    pub outbox_published: u64,
    pub projector_processed: u64,
    pub projector_pending: u64,
    pub rss_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
}

// ── 历史 ──

/// 历史时间范围。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum HistoryRange {
    #[default]
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
    #[serde(rename = "90d")]
    Quarter,
    #[serde(rename = "1y")]
    Year,
}

impl HistoryRange {
    pub fn duration(self) -> Duration {
        match self {
            HistoryRange::Day => Duration::hours(24),
            HistoryRange::Week => Duration::days(7),
            HistoryRange::Month => Duration::days(30),
            HistoryRange::Quarter => Duration::days(90),
            HistoryRange::Year => Duration::days(365),
        }
    }

    /// 曲线上一个点代表多长时间(每个范围约 300~370 个点)。
    pub fn step(self) -> Duration {
        match self {
            HistoryRange::Day => Duration::minutes(5),
            HistoryRange::Week => Duration::minutes(30),
            HistoryRange::Month => Duration::hours(2),
            HistoryRange::Quarter => Duration::hours(6),
            HistoryRange::Year => Duration::days(1),
        }
    }

    /// 从哪一层读:7 天以内读分钟级(保留 15 天),更长读小时级。
    pub fn tier(self) -> Tier {
        match self {
            HistoryRange::Day | HistoryRange::Week => Tier::Minute,
            _ => Tier::Hour,
        }
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// 时间范围,默认 24h。
    #[param(value_type = Option<HistoryRange>)]
    pub range: HistoryRange,
}

/// 历史报告:按进程分组的曲线 + 整个范围的合计 + 接口 / 数据库明细。
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HistoryReport {
    pub range: HistoryRange,
    #[serde(with = "time::serde::rfc3339")]
    pub from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub to: OffsetDateTime,
    /// 曲线上一个点代表的秒数。
    pub step_secs: u64,
    /// 数据是否持久化。`false` = 没配 ops 数据库,只有进程内存里最近一段(重启清空)。
    pub persistent: bool,
    /// 接口 / 数据库明细的起点:明细只留 30 天,范围更长时只覆盖最近 30 天。
    #[serde(with = "time::serde::rfc3339")]
    pub details_from: OffsetDateTime,
    pub instances: Vec<HistoryInstance>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HistoryInstance {
    pub role: InstanceRole,
    pub traffic: TrafficSummary,
    /// 时间升序;没有数据的时间段(进程没跑)不出点。
    pub points: Vec<HistoryPoint>,
    pub routes: Vec<RouteStats>,
    pub db_operations: Vec<DbOperationStats>,
}

// ── 日志 ──

/// 日志查询条件(都可选,结果按时间倒序)。
#[derive(Debug, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct LogsQuery {
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    /// 最低级别:`WARN` = WARN + ERROR,`ERROR` = 只看 ERROR。不给 = 全部。
    #[param(value_type = Option<Severity>)]
    pub level: Option<Severity>,
    #[param(value_type = Option<InstanceRole>)]
    pub instance: Option<InstanceRole>,
    /// 服务:app(业务)/ idm(认证)。单进程开发时按接口前缀 / 代码模块推断。
    #[param(value_type = Option<Service>)]
    pub service: Option<Service>,
    /// 消息 / 模块 / 接口的子串,不区分大小写。
    pub q: Option<String>,
    /// 精确匹配请求 id(响应头 `x-request-id`)。
    pub request_id: Option<String>,
    /// 页码,从 1 开始。
    pub page: u64,
    /// 每页条数,1~200,默认 50。
    pub size: u64,
}

impl Default for LogsQuery {
    fn default() -> Self {
        Self {
            from: None,
            to: None,
            level: None,
            instance: None,
            service: None,
            q: None,
            request_id: None,
            page: 1,
            size: 50,
        }
    }
}

/// 一条日志。
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct LogRecordView {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub instance: InstanceRole,
    /// 归属服务(app / idm)。
    pub service: Service,
    pub severity: Severity,
    /// 产生日志的模块(`http.access` = 失败 / 慢请求记录)。
    pub target: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// 其余结构化字段(敏感字段已脱敏)。
    #[schema(value_type = Object)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

//! auth_audit 的 **HTTP 线格式**:列表行 / 统计响应 / 查询参数,与领域模型互转;以及审计闭集
//! (`AuthEventType` / `AuthChannel` / `AuthOutcome` / `FailureReason`)的 OpenAPI schema。
//! 类型名即 schema 名(对前端的契约)。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::features::auth_audit::model::{
    self, AuthChannel, AuthEventType, AuthOutcome, FailureReason,
};

crate::closed_enum_to_schema!(
    AuthEventType,
    AuthEventType::ALL,
    "认证审计事件类型闭集。存储值不变(仍是 `emit` 写的 `\"auth.xxx\"` 字符串,免数据迁移),\n这里只是给它上一层强类型:emit 侧编译期防手滑字面量,读侧 utoipa 生成前端可辨识联合类型。\n故意不设 `#[serde(other)]` 兜底 —— 该列只由本仓 `auth::emit` 写入(闭集只增不改),\n出现未知值本身就是数据异常,该让它在解码处炸出来而不是悄悄吞掉。"
);
crate::closed_enum_to_schema!(
    AuthChannel,
    AuthChannel::ALL,
    "认证渠道闭集(`public` 前台 / `admin` 后台)。同 `AuthEventType` 头注:存储值不变,只加读侧\n强类型;无 `#[serde(other)]` 兜底,原因同上(唯一写者是本仓 emit)。"
);
crate::closed_enum_to_schema!(
    AuthOutcome,
    AuthOutcome::ALL,
    "认证结果闭集(`success` / `failure`)。同上头注。"
);
crate::closed_enum_to_schema!(
    FailureReason,
    FailureReason::ALL,
    "失败原因闭集。同上头注;`account_locked`/`rate_limited` 目前 emit 侧未产出(预留取值,\n闭集只增不改 —— 出现才炸,不提前拒绝合法但暂未使用的取值)。"
);

/// 读模型行(admin 端点返回 / SSE 帧 data)。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthEventRow {
    pub id: Uuid,
    pub event_type: AuthEventType,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub channel: AuthChannel,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub actor: Option<String>,
    pub outcome: AuthOutcome,
    pub failure_reason: Option<FailureReason>,
    pub ip: Option<String>, // inet → 文本回传
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

impl From<model::AuthEventRow> for AuthEventRow {
    fn from(r: model::AuthEventRow) -> Self {
        Self {
            id: r.id,
            event_type: r.event_type,
            occurred_at: r.occurred_at,
            channel: r.channel,
            user_id: r.user_id,
            identifier_attempted: r.identifier_attempted,
            session_id: r.session_id,
            actor: r.actor,
            outcome: r.outcome,
            failure_reason: r.failure_reason,
            ip: r.ip,
            user_agent: r.user_agent,
            country: r.country,
            city: r.city,
            os: r.os,
            browser: r.browser,
        }
    }
}

/// 列表过滤 query DTO(admin 端点入参;转成领域 `AuthEventQuery`)。空 = 不限。
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct AuthEventFilter {
    /// 事件类型(闭集;未知值在 Query 提取器被拒 → 400 bad_request,而非静默空结果)。
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    /// 联合模糊搜:`actor`(展示用户名/标识)+ `identifier_attempted`(失败场景提交的用户名/邮箱)
    /// + `ip`(文本),大小写不敏感子串。**下推到库**(全历史检索),取代前端内存过滤。空 = 不搜。
    pub q: Option<String>,
    /// 精确 IP 过滤(`ip = X`)。与 `q` 的子串搜互补;两者都给则 AND 组合。强类型 `IpAddr`:
    /// 非法值在 Query 提取器被拒 → 400(而非把裸串 cast 成 `::inet` 让 PG 抛 500;亦对齐内存侧规范化比较)。
    /// OpenAPI 里仍呈现为 string(utoipa 无 `IpAddr` schema)。
    #[param(value_type = String)]
    pub ip: Option<std::net::IpAddr>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

impl From<AuthEventFilter> for model::AuthEventQuery {
    /// `user_id` 由用例决定(单用户历史 `list_for_user` 覆盖,全局流为 None)。
    fn from(f: AuthEventFilter) -> Self {
        let user_id = None;
        let s = f;
        Self {
            user_id,
            event_type: s.event_type,
            outcome: s.outcome,
            q: s.q,
            ip: s.ip,
            from: s.from,
            to: s.to,
        }
    }
}

/// 统计区间 query DTO。空 = 默认最近 24h(缺省/clamp 在 service)。
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

/// 仪表盘统计(admin `/auth-events/stats`)。时间序列 + 各维度 group-by 计数。

#[derive(Debug, Serialize, ToSchema)]
pub struct StatBucket {
    #[serde(with = "time::serde::rfc3339")]
    pub t: OffsetDateTime,
    pub success: i64,
    pub failure: i64,
}

/// `types` group-by 计数的强类型版本。
#[derive(Debug, Serialize, ToSchema)]
pub struct TypeCount {
    pub key: AuthEventType,
    pub count: i64,
}

/// `reasons` group-by 计数的强类型版本(镜像 `TypeCount`)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ReasonCount {
    pub key: FailureReason,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IpStat {
    pub ip: String,
    pub failures: i64,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthKpi {
    pub total_events: i64,
    pub failed_count: i64,
    pub unique_ips: i64,
    pub success_rate: f64,
    /// (当前 - 上个等长窗口) / 上个等长窗口;上个窗口为 0 时记 0.0(无基数,不作 +∞/NaN)。
    pub total_delta: f64,
    pub failed_delta: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthStats {
    pub activity: Vec<StatBucket>,
    pub reasons: Vec<ReasonCount>,
    pub types: Vec<TypeCount>,
    pub top_ips: Vec<IpStat>,
    pub kpi: AuthKpi,
}

impl From<model::AuthStats> for AuthStats {
    fn from(s: model::AuthStats) -> Self {
        Self {
            activity: s
                .activity
                .into_iter()
                .map(|b| StatBucket {
                    t: b.t,
                    success: b.success,
                    failure: b.failure,
                })
                .collect(),
            reasons: s
                .reasons
                .into_iter()
                .map(|r| ReasonCount {
                    key: r.key,
                    count: r.count,
                })
                .collect(),
            types: s
                .types
                .into_iter()
                .map(|t| TypeCount {
                    key: t.key,
                    count: t.count,
                })
                .collect(),
            top_ips: s
                .top_ips
                .into_iter()
                .map(|i| IpStat {
                    ip: i.ip,
                    failures: i.failures,
                    total: i.total,
                })
                .collect(),
            kpi: AuthKpi {
                total_events: s.kpi.total_events,
                failed_count: s.kpi.failed_count,
                unique_ips: s.kpi.unique_ips,
                success_rate: s.kpi.success_rate,
                total_delta: s.kpi.total_delta,
                failed_delta: s.kpi.failed_delta,
            },
        }
    }
}

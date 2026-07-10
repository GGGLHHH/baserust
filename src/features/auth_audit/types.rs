use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// 认证审计事件类型闭集。存储值不变(仍是 `emit` 写的 `"auth.xxx"` 字符串,免数据迁移),
/// 这里只是给它上一层强类型:emit 侧编译期防手滑字面量,读侧 utoipa 生成前端可辨识联合类型。
/// 故意不设 `#[serde(other)]` 兜底 —— 该列只由本仓 `auth::emit` 写入(闭集只增不改),
/// 出现未知值本身就是数据异常,该让它在解码处炸出来而不是悄悄吞掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AuthEventType {
    #[serde(rename = "auth.login_succeeded")]
    #[sqlx(rename = "auth.login_succeeded")]
    LoginSucceeded,
    #[serde(rename = "auth.login_failed")]
    #[sqlx(rename = "auth.login_failed")]
    LoginFailed,
    #[serde(rename = "auth.admin_access_denied")]
    #[sqlx(rename = "auth.admin_access_denied")]
    AdminAccessDenied,
    #[serde(rename = "auth.refreshed")]
    #[sqlx(rename = "auth.refreshed")]
    Refreshed,
    #[serde(rename = "auth.logged_out")]
    #[sqlx(rename = "auth.logged_out")]
    LoggedOut,
    #[serde(rename = "auth.logout_all")]
    #[sqlx(rename = "auth.logout_all")]
    LogoutAll,
    #[serde(rename = "auth.password_changed")]
    #[sqlx(rename = "auth.password_changed")]
    PasswordChanged,
    #[serde(rename = "auth.registered")]
    #[sqlx(rename = "auth.registered")]
    Registered,
    #[serde(rename = "auth.account_deleted")]
    #[sqlx(rename = "auth.account_deleted")]
    AccountDeleted,
}

impl AuthEventType {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [AuthEventType; 9] = [
        AuthEventType::LoginSucceeded,
        AuthEventType::LoginFailed,
        AuthEventType::AdminAccessDenied,
        AuthEventType::Refreshed,
        AuthEventType::LoggedOut,
        AuthEventType::LogoutAll,
        AuthEventType::PasswordChanged,
        AuthEventType::Registered,
        AuthEventType::AccountDeleted,
    ];

    /// 发射到 outbox 的线上串(`idm::OutboxRepo::emit` 只吃 `&str`)。
    pub fn as_str(self) -> &'static str {
        match self {
            AuthEventType::LoginSucceeded => "auth.login_succeeded",
            AuthEventType::LoginFailed => "auth.login_failed",
            AuthEventType::AdminAccessDenied => "auth.admin_access_denied",
            AuthEventType::Refreshed => "auth.refreshed",
            AuthEventType::LoggedOut => "auth.logged_out",
            AuthEventType::LogoutAll => "auth.logout_all",
            AuthEventType::PasswordChanged => "auth.password_changed",
            AuthEventType::Registered => "auth.registered",
            AuthEventType::AccountDeleted => "auth.account_deleted",
        }
    }
}

/// `NewAuthEvent.event_type`(写模型,恒为本仓 emit 产出的合法串)→ 枚举,给内存 repo 的
/// 读侧映射用(pg 侧走 `sqlx::Type` 的 Decode,走不到这里)。见 `sqlx(rename)` 的反向表。
impl std::str::FromStr for AuthEventType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 经 ALL × as_str 查表(镜像 RoleName::from_str):加变体只补 ALL,不再手写第三份映射。
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| format!("未知 auth event_type: {s}"))
    }
}

/// 认证渠道闭集(`public` 前台 / `admin` 后台)。同 `AuthEventType` 头注:存储值不变,只加读侧
/// 强类型;无 `#[serde(other)]` 兜底,原因同上(唯一写者是本仓 emit)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AuthChannel {
    #[serde(rename = "public")]
    #[sqlx(rename = "public")]
    Public,
    #[serde(rename = "admin")]
    #[sqlx(rename = "admin")]
    Admin,
}

impl AuthChannel {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [AuthChannel; 2] = [AuthChannel::Public, AuthChannel::Admin];

    /// wire 串(== serde/sqlx rename;`wire_matches` 测试钉死不漂移)。
    pub fn as_str(self) -> &'static str {
        match self {
            AuthChannel::Public => "public",
            AuthChannel::Admin => "admin",
        }
    }
}

/// 见 `AuthEventType` 上同名 impl 的注释:内存 repo 读侧映射用,pg 侧走 `sqlx::Type` 走不到这里。
impl std::str::FromStr for AuthChannel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| format!("未知 channel: {s}"))
    }
}

/// 认证结果闭集(`success` / `failure`)。同上头注。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AuthOutcome {
    #[serde(rename = "success")]
    #[sqlx(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    #[sqlx(rename = "failure")]
    Failure,
}

impl AuthOutcome {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [AuthOutcome; 2] = [AuthOutcome::Success, AuthOutcome::Failure];

    /// filter 下推(`apply_filters`)/内存 repo 过滤要跟 `NewAuthEvent.outcome`(仍是 `String`)比较。
    pub fn as_str(self) -> &'static str {
        match self {
            AuthOutcome::Success => "success",
            AuthOutcome::Failure => "failure",
        }
    }
}

impl std::str::FromStr for AuthOutcome {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|o| o.as_str() == s)
            .ok_or_else(|| format!("未知 outcome: {s}"))
    }
}

/// 失败原因闭集。同上头注;`account_locked`/`rate_limited` 目前 emit 侧未产出(预留取值,
/// 闭集只增不改 —— 出现才炸,不提前拒绝合法但暂未使用的取值)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum FailureReason {
    #[serde(rename = "unknown_user")]
    #[sqlx(rename = "unknown_user")]
    UnknownUser,
    #[serde(rename = "bad_password")]
    #[sqlx(rename = "bad_password")]
    BadPassword,
    #[serde(rename = "no_admin_perm")]
    #[sqlx(rename = "no_admin_perm")]
    NoAdminPerm,
    #[serde(rename = "account_locked")]
    #[sqlx(rename = "account_locked")]
    AccountLocked,
    #[serde(rename = "rate_limited")]
    #[sqlx(rename = "rate_limited")]
    RateLimited,
}

/// idm 凭据失败原因 → 审计闭集(login/admin_login 两处发事件共用,消除逐字复制的 match)。
impl From<&idm::CredentialFailure> for FailureReason {
    fn from(f: &idm::CredentialFailure) -> Self {
        match f {
            idm::CredentialFailure::UnknownUser => Self::UnknownUser,
            idm::CredentialFailure::BadPassword => Self::BadPassword,
        }
    }
}

impl FailureReason {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [FailureReason; 5] = [
        FailureReason::UnknownUser,
        FailureReason::BadPassword,
        FailureReason::NoAdminPerm,
        FailureReason::AccountLocked,
        FailureReason::RateLimited,
    ];

    /// wire 串(== serde/sqlx rename;`wire_matches` 测试钉死不漂移)。
    pub fn as_str(self) -> &'static str {
        match self {
            FailureReason::UnknownUser => "unknown_user",
            FailureReason::BadPassword => "bad_password",
            FailureReason::NoAdminPerm => "no_admin_perm",
            FailureReason::AccountLocked => "account_locked",
            FailureReason::RateLimited => "rate_limited",
        }
    }
}

impl std::str::FromStr for FailureReason {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("未知 failure_reason: {s}"))
    }
}

/// 写模型:projector 从 envelope 组装后交 repo 落库(Phase 1 富化列不在此,DB 默认 null)。
#[derive(Debug, Clone)]
pub struct NewAuthEvent {
    pub id: Uuid,
    pub event_type: String,
    pub occurred_at: OffsetDateTime,
    pub channel: String,
    pub auth_method: String,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub actor: Option<String>,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub event_seq: i64,
}

/// 读模型行(admin 端点返回)。
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
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

/// 列表过滤 query DTO(admin 端点入参;`into_query` 组装成域内 `AuthEventQuery`)。空 = 不限。
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct AuthEventFilter {
    /// 事件类型(闭集;未知值在 Query 提取器被拒 → 400 bad_request,而非静默空结果)。
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    pub ip: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

impl AuthEventFilter {
    /// 组装域内查询(`user_id` 由端点决定:单用户历史传 `Some`,全局流传 `None`)。
    pub fn into_query(self, user_id: Option<Uuid>) -> AuthEventQuery {
        AuthEventQuery {
            user_id,
            event_type: self.event_type,
            outcome: self.outcome,
            ip: self.ip,
            from: self.from,
            to: self.to,
        }
    }
}

/// 统计区间 query DTO。空 = 默认最近 24h(缺省/clamp 在 service)。
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

/// 列表过滤(域内)。空 = 不限。
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<Uuid>,
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    pub ip: Option<String>,
    pub from: Option<OffsetDateTime>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// serde rename ↔ as_str ↔ FromStr 三方一致(加变体漏补 ALL/rename → 此测试挂,
    /// 防 emit 正常序列化、to_row 却 Poison 静默丢审计事件的漂移)。
    #[test]
    fn closed_enum_wire_round_trips() {
        for t in AuthEventType::ALL {
            assert_eq!(serde_json::to_value(t).unwrap().as_str(), Some(t.as_str()));
            assert_eq!(t.as_str().parse::<AuthEventType>().unwrap(), t);
        }
        for c in AuthChannel::ALL {
            assert_eq!(serde_json::to_value(c).unwrap().as_str(), Some(c.as_str()));
            assert_eq!(c.as_str().parse::<AuthChannel>().unwrap(), c);
        }
        for o in AuthOutcome::ALL {
            assert_eq!(serde_json::to_value(o).unwrap().as_str(), Some(o.as_str()));
            assert_eq!(o.as_str().parse::<AuthOutcome>().unwrap(), o);
        }
        for r in FailureReason::ALL {
            assert_eq!(serde_json::to_value(r).unwrap().as_str(), Some(r.as_str()));
            assert_eq!(r.as_str().parse::<FailureReason>().unwrap(), r);
        }
    }
}

//! auth_audit(认证审计)的**领域模型**:事件闭集、写模型 / 读模型、查询条件、仪表盘统计。
//! 纯 Rust:闭集只派生 serde(线上串 = 存储串 = emit 串),不知道 OpenAPI 与数据库 ——
//! schema 在 `adapters::http::dto`,数据库解码在 `adapters::postgres`。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// 认证审计事件类型闭集。存储值不变(仍是 `emit` 写的 `"auth.xxx"` 字符串,免数据迁移),
/// 这里只是给它上一层强类型:emit 侧编译期防手滑字面量,读侧(HTTP 适配)生成前端可辨识联合类型。
/// 故意不设 `#[serde(other)]` 兜底 —— 该列只由本仓 `auth::emit` 写入(闭集只增不改),
/// 出现未知值本身就是数据异常,该让它在解码处炸出来而不是悄悄吞掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthEventType {
    #[serde(rename = "auth.login_succeeded")]
    LoginSucceeded,
    #[serde(rename = "auth.login_failed")]
    LoginFailed,
    #[serde(rename = "auth.admin_access_denied")]
    AdminAccessDenied,
    #[serde(rename = "auth.refreshed")]
    Refreshed,
    #[serde(rename = "auth.logged_out")]
    LoggedOut,
    #[serde(rename = "auth.logout_all")]
    LogoutAll,
    #[serde(rename = "auth.password_changed")]
    PasswordChanged,
    #[serde(rename = "auth.registered")]
    Registered,
    #[serde(rename = "auth.account_deleted")]
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

/// 线上串 → 枚举(经 `ALL` × `as_str` 查表)。读侧映射(`to_row`)与 PG 适配器解码共用。
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthChannel {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "admin")]
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

/// 见 `AuthEventType` 上同名 impl 的注释。
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthOutcome {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureReason {
    #[serde(rename = "unknown_user")]
    UnknownUser,
    #[serde(rename = "bad_password")]
    BadPassword,
    #[serde(rename = "no_admin_perm")]
    NoAdminPerm,
    #[serde(rename = "account_locked")]
    AccountLocked,
    #[serde(rename = "rate_limited")]
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

/// 读模型行(admin 列表 / SSE 推送)。富化列(country/city/os/browser)Phase 1 恒为 None。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEventRow {
    pub id: Uuid,
    pub event_type: AuthEventType,
    pub occurred_at: OffsetDateTime,
    pub channel: AuthChannel,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub actor: Option<String>,
    pub outcome: AuthOutcome,
    pub failure_reason: Option<FailureReason>,
    /// inet → 文本。
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// `NewAuthEvent`(写模型,String)→ 读模型强类型行。**唯一的闭集解析权威**:
/// projector 在信任边界用它(Err → Poison);内存 repo 读侧 expect(单写者不变量,
/// 数据异常就炸,见上面闭集的头注)。
pub fn to_row(e: &NewAuthEvent) -> Result<AuthEventRow, String> {
    Ok(AuthEventRow {
        id: e.id,
        event_type: e.event_type.parse()?,
        occurred_at: e.occurred_at,
        channel: e.channel.parse()?,
        user_id: e.user_id,
        identifier_attempted: e.identifier_attempted.clone(),
        session_id: e.session_id,
        actor: e.actor.clone(),
        outcome: e.outcome.parse()?,
        failure_reason: e.failure_reason.as_deref().map(str::parse).transpose()?,
        ip: e.ip.map(|i| i.to_string()),
        user_agent: e.user_agent.clone(),
        country: None,
        city: None,
        os: None,
        browser: None,
    })
}

/// 列表过滤(域内)。空 = 不限。
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<Uuid>,
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    /// 联合模糊搜(actor + identifier_attempted + ip 文本,大小写不敏感子串)。
    pub q: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
}

/// 仪表盘统计:`[from, to)` 区间的时间序列 + 各维度 group-by 计数 + KPI。
#[derive(Debug, Clone, PartialEq)]
pub struct AuthStats {
    pub activity: Vec<StatBucket>,
    pub reasons: Vec<ReasonCount>,
    pub types: Vec<TypeCount>,
    pub top_ips: Vec<IpStat>,
    pub kpi: AuthKpi,
}

/// 一个小时桶:成功 / 失败次数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatBucket {
    pub t: OffsetDateTime,
    pub success: i64,
    pub failure: i64,
}

/// 按事件类型计数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeCount {
    pub key: AuthEventType,
    pub count: i64,
}

/// 按失败原因计数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonCount {
    pub key: FailureReason,
    pub count: i64,
}

/// 单个 IP 的失败 / 总次数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpStat {
    pub ip: String,
    pub failures: i64,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthKpi {
    pub total_events: i64,
    pub failed_count: i64,
    pub unique_ips: i64,
    pub success_rate: f64,
    /// (当前 - 上个等长窗口) / 上个等长窗口;上个窗口为 0 时记 0.0(无基数,不作 +∞/NaN)。
    pub total_delta: f64,
    pub failed_delta: f64,
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

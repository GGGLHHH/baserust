//! auth_audit(认证审计)的**领域模型**:事件闭集、写模型 / 读模型、查询条件、仪表盘统计。
//! 纯 Rust:闭集只派生 serde(线上串 = 存储串 = emit 串),不知道 OpenAPI 与数据库 ——
//! schema 在 `adapters::http::dto`,数据库解码在 `adapters::postgres`。

use std::net::IpAddr;
use std::str::FromStr;

use idm::CredentialFailure;
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
    /// 切换当前租户(多租户):旧会话吊销、换发带新租户的会话。`tenant_id` 记切换**后**的租户。
    #[serde(rename = "auth.tenant_switched")]
    TenantSwitched,
}

impl AuthEventType {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [AuthEventType; 10] = [
        AuthEventType::LoginSucceeded,
        AuthEventType::LoginFailed,
        AuthEventType::AdminAccessDenied,
        AuthEventType::Refreshed,
        AuthEventType::LoggedOut,
        AuthEventType::LogoutAll,
        AuthEventType::PasswordChanged,
        AuthEventType::Registered,
        AuthEventType::AccountDeleted,
        AuthEventType::TenantSwitched,
    ];

    /// 发射到 outbox 的线上串(`idm::OutboxRepo::emit` 只吃 `&str`)。
    #[must_use]
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
            AuthEventType::TenantSwitched => "auth.tenant_switched",
        }
    }
}

/// 线上串 → 枚举(经 `ALL` × `as_str` 查表)。读侧映射(`to_row`)与 PG 适配器解码共用。
impl FromStr for AuthEventType {
    type Err = String;

    fn from_str(wire: &str) -> Result<Self, Self::Err> {
        // 经 ALL × as_str 查表(镜像 RoleName::from_str):加变体只补 ALL,不再手写第三份映射。
        Self::ALL
            .into_iter()
            .find(|event_type| event_type.as_str() == wire)
            .ok_or_else(|| format!("未知 auth event_type: {wire}"))
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
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthChannel::Public => "public",
            AuthChannel::Admin => "admin",
        }
    }
}

/// 见 `AuthEventType` 上同名 impl 的注释。
impl FromStr for AuthChannel {
    type Err = String;

    fn from_str(wire: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|channel| channel.as_str() == wire)
            .ok_or_else(|| format!("未知 channel: {wire}"))
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
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthOutcome::Success => "success",
            AuthOutcome::Failure => "failure",
        }
    }
}

impl FromStr for AuthOutcome {
    type Err = String;

    fn from_str(wire: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == wire)
            .ok_or_else(|| format!("未知 outcome: {wire}"))
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
impl From<&CredentialFailure> for FailureReason {
    fn from(failure: &CredentialFailure) -> Self {
        match failure {
            CredentialFailure::UnknownUser => Self::UnknownUser,
            CredentialFailure::BadPassword => Self::BadPassword,
            // CredentialFailure 是 #[non_exhaustive]:已知变体都列在上面,通配只兜 idm 以后新加的原因(指南「Don't
            // omit patterns on non_exhaustive enums when matching」)。审计闭集没有「其他」,未知原因仍归到最泛化的
            // 「凭据不对」—— 审计事件照常落库、不改 OpenAPI 的闭集;但不能静默:记一条 WARN(经监控采集层进
            // ops.log_record),提醒升级 idm 后给闭集补上对应取值。核心 crate 本来就依赖 tracing,不新增依赖。
            unknown => {
                tracing::warn!(
                    failure = ?unknown,
                    "idm 新增了未映射的 CredentialFailure 变体,审计暂记为 bad_password;请给 FailureReason 补取值"
                );
                Self::BadPassword
            }
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
    #[must_use]
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

impl FromStr for FailureReason {
    type Err = String;

    fn from_str(wire: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == wire)
            .ok_or_else(|| format!("未知 failure_reason: {wire}"))
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
    pub ip: Option<IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    /// 事件所在的租户(多租户,spec §4.4):登录进某租户、切换、刷新该租户的会话等;登录失败、
    /// 平台上下文的事件没有租户 → `None`。
    pub tenant_id: Option<Uuid>,
    pub event_sequence: i64,
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
    /// 事件所在的租户;没有租户的事件(登录失败等)为 `None`。
    pub tenant_id: Option<Uuid>,
}

/// `NewAuthEvent`(写模型,String)→ 读模型强类型行。**唯一的闭集解析权威**:
/// projector 在信任边界用它(Err → Poison);内存 repo 读侧 expect(单写者不变量,
/// 数据异常就炸,见上面闭集的头注)。Err = 不在闭集内的那个 wire 串的说明。
impl TryFrom<&NewAuthEvent> for AuthEventRow {
    type Error = String;

    fn try_from(event: &NewAuthEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            id: event.id,
            event_type: event.event_type.parse()?,
            occurred_at: event.occurred_at,
            channel: event.channel.parse()?,
            user_id: event.user_id,
            identifier_attempted: event.identifier_attempted.clone(),
            session_id: event.session_id,
            actor: event.actor.clone(),
            outcome: event.outcome.parse()?,
            failure_reason: event
                .failure_reason
                .as_deref()
                .map(str::parse)
                .transpose()?,
            ip: event.ip.map(|ip| ip.to_string()),
            user_agent: event.user_agent.clone(),
            country: None,
            city: None,
            os: None,
            browser: None,
            tenant_id: event.tenant_id,
        })
    }
}

/// 同 `AuthEventRow::try_from`(见上);保留这个函数名给 projector / 测试的既有调用点。
pub fn to_row(event: &NewAuthEvent) -> Result<AuthEventRow, String> {
    AuthEventRow::try_from(event)
}

/// 列表过滤(域内)。空 = 不限。
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<Uuid>,
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    /// 联合模糊搜(actor + identifier_attempted + ip 文本,大小写不敏感子串)。
    pub query: Option<String>,
    pub ip: Option<IpAddr>,
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
    pub bucket_start: OffsetDateTime,
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

/// 仪表盘 KPI:区间内总数 / 失败数 / 去重 IP 数 / 成功率,以及与上个等长窗口的环比。
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
        for event_type in AuthEventType::ALL {
            assert_eq!(
                serde_json::to_value(event_type).unwrap().as_str(),
                Some(event_type.as_str())
            );
            assert_eq!(
                event_type.as_str().parse::<AuthEventType>().unwrap(),
                event_type
            );
        }
        for channel in AuthChannel::ALL {
            assert_eq!(
                serde_json::to_value(channel).unwrap().as_str(),
                Some(channel.as_str())
            );
            assert_eq!(channel.as_str().parse::<AuthChannel>().unwrap(), channel);
        }
        for outcome in AuthOutcome::ALL {
            assert_eq!(
                serde_json::to_value(outcome).unwrap().as_str(),
                Some(outcome.as_str())
            );
            assert_eq!(outcome.as_str().parse::<AuthOutcome>().unwrap(), outcome);
        }
        for reason in FailureReason::ALL {
            assert_eq!(
                serde_json::to_value(reason).unwrap().as_str(),
                Some(reason.as_str())
            );
            assert_eq!(reason.as_str().parse::<FailureReason>().unwrap(), reason);
        }
    }

    /// 已知的 idm 凭据失败原因逐个映射到同名审计取值(通配分支只兜 idm 以后新加的变体,
    /// 这里构造不出来;它的 WARN 由代码评审保证)。
    #[test]
    fn credential_failure_maps_known_variants() {
        assert_eq!(
            FailureReason::from(&CredentialFailure::UnknownUser),
            FailureReason::UnknownUser
        );
        assert_eq!(
            FailureReason::from(&CredentialFailure::BadPassword),
            FailureReason::BadPassword
        );
    }
}

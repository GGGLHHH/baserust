//! 前端错误上报:浏览器里的未捕获异常、没人处理的 Promise 拒绝、页面渲染出错,经
//! `POST /api/v1/public/client-errors` 进 ops 日志库(service = `web`),后台「系统监控 → 日志」
//! 按「前端」筛选查看。
//!
//! 免登录(登录页自己也可能出错),所以按**匿名可达的写入口**设防:
//! - 一次最多 [`MAX_BATCH`] 条、请求体 [`MAX_BODY_BYTES`] 封顶,各字段按字符截断;
//! - 进程内限流:每个 IP(IPv6 按 /64 网段)每分钟 [`PER_IP_PER_MINUTE`] 条、全站每分钟
//!   [`GLOBAL_PER_MINUTE`] 条。超出的丢弃,照样回 204 —— 别让前端以为失败而重发;丢了多少记进
//!   `/metrics`,每分钟第一次丢弃时打一条 WARN(日志页能看到「有错误没收进来」);
//! - 页面地址、脚本地址、调用栈里的 URL 去掉 query / hash(里面可能带 token),保留行号列号;
//! - 不信客户端时间,一律用收到的时间。
//!
//! 直接写日志库、不走采集队列:量已被限流封顶,而且写完就能在日志页查到。

use std::collections::HashMap;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;
use crate::infra::client_context::ClientContext;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::Json;
use crate::infra::monitor::lock_or_reset;
use crate::infra::monitor::logs::{self, truncate};
use crate::infra::monitor::store::{LogEntry, Service, Severity};
use crate::infra::telemetry;
use crate::kernel::app_error::AppError;

/// 一次最多上报几条。
pub const MAX_BATCH: usize = 10;
/// 请求体上限(10 条带完整调用栈也远用不完)。
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_CHARS: usize = 1_000;
const MAX_STACK_CHARS: usize = 4_000;
const MAX_SHORT_CHARS: usize = 300;
/// 每个 IP 每分钟最多收几条。
pub const PER_IP_PER_MINUTE: u32 = 30;
/// 全站每分钟最多收几条(防很多 IP 一起刷爆日志库)。
pub const GLOBAL_PER_MINUTE: u32 = 600;
const WINDOW: Duration = Duration::from_secs(60);

/// 错误来源。
#[derive(Clone, Copy, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientErrorKind {
    /// 未捕获的异常(`window.onerror`)。
    Error,
    /// 没人处理的 Promise 拒绝(`unhandledrejection`)。
    UnhandledRejection,
    /// 页面渲染出错(路由的错误边界接住的)。
    Render,
}

impl ClientErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ClientErrorKind::Error => "error",
            ClientErrorKind::UnhandledRejection => "unhandled_rejection",
            ClientErrorKind::Render => "render",
        }
    }
}

/// 一条前端错误。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientErrorReport {
    pub kind: ClientErrorKind,
    /// 错误消息。
    pub message: String,
    /// 调用栈。
    pub stack: Option<String>,
    /// 出错时的页面路径(`location.pathname`;带了 query / hash 也会被去掉)。
    pub page: Option<String>,
    /// 出错的脚本位置(`文件:行:列`)。
    pub source: Option<String>,
    /// 前端版本(构建号)。
    pub release: Option<String>,
}

/// 一批前端错误(1~10 条)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientErrorBatch {
    pub errors: Vec<ClientErrorReport>,
}

/// public 组。只在挂了 app 的进程上(App / Both)。
pub fn public_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(report_client_errors))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// 前端错误上报(免登录)。进后台「系统监控 → 日志」,服务为「前端」。超出限流的部分静默丢弃,同样回 204。
#[utoipa::path(
    post,
    path = "/client-errors",
    tag = "monitoring",
    request_body = ClientErrorBatch,
    responses(
        (status = 204, description = "已收下(超出限流的部分静默丢弃)"),
        (status = 400, description = "JSON 格式不对(如 kind 不认识),或请求体超过 64 KB", body = ErrorBody),
        (status = 422, description = "条数不在 1~10 之间", body = ErrorBody)
    )
)]
pub async fn report_client_errors(
    State(state): State<AppState>,
    client: ClientContext,
    Json(batch): Json<ClientErrorBatch>,
) -> Result<StatusCode, ApiError> {
    if batch.errors.is_empty() || batch.errors.len() > MAX_BATCH {
        return Err(AppError::Validation(format!("一次上报 1~{MAX_BATCH} 条")).into());
    }
    let ip = client.ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let want = batch.errors.len();
    let Admission {
        admitted,
        first_drop,
    } = admit_now(ip, want);
    if admitted < want {
        telemetry::client_errors_dropped(want - admitted);
        if first_drop {
            tracing::warn!(
                per_ip = PER_IP_PER_MINUTE,
                global = GLOBAL_PER_MINUTE,
                "前端错误上报超出限流,本分钟超出的部分丢弃(丢弃总数见 /metrics 的 {})",
                telemetry::CLIENT_ERRORS_DROPPED
            );
        }
    }
    if admitted == 0 {
        return Ok(StatusCode::NO_CONTENT);
    }
    let now = OffsetDateTime::now_utc();
    let instance = state.monitoring.role().as_str().to_owned();
    let entries: Vec<LogEntry> = batch
        .errors
        .into_iter()
        .take(admitted)
        .map(|r| to_entry(r, now, &instance, client.ip, client.user_agent.as_deref()))
        .collect();
    if let Err(error) = state.monitoring.store().insert_logs(&entries).await {
        tracing::warn!(target: logs::STORE_TARGET, error = %error, "前端错误上报:写日志库失败");
    }
    Ok(StatusCode::NO_CONTENT)
}

fn to_entry(
    report: ClientErrorReport,
    received_at: OffsetDateTime,
    instance: &str,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
) -> LogEntry {
    let mut attributes = Map::new();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            attributes.insert(key.to_owned(), Value::String(value));
        }
    };
    put("kind", Some(report.kind.as_str().to_owned()));
    put(
        "stack",
        report
            .stack
            .map(|s| truncate(&strip_url_queries(&s), MAX_STACK_CHARS)),
    );
    put(
        "source",
        report
            .source
            .map(|s| truncate(&strip_source_query(&s), MAX_SHORT_CHARS)),
    );
    put(
        "release",
        report.release.map(|s| truncate(&s, MAX_SHORT_CHARS)),
    );
    put("user_agent", user_agent.map(str::to_owned));
    put("client_ip", ip.map(|ip| ip.to_string()));
    let message = truncate(report.message.trim(), MAX_MESSAGE_CHARS);
    LogEntry {
        timestamp: received_at,
        instance: instance.to_owned(),
        service: Service::Web,
        severity: Severity::Error,
        target: "web".to_owned(),
        body: if message.is_empty() {
            "(没有错误消息)".to_owned()
        } else {
            message
        },
        request_id: None,
        method: None,
        route: report
            .page
            .map(|p| truncate(&strip_query(&p), MAX_SHORT_CHARS))
            .filter(|p| !p.is_empty()),
        status: None,
        duration_ms: None,
        attributes,
    }
}

/// 去掉 query 和 hash(里面可能有 token、邮箱之类)。
fn strip_query(text: &str) -> String {
    let end = text.find(['?', '#']).unwrap_or(text.len());
    text[..end].to_owned()
}

/// 脚本位置 `地址:行:列`:去掉地址里的 query / hash,行号列号留着。
fn strip_source_query(text: &str) -> String {
    let mut cut = text.len();
    // 从末尾拆下最多两段纯数字(行、列)
    for _ in 0..2 {
        match text[..cut].rfind(':') {
            Some(i) if i + 1 < cut && text[i + 1..cut].bytes().all(|b| b.is_ascii_digit()) => {
                cut = i
            }
            _ => break,
        }
    }
    format!("{}{}", strip_query(&text[..cut]), &text[cut..])
}

/// 调用栈里的 URL(含 `://` 的词)去掉 query / hash,到空白、`)`、`:` 为止(后面的行列号留着)。
/// 不是 URL 的词不动(消息里的问号、私有字段的 `#` 照旧)。
fn strip_url_queries(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word_start = 0;
    let mut skipping = false;
    for character in text.chars() {
        let ends_word = character.is_whitespace() || character == '(' || character == ')';
        if skipping {
            if ends_word || character == ':' {
                skipping = false;
            } else {
                continue;
            }
        }
        if (character == '?' || character == '#') && out[word_start..].contains("://") {
            skipping = true;
            continue;
        }
        out.push(character);
        if ends_word {
            word_start = out.len();
        }
    }
    out
}

/// 限流按谁算:IPv4 按地址;IPv6 按 /64 网段(一个用户通常就拿到一整段,按单个地址算等于不限)。
fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
    }
}

static LIMITER: LazyLock<Mutex<Limiter>> =
    LazyLock::new(|| Mutex::new(Limiter::new(PER_IP_PER_MINUTE, GLOBAL_PER_MINUTE)));

/// 按全局限流器给 `ip` 现在收 `want` 条。
///
/// 限流器锁中毒(只可能来自 [`Limiter::admit`] 内部 panic,纯计数,实际不会发生)时按
/// [`lock_or_reset`] 的锁中毒策略换一个新限流器:丢掉的只是本分钟的计数,最坏多收一个窗口的量。
fn admit_now(ip: IpAddr, want: usize) -> Admission {
    lock_or_reset(&LIMITER, || {
        Limiter::new(PER_IP_PER_MINUTE, GLOBAL_PER_MINUTE)
    })
    .admit(limit_key(ip), Instant::now(), want)
}

/// 一次 [`Limiter::admit`] 的结果。
#[derive(Debug, PartialEq, Eq)]
struct Admission {
    /// 这次能收几条。
    admitted: usize,
    /// 是不是本窗口第一次丢弃(只在第一次丢弃时打 WARN)。
    first_drop: bool,
}

/// 固定窗口计数(一分钟一清)。表里只记本分钟真收过的 IP,最多 `global` 个,不会无限长。
struct Limiter {
    per_ip: u32,
    global: u32,
    window_start: Option<Instant>,
    used_global: u32,
    used_by_ip: HashMap<IpAddr, u32>,
    /// 本窗口里已经丢弃过(只在第一次丢弃时打 WARN)。
    dropped: bool,
}

impl Limiter {
    fn new(per_ip: u32, global: u32) -> Self {
        Self {
            per_ip,
            global,
            window_start: None,
            used_global: 0,
            used_by_ip: HashMap::new(),
            dropped: false,
        }
    }

    /// 想收 `want` 条,返回这次能收几条、是不是本窗口第一次丢弃。
    fn admit(&mut self, ip: IpAddr, now: Instant, want: usize) -> Admission {
        if self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= WINDOW)
        {
            self.window_start = Some(now);
            self.used_global = 0;
            self.used_by_ip.clear();
            self.dropped = false;
        }
        let used_ip = self.used_by_ip.get(&ip).copied().unwrap_or(0);
        let room = (self.per_ip - used_ip).min(self.global - self.used_global);
        let granted = u32::try_from(want).unwrap_or(u32::MAX).min(room);
        if granted > 0 {
            self.used_global += granted;
            self.used_by_ip.insert(ip, used_ip + granted);
        }
        let admitted = granted as usize;
        let first_drop = admitted < want && !mem::replace(&mut self.dropped, true);
        Admission {
            admitted,
            first_drop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    fn admission(admitted: usize, first_drop: bool) -> Admission {
        Admission {
            admitted,
            first_drop,
        }
    }

    #[test]
    fn limiter_caps_per_ip_and_globally_then_resets() {
        let mut limiter = Limiter::new(3, 5);
        let start = Instant::now();
        assert_eq!(limiter.admit(ip(1), start, 2), admission(2, false));
        assert_eq!(
            limiter.admit(ip(1), start, 2),
            admission(1, true),
            "同一 IP 本分钟只剩 1 条,第一次丢弃"
        );
        assert_eq!(
            limiter.admit(ip(1), start, 1),
            admission(0, false),
            "本分钟已经报过丢弃"
        );
        assert_eq!(
            limiter.admit(ip(2), start, 3),
            admission(2, false),
            "全站只剩 2 条"
        );
        assert_eq!(limiter.admit(ip(3), start, 1), admission(0, false));
        assert_eq!(
            limiter.admit(ip(1), start + WINDOW, 3),
            admission(3, false),
            "下一分钟清零"
        );
        assert_eq!(
            limiter.admit(ip(1), start + WINDOW, 1),
            admission(0, true),
            "新窗口重新报"
        );
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let first_address: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let second_address: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limit_key(first_address), limit_key(second_address));
        assert_ne!(limit_key(first_address), limit_key(other));
        assert_eq!(limit_key(ip(1)), ip(1));
    }

    #[test]
    fn source_keeps_line_and_column() {
        assert_eq!(
            strip_source_query("https://h/app.js?v=1:10:5"),
            "https://h/app.js:10:5"
        );
        assert_eq!(strip_source_query("/a.js#x:3"), "/a.js:3");
        assert_eq!(strip_source_query("/a.js:3:4"), "/a.js:3:4");
        assert_eq!(strip_source_query("/a.js?t=1"), "/a.js");
    }

    #[test]
    fn stack_urls_lose_query_but_not_position() {
        assert_eq!(
            strip_url_queries(
                "Error: why?\n    at f (https://h/app.js?token=x:10:5)\n    at #priv (/b.js:1:2)"
            ),
            "Error: why?\n    at f (https://h/app.js:10:5)\n    at #priv (/b.js:1:2)"
        );
        assert_eq!(
            strip_url_queries("g@https://h/app.js?v=2#frag:3:4"),
            "g@https://h/app.js:3:4"
        );
    }

    #[test]
    fn strips_query_and_hash() {
        assert_eq!(strip_query("/admin/users?token=abc"), "/admin/users");
        assert_eq!(strip_query("/a#x?y"), "/a");
        assert_eq!(
            strip_query("https://h/assets/app.js?v=1"),
            "https://h/assets/app.js"
        );
        assert_eq!(strip_query("/plain"), "/plain");
    }

    #[test]
    fn entry_is_web_error_with_bounded_fields() {
        let report = ClientErrorReport {
            kind: ClientErrorKind::UnhandledRejection,
            message: "x".repeat(MAX_MESSAGE_CHARS + 50),
            stack: Some("at f (app.js:1:2)".to_owned()),
            page: Some("/admin/users?page=2".to_owned()),
            source: None,
            release: Some(String::new()),
        };
        let entry = to_entry(
            report,
            OffsetDateTime::now_utc(),
            "combined",
            Some(ip(7)),
            Some("UA"),
        );
        assert_eq!(entry.service, Service::Web);
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(entry.route.as_deref(), Some("/admin/users"));
        assert_eq!(
            entry.body.chars().count(),
            MAX_MESSAGE_CHARS + 1,
            "截断后带省略号"
        );
        assert_eq!(entry.attributes["kind"], "unhandled_rejection");
        assert_eq!(entry.attributes["client_ip"], "10.0.0.7");
        assert!(!entry.attributes.contains_key("release"), "空值不存");
        assert!(!entry.attributes.contains_key("source"));
    }
}

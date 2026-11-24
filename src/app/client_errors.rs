//! 前端错误上报:浏览器里的未捕获异常、没人处理的 Promise 拒绝、页面渲染出错,经
//! `POST /api/v1/public/client-errors` 进 ops 日志库(service = `web`),后台「系统监控 → 日志」
//! 按「前端」筛选查看。
//!
//! 免登录(登录页自己也可能出错),所以按**匿名可达的写入口**设防:
//! - 一次最多 [`MAX_BATCH`] 条、请求体 [`MAX_BODY_BYTES`] 封顶,各字段按字符截断;
//! - 进程内限流:每个 IP 每分钟 [`PER_IP_PER_MINUTE`] 条、全站每分钟 [`GLOBAL_PER_MINUTE`] 条。
//!   超出的静默丢弃,照样回 204 —— 别让前端以为失败而重发;
//! - 页面地址、脚本地址只留路径(去掉 query / hash,里面可能带 token);
//! - 不信客户端时间,一律用收到的时间。
//!
//! 直接写日志库、不走采集队列:量已被限流封顶,而且写完就能在日志页查到。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
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

use crate::app::state::AppState;
use crate::infra::client_context::ClientContext;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::Json;
use crate::infra::monitor::logs;
use crate::infra::monitor::store::{LogEntry, Service, Severity};
use crate::kernel::error::AppError;

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
        (status = 400, description = "JSON 格式不对(如 kind 不认识)", body = ErrorBody),
        (status = 413, description = "请求体超过 64 KB"),
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
    let admitted = LIMITER.lock().unwrap_or_else(|e| e.into_inner()).admit(
        ip,
        Instant::now(),
        batch.errors.len(),
    );
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
    if let Err(e) = state.monitoring.store().insert_logs(&entries).await {
        tracing::warn!(target: logs::STORE_TARGET, error = %e, "前端错误上报:写日志库失败");
    }
    Ok(StatusCode::NO_CONTENT)
}

fn to_entry(
    r: ClientErrorReport,
    ts: OffsetDateTime,
    instance: &str,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
) -> LogEntry {
    let mut attributes = Map::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            attributes.insert(k.to_owned(), Value::String(v));
        }
    };
    put("kind", Some(r.kind.as_str().to_owned()));
    put("stack", r.stack.map(|s| truncate(&s, MAX_STACK_CHARS)));
    put(
        "source",
        r.source
            .map(|s| truncate(&strip_query(&s), MAX_SHORT_CHARS)),
    );
    put("release", r.release.map(|s| truncate(&s, MAX_SHORT_CHARS)));
    put("user_agent", user_agent.map(str::to_owned));
    put("client_ip", ip.map(|ip| ip.to_string()));
    let message = truncate(r.message.trim(), MAX_MESSAGE_CHARS);
    LogEntry {
        ts,
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
        route: r
            .page
            .map(|p| truncate(&strip_query(&p), MAX_SHORT_CHARS))
            .filter(|p| !p.is_empty()),
        status: None,
        duration_ms: None,
        attributes,
    }
}

/// 去掉 query 和 hash(里面可能有 token、邮箱之类)。
fn strip_query(s: &str) -> String {
    let end = s.find(['?', '#']).unwrap_or(s.len());
    s[..end].to_owned()
}

/// 按字符截断(不能按字节切:多字节字符会 panic)。
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

static LIMITER: LazyLock<Mutex<Limiter>> =
    LazyLock::new(|| Mutex::new(Limiter::new(PER_IP_PER_MINUTE, GLOBAL_PER_MINUTE)));

/// 固定窗口计数(一分钟一清)。表里只记本分钟真收过的 IP,最多 `global` 个,不会无限长。
struct Limiter {
    per_ip: u32,
    global: u32,
    window_start: Option<Instant>,
    used_global: u32,
    used_by_ip: HashMap<IpAddr, u32>,
}

impl Limiter {
    fn new(per_ip: u32, global: u32) -> Self {
        Self {
            per_ip,
            global,
            window_start: None,
            used_global: 0,
            used_by_ip: HashMap::new(),
        }
    }

    /// 想收 `want` 条,返回这次能收几条(0 = 全部丢弃)。
    fn admit(&mut self, ip: IpAddr, now: Instant, want: usize) -> usize {
        if self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= WINDOW)
        {
            self.window_start = Some(now);
            self.used_global = 0;
            self.used_by_ip.clear();
        }
        let used_ip = self.used_by_ip.get(&ip).copied().unwrap_or(0);
        let room = (self.per_ip - used_ip).min(self.global - self.used_global);
        let n = u32::try_from(want).unwrap_or(u32::MAX).min(room);
        if n > 0 {
            self.used_global += n;
            self.used_by_ip.insert(ip, used_ip + n);
        }
        n as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn limiter_caps_per_ip_and_globally_then_resets() {
        let mut l = Limiter::new(3, 5);
        let t0 = Instant::now();
        assert_eq!(l.admit(ip(1), t0, 2), 2);
        assert_eq!(l.admit(ip(1), t0, 2), 1, "同一 IP 本分钟只剩 1 条");
        assert_eq!(l.admit(ip(1), t0, 1), 0);
        assert_eq!(l.admit(ip(2), t0, 3), 2, "全站只剩 2 条");
        assert_eq!(l.admit(ip(3), t0, 1), 0);
        assert_eq!(l.admit(ip(1), t0 + WINDOW, 3), 3, "下一分钟清零");
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
        let r = ClientErrorReport {
            kind: ClientErrorKind::UnhandledRejection,
            message: "x".repeat(MAX_MESSAGE_CHARS + 50),
            stack: Some("at f (app.js:1:2)".to_owned()),
            page: Some("/admin/users?page=2".to_owned()),
            source: None,
            release: Some(String::new()),
        };
        let e = to_entry(
            r,
            OffsetDateTime::now_utc(),
            "combined",
            Some(ip(7)),
            Some("UA"),
        );
        assert_eq!(e.service, Service::Web);
        assert_eq!(e.severity, Severity::Error);
        assert_eq!(e.route.as_deref(), Some("/admin/users"));
        assert_eq!(
            e.body.chars().count(),
            MAX_MESSAGE_CHARS + 1,
            "截断后带省略号"
        );
        assert_eq!(e.attributes["kind"], "unhandled_rejection");
        assert_eq!(e.attributes["client_ip"], "10.0.0.7");
        assert!(!e.attributes.contains_key("release"), "空值不存");
        assert!(!e.attributes.contains_key("source"));
    }
}

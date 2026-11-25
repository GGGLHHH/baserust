//! 日志采集:把 WARN 及以上的日志、失败请求(5xx)和慢请求收进 [`super::store::OpsStore`],
//! 后台「系统监控 → 日志」查看。
//!
//! - [`LogCaptureLayer`](tracing layer):收 WARN / ERROR 事件,带上所在 HTTP 请求的 request_id / 方法 / 路由;
//! - [`record_access`]:请求统计中间件对 5xx 与慢请求各记一条;
//! - 都进一个**有界队列**,由写入任务批量落库([`take_receiver`]);队列满了就丢、只计数,绝不拖慢请求;
//! - 写入前脱敏:字段名像密码 / token / cookie 的值一律替换,正文与字段值截断。

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Duration;

use serde_json::{Map, Value};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{span, Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use super::store::{classify_service, LogEntry, Severity};

/// 队列容量:写库跟不上时最多积这么多条,再多就丢。
const QUEUE_CAPACITY: usize = 10_000;
/// 慢请求阈值。
pub const SLOW_REQUEST: Duration = Duration::from_secs(1);
/// 正文最长字符数。
const MAX_BODY_CHARS: usize = 4_000;
/// 单个字段值最长字符数。
const MAX_VALUE_CHARS: usize = 1_000;
/// 写库失败时打日志用的 target:采集层跳过它,避免"写日志失败"的日志再进队列形成循环。
pub const STORE_TARGET: &str = "ops_store";

/// 本进程在日志里的实例名(app / idm / combined),启动时设一次。
static INSTANCE: OnceLock<String> = OnceLock::new();

pub fn set_instance(name: &str) {
    let _ = INSTANCE.set(name.to_owned());
}

fn instance() -> String {
    INSTANCE
        .get()
        .cloned()
        .unwrap_or_else(|| "combined".to_owned())
}

struct Sink {
    tx: mpsc::Sender<LogEntry>,
    rx: Mutex<Option<mpsc::Receiver<LogEntry>>>,
    dropped: AtomicU64,
}

static SINK: LazyLock<Sink> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    Sink {
        tx,
        rx: Mutex::new(Some(rx)),
        dropped: AtomicU64::new(0),
    }
});

/// 取走队列的接收端(写入任务启动时调一次;第二次调返回 `None`)。
pub fn take_receiver() -> Option<mpsc::Receiver<LogEntry>> {
    SINK.rx.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// 取出并清零"因队列满而丢弃"的条数(写入任务定期报告)。
pub fn take_dropped() -> u64 {
    SINK.dropped.swap(0, Ordering::Relaxed)
}

fn emit(entry: LogEntry) {
    if SINK.tx.try_send(entry).is_err() {
        SINK.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// 按字符截断(不能按字节切:多字节字符会 panic),截掉的用 `…` 标出。
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// 字段名像敏感信息 → 值不入库。
fn is_sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "cookie",
        "authorization",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|k| n.contains(k))
}

const REDACTED: &str = "[REDACTED]";

/// 收集事件字段:`message` 作正文,其余进 attributes。
#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    attrs: Map<String, Value>,
}

impl FieldCollector {
    fn put(&mut self, field: &Field, value: Value) {
        let name = field.name();
        if is_sensitive(name) {
            self.attrs
                .insert(name.to_owned(), Value::String(REDACTED.to_owned()));
        } else {
            self.attrs.insert(name.to_owned(), value);
        }
    }
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut s = String::new();
        let _ = write!(s, "{value:?}");
        if field.name() == "message" {
            self.message = Some(s);
        } else {
            self.put(field, Value::String(truncate(&s, MAX_VALUE_CHARS)));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.put(field, Value::String(truncate(value, MAX_VALUE_CHARS)));
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::from(value));
    }
}

/// HTTP 请求 span(`app::router::make_http_span` 建的 `http`)上的上下文。
#[derive(Clone, Default)]
struct HttpContext {
    request_id: Option<String>,
    method: Option<String>,
    route: Option<String>,
}

impl Visit for HttpContext {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let v = format!("{value:?}");
        self.record_str(field, &v);
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        let v = (!value.is_empty() && value != "-").then(|| value.to_owned());
        match field.name() {
            "request_id" => self.request_id = v,
            "method" => self.method = v,
            "route" => self.route = v,
            _ => {}
        }
    }
}

/// 采集 WARN / ERROR 日志的 tracing layer(装配见 `app::runtime::init_tracing`,配 [`LogCaptureLayer::wants`] 过滤)。
pub struct LogCaptureLayer;

impl LogCaptureLayer {
    /// 只放行:WARN 及以上的事件(跳过写库失败自己的日志),以及 `http` span(取请求上下文)。
    pub fn wants(meta: &tracing::Metadata<'_>) -> bool {
        if meta.is_span() {
            return meta.name() == "http";
        }
        *meta.level() <= Level::WARN && meta.target() != STORE_TARGET
    }
}

impl<S> Layer<S> for LogCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().name() != "http" {
            return;
        }
        let mut http = HttpContext::default();
        attrs.record(&mut http);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(http);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let severity = if *meta.level() == Level::ERROR {
            Severity::Error
        } else if *meta.level() == Level::WARN {
            Severity::Warn
        } else {
            return;
        };
        let mut fields = FieldCollector::default();
        event.record(&mut fields);
        let http = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<HttpContext>().cloned())
        });
        let http = http.unwrap_or_default();
        let instance = instance();
        let service = classify_service(&instance, meta.target(), http.route.as_deref());
        emit(LogEntry {
            ts: OffsetDateTime::now_utc(),
            instance,
            service,
            severity,
            target: meta.target().to_owned(),
            body: truncate(fields.message.as_deref().unwrap_or(""), MAX_BODY_CHARS),
            request_id: http.request_id,
            method: http.method,
            route: http.route,
            status: None,
            duration_ms: None,
            attributes: fields.attrs,
        });
    }
}

/// 请求统计中间件对**失败请求(5xx)与慢请求**各记一条(其余请求不进日志库)。
pub fn record_access(
    request_id: Option<String>,
    method: &str,
    route: &str,
    status: u16,
    elapsed: Duration,
) {
    let slow = elapsed >= SLOW_REQUEST;
    if status < 500 && !slow {
        return;
    }
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    let (severity, body) = if status >= 500 {
        (
            Severity::Error,
            format!("请求失败:{method} {route} 返回 {status}"),
        )
    } else {
        (
            Severity::Warn,
            format!("慢请求:{method} {route} 用时 {duration_ms:.0} ms"),
        )
    };
    let instance = instance();
    let service = classify_service(&instance, "http.access", Some(route));
    emit(LogEntry {
        ts: OffsetDateTime::now_utc(),
        instance,
        service,
        severity,
        target: "http.access".to_owned(),
        body,
        request_id,
        method: Some(method.to_owned()),
        route: Some(route.to_owned()),
        status: Some(status),
        duration_ms: Some(duration_ms),
        attributes: Map::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_records_only_failed_and_slow_requests() {
        let mut rx = take_receiver().expect("本测试是唯一的接收方");
        record_access(None, "GET", "/ok", 200, Duration::from_millis(5));
        record_access(
            Some("r1".into()),
            "GET",
            "/boom",
            503,
            Duration::from_millis(5),
        );
        record_access(None, "POST", "/slow", 200, Duration::from_millis(1500));
        let a = rx.try_recv().unwrap();
        assert_eq!(
            (a.severity, a.status, a.request_id.as_deref()),
            (Severity::Error, Some(503), Some("r1"))
        );
        let b = rx.try_recv().unwrap();
        assert_eq!(
            (b.severity, b.route.as_deref()),
            (Severity::Warn, Some("/slow"))
        );
        assert!(rx.try_recv().is_err(), "正常请求不记");
    }

    #[test]
    fn sensitive_field_names_are_detected() {
        for n in [
            "password",
            "new_password",
            "access_token",
            "Cookie",
            "authorization",
            "client_secret",
        ] {
            assert!(is_sensitive(n), "{n}");
        }
        for n in ["user_id", "route", "status", "identifier"] {
            assert!(!is_sensitive(n), "{n}");
        }
    }

    #[test]
    fn truncate_keeps_short_and_cuts_long() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("中文字符串", 2), "中文…");
    }

    #[test]
    fn collector_redacts_sensitive_values() {
        use tracing_subscriber::layer::SubscriberExt;
        type Captured = (Option<String>, Map<String, Value>);
        #[derive(Clone, Default)]
        struct Grab(std::sync::Arc<Mutex<Vec<Captured>>>);
        impl<S: Subscriber> Layer<S> for Grab {
            fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
                let mut f = FieldCollector::default();
                event.record(&mut f);
                self.0.lock().unwrap().push((f.message, f.attrs));
            }
        }
        let grab = Grab::default();
        let sub = tracing_subscriber::registry().with(grab.clone());
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(password = "hunter2", user_id = 7, "登录失败");
        });
        let got = grab.0.lock().unwrap();
        let (msg, attrs) = &got[0];
        assert_eq!(msg.as_deref(), Some("登录失败"));
        assert_eq!(attrs["password"], Value::String(REDACTED.to_owned()));
        assert_eq!(attrs["user_id"], Value::from(7));
    }
}

//! **埋点**:后台任务 / SSE / 认证事件的计数都从这里的函数打出去,一份数据写两处:
//! - 进程内监控 [`crate::infra::monitor`](后台「系统监控」页的数据源,恒开);
//! - `metrics` facade → `/metrics`(Prometheus 文本格式,`METRICS_ENABLED=true` 才有 recorder;
//!   没装 recorder 时宏是空操作,埋点处无条件调用即可)。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_nats::jetstream::consumer::pull::Config as PullConsumerConfig;
use async_nats::jetstream::consumer::Consumer;
use async_nats::jetstream::Message;
use metrics_process::Collector;
use tracing::Span;

use crate::infra::monitor::{self, ConsumerBacklog, ProjectorOutcome};

// ── 指标名(`/metrics` 里的名字;外部抓取方按名字引用,改名算破坏性变更) ──

/// 构建信息(常量 1,标签带版本)。
pub const BUILD_INFO: &str = "baserust_build_info";
/// 连接池连接数,标签 `pool`(app / idm / content / search)、`state`(idle / in_use)。
pub const DB_POOL_CONNECTIONS: &str = "baserust_db_pool_connections";
/// 连接池上限,标签 `pool`。
pub const DB_POOL_MAX: &str = "baserust_db_pool_max_connections";
/// outbox relay 成功发布的事件数,标签 `source`(idm / app)。
pub const OUTBOX_PUBLISHED: &str = "baserust_outbox_published_total";
/// outbox relay 发布失败次数(本批中止、下轮重试),标签 `source`。
pub const OUTBOX_PUBLISH_FAILURES: &str = "baserust_outbox_publish_failures_total";
/// 每轮从发件箱取到的条数(持续顶满 batch = 有积压),标签 `source`。
pub const OUTBOX_BATCH_SIZE: &str = "baserust_outbox_batch_size";
/// 最近一次 relay 轮询成功的时间戳(秒),标签 `source`。停涨 = relay 卡死。
pub const OUTBOX_LAST_POLL: &str = "baserust_outbox_last_successful_poll_timestamp_seconds";
/// projector 处理的消息数,标签 `projector`、`result`(ok / poison / transient)。
pub const PROJECTOR_MESSAGES: &str = "baserust_projector_messages_total";
/// 消息从发布到被 projector 处理的延迟(秒),标签 `projector`。
pub const PROJECTOR_LAG: &str = "baserust_projector_lag_seconds";
/// JetStream 消费者积压(未投递条数),标签 `consumer`。
pub const JETSTREAM_PENDING: &str = "baserust_jetstream_consumer_pending";
/// JetStream 消费者已投递未确认条数,标签 `consumer`。
pub const JETSTREAM_ACK_PENDING: &str = "baserust_jetstream_consumer_ack_pending";
/// 当前打开的 SSE 连接数,标签 `stream`(widgets / auth_events)。
pub const SSE_CONNECTIONS: &str = "baserust_sse_connections";
/// 认证审计事件数(登录成败 / 刷新 / 登出 / 注册…),标签 `event_type`。
pub const AUTH_EVENTS: &str = "baserust_auth_events_total";
/// 前端错误上报超出限流被丢弃的条数。
pub const CLIENT_ERRORS_DROPPED: &str = "baserust_client_errors_dropped_total";

/// 给指标写说明(`/metrics` 里的 `# HELP`)。装 recorder 后调一次。
pub fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_gauge!(BUILD_INFO, "构建信息(常量 1,标签带版本)");
    describe_gauge!(DB_POOL_CONNECTIONS, "数据库连接池连接数(idle / in_use)");
    describe_gauge!(DB_POOL_MAX, "数据库连接池上限");
    describe_counter!(OUTBOX_PUBLISHED, "outbox relay 成功发布的事件数");
    describe_counter!(OUTBOX_PUBLISH_FAILURES, "outbox relay 发布失败次数");
    describe_histogram!(OUTBOX_BATCH_SIZE, "每轮从发件箱取到的条数");
    describe_gauge!(
        OUTBOX_LAST_POLL,
        Unit::Seconds,
        "最近一次 relay 轮询成功的时间戳"
    );
    describe_counter!(PROJECTOR_MESSAGES, "projector 处理的消息数");
    describe_histogram!(
        PROJECTOR_LAG,
        Unit::Seconds,
        "消息从发布到被 projector 处理的延迟"
    );
    describe_gauge!(JETSTREAM_PENDING, "JetStream 消费者积压(未投递)");
    describe_gauge!(JETSTREAM_ACK_PENDING, "JetStream 消费者已投递未确认");
    describe_gauge!(SSE_CONNECTIONS, "当前打开的 SSE 连接数");
    describe_counter!(AUTH_EVENTS, "认证审计事件数");
    describe_counter!(CLIENT_ERRORS_DROPPED, "前端错误上报超出限流被丢弃的条数");
}

// ── 前端错误上报 ──

/// 超出限流丢弃了 `count` 条前端错误。
pub fn client_errors_dropped(count: usize) {
    metrics::counter!(CLIENT_ERRORS_DROPPED).increment(count as u64);
}

/// SSE 连接计数守卫:建流时 +1,流被丢弃(客户端断开 / 服务关停)时 -1。放进 stream 的状态里随流存活。
#[must_use = "守卫一丢弃连接数就减回去,要放进 stream 的状态里随流存活"]
pub struct SseConnectionGuard {
    stream: &'static str,
}

impl SseConnectionGuard {
    /// 给 `stream`(如 `widgets`)登记一条连接。
    pub fn new(stream: &'static str) -> Self {
        metrics::gauge!(SSE_CONNECTIONS, "stream" => stream).increment(1.0);
        monitor::global().sse_opened(stream);
        Self { stream }
    }
}

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        metrics::gauge!(SSE_CONNECTIONS, "stream" => self.stream).decrement(1.0);
        monitor::global().sse_closed(self.stream);
    }
}

/// `/metrics` 的周期性指标(进程资源 + 构建信息)。由 `app::monitoring::run_sampler` 每个采样间隔调一次。
pub struct MetricsSampler {
    process: Collector,
}

impl MetricsSampler {
    /// 写进程指标的说明并登记构建信息(`/metrics` 的 `baserust_build_info`)。
    #[must_use]
    pub fn new() -> Self {
        let process = Collector::default();
        process.describe();
        metrics::gauge!(BUILD_INFO, "version" => env!("CARGO_PKG_VERSION")).set(1.0);
        Self { process }
    }

    /// 采一次进程资源指标写进 recorder。
    pub fn collect(&self) {
        self.process.collect();
    }
}

impl Default for MetricsSampler {
    fn default() -> Self {
        Self::new()
    }
}

// ── outbox relay ──

/// relay 启动:失败计数先登记为 0(从没失败过时显示 0 而不是"无数据"),监控页上占一行。
pub fn outbox_started(source: &'static str) {
    metrics::counter!(OUTBOX_PUBLISH_FAILURES, "source" => source).absolute(0);
    monitor::global().outbox_registered(source);
}

/// 一轮轮询成功(不论取到几条)。
pub fn outbox_polled(source: &'static str, batch: usize) {
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs_f64())
        .unwrap_or_default();
    metrics::gauge!(OUTBOX_LAST_POLL, "source" => source).set(now_seconds);
    metrics::histogram!(OUTBOX_BATCH_SIZE, "source" => source).record(batch as f64);
    monitor::global().outbox_polled(source, batch);
}

/// 本轮成功发布了 `count` 条。
pub fn outbox_published(source: &'static str, count: usize) {
    metrics::counter!(OUTBOX_PUBLISHED, "source" => source).increment(count as u64);
    monitor::global().outbox_published(source, count);
}

/// 一次发布失败(本批就此中止,下一轮重试)。
pub fn outbox_publish_failed(source: &'static str) {
    metrics::counter!(OUTBOX_PUBLISH_FAILURES, "source" => source).increment(1);
    monitor::global().outbox_failed(source);
}

// ── projector ──

/// projector 处理完一条消息:计数(按结果)+ 记录从发布到处理的延迟。
pub fn record_projector_message(projector: &str, outcome: ProjectorOutcome, message: &Message) {
    metrics::counter!(PROJECTOR_MESSAGES, "projector" => projector.to_owned(), "result" => outcome.as_str())
        .increment(1);
    let lag = message.info().ok().map(|info| {
        let seconds = (time::OffsetDateTime::now_utc() - info.published).as_seconds_f64();
        Duration::from_secs_f64(seconds.max(0.0))
    });
    if let Some(lag) = lag {
        metrics::histogram!(PROJECTOR_LAG, "projector" => projector.to_owned())
            .record(lag.as_secs_f64());
    }
    monitor::global().projector_result(projector, outcome, lag);
}

/// 查一次 JetStream 消费者状态,报积压(由 projector 定时调用;查失败只跳过)。
pub async fn record_consumer_pending(consumer: &Consumer<PullConsumerConfig>, name: &str) {
    if let Ok(info) = consumer.get_info().await {
        metrics::gauge!(JETSTREAM_PENDING, "consumer" => name.to_owned())
            .set(info.num_pending as f64);
        metrics::gauge!(JETSTREAM_ACK_PENDING, "consumer" => name.to_owned())
            .set(info.num_ack_pending as f64);
        let backlog = ConsumerBacklog {
            pending: info.num_pending,
            ack_pending: info.num_ack_pending as u64,
        };
        monitor::global().projector_pending(name, backlog);
    }
}

/// projector 定时查积压的间隔。
pub const CONSUMER_INFO_INTERVAL: Duration = Duration::from_secs(15);

/// 处理一条消息的 span(其下挂 PG 调用等子 span;日志按它关联到某条消息)。
#[must_use]
pub fn projector_span(projector: &str) -> Span {
    tracing::info_span!("projector.apply", projector)
}

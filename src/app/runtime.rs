//! 进程启动样板:`run(select_mount)` —— 读 .env、load 配置、init 日志、装配 AppState、挂路由、serve(优雅退出)。
//! app bin(main.rs)与 idm bin(src/bin/idm.rs)都调它,只差挂载范围
//! (对应 Go 的 cmd/realestate 与 cmd/realestate-login:同一套 lib,两个瘦 main)。

use std::future::{Future, IntoFuture};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use axum::routing;
use axum_prometheus::{EndpointLabel, PrometheusMetricLayerBuilder};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::{signal, time};

use crate::app::{build_router, monitoring, AppState, Mount};
use crate::infra::config::Config;
use crate::infra::monitor::logs;
use crate::infra::monitor::report::InstanceRole;
use crate::infra::telemetry;

/// 启动一个进程:读 .env → 配置 → 日志 → 装配 → 按 `select_mount(&config)` 挂路由 → serve(优雅退出)。
/// mount 以回调传入:挂载范围可依赖配置(app bin 看 `idm_embedded`),而 config 由本函数统一 load。
pub async fn run(select_mount: impl FnOnce(&Config) -> Mount) -> anyhow::Result<()> {
    // 只加载项目根目录的 .env(不向上递归;缺文件不报错)
    let _ = dotenvy::from_path(".env");
    // config 先于日志:环境变量(含 RUST_LOG/LOG_FILE)全收口在 Config。
    // load 失败时 tracing 尚未 init —— anyhow 错误由 main 落 stderr,不丢。
    let config = Config::try_new().context("加载配置失败")?;
    let mount = select_mount(&config);
    init_tracing(&config)?;
    // 先定进程身份再装配:装配期间(连库、seed…)打出的警告也要标对是 app 还是 idm。
    logs::set_instance(InstanceRole::from(mount).as_str());

    let assembled = AppState::try_new(&config, mount).await?;
    let state = assembled.state;
    let background = assembled.background_tasks;
    let probes = state.probes.clone();
    let monitoring_setup = state.monitoring.clone();
    let app = build_router(state, &config, mount);
    // metrics(opt-in,METRICS_ENABLED):Prometheus 请求计数/延迟直方图 + /metrics 端点。
    // 放这(不进 build_router):prometheus 全局 recorder 只能 install 一次,oneshot 测试多次
    // build_router 会重复 install 而 panic;放进程启动唯一路径就稳。/metrics 内部端点,不进 OpenAPI。
    let app = if config.metrics_enabled {
        // endpoint 标签用路由模板(/widgets/{id});没匹配上路由的(404 扫描等)一律记 "unmatched",
        // 否则任意乱打的 URL 都会变成一条新时间序列(标签基数爆炸)。
        let (layer, handle) = PrometheusMetricLayerBuilder::new()
            .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(|_| {
                "unmatched".to_owned()
            }))
            .with_ignore_pattern("/metrics")
            .with_default_metrics()
            .build_pair();
        telemetry::describe_metrics();
        app.route(
            "/metrics",
            routing::get(move || async move { handle.render() }),
        )
        .layer(layer)
    } else {
        app
    };

    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("无法绑定 {}", config.bind_address))?;
    // 启动时打印关键地址(0.0.0.0 用 localhost 显示,方便点击)。
    let port = config.bind_address.port();
    let host = if config.bind_address.ip().is_unspecified() {
        "localhost".to_string()
    } else {
        config.bind_address.ip().to_string()
    };
    tracing::info!("启动 mount={mount:?}  监听 http://{host}:{port}");
    tracing::info!("API 文档 (Scalar)  http://{host}:{port}/docs");
    tracing::info!("OpenAPI JSON      http://{host}:{port}/api-docs/openapi.json");

    // 后台任务:outbox relay(各 schema 轮询发 JetStream)+ search projector(消费投影读模型);
    // 都随服务优雅退出而停。
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    for relay in background.relays {
        tokio::spawn(relay.run(shutdown_receiver.clone()));
    }
    if let Some(projector) = background.projector {
        tokio::spawn(projector.run(shutdown_receiver.clone()));
    }
    if let Some(auth_projector) = background.auth_projector {
        tokio::spawn(auth_projector.run(shutdown_receiver.clone()));
    }
    if let Some(auth_retention) = background.auth_retention {
        tokio::spawn(auth_retention.run(shutdown_receiver.clone()));
    }
    // 监控采样(后台监控页的历史曲线;开了 /metrics 时顺带刷新进程资源 / 连接池指标)。
    let metrics_endpoint = if config.metrics_enabled {
        monitoring::MetricsEndpoint::Enabled
    } else {
        monitoring::MetricsEndpoint::Disabled
    };
    tokio::spawn(monitoring::run_sampler(
        probes.clone(),
        metrics_endpoint,
        shutdown_receiver.clone(),
    ));
    // 监控历史与日志:每分钟落盘、日志批量写入、保留期清理(存储是 ops 库,没配就是内存)。
    tokio::spawn(monitoring::run_minute_flusher(
        monitoring_setup.clone(),
        probes,
        shutdown_receiver.clone(),
    ));
    tokio::spawn(monitoring::run_log_writer(
        monitoring_setup.clone(),
        shutdown_receiver.clone(),
    ));
    tokio::spawn(monitoring::run_retention(
        monitoring_setup,
        shutdown_receiver.clone(),
    ));

    // into_make_service_with_connect_info:给 SmartIpKeyExtractor 的 peer-IP fallback 提供 ConnectInfo
    // (生产 nginx 设 X-Forwarded-For 时走 header;直连/无代理时回落到对端 IP)。
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_sender.send(true);
    })
    .into_future();
    serve_until_drained(server, shutdown_receiver, DRAIN_TIMEOUT).await
}

/// 收到关闭信号后,最多再等这么久就放弃剩余连接。取值 < 容器 grace period(docker/k8s 默认 30s),
/// 才轮得到我们自己善终 —— 超了就是 SIGKILL,等于没做优雅退出。
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// 等 server 跑完,但给 drain **封顶**。
///
/// `with_graceful_shutdown` 停止 accept 后要等**所有**在途连接的 future 结束,而 SSE 流
/// (`widget_events` / `auth_events`)只在总线关闭时才结束 —— 没人关它,浏览器挂着一个
/// EventSource 就能让 drain 永不完成:等满 grace period 被 SIGKILL 硬杀、在途请求一起断
/// (正是 [`shutdown_signal`] 头注要避免的失败模式,滚动发布每次都中)。keep-alive 还在持续
/// 写帧,TCP 层也不会自己超时。故到点放弃剩余连接、主动善终。
///
/// 更彻底的做法是把 shutdown 信号送进 SSE handler 逐流 select 结束(要给 `AppState` 加字段);
/// 封顶这层对**任何**长连接都成立,先要它。
async fn serve_until_drained(
    server: impl Future<Output = io::Result<()>>,
    mut shutdown_receiver: watch::Receiver<bool>,
    cap: Duration,
) -> anyhow::Result<()> {
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result.context("服务器异常退出")?,
        _ = async {
            // 从**收到信号那刻**起算,不是从进程启动起算。
            let _ = shutdown_receiver.wait_for(|stopping| *stopping).await;
            time::sleep(cap).await;
        } => {
            tracing::warn!(
                timeout_secs = cap.as_secs(),
                "优雅退出超时:仍有长连接(SSE?)未结束,放弃 drain 直接退出"
            );
        }
    }
    Ok(())
}

/// 结构化日志 + 数据库操作计时。日志格式:`LOG_FORMAT`,不设按 `config.app_environment`(**prod → JSON**,机器可解析、
/// 便于采集;非 prod → 彩色易读)。级别:`config.log_filter()`(`RUST_LOG` 优先;缺省 prod=info、dev=debug)。
///
/// 过滤是**逐层**的:日志级别只管日志输出;[`DbTimingLayer`](crate::infra::monitor::DbTimingLayer)
/// 单独只收 `pg.*` span 给后台监控页计时,[`LogCaptureLayer`](crate::infra::monitor::logs::LogCaptureLayer)
/// 单独收 WARN 及以上进监控日志 —— 改 `RUST_LOG` 不影响这两样。
///
/// `LOG_FILE` 指定的文件建不出来 → 返回错误(进程启动失败)。
fn init_tracing(config: &Config) -> anyhow::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::path::Path;
    use std::sync::Mutex;

    use crate::infra::monitor::logs::LogCaptureLayer;
    use crate::infra::monitor::DbTimingLayer;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{fmt, EnvFilter, Layer};
    let prod = config.app_environment.is_production();

    // 文件日志**仅在设置了 LOG_FILE 时启用**:
    //   本地开发在 .env 里设 LOG_FILE=logs/dev.log 即可在文件观察(每次启动 truncate);
    //   容器/生产不设 → 只输出 stdout,由 docker 收集,绝不在容器内写文件。
    let file_layer = match &config.log_file {
        Some(path) => {
            if let Some(directory) = Path::new(path).parent() {
                fs::create_dir_all(directory).ok();
            }
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .with_context(|| format!("无法创建 LOG_FILE 指定的日志文件 {path}"))?;
            Some(
                fmt::layer()
                    .with_ansi(false)
                    .with_writer(Mutex::new(file))
                    .with_filter(EnvFilter::new(config.log_filter())),
            )
        }
        None => None,
    };

    // stdout:JSON(`LOG_FORMAT=json`,prod 默认)/ 彩色易读(`pretty`,非 prod 默认)。boxed 统一两分支类型。
    let json = match config.log_format.as_deref() {
        Some("json") => true,
        Some("pretty") => false,
        _ => prod,
    };
    let stdout_layer = if json {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    }
    .with_filter(EnvFilter::new(config.log_filter()));

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdout_layer)
        .with(DbTimingLayer.with_filter(filter_fn(DbTimingLayer::wants)))
        .with(LogCaptureLayer.with_filter(filter_fn(LogCaptureLayer::wants)))
        .init();
    Ok(())
}

/// 优雅退出信号:SIGINT(Ctrl-C)与 SIGTERM(docker stop / k8s)**都**触发。
/// 漏掉 SIGTERM,容器停机时 `with_graceful_shutdown` 的 future 永不 resolve
/// → 等满 grace period 被 SIGKILL 硬杀、在途请求断流。滚动发布必断。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use std::future;

        use tokio::signal::unix::{self, SignalKind};
        match unix::signal(SignalKind::terminate()) {
            Ok(mut terminate_signal) => {
                terminate_signal.recv().await;
            }
            Err(error) => {
                // 装不上就只靠 Ctrl-C;这里不能直接返回,否则 select! 立刻完成、进程启动即退出。
                tracing::error!("安装 SIGTERM handler 失败: {error}");
                future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = {
        use std::future;
        future::pending::<()>()
    };

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("收到关闭信号,优雅退出");
}

#[cfg(test)]
mod tests {
    use std::future::{self, Pending};
    use std::io;
    use std::time::Duration;

    use tokio::sync::watch;
    use tokio::time;

    use super::serve_until_drained;

    /// **drain 不能无限等**:模拟"连接 future 永不结束"(SSE 流就是这样 —— 只在总线关闭时才完)。
    /// 收到关闭信号后必须到点放弃返回;不封顶就会一直等到容器 grace period 用尽被 SIGKILL,
    /// 优雅退出形同虚设(滚动发布每次都中)。
    #[tokio::test]
    async fn drain_is_capped_when_connections_never_finish() {
        let (sender, receiver) = watch::channel(false);
        let never_ending: Pending<io::Result<()>> = future::pending();
        sender.send(true).unwrap(); // 已收到 SIGTERM
        let result = time::timeout(
            Duration::from_secs(5),
            serve_until_drained(never_ending, receiver, Duration::from_millis(50)),
        )
        .await
        .expect("drain 必须封顶返回,而不是一直等长连接(不封顶这里会挂到 5s 超时)");
        assert!(result.is_ok(), "放弃 drain 是正常退出,不是错误");
    }

    /// server 自己先跑完(无长连接挂着)→ 照常返回,不等满封顶时长。
    #[tokio::test]
    async fn normal_shutdown_returns_immediately() {
        async fn done() -> io::Result<()> {
            Ok(())
        }
        let (_sender, receiver) = watch::channel(false);
        let result = time::timeout(
            Duration::from_millis(500),
            serve_until_drained(done(), receiver, Duration::from_secs(3600)),
        )
        .await
        .expect("正常结束不该被封顶拖住");
        assert!(result.is_ok(), "正常结束应返回 Ok");
    }
}

//! 进程启动样板:`run(select_mount)` —— 读 .env、load 配置、init 日志、装配 AppState、挂路由、serve(优雅退出)。
//! app bin(main.rs)与 idm bin(src/bin/idm.rs)都调它,只差挂载范围
//! (对应 Go 的 cmd/realestate 与 cmd/realestate-login:同一套 lib,两个瘦 main)。

use std::future::IntoFuture;

use anyhow::Context;

use crate::app::{build_router, AppState, Mount};
use crate::infra::config::Config;

/// 启动一个进程:读 .env → 配置 → 日志 → 装配 → 按 `select_mount(&config)` 挂路由 → serve(优雅退出)。
/// mount 以回调传入:挂载范围可依赖配置(app bin 看 `idm_embedded`),而 config 由本函数统一 load。
pub async fn run(select_mount: impl FnOnce(&Config) -> Mount) -> anyhow::Result<()> {
    // 只加载项目根目录的 .env(不向上递归;缺文件不报错)
    let _ = dotenvy::from_path(".env");
    // config 先于日志:环境变量(含 RUST_LOG/LOG_FILE)全收口在 Config。
    // load 失败时 tracing 尚未 init —— anyhow 错误由 main 落 stderr,不丢。
    let config = Config::load().context("加载配置失败")?;
    init_tracing(&config);

    let mount = select_mount(&config);
    let (state, bg) = AppState::new(&config, mount).await?;
    let app = build_router(state, &config, mount);
    // metrics(opt-in,METRICS_ENABLED):Prometheus 请求计数/延迟直方图 + /metrics 端点。
    // 放这(不进 build_router):prometheus 全局 recorder 只能 install 一次,oneshot 测试多次
    // build_router 会重复 install 而 panic;放进程启动唯一路径就稳。/metrics 内部端点,不进 OpenAPI。
    let app = if config.metrics_enabled {
        let (layer, handle) = axum_prometheus::PrometheusMetricLayerBuilder::new()
            .with_ignore_pattern("/metrics")
            .with_default_metrics()
            .build_pair();
        app.route(
            "/metrics",
            axum::routing::get(move || async move { handle.render() }),
        )
        .layer(layer)
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("无法绑定 {}", config.bind_addr))?;
    // 启动时打印关键地址(0.0.0.0 用 localhost 显示,方便点击)。
    let port = config.bind_addr.port();
    let host = if config.bind_addr.ip().is_unspecified() {
        "localhost".to_string()
    } else {
        config.bind_addr.ip().to_string()
    };
    tracing::info!("启动 mount={mount:?}  监听 http://{host}:{port}");
    tracing::info!("API 文档 (Scalar)  http://{host}:{port}/docs");
    tracing::info!("OpenAPI JSON      http://{host}:{port}/api-docs/openapi.json");

    // 后台任务:outbox relay(各 schema 轮询发 JetStream)+ search projector(消费投影读模型);
    // 都随服务优雅退出而停。
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    for relay in bg.relays {
        tokio::spawn(relay.run(shutdown_rx.clone()));
    }
    if let Some(projector) = bg.projector {
        tokio::spawn(projector.run(shutdown_rx.clone()));
    }
    if let Some(auth_projector) = bg.auth_projector {
        tokio::spawn(auth_projector.run(shutdown_rx.clone()));
    }
    if let Some(auth_retention) = bg.auth_retention {
        tokio::spawn(auth_retention.run(shutdown_rx.clone()));
    }

    // into_make_service_with_connect_info:给 SmartIpKeyExtractor 的 peer-IP fallback 提供 ConnectInfo
    // (生产 nginx 设 X-Forwarded-For 时走 header;直连/无代理时回落到对端 IP)。
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .into_future();
    serve_until_drained(server, shutdown_rx, DRAIN_TIMEOUT).await
}

/// 收到关闭信号后,最多再等这么久就放弃剩余连接。取值 < 容器 grace period(docker/k8s 默认 30s),
/// 才轮得到我们自己善终 —— 超了就是 SIGKILL,等于没做优雅退出。
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    server: impl std::future::Future<Output = std::io::Result<()>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    cap: std::time::Duration,
) -> anyhow::Result<()> {
    tokio::pin!(server);
    tokio::select! {
        r = &mut server => r.context("服务器异常退出")?,
        _ = async {
            // 从**收到信号那刻**起算,不是从进程启动起算。
            let _ = shutdown_rx.wait_for(|stopping| *stopping).await;
            tokio::time::sleep(cap).await;
        } => {
            tracing::warn!(
                timeout_secs = cap.as_secs(),
                "优雅退出超时:仍有长连接(SSE?)未结束,放弃 drain 直接退出"
            );
        }
    }
    Ok(())
}

/// 结构化日志。按 `config.app_env` 切格式:**prod → JSON**(机器可解析、便于采集);非 prod → 彩色易读。
/// 级别:`config.log_filter()`(`RUST_LOG` 优先;缺省 prod=info、dev=debug)。
fn init_tracing(config: &Config) {
    use tracing_subscriber::{
        fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    };
    let prod = config.app_env.is_prod();
    let filter = EnvFilter::new(config.log_filter());

    // 文件日志**仅在设置了 LOG_FILE 时启用**:
    //   本地开发在 .env 里设 LOG_FILE=logs/dev.log 即可在文件观察(每次启动 truncate);
    //   容器/生产不设 → 只输出 stdout,由 docker/k8s 收集,绝不在容器内写文件。
    let file_layer = config.log_file.as_ref().map(|path| {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("无法创建 LOG_FILE 指定的日志文件");
        fmt::layer()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
    });

    // stdout:prod 结构化 JSON / 非 prod 彩色。boxed 统一两分支类型。
    let stdout_layer = if prod {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .init();
}

/// 优雅退出信号:SIGINT(Ctrl-C)与 SIGTERM(docker stop / k8s)**都**触发。
/// 漏掉 SIGTERM,容器停机时 `with_graceful_shutdown` 的 future 永不 resolve
/// → 等满 grace period 被 SIGKILL 硬杀、在途请求断流。滚动发布必断。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::error!("安装 SIGTERM handler 失败: {e}"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("收到关闭信号,优雅退出");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::serve_until_drained;

    /// **drain 不能无限等**:模拟"连接 future 永不结束"(SSE 流就是这样 —— 只在总线关闭时才完)。
    /// 收到关闭信号后必须到点放弃返回;不封顶就会一直等到容器 grace period 用尽被 SIGKILL,
    /// 优雅退出形同虚设(滚动发布每次都中)。
    #[tokio::test]
    async fn drain_is_capped_when_connections_never_finish() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let never_ending = std::future::pending::<std::io::Result<()>>();
        tx.send(true).unwrap(); // 已收到 SIGTERM
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            serve_until_drained(never_ending, rx, Duration::from_millis(50)),
        )
        .await;
        assert!(
            r.is_ok(),
            "drain 必须封顶返回,而不是一直等长连接(不封顶这里会挂到 5s 超时)"
        );
        assert!(r.unwrap().is_ok(), "放弃 drain 是正常退出,不是错误");
    }

    /// server 自己先跑完(无长连接挂着)→ 照常返回,不等满封顶时长。
    #[tokio::test]
    async fn normal_shutdown_returns_immediately() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let done = async { Ok::<(), std::io::Error>(()) };
        let r = tokio::time::timeout(
            Duration::from_millis(500),
            serve_until_drained(done, rx, Duration::from_secs(3600)),
        )
        .await;
        assert!(r.is_ok() && r.unwrap().is_ok(), "正常结束不该被封顶拖住");
    }
}

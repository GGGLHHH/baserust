//! 进程启动样板:`run(mount)` —— 读 .env、init 日志、装配 AppState、按 mount 挂路由、serve(优雅退出)。
//! app bin(main.rs)与 idm bin(src/bin/idm.rs)都调它,只差挂载范围
//! (对应 Go 的 cmd/realestate 与 cmd/realestate-login:同一套 lib,两个瘦 main)。

use anyhow::Context;

use crate::app::{build_router, AppState, Mount};
use crate::infra::config::Config;

/// 启动一个进程:读 .env → 日志 → 配置 → 装配 → 按 `mount` 挂路由 → serve(优雅退出)。
pub async fn run(mount: Mount) -> anyhow::Result<()> {
    // 只加载项目根目录的 .env(不向上递归;缺文件不报错)
    let _ = dotenvy::from_path(".env");
    init_tracing();

    let config = Config::load().context("加载配置失败")?;
    let state = AppState::new(&config, mount).await?;
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

    // into_make_service_with_connect_info:给 SmartIpKeyExtractor 的 peer-IP fallback 提供 ConnectInfo
    // (生产 nginx 设 X-Forwarded-For 时走 header;直连/无代理时回落到对端 IP)。
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("服务器异常退出")?;
    Ok(())
}

/// 结构化日志。按 `APP_ENV` 切格式:**prod → JSON**(机器可解析、便于采集);非 prod → 彩色易读。
/// 级别:`RUST_LOG` 优先;缺省 prod=info、dev=debug。
/// 注:此处自读 `APP_ENV`(早于 Config::load,保证 load 失败也有日志);与 Config.app_env 同源。
fn init_tracing() {
    use tracing_subscriber::{
        fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    };
    let prod = std::env::var("APP_ENV")
        .map(|e| e.eq_ignore_ascii_case("prod"))
        .unwrap_or(false);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if prod { "info" } else { "debug" }));

    // 文件日志**仅在设置了 LOG_FILE 时启用**:
    //   本地开发在 .env 里设 LOG_FILE=logs/dev.log 即可在文件观察(每次启动 truncate);
    //   容器/生产不设 → 只输出 stdout,由 docker/k8s 收集,绝不在容器内写文件。
    let file_layer = std::env::var("LOG_FILE").ok().map(|path| {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
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

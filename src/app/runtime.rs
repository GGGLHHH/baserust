//! 进程启动样板:`run(select_mount)` —— 读 .env、load 配置、init 日志、装配 AppState、挂路由、serve(优雅退出)。
//! app bin(main.rs)与 idm bin(src/bin/idm.rs)都调它,只差挂载范围
//! (对应 Go 的 cmd/realestate 与 cmd/realestate-login:同一套 lib,两个瘦 main)。

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

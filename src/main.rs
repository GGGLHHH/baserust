//! xchangeai —— Rust 后端脚手架 bin 入口。业务逻辑都在 lib(见 lib.rs);此处仅启动。
//!
//! 加新业务模块:在 `src/features/` 下照抄 widget/ 的文件结构,在 `features/mod.rs` 注册,
//! 再到 `app/router.rs` 的 build_router 里 `.nest("/api/v1", xxx::router())` 一行。

use anyhow::Context;

use xchangeai::app::{build_router, AppState};
use xchangeai::infra::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 只加载项目根目录的 .env(不向上递归;缺文件不报错)
    let _ = dotenvy::from_path(".env");
    init_tracing();

    let config = Config::load().context("加载配置失败")?;
    let state = AppState::new(&config).await?;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("无法绑定 {}", config.bind_addr))?;
    // 启动时打印关键地址(0.0.0.0 用 localhost 显示,方便点击),类似 huma 的启动提示。
    let port = config.bind_addr.port();
    let host = if config.bind_addr.ip().is_unspecified() {
        "localhost".to_string()
    } else {
        config.bind_addr.ip().to_string()
    };
    tracing::info!("监听中            http://{host}:{port}");
    tracing::info!("API 文档 (Scalar)  http://{host}:{port}/docs");
    tracing::info!("OpenAPI JSON      http://{host}:{port}/api-docs/openapi.json");
    tracing::info!("OpenAPI YAML      http://{host}:{port}/api-docs/openapi.yaml");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("服务器异常退出")?;
    Ok(())
}

/// 结构化日志:RUST_LOG 控制级别(如 `info,xchangeai=debug`),默认 debug。
fn init_tracing() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    // 开发默认全开到 debug;RUST_LOG 可覆盖(trace 更底层 / info 收敛)。
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

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
        // 无色 + 放在 stdout 层之前:先把 span 字段格式化成无 ANSI,文件因此干净可 grep。
        fmt::layer()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer) // Option<Layer>:没设 LOG_FILE 时为 None,不启用
        .with(fmt::layer()) // stdout —— 终端 / 容器日志
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

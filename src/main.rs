//! xchangeai —— Rust 后端脚手架入口。
//!
//! 加新业务模块:在 src/ 下照抄 widget/ 的文件结构,然后在 `build_router` 里 `.merge()` 一行。

mod audit;
mod config;
mod error;
mod extract;
mod health;
mod openapi;
mod pagination;
mod state;
mod widget;

use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::config::Config;
use crate::state::AppState;

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

/// 组装路由。各业务模块贡献一个 `OpenApiRouter`,在此合并;OpenAPI 规范自动汇总。
fn build_router(state: AppState) -> Router {
    let (router, api) = OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .merge(health::router())
        // 业务路由统一挂到 /api/v1;nest 会同步给 OpenAPI 的 path 加上该前缀。
        // health(探针)与文档端点保持在根,不随 API 版本走。
        .nest("/api/v1", widget::router())
        .split_for_parts();

    router
        // 中间件栈(外→内,请求时外层先执行):
        //   SetRequestId 最外先给请求打 x-request-id → TraceLayer 把它带进 span(日志按 id 关联)
        //   PropagateRequestId 把同一 id 回写响应头 → 客户端报障给 id 即可 grep
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_span)
                // 把请求完成日志提到 INFO,否则默认 DEBUG 会被 info filter 吞掉、
                // 带 request_id 的 span 就永远不出现在日志里
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(CatchPanicLayer::new())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // 文档端点(/docs、/api-docs/*)在中间件之后 merge → 不进访问日志:
        // Scalar UI 会反复拉 spec,记下来全是噪音。axum 的 layer 只作用于它之前已注册的路由。
        .merge(openapi::doc_routes(api))
        .with_state(state)
}

/// 给每个请求建带 method/path/request_id 的 tracing span,日志即可按 request_id 关联。
fn make_http_span(req: &Request<Body>) -> tracing::Span {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    tracing::info_span!(
        "http",
        method = %req.method(),
        path = %req.uri().path(),
        request_id = %request_id,
    )
}

/// 结构化日志:RUST_LOG 控制级别(如 `info,xchangeai=debug`),默认 info。
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("收到关闭信号,优雅退出");
}

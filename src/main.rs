//! xchangeai —— Rust 后端脚手架入口。
//!
//! 加新业务模块:在 src/ 下照抄 widget/ 的文件结构,然后在 `build_router` 里 `.merge()` 一行。

mod config;
mod error;
mod health;
mod openapi;
mod state;
mod widget;

use std::time::Duration;

use anyhow::Context;
use axum::http::StatusCode;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
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
    tracing::info!(addr = %config.bind_addr, "监听中");

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
        .merge(widget::router())
        .split_for_parts();

    router
        .merge(openapi::doc_routes(api))
        // 中间件栈:请求日志关联 + 超时 + panic 兜底(加 CORS = 开 tower-http 的 cors feature 再 .layer)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

/// 结构化日志:RUST_LOG 控制级别(如 `info,xchangeai=debug`),默认 info。
fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("收到关闭信号,优雅退出");
}

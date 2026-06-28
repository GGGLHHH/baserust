//! 路由装配:各业务模块贡献一个 OpenApiRouter,在此合并;OpenAPI 规范自动汇总。
//! 加业务模块:在 build_router 里 `.nest("/api/v1", xxx::router())` 一行。

use std::time::Duration;

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

use crate::app::AppState;
use crate::features::widget;
use crate::health;
use crate::infra::openapi;

/// 组装路由。各业务模块贡献一个 `OpenApiRouter`,在此合并;OpenAPI 规范自动汇总。
pub fn build_router(state: AppState) -> Router {
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

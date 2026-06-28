//! 路由装配:各业务模块贡献一个 OpenApiRouter,在此合并;OpenAPI 规范自动汇总。
//! 加业务模块:在 build_router 里 `.nest("/api/v1", xxx::router())` 一行。
//!
//! 中间件栈:统一错误契约(panic/timeout 也走 `ErrorBody` JSON)+ 安全头 + CORS(按 profile)。
//! 文档端点仅非 prod 暴露。

use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::app::AppState;
use crate::features::{idm, widget};
use crate::health;
use crate::infra::config::Config;
use crate::infra::error::ErrorBody;
use crate::infra::openapi;

/// 请求处理超时上限,超过返回 408 + 统一错误契约。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 组装路由。各业务模块贡献一个 `OpenApiRouter`,在此合并;OpenAPI 规范自动汇总。
pub fn build_router(state: AppState, config: &Config) -> Router {
    let (router, api) = OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .merge(health::router())
        // 业务路由统一挂到 /api/v1;nest 会同步给 OpenAPI 的 path 加上该前缀。
        // 多模块:先 merge 再 nest 一次(axum 不允许重复 nest 同前缀)。
        .nest("/api/v1", widget::router().merge(idm::router()))
        .split_for_parts();

    let router = router
        // 中间件栈(外→内,请求时外层先执行)。
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_span)
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // timeout:超时也走 ErrorBody JSON(tower-http TimeoutLayer 只给空体,故自己包一层)
        .layer(middleware::from_fn(timeout_middleware))
        // panic:兜底为 500 + ErrorBody JSON(原始 panic 信息只进日志,绝不泄露给客户端)
        .layer(CatchPanicLayer::custom(handle_panic))
        // 安全响应头(基础 web 安全基线;HSTS 留给 nginx/TLS 终止处加)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        // CORS:prod 用白名单(CORS_ALLOWED_ORIGINS),dev/staging 宽松便于前端联调
        .layer(cors_layer(config))
        // 鉴权:best-effort 解析 Bearer JWT,验过塞 AuthUser 进 extensions(无/非法不报错,下游决定)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            idm::authenticate,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    // 文档端点(/docs、/api-docs/*)只在**非 prod** 暴露,prod 收起减少攻击面。
    let router = if config.app_env.expose_docs() {
        router.merge(openapi::doc_routes(api))
    } else {
        router
    };

    router.with_state(state)
}

/// CORS 层:prod 用配置白名单(空则等于不放行任何跨源);dev/staging 走 permissive(任意源,便于联调)。
fn cors_layer(config: &Config) -> CorsLayer {
    if config.app_env.is_prod() {
        let origins: Vec<HeaderValue> = config
            .cors_origins()
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::permissive()
    }
}

/// 请求超时中间件:超过 `REQUEST_TIMEOUT` 返回 408 + 统一 `ErrorBody`(非 tower-http 默认空体)。
async fn timeout_middleware(req: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!(timeout_secs = REQUEST_TIMEOUT.as_secs(), "请求超时");
            error_response(StatusCode::REQUEST_TIMEOUT, "timeout", "请求超时")
        }
    }
}

/// panic 兜底:原始 panic 信息进**日志**,响应给统一的 500 `ErrorBody`(不泄露内部措辞)。
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "未知 panic".to_owned());
    tracing::error!(detail, "请求处理 panic,已兜底为 500");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "内部服务器错误",
    )
}

/// 构造与 `AppError` 同形的 `{code,error}` 响应,供 panic/timeout 这类绕过 AppError 的路径复用。
fn error_response(status: StatusCode, code: &'static str, msg: &str) -> Response {
    let body = ErrorBody {
        code,
        error: msg.to_owned(),
    };
    (status, Json(body)).into_response()
}

/// 给每个请求建带 method/path/request_id 的 tracing span,日志即可按 request_id 关联。
fn make_http_span(req: &Request) -> tracing::Span {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    /// panic 必须被兜成统一的 ErrorBody JSON,且原始 panic 信息不泄露给客户端。
    #[tokio::test]
    async fn panic_becomes_error_json_not_leaky_text() {
        // 具名 fn 给明确返回类型,避开闭包 `async { panic!() }` 的 never-type fallback。
        async fn boom() -> StatusCode {
            panic!("内部细节 boom-secret")
        }
        let app = Router::new()
            .route("/boom", get(boom))
            .layer(CatchPanicLayer::custom(handle_panic));
        let resp = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            s.contains("\"code\":\"internal\""),
            "应是 ErrorBody JSON: {s}"
        );
        assert!(s.contains("内部服务器错误"));
        assert!(!s.contains("boom-secret"), "原始 panic 信息不可泄露: {s}");
    }
}

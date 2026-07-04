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
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::{GovernorError, GovernorLayer};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::app::AppState;
use crate::features::{auth, content, widget};
use crate::health;
use crate::infra::config::Config;
use crate::infra::error::ErrorBody;
use crate::infra::openapi;

/// 请求处理超时上限,超过返回 408 + 统一错误契约。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 路由挂载范围。本地开发单进程挂 `Both`;生产分进程各挂 `App` / `Idm`,
/// 由 nginx 按 `/api/v1/auth` 前缀分流(→ idm 容器,其余 → app 容器)。
#[derive(Clone, Copy, Debug)]
pub enum Mount {
    /// 只 app 业务(widget) —— 生产 app 进程。
    App,
    /// 只 idm(auth/me,端点都在 /auth 下) —— 生产 idm 进程。
    Idm,
    /// app + idm —— 本地开发单进程。
    Both,
}

/// 组装路由。按 `mount` 决定挂哪些模块;OpenAPI 规范自动汇总。
/// widget(/widgets)与 auth(/auth/*)都是 app 拥有的 `OpenApiRouter<AppState>`,各自 path 相对,
/// 统一 nest 到 /api/v1 下 —— 两次 nest 同前缀会 panic,故**先 merge 再 nest 一次**。
pub fn build_router(state: AppState, config: &Config, mount: Mount) -> Router {
    let needs_app = matches!(mount, Mount::App | Mount::Both);
    let needs_idm = matches!(mount, Mount::Idm | Mount::Both);

    // health 在根(/livez 等不带 /api/v1);业务模块按 mount 装配,统一 nest /api/v1。
    let mut api_router =
        OpenApiRouter::with_openapi(openapi::ApiDoc::openapi()).merge(health::router());
    let mut features = OpenApiRouter::new();
    if needs_app {
        features = features.merge(widget::router()).merge(content::router());
    }
    if needs_idm {
        features = features.merge(auth::router());
    }
    api_router = api_router.nest("/api/v1", features);
    let (router, mut api) = api_router.split_for_parts();
    // per-operation security 由单一来源表注入(必须 split 后做,modifier 跑时 paths 还空)。
    openapi::inject_operation_security(&mut api);

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
        // 鉴权:best-effort 解析 token(cookie 优先/Bearer 兜底),验过塞 AuthUser 进 extensions(无/非法不报错,下游决定)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    // 限流(opt-in,RATE_LIMIT_ENABLED):按 IP 令牌桶,超限 429 + 统一 ErrorBody。
    // 加在最外(请求最先过),IP 滥用在鉴权/业务前就挡;429 经 error_handler 出错误契约。
    let router = if config.rate_limit_enabled {
        let gov = GovernorConfigBuilder::default()
            .per_second(config.rate_limit_per_sec as u64)
            .burst_size(config.rate_limit_burst)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("限流配置应合法");
        router.layer(GovernorLayer::new(gov).error_handler(rate_limit_response))
    } else {
        router
    };

    // 文档端点(/docs、/api-docs/*)只在**非 prod** 暴露,prod 收起减少攻击面。
    let router = if config.app_env.expose_docs() {
        router.merge(openapi::doc_routes(api))
    } else {
        router
    };

    router.with_state(state)
}

/// 合并后的 OpenAPI 规范(`Both` 全量)。运行时 doc 端点与契约测试**同源**复用此装配
/// (镜像 `build_router` 的 `Mount::Both` 分支)—— 避免测试复制装配逻辑而与运行时漂移。
pub fn api_spec() -> utoipa::openapi::OpenApi {
    let mut api = OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .merge(health::router())
        .nest(
            "/api/v1",
            OpenApiRouter::new()
                .merge(widget::router())
                .merge(content::router())
                .merge(auth::router()),
        )
        .split_for_parts()
        .1;
    openapi::inject_operation_security(&mut api); // 与 build_router 同源:doc 端点与契约测试都经此注入
    api
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
    timeout_or_408(REQUEST_TIMEOUT, next.run(req)).await
}

/// 把响应 future 套超时:超时 → 408 + 统一 `ErrorBody`(非 tower-http 默认空体)。
/// 抽出 `Duration` 形参 → 可用极短超时单测,逻辑零重复(避免测试复刻一份超时逻辑)。
async fn timeout_or_408(
    dur: Duration,
    fut: impl std::future::Future<Output = Response>,
) -> Response {
    match tokio::time::timeout(dur, fut).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!(timeout_secs = dur.as_secs(), "request timed out");
            error_response(StatusCode::REQUEST_TIMEOUT, "timeout", "Request timed out")
        }
    }
}

/// panic 兜底:原始 panic 信息进**日志**,响应给统一的 500 `ErrorBody`(不泄露内部措辞)。
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown panic".to_owned());
    tracing::error!(detail, "request panicked, fell back to 500");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal server error",
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

/// 限流超限 → 统一 `ErrorBody`,透传 governor 的 retry-after 等 header(错误契约也覆盖限流)。
fn rate_limit_response(err: GovernorError) -> Response {
    match err {
        GovernorError::TooManyRequests { headers, .. } => {
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests, please try again later",
            );
            if let Some(h) = headers {
                resp.headers_mut().extend(h);
            }
            resp
        }
        GovernorError::UnableToExtractKey => error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Could not identify request source",
        ),
        GovernorError::Other { code, headers, .. } => {
            let mut resp = error_response(code, "internal", "Rate limit error");
            if let Some(h) = headers {
                resp.headers_mut().extend(h);
            }
            resp
        }
    }
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
        assert!(s.contains("Internal server error"));
        assert!(!s.contains("boom-secret"), "原始 panic 信息不可泄露: {s}");
    }

    /// 横切错误契约:**超时也回统一 `ErrorBody`**(408 + `{code:"timeout"}`),不是空体。
    /// 直测抽出的 `timeout_or_408`(极短超时 + 永不返回的慢 future),不必等真实 30s。
    #[tokio::test]
    async fn timeout_yields_408_errorbody() {
        let resp = timeout_or_408(Duration::from_millis(5), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::OK.into_response()
        })
        .await;
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            s.contains("\"code\":\"timeout\""),
            "应是统一 ErrorBody: {s}"
        );
    }
}

//! 路由装配:各业务模块贡献一个 OpenApiRouter,按 `public` / `frontend` / `admin` 三组
//! 合并后统一 nest 到 `/api/v1` 下(auth 也按此三组分别 merge);OpenAPI 规范自动汇总。
//! 加业务模块:在 build_router 对应组里 `.merge(xxx::router())` 一行。
//!
//! 中间件栈:统一错误契约(panic/timeout 也走 `ErrorBody` JSON)+ 安全头 + CORS(按 profile)。
//! 组闸:`frontend` 组统一挂 `require_login`,`admin` 组统一挂 `require_admin_login`
//! (粗过滤、防御纵深第一层;端点内 role/scope/字段级三轴照旧)。
//! 文档端点仅非 prod 暴露。

use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
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
use crate::features::{auth, auth_audit, content, profile, users, widget};
use crate::health;
use crate::infra::config::Config;
use crate::infra::error::{ErrorBody, ErrorCode};
use crate::infra::openapi;

/// 请求处理超时上限,超过返回 408 + 统一错误契约。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 路由挂载范围。本地开发单进程挂 `Both`;生产分进程各挂 `App` / `Idm`,
/// 由 nginx 按 `/api/v1/{public,frontend,admin}/auth` 前缀分流(→ idm 容器,其余 → app 容器)。
#[derive(Clone, Copy, Debug)]
pub enum Mount {
    /// 只 app 业务(widget) —— 生产 app 进程。
    App,
    /// 只 idm(auth,端点分 public/frontend/admin 三组挂) —— 生产 idm 进程。
    Idm,
    /// app + idm —— 本地开发单进程。
    Both,
}

/// 组装路由。按 `mount` 决定挂哪些模块;业务模块(含 auth)按 public(无闸)/ frontend(需登录)/
/// admin(admin:login 准入)三组分别 merge,各组统一 nest 到 /api/v1 下再上组闸。
/// 两次 nest 同前缀会 panic,故**先 merge 再 nest 一次**。
pub fn build_router(state: AppState, config: &Config, mount: Mount) -> Router {
    let needs_app = matches!(mount, Mount::App | Mount::Both);
    let needs_idm = matches!(mount, Mount::Idm | Mount::Both);

    // health 在根(/livez 等不带 /api/v1);业务模块按 mount 装配进三组,统一 nest /api/v1。
    let mut api_router =
        OpenApiRouter::with_openapi(openapi::ApiDoc::openapi()).merge(health::router());
    let mut public = OpenApiRouter::new();
    let mut frontend = OpenApiRouter::new();
    let mut admin = OpenApiRouter::new();
    let mut admin_open = OpenApiRouter::new(); // admin 组闸外(admin_login)
    if needs_app {
        frontend = frontend
            .merge(widget::router())
            .merge(content::router())
            .merge(profile::router())
            // permissions/me:app 侧回答"能干什么"(policy 权威;idm 的 /auth/me 只给身份事实)
            .merge(crate::infra::authz::router());
        admin = admin.merge(widget::admin_router());
    }
    if needs_idm {
        public = public.merge(auth::public_router());
        frontend = frontend.merge(auth::me_router());
        // 后台资料/头像端点写 app schema(profiles/contents):只在同进程也连了 app 侧
        // (Mount::Both)时挂 —— 纯 idm 进程的 profiles/contents 是内存占位 repo,挂上去
        // 写操作会 200 却静默丢失、重启蒸发(fail-closed:不挂 → 404,镜像 auth_audit 未接线范式)。
        // ponytail: 分进程拓扑要启用它,需给 idm 进程连 app 库,或把路径挪出 /admin/auth 前缀归 app 进程。
        let mut auth_admin = OpenApiRouter::new()
            .merge(users::admin_router())
            .merge(auth_audit::admin_router());
        if needs_app {
            auth_admin = auth_admin.merge(profile::admin_router());
        }
        admin = admin.merge(auth::admin_router()).nest("/auth", auth_admin);
        admin_open = admin_open.merge(auth::admin_login_router());
    }
    // 组闸(粗过滤,防御纵深第一层;端点内三轴照旧)。layer 只包**调用时已有**的路由。
    let frontend = frontend.layer(middleware::from_fn(crate::infra::authz::require_login));
    let admin = admin
        .layer(middleware::from_fn_with_state(
            state.policy.clone(),
            crate::infra::authz::require_admin_login,
        ))
        .merge(admin_open); // 闸后 merge:layer 只包已有路由,login 免闸
    let features = OpenApiRouter::new()
        .nest("/public", public)
        .nest("/frontend", frontend)
        .nest("/admin", admin);
    api_router = api_router.nest("/api/v1", features);
    let (router, mut api) = api_router.split_for_parts();
    // per-operation security 由单一来源表注入(必须 split 后做,modifier 跑时 paths 还空)。
    openapi::inject_operation_security(&mut api);

    let router = router
        // 兜底:未知路径 / 方法不对也要出统一 `ErrorBody`。axum 默认给的是**裸状态码 + 空 body** ——
        // 客户端只要无条件解错误体,就会在 404/405 上炸,而 401/403/408/429/500 全都正常,
        // 正好破掉"每个错误都是 {code,error}"这条契约(本模块头注的核心承诺)。
        // 404 用 NotFound;405 归 BadRequest(错误码是闭集,不为此单开一个)。
        //
        // **必须注册在整条 `.layer()` 链之前**:`Router::layer` 只包"调用时已存在"的路由(含
        // fallback),而 `Router::fallback` 会用一个**全新未包装**的 handler 覆盖掉 catch-all ——
        // 放到链尾等于让 404/405 绕过整个栈:没 CORS(浏览器读不到跨域错误体)、没安全头、没
        // request-id。此处所有路由都已注册完毕,故也不影响 `method_not_allowed_fallback` 的遍历。
        .fallback(|| async {
            error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, "未找到")
        })
        .method_not_allowed_fallback(|| async {
            error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::BadRequest,
                "该路径不支持此方法",
            )
        })
        // 内层中间件栈(tower 语义:后 .layer() 更外、请求最先过,故**自内向外**书写)。
        // CORS / 安全响应头 / 限流刻意包在此栈**之外**(见下),好让限流 429、panic 500 等短路响应
        // 也带上 CORS 与安全头 —— 否则浏览器读不到跨域的错误响应。
        //
        // timeout:超时也走 ErrorBody JSON(tower-http TimeoutLayer 只给空体,故自己包一层)
        .layer(middleware::from_fn(timeout_middleware))
        // panic:兜底为 500 + ErrorBody JSON(原始 panic 信息只进日志,绝不泄露给客户端)
        .layer(CatchPanicLayer::custom(handle_panic))
        // Trace 必须在 panic/timeout **之外**:span 在它们之内才进得去。
        // 放最内(旧接法)时,`handle_panic` 的 error! 是在 unwind 过 Trace 之后才打的、
        // `timeout_or_408` 的 warn! 同理 —— 两条日志都不带 method/path/request_id,
        // 而"原始细节只进日志"的范式恰恰指望这些细节能对回某个请求;且 unwind/取消会让
        // `DefaultOnResponse` 根本不触发 → panic 与超时的请求**一条访问日志都没有**,
        // 偏偏它们正是你要翻日志找的那些。仍在 SetRequestId 之内(span 要读 x-request-id 头)。
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_span)
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // 可信反代跳数(TRUSTED_PROXY_HOPS)注入 extension,供 ClientContext 提取器解析真实客户端 IP
        .layer(axum::Extension(crate::infra::client_context::TrustedHops(
            config.trusted_proxy_hops,
        )))
        // 鉴权:best-effort 解析 token(cookie 优先/Bearer 兜底),验过塞 AuthUser 进 extensions(无/非法不报错,下游决定)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    // 限流(opt-in,RATE_LIMIT_ENABLED):按 IP 令牌桶,超限 429 + 统一 ErrorBody。
    // 加在最外(请求最先过),IP 滥用在鉴权/业务前就挡;429 经 error_handler 出错误契约。
    // 键提取复用 resolve_client_ip 的"信 N 层反代"语义 —— SmartIpKeyExtractor 信 XFF 最左
    // (客户端可伪造,每请求换一个假 IP 即绕过限流),不可用。
    let router = if config.rate_limit_enabled {
        // `period` = **补一个令牌的间隔**,不是速率 —— `per_second(n)` 是 `period = n 秒`(补一个/n 秒),
        // 与 `RATE_LIMIT_PER_SEC`("每秒补 n 个")正好互为倒数:直接喂会慢 n² 倍(默认 10 → 0.1 req/s)。
        // 故取倒数 `1s / n`。`max(1)`:period/burst 为零时 `finish()` 返 None → 启动 panic;
        // 配 0 应退化成"最严但能跑",不是炸进程。
        let per_sec = config.rate_limit_per_sec.max(1);
        let gov = GovernorConfigBuilder::default()
            .period(Duration::from_secs(1) / per_sec)
            .burst_size(config.rate_limit_burst.max(1))
            .key_extractor(TrustedIpKeyExtractor {
                trusted_hops: config.trusted_proxy_hops,
            })
            .finish()
            .expect("限流配置应合法");
        router.layer(GovernorLayer::new(gov).error_handler(rate_limit_response))
    } else {
        router
    };

    // CORS + 安全响应头包在**最外**(限流之外):限流 429 / panic 500 等短路响应也带上它们
    // —— 否则浏览器读不到跨域的错误响应(429 body 被 CORS 挡),且这些响应缺安全头。
    let router = router
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
        .layer(cors_layer(config));

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
                .nest("/public", OpenApiRouter::new().merge(auth::public_router()))
                .nest(
                    "/frontend",
                    OpenApiRouter::new()
                        .merge(widget::router())
                        .merge(content::router())
                        .merge(profile::router())
                        .merge(crate::infra::authz::router())
                        .merge(auth::me_router()),
                )
                .nest(
                    "/admin",
                    OpenApiRouter::new()
                        .merge(widget::admin_router())
                        .merge(auth::admin_router())
                        .nest(
                            "/auth",
                            OpenApiRouter::new()
                                .merge(users::admin_router())
                                .merge(profile::admin_router())
                                .merge(auth_audit::admin_router()),
                        )
                        .merge(auth::admin_login_router()),
                ),
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
            error_response(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::Timeout,
                "Request timed out",
            )
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
        ErrorCode::Internal,
        "Internal server error",
    )
}

/// 构造与 `AppError` 同形的 `{code,error}` 响应,供 panic/timeout 这类绕过 AppError 的路径复用。
fn error_response(status: StatusCode, code: ErrorCode, msg: &str) -> Response {
    let body = ErrorBody {
        code,
        error: msg.to_owned(),
    };
    (status, Json(body)).into_response()
}

/// 限流键 = 可信客户端 IP(与审计同源:`resolve_client_ip` 按"信任 N 层反代"取
/// `XFF[len-N]`,拒最左伪造值;缺头回退 X-Real-IP → socket peer)。取不到键 → 400。
#[derive(Clone)]
struct TrustedIpKeyExtractor {
    trusted_hops: usize,
}

impl KeyExtractor for TrustedIpKeyExtractor {
    type Key = std::net::IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        crate::infra::client_context::client_ip_from_headers(req.headers(), peer, self.trusted_hops)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// 限流超限 → 统一 `ErrorBody`,透传 governor 的 retry-after 等 header(错误契约也覆盖限流)。
fn rate_limit_response(err: GovernorError) -> Response {
    match err {
        GovernorError::TooManyRequests { headers, .. } => {
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::RateLimited,
                "Too many requests, please try again later",
            );
            if let Some(h) = headers {
                resp.headers_mut().extend(h);
            }
            resp
        }
        GovernorError::UnableToExtractKey => error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::BadRequest,
            "Could not identify request source",
        ),
        GovernorError::Other { code, headers, .. } => {
            let mut resp = error_response(code, ErrorCode::Internal, "Rate limit error");
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

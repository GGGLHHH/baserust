//! 限流契约测试:opt-in 开启后,**同一 IP** 连发超 burst → 429 + 统一 `ErrorBody`。
//! SmartIp 从 `X-Forwarded-For` 取 IP(oneshot 无 ConnectInfo,但带该 header 即可)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt; // oneshot

use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use baserust::infra::authz::Policy;
use baserust::infra::config::Config;
use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 内存 app + **限流开启**(burst=2,per_sec=1)。
fn rate_limited_app() -> Router {
    let bus: Arc<dyn baserust::features::widget::EventBus> =
        Arc::new(baserust::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: baserust::features::profile::ProfileService::new(
            std::sync::Arc::new(baserust::features::profile::InMemoryProfileRepo::new()),
            std::sync::Arc::new(baserust::features::profile::StaticAvatarProbe::empty()),
        ),
        contents: content::ContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(content::InMemoryObjectStore::new()),
            "memory",
        ),
        // 仅供 /health 用:此 fixture 的 AuthService 走 idm 默认 HS256 便捷构造,与 state 的
        // EdDSA token_verifier 算法不同 —— **不可扩展到登录/鉴权类断言**(HS256 签的 token 会被
        // EdDSA-only verifier 静默判空 scope 而非报错,假绿)。要打认证端点见 auth_api 的 fixture。
        auth: AuthService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(FakeHasher),
            "test-secret",
            900,
            604_800,
        ),
        user_admin: baserust::features::users::UserAdminService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(baserust::features::users::StaticProfileDirectory::empty()),
            None,
        ),
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(Policy::default()),
        token_signer: Some(Arc::new(AppTokenSigner::dev())),
        token_verifier: Arc::new(AppTokenVerifier::dev()),
        idm_outbox: None,
        auth_events: None,
    };
    let config = Config {
        rate_limit_enabled: true,
        rate_limit_per_sec: 1,
        rate_limit_burst: 2,
        ..Config::default()
    };
    build_router(state, &config, Mount::Both)
}

#[tokio::test]
async fn over_burst_same_ip_gets_429_errorbody() {
    let app = rate_limited_app();
    let mut last_status = StatusCode::OK;
    let mut body_429 = String::new();
    // burst=2、同 IP 连发 5 次 → 必触 429
    for _ in 0..5 {
        let req = Request::get("/health")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        last_status = resp.status();
        if last_status == StatusCode::TOO_MANY_REQUESTS {
            body_429 = String::from_utf8(
                axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            break;
        }
    }
    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "同 IP 超 burst 应 429"
    );
    assert!(
        body_429.contains("\"code\":\"rate_limited\""),
        "429 必须走统一 ErrorBody 契约: {body_429}"
    );
}

#[tokio::test]
async fn rate_limit_off_by_default_lets_all_through() {
    // Config::default() → rate_limit_enabled=false → 不挂限流,连发不 429。
    let bus: Arc<dyn baserust::features::widget::EventBus> =
        Arc::new(baserust::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: baserust::features::profile::ProfileService::new(
            std::sync::Arc::new(baserust::features::profile::InMemoryProfileRepo::new()),
            std::sync::Arc::new(baserust::features::profile::StaticAvatarProbe::empty()),
        ),
        contents: content::ContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(content::InMemoryObjectStore::new()),
            "memory",
        ),
        // 仅供 /health 用:此 fixture 的 AuthService 走 idm 默认 HS256 便捷构造,与 state 的
        // EdDSA token_verifier 算法不同 —— **不可扩展到登录/鉴权类断言**(HS256 签的 token 会被
        // EdDSA-only verifier 静默判空 scope 而非报错,假绿)。要打认证端点见 auth_api 的 fixture。
        auth: AuthService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(FakeHasher),
            "test-secret",
            900,
            604_800,
        ),
        user_admin: baserust::features::users::UserAdminService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(baserust::features::users::StaticProfileDirectory::empty()),
            None,
        ),
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(Policy::default()),
        token_signer: Some(Arc::new(AppTokenSigner::dev())),
        token_verifier: Arc::new(AppTokenVerifier::dev()),
        idm_outbox: None,
        auth_events: None,
    };
    let app = build_router(state, &Config::default(), Mount::Both);
    for _ in 0..10 {
        let resp = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "默认关闭限流,不应 429");
    }
}

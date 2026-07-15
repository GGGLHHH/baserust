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

/// 内存 app + **限流开启**,配额由参数给(`per_sec` = 每秒补的令牌数,`burst` = 桶容量)。
fn rate_limited_app(per_sec: u32, burst: u32) -> Router {
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
        auth_audit: None,
        auth_events_bus: None,
    };
    let config = Config {
        rate_limit_enabled: true,
        rate_limit_per_sec: per_sec,
        rate_limit_burst: burst,
        ..Config::default()
    };
    build_router(state, &config, Mount::Both)
}

/// 打 /health,带固定 IP(oneshot 无 ConnectInfo,靠 XFF 给 key extractor 取键)。
async fn hit(app: &Router) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get("/health")
                .header("x-forwarded-for", "1.2.3.4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn over_burst_same_ip_gets_429_errorbody() {
    let app = rate_limited_app(1, 2);
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

/// **单位钉死**:`RATE_LIMIT_PER_SEC` 是"每秒补 N 个令牌",不是"每 N 秒补一个"。
/// 底层 `GovernorConfigBuilder::period` 要的是**补一个的间隔**,故接线必须取倒数(1s/N)。
/// per_sec=10 → 100ms 补一个:耗干 burst 后等 300ms 必须放行。
/// 曾经的 `per_second(10)` 把 period 设成 **10 秒**(慢 100 倍),这里会红;
/// 原有的 per_sec=1 用例两种接线同解(1s/1 = 1s),照不出来 —— 所以要这条。
#[tokio::test]
async fn per_sec_is_a_rate_not_an_interval() {
    let app = rate_limited_app(10, 1); // 容量 1,每 100ms 补一个
    assert_eq!(hit(&app).await, StatusCode::OK, "首个请求吃掉 burst");
    assert_eq!(
        hit(&app).await,
        StatusCode::TOO_MANY_REQUESTS,
        "桶空,紧接着必 429"
    );
    // 300ms > 100ms 的补充间隔(留足余量抗抖动);若 period 被当成 10s,这里仍是 429 → 红。
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        hit(&app).await,
        StatusCode::OK,
        "per_sec=10 → 100ms 应补回一个令牌;仍 429 说明 period 被当成了 10 秒(慢 100 倍)"
    );
}

/// per_sec / burst 配 0 不应炸进程:`finish()` 对零 period/burst 返 None → `expect` panic。
/// 钳到 1 = "最严但能跑"。零环境变量静默启动是本仓的硬约束,配错值不该是启动期 panic。
#[tokio::test]
async fn zero_quota_does_not_panic_at_build() {
    let app = rate_limited_app(0, 0);
    let s = hit(&app).await;
    assert!(
        s == StatusCode::OK || s == StatusCode::TOO_MANY_REQUESTS,
        "配 0 应能起且正常限流,得到 {s}"
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
        auth_audit: None,
        auth_events_bus: None,
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

//! 组闸行为契约:public 免登录可达 / frontend 需登录(401)/ admin 需 admin:login 后台准入(401/403)/
//! admin_login 验密后自查。细粒度授权契约在 openapi_authz_test;这里只钉"防御纵深第一层"。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use baserust::app::{build_router, AppState, Mount};
use baserust::infra::config::Config;

async fn setup() -> (Router, AppState) {
    let config = Config::default();
    let (state, _bg) = AppState::new(&config, Mount::Both).await.unwrap();
    let app = build_router(state.clone(), &config, Mount::Both);
    (app, state)
}

/// 直接经 service 拿 access token(seed 账号,密码 pwd)。
async fn bearer(state: &AppState, who: &str) -> String {
    state
        .auth
        .login(idm::LoginInput {
            identifier: who.to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap()
        .access_token
}

async fn get(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::get(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn post_login(app: &Router, uri: &str, identifier: &str) -> axum::response::Response {
    let body = format!(r#"{{"identifier":"{identifier}","password":"pwd"}}"#);
    app.clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// public 组:免登录可达(无组闸)。
#[tokio::test]
async fn public_group_reachable_without_token() {
    // public 组无需 token 可达 —— 这个架构断言仍然成立,只是不再用 widget_stats 证明:
    // 它上租户轴后挪进了 frontend 组(spec §6.1,「public + 租户数据」是反模式)。
    // 改用 login:它是真正无租户语义的 public 端点(注册/登录本就发生在有租户之前)。
    let (app, _state) = setup().await;
    let resp = post_login(&app, "/api/v1/public/auth/login", "user").await;
    assert_eq!(resp.status(), StatusCode::OK, "public 组应无需 token 可达");
}

/// frontend 组:无 token → 401 统一 ErrorBody;登录即过组闸。
#[tokio::test]
async fn frontend_group_requires_login() {
    let (app, state) = setup().await;
    let (s, body) = get(&app, "/api/v1/frontend/widgets", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.contains("\"code\""), "应是统一 ErrorBody: {body}");
    let t = bearer(&state, "user").await;
    let (s, _) = get(&app, "/api/v1/frontend/widgets", Some(&t)).await;
    assert_eq!(s, StatusCode::OK);
}

/// 组内未知路径 → 404 不过闸(axum `.layer()` 只包已注册路由,不包 fallback;spec 实证修正后钉死)。
/// 已注册路由未登录仍 401 —— 这两条合起来钉住"闸只管注册路由"的真实语义。
/// **且 404 也得出统一 `ErrorBody`**:axum 默认兜底是裸状态码 + 空 body,客户端无条件解错误体
/// 就会在这炸(而 401/403 都正常)—— 原来这条只断言状态码、没看 body,所以一直没发现。
#[tokio::test]
async fn frontend_unknown_path_is_404_not_gated() {
    let (app, _state) = setup().await;
    let (s, body) = get(&app, "/api/v1/frontend/no-such-thing", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        body.contains("\"code\":\"not_found\""),
        "404 也必须走统一 ErrorBody 契约: {body}"
    );
}

/// 方法不对 → 405,同样出统一 `ErrorBody`(默认兜底是空 body)。
#[tokio::test]
async fn wrong_method_is_405_with_error_body() {
    let (app, _state) = setup().await;
    // /health 只注册了 GET
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("\"code\""),
        "405 也必须走统一 ErrorBody 契约: {body}"
    );
}

/// **兜底响应也得过中间件栈**:`Router::layer` 只包"调用时已存在"的路由,而 `Router::fallback`
/// 会用全新未包装的 handler 覆盖 catch-all —— 注册晚于 `.layer()` 就等于让 404/405 绕过整个栈:
/// 没 CORS(浏览器读不到跨域错误体)、没安全头、没 request-id。这里钉住注册顺序。
#[tokio::test]
async fn fallback_responses_still_pass_through_middleware() {
    let (app, _state) = setup().await;
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/v1/definitely-not-a-route")
                .header("origin", "http://example.test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let h = resp.headers();
    assert!(
        h.contains_key("x-request-id"),
        "404 也该带 request-id(否则日志里对不回这条请求)"
    );
    assert!(
        h.contains_key("x-content-type-options") && h.contains_key("x-frame-options"),
        "404 也该带安全响应头"
    );
    assert!(
        h.contains_key("access-control-allow-origin"),
        "404 也该带 CORS —— 否则浏览器根本读不到这个错误体"
    );
}

/// admin 组闸:401(未登录)/ 403(user 无 admin:login)/ 200(admin + superadmin 皆有后台准入)。
/// 用 admin_get_me 探——它端点内 perm 为 None,403 只能来自组闸(闸的独立证据)。
#[tokio::test]
async fn admin_group_gate_401_403_200() {
    let (app, state) = setup().await;
    let (s, _) = get(&app, "/api/v1/admin/auth/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let t = bearer(&state, "user").await;
    let (s, body) = get(&app, "/api/v1/admin/auth/me", Some(&t)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(body.contains("\"code\""), "应是统一 ErrorBody: {body}");

    // admin(有 admin:login,但无 users:admin)也过后台准入闸 —— 拆分后的核心行为
    let t = bearer(&state, "admin").await;
    let (s, _) = get(&app, "/api/v1/admin/auth/me", Some(&t)).await;
    assert_eq!(s, StatusCode::OK, "admin 有 admin:login → 过组闸");

    let t = bearer(&state, "superadmin").await;
    let (s, body) = get(&app, "/api/v1/admin/auth/me", Some(&t)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("superadmin"), "应返回当前管理员: {body}");
}

/// admin_login:admin + superadmin(皆有 admin:login)→ 200 + 双 cookie;
/// user 凭据对但无 admin:login → 403 且**零 Set-Cookie**。
#[tokio::test]
async fn admin_login_rejects_non_admin_without_tokens() {
    let (app, _state) = setup().await;

    for who in ["superadmin", "admin"] {
        let resp = post_login(&app, "/api/v1/admin/auth/login", who).await;
        assert_eq!(resp.status(), StatusCode::OK, "{who} 应能登后台");
        let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2, "{who}: access + refresh cookie");
    }

    let resp = post_login(&app, "/api/v1/admin/auth/login", "user").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "403 不得发任何 cookie"
    );
}

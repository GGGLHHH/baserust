//! 组闸行为契约:public 免登录可达 / frontend 需登录(401)/ admin 需 admin:login 后台准入(401/403)/
//! admin_login 验密后自查。细粒度授权契约在 openapi_authz_test;这里只钉"防御纵深第一层"。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::{body, Router};
use idm::LoginInput;
use tower::ServiceExt;

use baserust::app::{build_router, AppState, Mount};
use baserust::infra::config::Config;

async fn setup() -> (Router, AppState) {
    let config = Config::default();
    let state = AppState::try_new(&config, Mount::Both).await.unwrap().state;
    let app = build_router(state.clone(), &config, Mount::Both);
    (app, state)
}

/// 直接经 service 拿 access token(seed 账号,密码 pwd)。
async fn bearer(state: &AppState, who: &str) -> String {
    state
        .auth
        .login(LoginInput {
            identifier: who.to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap()
        .access_token
}

async fn get(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::get(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn post_login(app: &Router, uri: &str, identifier: &str) -> Response {
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
    let (app, _state) = setup().await;
    let response = post_login(&app, "/api/v1/public/auth/login", "user").await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// frontend 组:无 token → 401 统一 ErrorBody;登录即过组闸。
#[tokio::test]
async fn frontend_group_requires_login() {
    let (app, state) = setup().await;
    let (status, body) = get(&app, "/api/v1/frontend/widgets", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("\"code\""), "应是统一 ErrorBody: {body}");
    let token = bearer(&state, "user").await;
    let (status, _) = get(&app, "/api/v1/frontend/widgets", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
}

/// 组内未知路径 → 404 不过闸(axum `.layer()` 只包已注册路由,不包 fallback;spec 实证修正后钉死)。
/// 已注册路由未登录仍 401 —— 这两条合起来钉住"闸只管注册路由"的真实语义。
/// **且 404 也得出统一 `ErrorBody`**:axum 默认兜底是裸状态码 + 空 body,客户端无条件解错误体
/// 就会在这炸(而 401/403 都正常)—— 原来这条只断言状态码、没看 body,所以一直没发现。
#[tokio::test]
async fn frontend_unknown_path_is_404_not_gated() {
    let (app, _state) = setup().await;
    let (status, body) = get(&app, "/api/v1/frontend/no-such-thing", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = String::from_utf8(
        body::to_bytes(response.into_body(), usize::MAX)
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
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/definitely-not-a-route")
                .header("origin", "http://example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let headers = response.headers();
    assert!(
        headers.contains_key("x-request-id"),
        "404 也该带 request-id(否则日志里对不回这条请求)"
    );
    assert!(
        headers.contains_key("x-content-type-options") && headers.contains_key("x-frame-options"),
        "404 也该带安全响应头"
    );
    assert!(
        headers.contains_key("access-control-allow-origin"),
        "404 也该带 CORS —— 否则浏览器根本读不到这个错误体"
    );
}

/// admin 组闸:401(未登录)/ 403(user 无 admin:login)/ 200(admin + superadmin 皆有后台准入)。
/// 用 admin_get_me 探——它端点内 perm 为 None,403 只能来自组闸(闸的独立证据)。
#[tokio::test]
async fn admin_group_gate_401_403_200() {
    let (app, state) = setup().await;
    let (status, _) = get(&app, "/api/v1/admin/auth/me", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let token = bearer(&state, "user").await;
    let (status, body) = get(&app, "/api/v1/admin/auth/me", Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("\"code\""), "应是统一 ErrorBody: {body}");

    // admin(有 admin:login,但无 users:admin)也过后台准入闸 —— 拆分后的核心行为
    let token = bearer(&state, "admin").await;
    let (status, _) = get(&app, "/api/v1/admin/auth/me", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "admin 有 admin:login → 过组闸");

    let token = bearer(&state, "superadmin").await;
    let (status, body) = get(&app, "/api/v1/admin/auth/me", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("superadmin"), "应返回当前管理员: {body}");
}

/// admin_login:superadmin / admin(默认租户 admin)/ user(默认 mock 的演示租户里是 admin,后台登录挑进那里)
/// → 200 + 双 cookie;刚注册的账号(只在默认租户当 user,哪都没有 admin:login)→ 403 且**零 Set-Cookie**。
#[tokio::test]
async fn admin_login_rejects_non_admin_without_tokens() {
    let (app, _state) = setup().await;

    for who in ["superadmin", "admin", "user"] {
        let response = post_login(&app, "/api/v1/admin/auth/login", who).await;
        assert_eq!(response.status(), StatusCode::OK, "{who} 应能登后台");
        let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2, "{who}: access + refresh cookie");
    }

    let registered = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"plain","password":"pwd"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(registered.status(), StatusCode::CREATED);
    let response = post_login(&app, "/api/v1/admin/auth/login", "plain").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "403 不得发任何 cookie"
    );
}

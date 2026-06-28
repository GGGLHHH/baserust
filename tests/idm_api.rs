//! idm 对外接口**契约测试**。钉死线上形状:端点 + 状态码 + body 字段 + httponly cookie + 防枚举。
//! 断言只看 JSON 字段/状态码/Set-Cookie,**不 import idm DTO 类型** —— 契约是"线上形状"。
//!
//! 认证用 httponly cookie:login/register 把 token 写进 Set-Cookie、body 只返 UserResponse;
//! 鉴权 cookie 优先、Bearer 兜底。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use xchangeai::app::{build_router, AppState};
use xchangeai::features::idm::{AuthService, FakeHasher, InMemorySessionRepo, InMemoryUserRepo};
use xchangeai::features::widget::{InMemoryWidgetRepo, WidgetService};

fn test_app() -> Router {
    let state = AppState {
        widgets: WidgetService::new(Arc::new(InMemoryWidgetRepo::new())),
        auth: test_auth(),
        db_pool: None,
        cookie_secure: false,
    };
    build_router(state, &xchangeai::infra::config::Config::default())
}

/// 测试用 AuthService:FakeHasher(躲 argon2 ~100ms)+ 内存 repo + 固定 secret。
fn test_auth() -> AuthService {
    AuthService::new(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(FakeHasher),
        "test-secret",
        900,
        604_800,
    )
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn post_json(uri: &str, json: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_owned()))
        .unwrap()
}

/// 所有 Set-Cookie 拼成一行,便于断言。
fn set_cookie_line(resp: &Response) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// 提取 Set-Cookie 里某个 cookie 的值。
fn cookie_value(resp: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.strip_prefix(&prefix)
                .map(|rest| rest.split(';').next().unwrap_or("").to_owned())
        })
}

fn get_plain(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}
fn get_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::get(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}
fn get_with_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ── 注册 ──

#[tokio::test]
async fn register_sets_httponly_cookie_and_returns_user() {
    let resp = test_app()
        .oneshot(post_json(
            "/api/v1/auth/register",
            r#"{"username":"alice","email":"a@b.com","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // token 进 httponly cookie,不进 body
    let cookies = set_cookie_line(&resp);
    assert!(
        cookies.contains("access_token="),
        "应 Set-Cookie access_token: {cookies}"
    );
    assert!(
        cookies.contains("refresh_token="),
        "应 Set-Cookie refresh_token: {cookies}"
    );
    assert!(
        cookies.to_lowercase().contains("httponly"),
        "cookie 必须 HttpOnly: {cookies}"
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("\"username\":\"alice\""),
        "body 应是 UserResponse: {body}"
    );
    assert!(!body.contains("access_token"), "token 不该进 body: {body}");
    assert!(!body.contains("password"), "绝不回显密码: {body}");
}

#[tokio::test]
async fn register_duplicate_username_is_409() {
    let app = test_app();
    let body = r#"{"username":"dupuser","email":"dup@b.com","password":"password123"}"#;
    app.clone()
        .oneshot(post_json("/api/v1/auth/register", body))
        .await
        .unwrap();
    let resp = app
        .oneshot(post_json("/api/v1/auth/register", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(body_string(resp).await.contains("\"code\":\"conflict\""));
}

#[tokio::test]
async fn register_weak_password_is_422() {
    let resp = test_app()
        .oneshot(post_json(
            "/api/v1/auth/register",
            r#"{"username":"bob","email":"b@b.com","password":"short"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn register_malformed_json_is_400() {
    let resp = test_app()
        .oneshot(post_json("/api/v1/auth/register", r#"{not json"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 登录 + 鉴权 ──

#[tokio::test]
async fn login_sets_cookie_then_me_works_via_cookie_and_bearer() {
    let app = test_app();
    app.clone()
        .oneshot(post_json(
            "/api/v1/auth/register",
            r#"{"username":"loginuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/login",
            r#"{"identifier":"loginuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let token = cookie_value(&resp, "access_token").expect("login 应 Set-Cookie access_token");

    // cookie 鉴权
    let via_cookie = app
        .clone()
        .oneshot(get_with_cookie(
            "/api/v1/me",
            &format!("access_token={token}"),
        ))
        .await
        .unwrap();
    assert_eq!(via_cookie.status(), StatusCode::OK);
    assert!(body_string(via_cookie)
        .await
        .contains("\"username\":\"loginuser\""));

    // Bearer 兜底(同一 token 也认)
    let via_bearer = app
        .oneshot(get_with_bearer("/api/v1/me", &token))
        .await
        .unwrap();
    assert_eq!(via_bearer.status(), StatusCode::OK);
}

/// 防枚举:密码错 与 用户不存在 必须返回**逐字节相同**的 401(同码同文案),无法区分。
#[tokio::test]
async fn login_wrong_password_and_unknown_identifier_are_indistinguishable() {
    let app = test_app();
    app.clone()
        .oneshot(post_json(
            "/api/v1/auth/register",
            r#"{"username":"realuser","password":"password123"}"#,
        ))
        .await
        .unwrap();

    let wrong_pw = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/login",
            r#"{"identifier":"realuser","password":"WRONGpass1"}"#,
        ))
        .await
        .unwrap();
    let unknown = app
        .oneshot(post_json(
            "/api/v1/auth/login",
            r#"{"identifier":"nobody","password":"password123"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(wrong_pw.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(wrong_pw).await,
        body_string(unknown).await,
        "密码错与用户不存在的响应必须逐字节相同(防枚举)"
    );
}

// ── 受保护端点 ──

#[tokio::test]
async fn me_without_credentials_is_401() {
    let resp = test_app().oneshot(get_plain("/api/v1/me")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_with_garbage_cookie_is_401() {
    let resp = test_app()
        .oneshot(get_with_cookie(
            "/api/v1/me",
            "access_token=garbage.token.xxx",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── 登出 ──

#[tokio::test]
async fn logout_clears_cookies_and_204() {
    let resp = test_app()
        .oneshot(
            Request::post("/api/v1/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // 清除 = 回收同名 cookie(Max-Age=0 / 空值)
    let cookies = set_cookie_line(&resp);
    assert!(
        cookies.contains("access_token="),
        "logout 应回收 access cookie: {cookies}"
    );
    assert!(
        cookies.contains("refresh_token="),
        "logout 应回收 refresh cookie: {cookies}"
    );
}

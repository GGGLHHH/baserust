//! 组闸行为契约:public 免登录可达 / frontend 需登录(401)/ admin 需 users:admin(401/403)/
//! admin_login 验密后自查。细粒度授权契约在 openapi_authz_test;这里只钉"防御纵深第一层"。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use xchangeai::app::{build_router, AppState, Mount};
use xchangeai::infra::config::Config;

async fn setup() -> (Router, AppState) {
    let config = Config::default();
    let state = AppState::new(&config, Mount::Both).await.unwrap();
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
    let (app, _state) = setup().await;
    let (s, _) = get(&app, "/api/v1/public/widgets/stats", None).await;
    assert_eq!(s, StatusCode::OK);
    let resp = post_login(&app, "/api/v1/public/auth/login", "user").await;
    assert_eq!(resp.status(), StatusCode::OK);
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
#[tokio::test]
async fn frontend_unknown_path_is_404_not_gated() {
    let (app, _state) = setup().await;
    let (s, _) = get(&app, "/api/v1/frontend/no-such-thing", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// admin 组闸:401(未登录)/ 403(登录但无 users:admin)/ 200(superadmin)。
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

    let t = bearer(&state, "superadmin").await;
    let (s, body) = get(&app, "/api/v1/admin/auth/me", Some(&t)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("superadmin"), "应返回当前管理员: {body}");
}

/// admin_login:superadmin → 200 + 双 cookie;user 凭据对但无 users:admin → 403 且**零 Set-Cookie**。
#[tokio::test]
async fn admin_login_rejects_non_admin_without_tokens() {
    let (app, _state) = setup().await;

    let resp = post_login(&app, "/api/v1/admin/auth/login", "superadmin").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies.len(), 2, "access + refresh cookie");

    let resp = post_login(&app, "/api/v1/admin/auth/login", "user").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "403 不得发任何 cookie"
    );
}

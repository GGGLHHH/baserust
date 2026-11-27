//! auth 对外接口**契约测试**。钉死线上形状:端点 + 状态码 + body 字段 + httponly cookie + 防枚举。
//! 断言只看 JSON 字段/状态码/Set-Cookie,**不 import DTO 类型** —— 契约是"线上形状"。
//!
//! idm 削成纯库后,HTTP 边界(端点/校验/cookie)归 app,这套契约从 idm crate 搬来,改打 app 的真实
//! 路由(`build_router`,内存 repo、无 DB)—— 等于"app 拥有 auth HTTP"的黑盒回归。

use axum::body;
use baserust::app::{AppAuthService, AppContentService};
use baserust::features::profile::{InMemoryProfileRepo, ProfileService, StaticAvatarProbe};
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::features::users::{StaticProfileDirectory, UserAdminService};
use baserust::features::widget::{EventBus, MemoryEventBus};
use baserust::infra::config::Config;
use baserust::kernel::authorization::Policy;
use idm::{InMemoryMemberRepo, InMemoryTenantRepo};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 内存仓储的测试 app(无 DB);AppState 字段 pub,直接装配,过完整中间件栈打真实 auth 端点。
fn test_app() -> Router {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());
    let bus: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: ProfileService::new(
            Arc::new(InMemoryProfileRepo::new()),
            Arc::new(StaticAvatarProbe::new()),
        ),
        contents: AppContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(content::InMemoryObjectStore::new()),
            "memory",
        ),
        auth: test_auth(signer.clone(), verifier.clone()),
        user_admin: UserAdminService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory::new()),
            None,
        ),
        tenant_admin: TenantAdminService::new(
            Arc::new(InMemoryTenantRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(StaticMemberProfiles::new()),
            None,
        ),
        probes: Default::default(),
        monitoring: Default::default(),
        cookie_secure: false,
        policy: Arc::new(Policy::default()), // 这套契约不测授权
        token_signer: Some(signer),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    build_router(state, &Config::default(), Mount::Both)
}

/// 测试用 AuthService:FakeHasher(躲 argon2 ~100ms)+ 内存 repo + **生产同款非对称签验**(app 显式 claim)。
fn test_auth(signer: Arc<AppTokenSigner>, verifier: Arc<AppTokenVerifier>) -> Arc<AppAuthService> {
    let auth = AppAuthService::builder(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(InMemoryRoleRepo::new()),
        Arc::new(InMemoryMemberRepo::new()),
    )
    .hasher(FakeHasher)
    // 独立的空角色仓储:注册不授租户角色(配置了目录里没有的角色会响亮失败)
    .signup_roles(Vec::<String>::new())
    .signer(signer)
    .verifier(verifier)
    .access_ttl(time::Duration::seconds(900))
    .refresh_ttl(time::Duration::seconds(604_800))
    .build();
    Arc::new(auth)
}

async fn body_string(response: Response) -> String {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
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
fn set_cookie_line(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// 提取 Set-Cookie 里某个 cookie 的值。
fn cookie_value(response: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix(&prefix)
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
fn post_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::post(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

// ── 注册 ──

#[tokio::test]
async fn register_sets_httponly_cookie_and_returns_user() {
    let response = test_app()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            r#"{"username":"alice","email":"a@b.com","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    // token 进 httponly cookie,不进 body
    let cookies = set_cookie_line(&response);
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
    let body = body_string(response).await;
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
        .oneshot(post_json("/api/v1/public/auth/register", body))
        .await
        .unwrap();
    let response = app
        .oneshot(post_json("/api/v1/public/auth/register", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(body_string(response)
        .await
        .contains("\"code\":\"conflict\""));
}

#[tokio::test]
async fn register_weak_password_is_422() {
    // 低于 password 最小长度(min=3)→ 422;此处发 2 字符。
    let response = test_app()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            r#"{"username":"bob","email":"b@b.com","password":"ab"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn register_malformed_json_is_400() {
    let response = test_app()
        .oneshot(post_json("/api/v1/public/auth/register", r#"{not json"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── 登录 + 鉴权 ──

#[tokio::test]
async fn login_sets_cookie_then_me_works_via_cookie_and_bearer() {
    let app = test_app();
    app.clone()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            r#"{"username":"loginuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"loginuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let token = cookie_value(&response, "access_token").expect("login 应 Set-Cookie access_token");

    // cookie 鉴权
    let via_cookie = app
        .clone()
        .oneshot(get_with_cookie(
            "/api/v1/frontend/auth/me",
            &format!("access_token={token}"),
        ))
        .await
        .unwrap();
    assert_eq!(via_cookie.status(), StatusCode::OK);
    let me_body = body_string(via_cookie).await;
    assert!(me_body.contains("\"username\":\"loginuser\""));
    assert!(
        me_body.contains("\"roles\":[]"),
        "新用户 roles 应为空数组: {me_body}"
    );

    // Bearer 兜底(同一 token 也认)
    let via_bearer = app
        .oneshot(get_with_bearer("/api/v1/frontend/auth/me", &token))
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
            "/api/v1/public/auth/register",
            r#"{"username":"realuser","password":"password123"}"#,
        ))
        .await
        .unwrap();

    let wrong_password = app
        .clone()
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"realuser","password":"WRONGpass1"}"#,
        ))
        .await
        .unwrap();
    let unknown = app
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"nobody","password":"password123"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(wrong_password).await,
        body_string(unknown).await,
        "密码错与用户不存在的响应必须逐字节相同(防枚举)"
    );
}

// ── 受保护端点 ──

#[tokio::test]
async fn me_without_credentials_is_401() {
    let response = test_app()
        .oneshot(get_plain("/api/v1/frontend/auth/me"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_with_garbage_cookie_is_401() {
    let response = test_app()
        .oneshot(get_with_cookie(
            "/api/v1/frontend/auth/me",
            "access_token=garbage.token.xxx",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── 登出 ──

#[tokio::test]
async fn logout_clears_cookies_and_204() {
    let response = test_app()
        .oneshot(
            Request::post("/api/v1/public/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // 清除 = 回收同名 cookie(Max-Age=0 / 空值)
    let cookies = set_cookie_line(&response);
    assert!(
        cookies.contains("access_token="),
        "logout 应回收 access cookie: {cookies}"
    );
    assert!(
        cookies.contains("refresh_token="),
        "logout 应回收 refresh cookie: {cookies}"
    );
}

/// refresh 轮换:旧 refresh 一次性 —— 刷新后发新 token,旧的失效(防重放)。
#[tokio::test]
async fn refresh_rotates_and_old_token_is_revoked() {
    let app = test_app();
    app.clone()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            r#"{"username":"refuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    let login = app
        .clone()
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"refuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    let old = cookie_value(&login, "refresh_token").expect("login 应发 refresh cookie");

    // 带 refresh cookie 刷新 → 200 + 轮换出新 refresh
    let response = app
        .clone()
        .oneshot(post_with_cookie(
            "/api/v1/public/auth/refresh",
            &format!("refresh_token={old}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let new = cookie_value(&response, "refresh_token").expect("refresh 应发新 refresh cookie");
    assert_ne!(old, new, "refresh 应轮换:新旧 token 不同");

    // 旧 refresh 已撤销 → 再用 → 401(防重放)
    let reuse = app
        .oneshot(post_with_cookie(
            "/api/v1/public/auth/refresh",
            &format!("refresh_token={old}"),
        ))
        .await
        .unwrap();
    assert_eq!(
        reuse.status(),
        StatusCode::UNAUTHORIZED,
        "旧 refresh 轮换后应失效"
    );
}

// ── me 修改 ──

/// 带 cookie 的任意方法请求(PATCH/DELETE/POST + 可选 json body)。
fn request_with_cookie(method: &str, uri: &str, cookie: &str, json: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie);
    let body = if let Some(json_body) = json {
        builder = builder.header("content-type", "application/json");
        Body::from(json_body.to_owned())
    } else {
        Body::empty()
    };
    builder.body(body).unwrap()
}

/// 注册一个用户,返回 register 响应(含 Set-Cookie)。
async fn register_user(app: &Router, username: &str, password: &str) -> Response {
    app.clone()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            &format!(r#"{{"username":"{username}","password":"{password}"}}"#),
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn update_me_changes_username() {
    let app = test_app();
    let registered = register_user(&app, "upduser", "password123").await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .oneshot(request_with_cookie(
            "PUT",
            "/api/v1/frontend/auth/me",
            &cookie,
            Some(r#"{"username":"upduser2"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_string(response)
        .await
        .contains("\"username\":\"upduser2\""));
}

#[tokio::test]
async fn delete_me_soft_deletes_and_blocks_login() {
    let app = test_app();
    let registered = register_user(&app, "deluser", "password123").await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "DELETE",
            "/api/v1/frontend/auth/me",
            &cookie,
            Some(r#"{"password":"password123"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // 软删后再登录 → 401
    let relogin = app
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"deluser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(relogin.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_old_fails_new_works() {
    let app = test_app();
    let registered = register_user(&app, "pwuser", "password123").await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "POST",
            "/api/v1/frontend/auth/me/password",
            &cookie,
            Some(r#"{"current_password":"password123","new_password":"newpass456"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // 旧密码 → 401,新密码 → 200
    let old = app
        .clone()
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"pwuser","password":"password123"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED, "旧密码应失效");
    let new = app
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"pwuser","password":"newpass456"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(new.status(), StatusCode::OK, "新密码应可登录");
}

// ── 进程内 seed ──

/// 走真实 `AppState::try_new`(非 test_app 直构)→ dev 内存模式启动时进程内 seed:
/// seed.toml 的 superadmin/pwd 可登录、且带 superadmin 角色。覆盖 test_app 绕过的 seed 路径。
/// 用真 Argon2(seed 与登录验密同一把),稍慢但端到端证明 seed 生效。
#[tokio::test]
async fn in_process_seed_lets_superadmin_log_in() {
    let config = Config::default(); // dev → seed_on_start = true
    let state = AppState::try_new(&config, Mount::Both).await.unwrap().state;
    let app = build_router(state, &config, Mount::Both);

    let response = app
        .oneshot(post_json(
            "/api/v1/public/auth/login",
            r#"{"identifier":"superadmin","password":"pwd"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "seed 的 superadmin 应能登录"
    );
    let body = body_string(response).await;
    assert!(body.contains("\"username\":\"superadmin\""), "body: {body}");
    assert!(
        body.contains("\"roles\":[\"superadmin\"]"),
        "superadmin 应被授予 superadmin 角色: {body}"
    );
}

//! widget API 集成测试 —— lib.rs 拆分解锁的能力:
//! tests/ 直接 import 库、用内存仓储 oneshot 打**真实端点**(过完整中间件栈),无需数据库。
//! 加业务模块后,照此对其端点写黑盒测试。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use uuid::Uuid;

use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};
use xchangeai::app::{build_router, AppState};
use xchangeai::features::auth::AppTokens;
use xchangeai::features::widget::{InMemoryWidgetRepo, WidgetService};
use xchangeai::infra::authz::{Perm, Policy};

/// 内存仓储的测试 app(无 DB)+ **admin 令牌**(widget 端点现需登录 + RBAC + ownership)。
/// admin 有 read:all → 看全部,故沿用原有"建后即见"断言;struct 直建不跑 mock seed,repo 空、不受干扰。
fn test_app() -> (Router, String) {
    let tokens = Arc::new(AppTokens::new("test-secret"));
    // admin 满权令牌(roles=[admin],scope 空):mint 即可,不必走真实登录。
    let admin = tokens
        .mint_scoped(Uuid::nil(), "admin", vec!["admin".to_owned()], vec![], 900)
        .unwrap();
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(xchangeai::features::widget::StaticUserDirectory::empty()),
        ),
        auth: test_auth(tokens.clone()),
        db_pool: None, // 内存模式:readyz 恒就绪
        cookie_secure: false,
        policy: Arc::new(test_policy()),
        tokens,
    };
    let app = build_router(
        state,
        &xchangeai::infra::config::Config::default(),
        xchangeai::app::Mount::Both,
    );
    (app, admin)
}

/// 测试授权策略:admin 角色拿全部 widget 权限(含 read:all → 看全部)。
fn test_policy() -> Policy {
    Policy::from_roles([(
        "admin".to_owned(),
        vec![
            Perm::WidgetRead,
            Perm::WidgetReadAll,
            Perm::WidgetWrite,
            Perm::WidgetDelete,
        ],
    )])
}

/// 测试用 AuthService:FakeHasher + 内存 repo + **生产同款 AppTokens**(claim 带 roles,中间件才认)。
fn test_auth(tokens: Arc<AppTokens>) -> AuthService {
    AuthService::builder(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(InMemoryRoleRepo::new()),
    )
    .hasher(Arc::new(FakeHasher))
    .signer(tokens.clone())
    .verifier(tokens)
    .access_ttl_secs(900)
    .refresh_ttl_secs(604_800)
    .build()
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, json: &str, token: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn health_ok() {
    let (app, tok) = test_app();
    let resp = app.oneshot(get("/health", &tok)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// widget 端点**必须登录**:无 token → 401。
#[tokio::test]
async fn widgets_require_auth_401() {
    let (app, _tok) = test_app();
    let resp = app
        .oneshot(Request::get("/api/v1/widgets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_then_list_offset() {
    let (app, tok) = test_app();
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/widgets", r#"{"name":"alpha"}"#, &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app.oneshot(get("/api/v1/widgets", &tok)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("alpha"));
    // 默认 offset 模式,PageInfo 内部标签 mode=offset
    assert!(body.contains("\"mode\":\"offset\""));
}

#[tokio::test]
async fn cursor_first_page_ok() {
    let (app, tok) = test_app();
    app.clone()
        .oneshot(post_json("/api/v1/widgets", r#"{"name":"a"}"#, &tok))
        .await
        .unwrap();
    // 空 cursor = cursor 模式首页
    let resp = app
        .oneshot(get("/api/v1/widgets?cursor=&size=2", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("\"mode\":\"cursor\""));
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(post_json("/api/v1/widgets", r#"{"name":""}"#, &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get("/api/v1/widgets?cursor=!!!bad", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get("/api/v1/widgets?page=1&cursor=xxx", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn missing_widget_is_404() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get(
            "/api/v1/widgets/00000000-0000-0000-0000-000000000000",
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

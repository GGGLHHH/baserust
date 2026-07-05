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
    let bus: Arc<dyn xchangeai::features::widget::EventBus> =
        Arc::new(xchangeai::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(xchangeai::features::widget::StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: xchangeai::features::profile::ProfileService::new(
            std::sync::Arc::new(xchangeai::features::profile::InMemoryProfileRepo::new()),
            std::sync::Arc::new(xchangeai::features::profile::StaticAvatarProbe::empty()),
        ),
        contents: test_contents(),
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

/// 测试用 content 服务:全内存(repo + ObjectStore),不碰 DB/minio。
fn test_contents() -> content::ContentService {
    content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
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

fn put_json(uri: &str, json: &str, token: &str) -> Request<Body> {
    Request::put(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json.to_owned()))
        .unwrap()
}

fn delete_req(uri: &str, token: &str) -> Request<Body> {
    Request::delete(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// 建后从 201 响应体取 id(响应是 `Widget` JSON)。
async fn created_id(resp: Response) -> String {
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    v["id"].as_str().unwrap().to_owned()
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
        .oneshot(
            Request::get("/api/v1/frontend/widgets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_then_list_offset() {
    let (app, tok) = test_app();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"alpha"}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .oneshot(get("/api/v1/frontend/widgets", &tok))
        .await
        .unwrap();
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
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"a"}"#,
            &tok,
        ))
        .await
        .unwrap();
    // 空 cursor = cursor 模式首页
    let resp = app
        .oneshot(get("/api/v1/frontend/widgets?cursor=&size=2", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("\"mode\":\"cursor\""));
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":""}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get("/api/v1/frontend/widgets?cursor=!!!bad", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get("/api/v1/frontend/widgets?page=1&cursor=xxx", &tok))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn missing_widget_is_404() {
    let (app, tok) = test_app();
    let resp = app
        .oneshot(get(
            "/api/v1/frontend/widgets/00000000-0000-0000-0000-000000000000",
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 重名 → **409**:name 存活行内全局唯一,重复 create → Conflict(DB 约束违例下钻,非 500)。
#[tokio::test]
async fn duplicate_name_is_409() {
    let (app, tok) = test_app();
    let first = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"dup"}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let dup = app
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"dup"}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

/// PUT **全量替换**:建后 PUT 改名 → 200,且改名生效(写动词状态码端到端契约)。
#[tokio::test]
async fn put_full_replace_renames_returns_200() {
    let (app, tok) = test_app();
    let created = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"before"}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let id = created_id(created).await;

    let put = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/widgets/{id}"),
            r#"{"name":"after"}"#,
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    assert!(body_string(put).await.contains("after"));

    let got = app
        .oneshot(get(&format!("/api/v1/frontend/widgets/{id}"), &tok))
        .await
        .unwrap();
    assert!(body_string(got).await.contains("after"), "改名应持久");
}

/// DELETE **软删** → 204,且删后 GET → 404(204 契约 + 软删后不可见)。
#[tokio::test]
async fn delete_soft_deletes_returns_204_then_404() {
    let (app, tok) = test_app();
    let created = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"doomed"}"#,
            &tok,
        ))
        .await
        .unwrap();
    let id = created_id(created).await;

    let del = app
        .clone()
        .oneshot(delete_req(&format!("/api/v1/frontend/widgets/{id}"), &tok))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let got = app
        .oneshot(get(&format!("/api/v1/frontend/widgets/{id}"), &tok))
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::NOT_FOUND, "软删后应 404");
}

/// SSE:开流 → create → 第一帧就是 created 事件(keep-alive 15s 远大于测试窗口,不会先到)。
#[tokio::test]
async fn sse_stream_receives_created_event() {
    use futures_util::StreamExt;
    let (app, admin) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body().into_data_stream();

    // handler 返回时订阅已建立 → 此刻 create 必被本流看到
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/v1/frontend/widgets")
                .header("authorization", format!("Bearer {admin}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"sse-demo"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
        .await
        .expect("5s 内应收到 SSE 帧")
        .expect("流不应结束")
        .unwrap();
    let text = String::from_utf8(frame.to_vec()).unwrap();
    assert!(text.contains("event: created"), "应是 created 帧: {text}");
    assert!(
        text.contains(r#""name":"sse-demo""#),
        "应含 widget JSON: {text}"
    );
}

/// 未认证 → 401(EventSource 只能靠 cookie/无 header,这里用无凭据模拟)。
#[tokio::test]
async fn sse_requires_auth() {
    let (app, _admin) = test_app();
    let resp = app
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 降权令牌(scope 只有 write,无 read)→ 403:scope 只收窄不放大。
#[tokio::test]
async fn sse_requires_read_scope() {
    let (app, _admin) = test_app();
    let tokens = AppTokens::new("test-secret"); // 与 test_app 同 secret,验签才过
    let scoped = tokens
        .mint_scoped(
            Uuid::nil(),
            "admin",
            vec!["admin".to_owned()],
            vec![Perm::WidgetWrite],
            900,
        )
        .unwrap();
    let resp = app
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .header("authorization", format!("Bearer {scoped}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

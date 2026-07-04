//! content API 集成测试 —— 内存 AppState(repo + ObjectStore 全内存,无 DB/无 minio),
//! oneshot 过完整中间件栈打**真实端点**。镜像 widget_api 的黑盒风格。
//!
//! 覆盖:multipart 上传→下载往返、get/list、401(未认证)、403(缺 contents:write)、404(不存在)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use uuid::Uuid;

use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};
use xchangeai::app::{build_router, AppState, Mount};
use xchangeai::features::auth::AppTokens;
use xchangeai::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use xchangeai::infra::authz::{Perm, Policy};

/// 内存 app + 两枚令牌:`admin`(read+write+delete)与 `viewer`(只 read)。
/// admin/viewer 各有独立 owner uuid(content list 按 owner 过滤,故 admin 上传 admin 才看得到)。
fn test_app() -> (Router, String, String) {
    let tokens = Arc::new(AppTokens::new("test-secret"));
    let admin = tokens
        .mint_scoped(
            Uuid::from_u128(1),
            "admin",
            vec!["admin".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    let viewer = tokens
        .mint_scoped(
            Uuid::from_u128(2),
            "viewer",
            vec!["viewer".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
        ),
        contents: content::ContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(content::InMemoryObjectStore::new()),
            "memory",
        ),
        auth: test_auth(tokens.clone()),
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(test_policy()),
        tokens,
    };
    let app = build_router(
        state,
        &xchangeai::infra::config::Config::default(),
        Mount::Both,
    );
    (app, admin, viewer)
}

/// admin → 全 content 权;viewer → 只读(用于 403 用例)。
fn test_policy() -> Policy {
    Policy::from_roles([
        (
            "admin".to_owned(),
            vec![Perm::ContentRead, Perm::ContentWrite, Perm::ContentDelete],
        ),
        ("viewer".to_owned(), vec![Perm::ContentRead]),
    ])
}

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

async fn body_bytes(resp: Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn body_string(resp: Response) -> String {
    String::from_utf8(body_bytes(resp).await).unwrap()
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

/// 手搓 multipart/form-data 体:file(带 filename + content-type)+ name + tags 三部分。
fn upload_req(token: &str, file_name: &str, content_type: &str, data: &[u8]) -> Request<Body> {
    let boundary = "BOUNDARYtest123";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\ndoc\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"tags\"\r\n\r\na,b\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Request::post("/api/v1/contents/upload")
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

/// 从上传 201 响应体取 content.id(响应是 `UploadResponse` JSON)。
async fn uploaded_content_id(resp: Response) -> String {
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    v["content"]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn upload_then_download_round_trip() {
    let (app, admin, _viewer) = test_app();
    let payload = b"hello content bytes";
    let up = app
        .clone()
        .oneshot(upload_req(&admin, "hello.txt", "text/plain", payload))
        .await
        .unwrap();
    assert_eq!(up.status(), StatusCode::CREATED);
    let body = body_string(up).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["content"]["status"], "uploaded");
    assert_eq!(v["object"]["status"], "uploaded");
    let id = v["content"]["id"].as_str().unwrap().to_owned();

    // 下载主对象:字节原样取回,Content-Type 取自元数据。
    let down = app
        .oneshot(get(&format!("/api/v1/contents/{id}/download"), &admin))
        .await
        .unwrap();
    assert_eq!(down.status(), StatusCode::OK);
    let ct = down
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        ct.starts_with("text/plain"),
        "content-type 应来自元数据: {ct}"
    );
    assert_eq!(body_bytes(down).await, payload);
}

#[tokio::test]
async fn upload_then_get_and_list() {
    let (app, admin, _viewer) = test_app();
    let up = app
        .clone()
        .oneshot(upload_req(
            &admin,
            "f.bin",
            "application/octet-stream",
            b"xyz",
        ))
        .await
        .unwrap();
    let id = uploaded_content_id(up).await;

    // get 单条
    let got = app
        .clone()
        .oneshot(get(&format!("/api/v1/contents/{id}"), &admin))
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert!(body_string(got).await.contains(&id));

    // list:owner=admin → 含刚建的
    let list = app.oneshot(get("/api/v1/contents", &admin)).await.unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    assert!(body_string(list).await.contains(&id));
}

/// content 端点**必须登录**:无 token → 401。
#[tokio::test]
async fn contents_require_auth_401() {
    let (app, _admin, _viewer) = test_app();
    let resp = app
        .oneshot(
            Request::get("/api/v1/contents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 缺 `contents:write`:viewer(只 read)POST /contents → 403(认证了但权限不够)。
#[tokio::test]
async fn create_without_write_perm_403() {
    let (app, _admin, viewer) = test_app();
    let resp = app
        .oneshot(post_json("/api/v1/contents", r#"{}"#, &viewer))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// 不存在的 content → 404。
#[tokio::test]
async fn missing_content_is_404() {
    let (app, admin, _viewer) = test_app();
    let resp = app
        .oneshot(get(
            "/api/v1/contents/00000000-0000-0000-0000-000000000000",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

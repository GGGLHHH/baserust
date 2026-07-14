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

use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use baserust::infra::authz::{Perm, Policy};
use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 内存 app + 两枚令牌:`admin`(read+write+delete)与 `viewer`(只 read),store 可注入
/// (presign 用例喂覆写 URL 方法的假 store)。admin/viewer 各有独立 owner uuid(content list 按
/// owner 过滤,故 admin 上传 admin 才看得到)。
fn test_app_with_store(store: Arc<dyn content::ObjectStore>) -> (Router, String, String) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());
    let admin = signer
        .mint_scoped(
            Uuid::from_u128(1),
            "admin",
            vec!["admin".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    let viewer = signer
        .mint_scoped(
            Uuid::from_u128(2),
            "viewer",
            vec!["viewer".to_owned()],
            vec![],
            900,
        )
        .unwrap();
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
            store,
            "memory",
        ),
        auth: test_auth(signer.clone(), verifier.clone()),
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
        policy: Arc::new(test_policy()),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
    };
    let app = build_router(
        state,
        &baserust::infra::config::Config::default(),
        Mount::Both,
    );
    (app, admin, viewer)
}

fn test_app() -> (Router, String, String) {
    test_app_with_store(Arc::new(content::InMemoryObjectStore::new()))
}

/// admin → 全 content 权;viewer → 只读(用于 403 用例)。
fn test_policy() -> Policy {
    Policy::from_roles([
        (
            "admin".to_owned(),
            vec![Perm::ContentRead, Perm::ContentWrite, Perm::ContentDelete],
        ),
        ("viewer".to_owned(), vec![Perm::ContentRead]),
        // 跨用户管理位:验证 :all 是 ownership 的 mode 开关(非 gate)
        (
            "auditor".to_owned(),
            vec![
                Perm::ContentRead,
                Perm::ContentReadAll,
                Perm::ContentWrite,
                Perm::ContentWriteAll,
                Perm::ContentDelete,
            ],
        ),
    ])
}

fn test_auth(signer: Arc<AppTokenSigner>, verifier: Arc<AppTokenVerifier>) -> AuthService {
    AuthService::builder(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(InMemoryRoleRepo::new()),
    )
    .hasher(Arc::new(FakeHasher))
    .signer(signer)
    .verifier(verifier)
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
    Request::post("/api/v1/frontend/contents/upload")
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
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/download"),
            &admin,
        ))
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
        .oneshot(get(&format!("/api/v1/frontend/contents/{id}"), &admin))
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert!(body_string(got).await.contains(&id));

    // list:owner=admin → 含刚建的
    let list = app
        .oneshot(get("/api/v1/frontend/contents", &admin))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    assert!(body_string(list).await.contains(&id));
}

/// content 端点**必须登录**:无 token → 401。
#[tokio::test]
async fn contents_require_auth_401() {
    let (app, _admin, _viewer) = test_app();
    let resp = app
        .oneshot(
            Request::get("/api/v1/frontend/contents")
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
        .oneshot(post_json("/api/v1/frontend/contents", r#"{}"#, &viewer))
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
            "/api/v1/frontend/contents/00000000-0000-0000-0000-000000000000",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 代理回退路径(memory 后端,presign 不可用):preview 直接吐字节,inline + 上传时的 mime。
#[tokio::test]
async fn preview_proxies_bytes_inline_on_memory_backend() {
    let (app, admin, _) = test_app();
    let resp = app
        .clone()
        .oneshot(upload_req(&admin, "a.png", "image/png", b"png-bytes"))
        .await
        .unwrap();
    let id = uploaded_content_id(resp).await;
    let resp = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "image/png");
    assert!(resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("inline"));
    // inline + 用户可控 mime = XSS 面,sandbox 必须在(恶意 html/svg 拿不到 app origin)。
    assert_eq!(resp.headers()["content-security-policy"], "sandbox");
    assert_eq!(body_bytes(resp).await, b"png-bytes".to_vec());
}

/// 活动内容(text/html、svg 等)预览必须**降级 attachment**,绝不 inline —— presign 拓扑下 app 加不了
/// CSP 且与 app 同源,inline 渲染即同源无 CSP 的存储型 XSS。栅格图仍 inline(见上一测试)。
#[tokio::test]
async fn preview_forces_attachment_for_active_content() {
    let (app, admin, _) = test_app();
    let resp = app
        .clone()
        .oneshot(upload_req(
            &admin,
            "x.html",
            "text/html",
            b"<script>alert(1)</script>",
        ))
        .await
        .unwrap();
    let id = uploaded_content_id(resp).await;
    let resp = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment"),
        "活动内容必须降级 attachment,不能 inline 渲染"
    );
}

/// presign 路径:注入覆写 URL 方法的 store → 307 + Location;download 的 Location 带 filename
/// (上传后改名,Location 必须签新名,证伪 metadata 优先决议)。
#[tokio::test]
async fn preview_and_download_redirect_when_presign_available() {
    let (app, admin, _) =
        test_app_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new())));
    let resp = app
        .clone()
        .oneshot(upload_req(&admin, "a.png", "image/png", b"x"))
        .await
        .unwrap();
    let id = uploaded_content_id(resp).await;

    // 证伪"metadata 优先":把元数据里的 filename 改掉(object 行仍是 a.png),
    // download 的签名 URL 必须用新名 —— 只读 object 行的退化实现会在这里翻车。
    let resp = app
        .clone()
        .oneshot(
            Request::put(format!("/api/v1/frontend/contents/{id}/metadata"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::from(
                    r#"{"tags":[],"file_name":"renamed.pdf","mime_type":"image/png"}"#.to_owned(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    for (path, want) in [
        (format!("/api/v1/frontend/contents/{id}/preview"), "?inline"),
        (
            format!("/api/v1/frontend/contents/{id}/download"),
            "dl=renamed.pdf",
        ),
    ] {
        let resp = app.clone().oneshot(get(&path, &admin)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        // no-store 防错配置 CDN/代理缓存 300s 签名 URL —— 回归不可见就是白加。
        assert_eq!(resp.headers()["cache-control"], "no-store", "{path}");
        assert!(
            resp.headers()["location"].to_str().unwrap().contains(want),
            "{path}: {:?}",
            resp.headers()["location"]
        );
    }
}

/// 错误语义不变:未上传(仅 create)→ preview 409;未认证 → 401。
#[tokio::test]
async fn preview_guards_not_ready_and_auth() {
    let (app, admin, _) = test_app();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents",
            r#"{"name":"raw"}"#,
            &admin,
        ))
        .await
        .unwrap();
    // create 响应是扁平 ContentResponse(非 upload 的 {content,object} 形状),直接取 id。
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let id = v["id"].as_str().unwrap().to_owned();
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT); // NotReady → 409

    let resp = app
        .oneshot(
            Request::get(format!("/api/v1/frontend/contents/{id}/preview"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 覆写 URL 方法的测试 store(字节走内存):验证 handler 的 307 分支与 Location 透传。
struct PresignStore(content::InMemoryObjectStore);

#[async_trait::async_trait]
impl content::ObjectStore for PresignStore {
    async fn upload(
        &self,
        p: content::UploadParams,
        d: bytes::Bytes,
    ) -> Result<(), content::ContentError> {
        self.0.upload(p, d).await
    }
    async fn download(&self, k: &str) -> Result<bytes::Bytes, content::ContentError> {
        self.0.download(k).await
    }
    async fn delete(&self, k: &str) -> Result<(), content::ContentError> {
        self.0.delete(k).await
    }
    async fn object_meta(&self, k: &str) -> Result<content::ObjectMeta, content::ContentError> {
        self.0.object_meta(k).await
    }
    async fn download_url(
        &self,
        k: &str,
        f: Option<&str>,
    ) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!(
            "https://cdn.test/{k}?dl={}",
            f.unwrap_or("-")
        )))
    }
    async fn preview_url(&self, k: &str) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!("https://cdn.test/{k}?inline")))
    }
    async fn upload_url(
        &self,
        k: &str,
        mime: Option<&str>,
    ) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!(
            "https://cdn.test/put/{k}?mime={}",
            mime.unwrap_or("-")
        )))
    }
}

/// 两步上传(memory 全流程):prepare → 201 + upload_url null(回退信号)+ 双 Created;
/// 模拟客户端 PUT(直写注入的 store)→ confirm → 200 uploaded → preview 可读。
#[tokio::test]
async fn two_step_upload_full_flow_on_memory() {
    use content::ObjectStore as _; // store.upload(...) 是 trait 方法,须引入 trait
    let store = Arc::new(content::InMemoryObjectStore::new());
    let (app, admin, _) = test_app_with_store(store.clone());
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            r#"{"name":"two-step","file_name":"a.txt","mime_type":"text/plain","tags":["t"]}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert!(v["upload_url"].is_null(), "memory 后端应给回退信号");
    assert_eq!(v["content"]["status"], "created");
    assert_eq!(v["object"]["status"], "created");
    let id = v["content"]["id"].as_str().unwrap().to_owned();
    let key = v["object"]["object_key"].as_str().unwrap().to_owned();

    // 未传就销账 → 409(NotReady)
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 模拟第二步:客户端 PUT(直写同一个 store)
    store
        .upload(
            content::UploadParams {
                object_key: key,
                mime_type: Some("text/plain".to_owned()),
                file_name: None,
            },
            bytes::Bytes::from_static(b"two-step bytes"),
        )
        .await
        .unwrap();

    // 销账 → uploaded;preview 能读回
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["status"], "uploaded");

    // 幂等重试(网络抖动重发)在 HTTP 边界也必须 200,不是 409。
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"two-step bytes".to_vec());
}

/// presign 后端:upload_url 非空且 mime 透传(签进凭证的前提)。
#[tokio::test]
async fn prepare_returns_signed_url_when_backend_supports() {
    let (app, admin, _) =
        test_app_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new())));
    let resp = app
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            r#"{"file_name":"b.png","mime_type":"image/png"}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let url = v["upload_url"].as_str().expect("该后端应给凭证");
    assert!(url.contains("mime=image/png"), "{url}");
}

/// 鉴权:viewer(无 write)prepare → 403;无凭据 confirm → 401。
#[tokio::test]
async fn two_step_endpoints_enforce_authz() {
    let (app, _admin, viewer) = test_app();
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            "{}",
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = app
        .oneshot(
            Request::post(
                "/api/v1/frontend/contents/00000000-0000-0000-0000-000000000000/confirm-upload",
            )
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 行级 ownership:非 owner 的单条读写一律 404(不区分,防泄露存在);
/// `contents:read:all` / `contents:write:all` 是 mode 开关 —— 持有者跨用户可读可删。
#[tokio::test]
async fn cross_user_content_is_404_unless_all_mode() {
    let (app, admin, viewer) = test_app();
    let resp = app
        .clone()
        .oneshot(upload_req(&admin, "own.txt", "text/plain", b"secret"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = uploaded_content_id(resp).await;

    // viewer(有 contents:read,无 :all)读他人的 → 404(不是 200,也不是 403)
    for uri in [
        format!("/api/v1/frontend/contents/{id}"),
        format!("/api/v1/frontend/contents/{id}/download"),
        format!("/api/v1/frontend/contents/{id}/objects"),
        format!("/api/v1/frontend/contents/{id}/metadata"),
    ] {
        let resp = app.clone().oneshot(get(&uri, &viewer)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri} 非本人应 404");
    }

    // preview 折中:非 owner 的非图片 → 404(否则 download 的 404 守卫被兄弟端点绕过)
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "非 owner 预览非图片应 404"
    );
    // 非 owner 的 image/* 也 404:preview 严格按 owner 隔离,不再放行任意图片。
    // 头像跨用户展示改走 /profiles/{id}/avatar 专用端点(见 profile_api),不从这里绕过。
    let resp = app
        .clone()
        .oneshot(upload_req(&admin, "a.png", "image/png", b"\x89PNG"))
        .await
        .unwrap();
    let img_id = uploaded_content_id(resp).await;
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{img_id}/preview"),
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "非 owner 预览图片也应 404(严格 owner 隔离)"
    );

    // auditor(read:all + write:all)跨用户读 → 200,删 → 204
    let signer = AppTokenSigner::dev();
    let auditor = signer
        .mint_scoped(
            Uuid::from_u128(3),
            "auditor",
            vec!["auditor".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/frontend/contents/{id}"), &auditor))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "read:all 应可读他人内容");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/frontend/contents/{id}"))
                .header("authorization", format!("Bearer {auditor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "write:all 应可删他人内容"
    );

    // owner 本人始终可读自己的(已被删 → 404 属正常;此处验证的是删除前 admin 可读,上面用例已覆盖)
}

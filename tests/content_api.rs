//! content API 集成测试 —— 内存 AppState(repo + ObjectStore 全内存,无 DB/无 minio),
//! oneshot 过完整中间件栈打**真实端点**。镜像 widget_api 的黑盒风格。
//!
//! 覆盖:multipart 上传→下载往返、get/list、401(未认证)、403(缺 contents:write)、404(不存在)。

use axum::body;
use baserust::app::{AppAuthService, AppContentService};
use baserust::features::auth::ScopedTenant;
use baserust::features::profile::{InMemoryProfileRepo, ProfileService, StaticAvatarProbe};
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::features::users::{StaticProfileDirectory, UserAdminService};
use baserust::features::widget::{EventBus, MemoryEventBus};
use baserust::infra::config::Config;
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use bytes::Bytes;
use idm::{InMemoryMemberRepo, InMemoryTenantRepo};
use serde_json::Value;
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
use baserust::kernel::authorization::{Permission, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 内存 app + 两枚令牌:`admin`(read+write+delete)与 `viewer`(只 read),store 可注入
/// (presign 用例喂覆写 URL 方法的假 store)。admin/viewer 各有独立 owner uuid(content list 按
/// owner 过滤,故 admin 上传 admin 才看得到)。
fn test_app_with_store(store: Arc<dyn content::ObjectStore>) -> TestApp {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());
    let admin = signer
        .mint_scoped(
            Uuid::from_u128(1),
            "admin",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["admin".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
    let viewer = signer
        .mint_scoped(
            Uuid::from_u128(2),
            "viewer",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["viewer".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
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
            store,
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
        policy: Arc::new(test_policy()),
        token_signer: Some(signer),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(state, &Config::default(), Mount::Both);
    TestApp { app, admin, viewer }
}

/// 内存 app 及其两枚令牌。
struct TestApp {
    app: Router,
    /// admin 的令牌(content 全权)。
    admin: String,
    /// viewer 的令牌(只读)。
    viewer: String,
}

fn test_app() -> TestApp {
    test_app_with_store(Arc::new(content::InMemoryObjectStore::new()))
}

/// admin → 全 content 权;viewer → 只读(用于 403 用例)。
fn test_policy() -> Policy {
    Policy::new([
        (
            "admin".to_owned(),
            vec![
                Permission::ContentRead,
                Permission::ContentWrite,
                Permission::ContentDelete,
            ],
        ),
        ("viewer".to_owned(), vec![Permission::ContentRead]),
        // 跨用户管理位:验证 :all 是 ownership 的 mode 开关(非 gate)
        (
            "auditor".to_owned(),
            vec![
                Permission::ContentRead,
                Permission::ContentReadAll,
                Permission::ContentWrite,
                Permission::ContentWriteAll,
                Permission::ContentDelete,
            ],
        ),
    ])
}

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

async fn body_bytes(response: Response) -> Vec<u8> {
    body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn body_string(response: Response) -> String {
    String::from_utf8(body_bytes(response).await).unwrap()
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
fn upload_request(token: &str, file_name: &str, content_type: &str, data: &[u8]) -> Request<Body> {
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
async fn uploaded_content_id(response: Response) -> String {
    let uploaded: Value = serde_json::from_str(&body_string(response).await).unwrap();
    uploaded["content"]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn upload_then_download_round_trip() {
    let TestApp { app, admin, .. } = test_app();
    let payload = b"hello content bytes";
    let upload_response = app
        .clone()
        .oneshot(upload_request(&admin, "hello.txt", "text/plain", payload))
        .await
        .unwrap();
    assert_eq!(upload_response.status(), StatusCode::CREATED);
    let body = body_string(upload_response).await;
    let uploaded: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(uploaded["content"]["status"], "uploaded");
    assert_eq!(uploaded["object"]["status"], "uploaded");
    let id = uploaded["content"]["id"].as_str().unwrap().to_owned();

    // 下载主对象:字节原样取回,Content-Type 取自元数据。
    let download_response = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/download"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(download_response.status(), StatusCode::OK);
    let content_type = download_response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        content_type.starts_with("text/plain"),
        "content-type 应来自元数据: {content_type}"
    );
    assert_eq!(body_bytes(download_response).await, payload);
}

#[tokio::test]
async fn upload_then_get_and_list() {
    let TestApp { app, admin, .. } = test_app();
    let upload_response = app
        .clone()
        .oneshot(upload_request(
            &admin,
            "f.bin",
            "application/octet-stream",
            b"xyz",
        ))
        .await
        .unwrap();
    let id = uploaded_content_id(upload_response).await;

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
    let TestApp { app, .. } = test_app();
    let response = app
        .oneshot(
            Request::get("/api/v1/frontend/contents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 缺 `contents:write`:viewer(只 read)POST /contents → 403(认证了但权限不够)。
#[tokio::test]
async fn create_without_write_perm_403() {
    let TestApp { app, viewer, .. } = test_app();
    let response = app
        .oneshot(post_json("/api/v1/frontend/contents", r#"{}"#, &viewer))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 不存在的 content → 404。
#[tokio::test]
async fn missing_content_is_404() {
    let TestApp { app, admin, .. } = test_app();
    let response = app
        .oneshot(get(
            "/api/v1/frontend/contents/00000000-0000-0000-0000-000000000000",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 代理回退路径(memory 后端,presign 不可用):preview 直接吐字节,inline + 上传时的 mime。
#[tokio::test]
async fn preview_proxies_bytes_inline_on_memory_backend() {
    let TestApp { app, admin, .. } = test_app();
    let response = app
        .clone()
        .oneshot(upload_request(&admin, "a.png", "image/png", b"png-bytes"))
        .await
        .unwrap();
    let id = uploaded_content_id(response).await;
    let response = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/png");
    assert!(response.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("inline"));
    // inline + 用户可控 mime = XSS 面,sandbox 必须在(恶意 html/svg 拿不到 app origin)。
    assert_eq!(response.headers()["content-security-policy"], "sandbox");
    assert_eq!(body_bytes(response).await, b"png-bytes".to_vec());
}

/// 活动内容(text/html、svg 等)预览必须**降级 attachment**,绝不 inline —— presign 拓扑下 app 加不了
/// CSP 且与 app 同源,inline 渲染即同源无 CSP 的存储型 XSS。栅格图仍 inline(见上一测试)。
#[tokio::test]
async fn preview_forces_attachment_for_active_content() {
    let TestApp { app, admin, .. } = test_app();
    let response = app
        .clone()
        .oneshot(upload_request(
            &admin,
            "x.html",
            "text/html",
            b"<script>alert(1)</script>",
        ))
        .await
        .unwrap();
    let id = uploaded_content_id(response).await;
    let response = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-disposition"]
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
    let TestApp { app, admin, .. } =
        test_app_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new())));
    let response = app
        .clone()
        .oneshot(upload_request(&admin, "a.png", "image/png", b"x"))
        .await
        .unwrap();
    let id = uploaded_content_id(response).await;

    // 证伪"metadata 优先":把元数据里的 filename 改掉(object 行仍是 a.png),
    // download 的签名 URL 必须用新名 —— 只读 object 行的退化实现会在这里翻车。
    let response = app
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
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    for (path, want) in [
        (format!("/api/v1/frontend/contents/{id}/preview"), "?inline"),
        (
            format!("/api/v1/frontend/contents/{id}/download"),
            "dl=renamed.pdf",
        ),
    ] {
        let response = app.clone().oneshot(get(&path, &admin)).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        // no-store 防错配置 CDN/代理缓存 300s 签名 URL —— 回归不可见就是白加。
        assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
        assert!(
            response.headers()["location"]
                .to_str()
                .unwrap()
                .contains(want),
            "{path}: {:?}",
            response.headers()["location"]
        );
    }
}

/// 错误语义不变:未上传(仅 create)→ preview 409;未认证 → 401。
#[tokio::test]
async fn preview_guards_not_ready_and_auth() {
    let TestApp { app, admin, .. } = test_app();
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents",
            r#"{"name":"raw"}"#,
            &admin,
        ))
        .await
        .unwrap();
    // create 响应是扁平 ContentResponse(非 upload 的 {content,object} 形状),直接取 id。
    let created: Value = serde_json::from_str(&body_string(response).await).unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT); // NotReady → 409

    let response = app
        .oneshot(
            Request::get(format!("/api/v1/frontend/contents/{id}/preview"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 覆写 URL 方法的测试 store(字节走内存):验证 handler 的 307 分支与 Location 透传。
struct PresignStore(content::InMemoryObjectStore);

#[async_trait::async_trait]
impl content::ObjectStore for PresignStore {
    async fn upload(
        &self,
        params: content::UploadRequest,
        data: Bytes,
    ) -> Result<(), content::ContentError> {
        self.0.upload(params, data).await
    }
    async fn download(&self, key: &str) -> Result<Bytes, content::ContentError> {
        self.0.download(key).await
    }
    async fn delete(&self, key: &str) -> Result<(), content::ContentError> {
        self.0.delete(key).await
    }
    async fn metadata(
        &self,
        key: &str,
    ) -> Result<content::StoredObjectMetadata, content::ContentError> {
        self.0.metadata(key).await
    }
    async fn download_url(
        &self,
        key: &str,
        file_name: Option<&str>,
    ) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!(
            "https://cdn.test/{key}?dl={}",
            file_name.unwrap_or("-")
        )))
    }
    async fn preview_url(&self, key: &str) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!("https://cdn.test/{key}?inline")))
    }
    async fn upload_url(
        &self,
        key: &str,
        mime: Option<&str>,
    ) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!(
            "https://cdn.test/put/{key}?mime={}",
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
    let TestApp { app, admin, .. } = test_app_with_store(store.clone());
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            r#"{"name":"two-step","file_name":"a.txt","mime_type":"text/plain","tags":["t"]}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let prepared: Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert!(prepared["upload_url"].is_null(), "memory 后端应给回退信号");
    assert_eq!(prepared["content"]["status"], "created");
    assert_eq!(prepared["object"]["status"], "created");
    let id = prepared["content"]["id"].as_str().unwrap().to_owned();
    let key = prepared["object"]["object_key"]
        .as_str()
        .unwrap()
        .to_owned();

    // 未传就销账 → 409(NotReady)
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // 模拟第二步:客户端 PUT(直写同一个 store)
    store
        .upload(
            {
                let mut request = content::UploadRequest::new(key);
                request.mime_type = Some("text/plain".to_owned());
                request
            },
            Bytes::from_static(b"two-step bytes"),
        )
        .await
        .unwrap();

    // 销账 → uploaded;preview 能读回
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let confirmed: Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert_eq!(confirmed["status"], "uploaded");

    // 幂等重试(网络抖动重发)在 HTTP 边界也必须 200,不是 409。
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
            "{}",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, b"two-step bytes".to_vec());
}

/// presign 后端:upload_url 非空且 mime 透传(签进凭证的前提)。
#[tokio::test]
async fn prepare_returns_signed_url_when_backend_supports() {
    let TestApp { app, admin, .. } =
        test_app_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new())));
    let response = app
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            r#"{"file_name":"b.png","mime_type":"image/png"}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let prepared: Value = serde_json::from_str(&body_string(response).await).unwrap();
    let url = prepared["upload_url"].as_str().expect("该后端应给凭证");
    assert!(url.contains("mime=image/png"), "{url}");
}

/// 鉴权:viewer(无 write)prepare → 403;无凭据 confirm → 401。
#[tokio::test]
async fn two_step_endpoints_enforce_authz() {
    let TestApp { app, viewer, .. } = test_app();
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            "{}",
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 行级 ownership:非 owner 的单条读写一律 404(不区分,防泄露存在);
/// `contents:read:all` / `contents:write:all` 是 mode 开关 —— 持有者跨用户可读可删。
#[tokio::test]
async fn cross_user_content_is_404_unless_all_mode() {
    let TestApp { app, admin, viewer } = test_app();
    let response = app
        .clone()
        .oneshot(upload_request(&admin, "own.txt", "text/plain", b"secret"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = uploaded_content_id(response).await;

    // viewer(有 contents:read,无 :all)读他人的 → 404(不是 200,也不是 403)
    for uri in [
        format!("/api/v1/frontend/contents/{id}"),
        format!("/api/v1/frontend/contents/{id}/download"),
        format!("/api/v1/frontend/contents/{id}/objects"),
        format!("/api/v1/frontend/contents/{id}/metadata"),
    ] {
        let response = app.clone().oneshot(get(&uri, &viewer)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{uri} 非本人应 404"
        );
    }

    // preview 折中:非 owner 的非图片 → 404(否则 download 的 404 守卫被兄弟端点绕过)
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{id}/preview"),
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "非 owner 预览非图片应 404"
    );
    // 非 owner 的 image/* 也 404:preview 严格按 owner 隔离,不再放行任意图片。
    // 头像跨用户展示改走 /profiles/{id}/avatar 专用端点(见 profile_api),不从这里绕过。
    let response = app
        .clone()
        .oneshot(upload_request(&admin, "a.png", "image/png", b"\x89PNG"))
        .await
        .unwrap();
    let image_id = uploaded_content_id(response).await;
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{image_id}/preview"),
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "非 owner 预览图片也应 404(严格 owner 隔离)"
    );

    // auditor(read:all + write:all)跨用户读 → 200,删 → 204
    let signer = AppTokenSigner::new_with_development_key();
    let auditor = signer
        .mint_scoped(
            Uuid::from_u128(3),
            "auditor",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["auditor".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/frontend/contents/{id}"), &auditor))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "read:all 应可读他人内容");
    let response = app
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
        response.status(),
        StatusCode::NO_CONTENT,
        "write:all 应可删他人内容"
    );

    // owner 本人始终可读自己的(已被删 → 404 属正常;此处验证的是删除前 admin 可读,上面用例已覆盖)
}

/// **mime 是服务端所有物**:上传后 `PUT /metadata` 改不动它。
///
/// 这是 presign 分支存储型 XSS 的根因闸:presign 出的 URL 只 override disposition,浏览器拿到的
/// Content-Type 恒是**上传时存进对象存储的那个**;而 inline 安全闸读的是 DB 里的 mime。两者能分叉,
/// 攻击者就能 `text/html` 上传 → 改 mime 成 `image/png` 骗过闸门 → presign 拿回 text/html + inline。
/// 让 mime 不可改,分叉不存在。
#[tokio::test]
async fn metadata_put_cannot_mutate_mime_so_gate_and_stored_ct_cannot_diverge() {
    let TestApp { app, admin, .. } =
        test_app_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new())));
    // 以 text/html 上传(存储里的 Content-Type 自此固定成 text/html)
    let upload_response = app
        .clone()
        .oneshot(upload_request(
            &admin,
            "evil.html",
            "text/html",
            b"<script>x</script>",
        ))
        .await
        .unwrap();
    assert_eq!(upload_response.status(), StatusCode::CREATED);
    let id = uploaded_content_id(upload_response).await;

    // 攻击动作:把 mime 改成惰性类型骗闸门 —— 必须无效
    let response = app
        .clone()
        .oneshot(
            Request::put(format!("/api/v1/frontend/contents/{id}/metadata"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::from(
                    r#"{"tags":[],"file_name":"evil.html","mime_type":"image/png"}"#.to_owned(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // mime 未被改写(仍是上传时那个 = 存储里那个)
    let metadata_response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/frontend/contents/{id}/metadata"))
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let metadata: Value = serde_json::from_str(&body_string(metadata_response).await).unwrap();
    assert_eq!(
        metadata["mime_type"].as_str(),
        Some("text/html"),
        "mime 必须仍是上传时的值;可改 = 能与存储里的 Content-Type 分叉"
    );

    // 闸门据此仍判"不可 inline" → 强制 attachment(presign 分支给的是下载凭证,不是 ?inline)
    let preview_response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/frontend/contents/{id}/preview"))
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preview_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = preview_response.headers()["location"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        !location.contains("?inline"),
        "活动内容绝不能拿到 inline 预览凭证: {location}"
    );
}

/// **一步上传也要校验**:multipart 是手解的,没有 `Json<T>` 那层 derive 校验 —— 本端点曾是唯一
/// 不 validate 的写 handler。上限与 JSON 两步上传(`PrepareUploadRequest`)对齐。
/// `file_name` 尤其要封顶:它会被编进 `Content-Disposition` 当 S3 PUT 的**请求头**,
/// 几十 KB 的文件名足以让后端拒绝,而 2MB body 上限随手塞得下。
#[tokio::test]
async fn upload_rejects_oversized_fields() {
    let TestApp { app, admin, .. } = test_app();

    // 超长 file_name(> 255)→ 422,而不是带着几十 KB 的头去打对象存储
    let long_name = format!("{}.txt", "a".repeat(300));
    let response = app
        .clone()
        .oneshot(upload_request(&admin, &long_name, "text/plain", b"x"))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "超长 file_name 应 422"
    );

    // 超长 mime_type(> 255)同理
    let long_mime = format!("text/{}", "b".repeat(300));
    let response = app
        .clone()
        .oneshot(upload_request(&admin, "ok.txt", &long_mime, b"x"))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "超长 mime_type 应 422"
    );

    // 正常的照常 201(别把闸收成谁都传不了)
    let response = app
        .oneshot(upload_request(&admin, "fine.txt", "text/plain", b"x"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED, "正常上传应 201");
}

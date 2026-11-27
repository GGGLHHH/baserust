//! content(内容 / 对象存储)的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架
//! (换底座只换 `http_support::serve`)。与 `content_api.rs`(axum oneshot)覆盖同一组场景并补强。
//!
//! 授权两套口径:
//! - **seed 策略**(`TestServer::start`):`user` = read + write(**无 delete、无 :all**),
//!   `admin` / `superadmin` = 含 `contents:read:all` / `contents:write:all` / delete 的全权 —— 验证真实默认。
//! - **测试策略**([`owner_policy`]):`user` = read + write + delete 无 :all,这样写侧 / 删侧的
//!   ownership 闸(非本人 → 404)都能打到。
//!
//! 字节后端:内存模式是进程内 `InMemoryObjectStore`(不支持 presign → preview/download 代理字节、
//! upload-url 回 `upload_url: null`)。presign(307 跳转)与两步上传全流程需要"能签 URL / 能被客户端
//! 直写"的后端,经 `TestServer::start_with` 换 content 库的 `ObjectStore` 端口(领域类型,与 web 框架无关)。
//!
//! covers: GET /api/v1/frontend/contents
//! covers: POST /api/v1/frontend/contents
//! covers: POST /api/v1/frontend/contents/upload
//! covers: POST /api/v1/frontend/contents/upload-url
//! covers: GET /api/v1/frontend/contents/{id}
//! covers: PUT /api/v1/frontend/contents/{id}
//! covers: DELETE /api/v1/frontend/contents/{id}
//! covers: POST /api/v1/frontend/contents/{id}/confirm-upload
//! covers: GET /api/v1/frontend/contents/{id}/download
//! covers: GET /api/v1/frontend/contents/{id}/metadata
//! covers: PUT /api/v1/frontend/contents/{id}/metadata
//! covers: GET /api/v1/frontend/contents/{id}/objects
//! covers: GET /api/v1/frontend/contents/{id}/preview

mod http_support;

use baserust::app::AppContentService;
use bytes::Bytes;
use std::sync::Arc;

use baserust::kernel::authorization::{Permission, Policy};
use content::ObjectStore as _;
use http_support::{
    admin_scoped, expect, expect_error, expect_json, mint, user_token, Client, TestServer, ADMIN,
    PASSWORD, USER,
};
use reqwest::multipart::{Form, Part};
use reqwest::{Method, Response, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const CONTENTS: &str = "/api/v1/frontend/contents";
const NIL: &str = "00000000-0000-0000-0000-000000000000";
/// 默认租户(seed 账号 / `user_token` 登录后的当前租户;内容落当前租户)。
const DEFAULT_TENANT: &str = "00000000-0000-0000-0000-000000000001";

// ───────────────────────────── 帮手 ─────────────────────────────

/// 测试策略:`user` 管自己的内容(含 delete,无 :all);`viewer` 只读;`auditor` 跨用户全权。
fn owner_policy() -> Policy {
    Policy::new([
        (
            "user".to_owned(),
            vec![
                Permission::ContentRead,
                Permission::ContentWrite,
                Permission::ContentDelete,
            ],
        ),
        ("viewer".to_owned(), vec![Permission::ContentRead]),
        (
            "auditor".to_owned(),
            vec![
                Permission::ContentReadAll,
                Permission::ContentWriteAll,
                Permission::ContentDelete,
            ],
        ),
    ])
}

async fn start_owner_policy() -> TestServer {
    TestServer::start_with(|state| state.policy = Arc::new(owner_policy())).await
}

/// 换 content 的字节后端(仓储换新的内存实现;其余装配不动)。
async fn start_with_store(store: Arc<dyn content::ObjectStore>) -> TestServer {
    TestServer::start_with(move |state| {
        state.contents = AppContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            store,
            "memory",
        );
    })
    .await
}

/// 一个新主体(seed 策略下的 `user` 角色)的 Bearer 会话。
fn new_user(server: &TestServer) -> Client {
    server.bearer(&user_token().0)
}

/// 满权 admin(seed 策略:含 :all 与 delete)的 Bearer 会话,主体是新 uuid。
fn new_admin(server: &TestServer) -> Client {
    server.bearer(&mint(
        Uuid::now_v7(),
        "admin",
        &[],
        Some(http_support::DEFAULT_TENANT),
        &["admin"],
        vec![],
    ))
}

/// 一步上传的 multipart 表单:file(带文件名 + content-type)+ name + tags(逗号分隔,含空白与空项)。
fn file_form(file_name: &str, mime: &str, data: &[u8]) -> Form {
    Form::new()
        .part("file", file_part(file_name, mime, data))
        .text("name", "doc")
        .text("tags", "a, b,,")
}

fn file_part(file_name: &str, mime: &str, data: &[u8]) -> Part {
    Part::bytes(data.to_vec())
        .file_name(file_name.to_owned())
        .mime_str(mime)
        .unwrap()
}

/// 一步上传 → 201,返回 `UploadResponse` JSON(`{content, object}`)。
async fn upload(client: &Client, file_name: &str, mime: &str, data: &[u8]) -> Value {
    expect_json(
        client
            .post_multipart(
                &format!("{CONTENTS}/upload"),
                file_form(file_name, mime, data),
            )
            .await,
        StatusCode::CREATED,
    )
    .await
}

/// 一步上传,只要 content id。
async fn upload_id(client: &Client, file_name: &str, mime: &str, data: &[u8]) -> String {
    string_of(&upload(client, file_name, mime, data).await["content"]["id"])
}

/// 仅建 content 行(status=created,无对象无字节)→ id。
async fn create(client: &Client, body: Value) -> String {
    let created = expect_json(client.post_json(CONTENTS, &body).await, StatusCode::CREATED).await;
    string_of(&created["id"])
}

fn string_of(value: &Value) -> String {
    value
        .as_str()
        .unwrap_or_else(|| panic!("应是字符串: {value}"))
        .to_owned()
}

fn header(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("缺响应头 {name}: {:?}", response.headers()))
        .to_str()
        .unwrap()
        .to_owned()
}

/// 断言 200 并取回原始字节(下载 / 预览代理路径)。
async fn expect_bytes(response: Response) -> Vec<u8> {
    let status = response.status();
    let url = response.url().to_string();
    let body = response.bytes().await.unwrap().to_vec();
    assert_eq!(
        status,
        StatusCode::OK,
        "{url} → {status},body: {}",
        String::from_utf8_lossy(&body)
    );
    body
}

/// 列表里的全部 id。
async fn list_ids(client: &Client) -> Vec<String> {
    let contents = expect_json(client.get(CONTENTS).await, StatusCode::OK).await;
    contents
        .as_array()
        .unwrap_or_else(|| panic!("列表应是 JSON 数组: {contents}"))
        .iter()
        .map(|c| string_of(&c["id"]))
        .collect()
}

/// 覆写 URL 方法的测试 store(字节仍走内存):模拟 minio/S3 的 presign 能力,验证 307 分支与 Location 透传。
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

// ───────────────────────────── 认证 / 权限闸 ─────────────────────────────

/// 全部 13 个端点都**必须登录**:无凭据 → 401 + 统一错误体(认证先于 body 解析与存在性判断)。
#[tokio::test]
async fn all_content_endpoints_require_auth_401() {
    let server = TestServer::start().await;
    let anonymous = server.anonymous();
    let item = format!("{CONTENTS}/{NIL}");
    let cases: Vec<(Method, String)> = vec![
        (Method::GET, CONTENTS.to_owned()),
        (Method::POST, CONTENTS.to_owned()),
        (Method::POST, format!("{CONTENTS}/upload")),
        (Method::POST, format!("{CONTENTS}/upload-url")),
        (Method::GET, item.clone()),
        (Method::PUT, item.clone()),
        (Method::DELETE, item.clone()),
        (Method::POST, format!("{item}/confirm-upload")),
        (Method::GET, format!("{item}/download")),
        (Method::GET, format!("{item}/metadata")),
        (Method::PUT, format!("{item}/metadata")),
        (Method::GET, format!("{item}/objects")),
        (Method::GET, format!("{item}/preview")),
    ];
    for (method, path) in cases {
        let response = if path.ends_with("/upload") {
            anonymous
                .post_multipart(&path, file_form("a.txt", "text/plain", b"x"))
                .await
        } else {
            anonymous
                .request(method.clone(), &path)
                .json(&json!({ "tags": [] }))
                .send()
                .await
                .unwrap()
        };
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        expect_error(response, StatusCode::UNAUTHORIZED, "unauthorized").await;
    }
}

/// 降权令牌只有 `contents:read` → 所有写端点 403(权限闸先于存在性:对不存在的 id 也是 403)。
#[tokio::test]
async fn read_only_scope_is_403_on_every_write_endpoint() {
    let server = TestServer::start().await;
    let read_only = server.bearer(&admin_scoped(vec![Permission::ContentRead]));
    let item = format!("{CONTENTS}/{NIL}");
    expect_error(
        read_only.post_json(CONTENTS, &json!({ "name": "x" })).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only
            .post_multipart(
                &format!("{CONTENTS}/upload"),
                file_form("a.txt", "text/plain", b"x"),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only
            .post_json(&format!("{CONTENTS}/upload-url"), &json!({}))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only.put_json(&item, &json!({ "name": "x" })).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only
            .put_json(&format!("{item}/metadata"), &json!({ "tags": [] }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only
            .post_empty(&format!("{item}/confirm-upload"))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only.delete(&item).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 读端点照常放行(列表为空,单条不存在 → 404,说明过了权限闸)
    let ids = list_ids(&read_only).await;
    assert!(ids.is_empty(), "{ids:?}");
    expect_error(
        read_only.get(&item).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 降权令牌只有 `contents:write` → 所有读端点 403。
#[tokio::test]
async fn write_only_scope_is_403_on_every_read_endpoint() {
    let server = TestServer::start().await;
    let admin = new_admin(&server);
    let id = upload_id(&admin, "a.txt", "text/plain", b"x").await;
    let write_only = server.bearer(&admin_scoped(vec![Permission::ContentWrite]));
    let item = format!("{CONTENTS}/{id}");
    for path in [
        CONTENTS.to_owned(),
        item.clone(),
        format!("{item}/download"),
        format!("{item}/metadata"),
        format!("{item}/objects"),
        format!("{item}/preview"),
    ] {
        expect_error(
            write_only.get(&path).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
}

/// seed 策略的 `user` 没有 `contents:delete`:删自己的也 403,内容仍在;
/// seed 的 `admin` 有 → 204 空 body,删后单条 / 子资源 404、列表不再含它。
#[tokio::test]
async fn delete_needs_delete_perm_then_soft_deletes() {
    let server = TestServer::start().await;
    let user = server.login(USER, PASSWORD).await;
    let id = upload_id(&user, "a.txt", "text/plain", b"x").await;
    expect_error(
        user.delete(&format!("{CONTENTS}/{id}")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;

    let admin = server.login(ADMIN, PASSWORD).await;
    let mine = upload_id(&admin, "b.txt", "text/plain", b"y").await;
    let body = expect(
        admin.delete(&format!("{CONTENTS}/{mine}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");
    for path in [
        format!("{CONTENTS}/{mine}"),
        format!("{CONTENTS}/{mine}/download"),
        format!("{CONTENTS}/{mine}/preview"),
        format!("{CONTENTS}/{mine}/metadata"),
        format!("{CONTENTS}/{mine}/objects"),
    ] {
        expect_error(admin.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
    }
    assert!(
        !list_ids(&admin).await.contains(&mine),
        "软删后不应再出现在列表"
    );
    // 再删一次 → 404(已软删 = 不存在)
    expect_error(
        admin.delete(&format!("{CONTENTS}/{mine}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

// ───────────────────────────── 一步上传 / 下载 ─────────────────────────────

/// 一步上传(cookie 会话)→ 201 {content, object} 皆 uploaded;owner = 当前用户;
/// 下载取回原字节,Content-Type / Content-Disposition 来自元数据。
#[tokio::test]
async fn upload_then_download_round_trip() {
    let server = TestServer::start().await;
    let user = server.login(USER, PASSWORD).await;
    let me = expect_json(user.get("/api/v1/frontend/auth/me").await, StatusCode::OK).await;

    let payload = b"hello content bytes";
    let uploaded = upload(&user, "hello.txt", "text/plain", payload).await;
    let content = &uploaded["content"];
    let object = &uploaded["object"];
    assert_eq!(content["status"], "uploaded", "{uploaded}");
    assert_eq!(object["status"], "uploaded", "{uploaded}");
    assert_eq!(content["owner_id"], me["id"], "owner 必须是认证主体");
    assert_eq!(
        content["tenant_id"], DEFAULT_TENANT,
        "落当前租户(seed user 登录进默认租户)"
    );
    assert_eq!(content["name"], "doc");
    assert_eq!(content["derivation_type"], "original");
    assert_eq!(object["content_id"], content["id"]);
    assert_eq!(object["file_name"], "hello.txt");
    assert_eq!(object["storage_backend_name"], "memory");
    assert_eq!(object["version"], 1);
    let id = string_of(&content["id"]);
    assert!(
        string_of(&object["object_key"]).starts_with(&format!("tenants/{DEFAULT_TENANT}/{id}/")),
        "默认 object_key = tenants/{{tenant_id}}/{{content_id}}/{{uuid}}: {uploaded}"
    );

    let response = user.get(&format!("{CONTENTS}/{id}/download")).await;
    assert!(
        header(&response, "content-type").starts_with("text/plain"),
        "content-type 应来自元数据"
    );
    let display_name = header(&response, "content-disposition");
    assert!(
        display_name.starts_with("attachment; filename=\"hello.txt\""),
        "下载应是 attachment + 原文件名: {display_name}"
    );
    assert_eq!(expect_bytes(response).await, payload);
}

/// 上传后:单条 / 列表 / 对象 / 元数据四个读端点的形状。
#[tokio::test]
async fn upload_then_get_list_objects_metadata() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let uploaded = upload(&user, "f.bin", "application/octet-stream", b"xyz").await;
    let id = string_of(&uploaded["content"]["id"]);

    let got = expect_json(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["id"], id.as_str());
    assert_eq!(got["status"], "uploaded");
    assert!(got["created_at"].is_string() && got["updated_at"].is_string());

    assert_eq!(list_ids(&user).await, vec![id.clone()]);

    let objects = expect_json(
        user.get(&format!("{CONTENTS}/{id}/objects")).await,
        StatusCode::OK,
    )
    .await;
    let objects = objects.as_array().unwrap();
    assert_eq!(objects.len(), 1, "{objects:?}");
    assert_eq!(objects[0]["id"], uploaded["object"]["id"]);
    assert_eq!(objects[0]["object_key"], uploaded["object"]["object_key"]);
    assert_eq!(objects[0]["status"], "uploaded");

    let metadata = expect_json(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["content_id"], id.as_str());
    assert_eq!(
        metadata["tags"],
        json!(["a", "b"]),
        "tags 逗号分隔、trim、去空项"
    );
    assert_eq!(metadata["file_size"], 3);
    assert_eq!(metadata["file_name"], "f.bin");
    assert_eq!(metadata["mime_type"], "application/octet-stream");
    assert_eq!(metadata["metadata"], json!({}));
}

/// 下载文件名走 RFC 6266:非 ASCII 进 `filename*`(百分号编码),`filename=` 是净化后的 ASCII 兜底。
#[tokio::test]
async fn download_disposition_encodes_non_ascii_filename() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    // 原样发 UTF-8 文件名(不让客户端先做百分号编码)
    let form = Form::new()
        .percent_encode_noop()
        .part("file", file_part("报表.txt", "text/plain", b"x"));
    let uploaded = expect_json(
        user.post_multipart(&format!("{CONTENTS}/upload"), form)
            .await,
        StatusCode::CREATED,
    )
    .await;
    let id = string_of(&uploaded["content"]["id"]);
    let response = user.get(&format!("{CONTENTS}/{id}/download")).await;
    let display_name = header(&response, "content-disposition");
    assert!(
        display_name.starts_with("attachment; filename=\"__.txt\""),
        "{display_name}"
    );
    assert!(
        display_name.contains("filename*=UTF-8''%E6%8A%A5%E8%A1%A8.txt"),
        "{display_name}"
    );
    expect_bytes(response).await;
}

/// 一步上传的边界:缺 file 部分 / 超长字段 → 422;非 multipart → 400;正常的照常 201。
/// (`tenant_id` 已不是表单字段:租户只来自令牌,传了也当未知部分忽略,见 `upload_lands_in_current_tenant`。)
#[tokio::test]
async fn upload_validation_and_bad_requests() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let upload_path = format!("{CONTENTS}/upload");

    // 缺 file 部分
    expect_error(
        user.post_multipart(&upload_path, Form::new().text("name", "no-file"))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // 超长 file_name(> 255):它会被编进对象存储的请求头,必须封顶
    let long_name = format!("{}.txt", "a".repeat(300));
    expect_error(
        user.post_multipart(&upload_path, file_form(&long_name, "text/plain", b"x"))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // 超长 mime(> 255)
    let long_mime = format!("text/{}", "b".repeat(300));
    expect_error(
        user.post_multipart(&upload_path, file_form("ok.txt", &long_mime, b"x"))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // tags 超 64 个
    let many_tags = (0..65)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let form = Form::new()
        .part("file", file_part("ok.txt", "text/plain", b"x"))
        .text("tags", many_tags);
    expect_error(
        user.post_multipart(&upload_path, form).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // 超长 name(> 255)
    let form = Form::new()
        .part("file", file_part("ok.txt", "text/plain", b"x"))
        .text("name", "n".repeat(256));
    expect_error(
        user.post_multipart(&upload_path, form).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // body 不是 multipart → 400 + 统一错误体(不漏框架默认纯文本)
    expect_error(
        user.post_json(&upload_path, &json!({ "file": "x" })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    // 失败的请求都没留下内容;正常的照常 201
    assert!(list_ids(&user).await.is_empty(), "校验失败不应建行");
    upload(&user, "fine.txt", "text/plain", b"x").await;
}

// ───────────────────────────── 租户隔离 ─────────────────────────────

/// 某租户里的成员会话(随机主体)。
fn member_of(server: &TestServer, tenant: Uuid, roles: &[&str]) -> Client {
    server.bearer(&mint(Uuid::now_v7(), "m", &[], Some(tenant), roles, vec![]))
}

/// 内容落**当前租户**(令牌里的租户):一步上传 / 建内容 / 两步上传的 `tenant_id` 都是它,对象 key 带它的前缀;
/// 请求里自报的 `tenant_id`(表单部分 / JSON 字段)不再是契约的一部分,一律忽略。
#[tokio::test]
async fn upload_lands_in_current_tenant() {
    let server = TestServer::start().await;
    let tenant = Uuid::now_v7();
    let other = Uuid::now_v7().to_string();
    let client = member_of(&server, tenant, &["user"]);
    let tenant_id = tenant.to_string();

    let form = file_form("a.txt", "text/plain", b"x").text("tenant_id", other.clone());
    let uploaded = expect_json(
        client
            .post_multipart(&format!("{CONTENTS}/upload"), form)
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(uploaded["content"]["tenant_id"], tenant_id, "{uploaded}");
    let id = string_of(&uploaded["content"]["id"]);
    assert!(
        string_of(&uploaded["object"]["object_key"])
            .starts_with(&format!("tenants/{tenant_id}/{id}/")),
        "key 带当前租户前缀: {uploaded}"
    );

    let created = expect_json(
        client
            .post_json(CONTENTS, &json!({ "name": "raw", "tenant_id": other }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["tenant_id"], tenant_id, "{created}");

    let prepared = expect_json(
        client
            .post_json(
                &format!("{CONTENTS}/upload-url"),
                &json!({ "file_name": "b.txt", "mime_type": "text/plain", "tenant_id": other }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(prepared["content"]["tenant_id"], tenant_id, "{prepared}");
    let id = string_of(&prepared["content"]["id"]);
    assert!(string_of(&prepared["object"]["object_key"])
        .starts_with(&format!("tenants/{tenant_id}/{id}/")));
    assert_eq!(list_ids(&client).await.len(), 3);
}

/// 别的租户的内容 → 404(哪怕是同一个用户、哪怕持 `:all`):读 / 改 / 删 / 下载 / 预览 / 对象 / 元数据都碰不到,
/// 列表里也没有;回到原租户一切照旧。
#[tokio::test]
async fn content_of_other_tenant_is_404() {
    let server = TestServer::start().await;
    let (tenant_a, tenant_b) = (Uuid::now_v7(), Uuid::now_v7());
    let user_id = Uuid::now_v7();
    let in_a = server.bearer(&mint(user_id, "u", &[], Some(tenant_a), &["admin"], vec![]));
    let in_b = server.bearer(&mint(user_id, "u", &[], Some(tenant_b), &["admin"], vec![]));
    let id = upload_id(&in_a, "secret.txt", "text/plain", b"tenant a").await;

    let item = format!("{CONTENTS}/{id}");
    for path in [
        item.clone(),
        format!("{item}/download"),
        format!("{item}/preview"),
        format!("{item}/objects"),
        format!("{item}/metadata"),
    ] {
        expect_error(in_b.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
    }
    expect_error(
        in_b.put_json(&item, &json!({ "name": "pwned" })).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        in_b.put_json(&format!("{item}/metadata"), &json!({ "tags": ["x"] }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        in_b.post_empty(&format!("{item}/confirm-upload")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(in_b.delete(&item).await, StatusCode::NOT_FOUND, "not_found").await;
    assert!(list_ids(&in_b).await.is_empty(), "别的租户的列表看不到");

    let got = expect_json(in_a.get(&item).await, StatusCode::OK).await;
    assert_eq!(got["name"], "doc", "别的租户改不动、删不掉: {got}");
    assert_eq!(list_ids(&in_a).await, vec![id]);
}

/// 没有当前租户的令牌(平台上下文)调 content 接口 → 403 `tenant_required`。
#[tokio::test]
async fn content_endpoints_require_current_tenant() {
    let server = TestServer::start().await;
    let client = server.bearer(&mint(
        Uuid::now_v7(),
        "sa",
        &["superadmin"],
        None,
        &[],
        vec![],
    ));
    expect_error(
        client.get(CONTENTS).await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
    expect_error(
        client
            .post_multipart(
                &format!("{CONTENTS}/upload"),
                file_form("a.txt", "text/plain", b"x"),
            )
            .await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
    expect_error(
        client.get(&format!("{CONTENTS}/{NIL}")).await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
}

// ───────────────────────────── 建 / 改(JSON) ─────────────────────────────

/// POST 建内容 → 201 扁平 ContentResponse(status=created);未上传字节:对象为空、元数据 404、
/// download / preview 409(未就绪)。
#[tokio::test]
async fn create_content_then_reads_before_upload() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let created = expect_json(
        user.post_json(
            CONTENTS,
            &json!({ "name": "raw", "description": "d", "document_type": "pdf", "owner_type": "user" }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["status"], "created");
    assert_eq!(created["name"], "raw");
    assert_eq!(created["description"], "d");
    assert_eq!(created["document_type"], "pdf");
    assert_eq!(created["owner_type"], "user");
    assert_eq!(
        created["derivation_type"], "original",
        "缺省派生类型 = original"
    );
    assert_eq!(created["tenant_id"], DEFAULT_TENANT);
    let id = string_of(&created["id"]);

    let got = expect_json(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["status"], "created");
    assert_eq!(list_ids(&user).await, vec![id.clone()]);
    let objects = expect_json(
        user.get(&format!("{CONTENTS}/{id}/objects")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(objects, json!([]), "仅建账不建对象");
    expect_error(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        user.get(&format!("{CONTENTS}/{id}/download")).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        user.get(&format!("{CONTENTS}/{id}/preview")).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
}

/// 建内容的边界:空 body 也行(全可选);超长字段 422;坏 JSON 400;坏路径参数 400;不存在 404。
#[tokio::test]
async fn create_validation_and_lookup_errors() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    create(&user, json!({})).await;
    for body in [
        json!({ "name": "n".repeat(256) }),
        json!({ "description": "d".repeat(2001) }),
        json!({ "document_type": "t".repeat(65) }),
        json!({ "derivation_type": "x".repeat(33) }),
        json!({ "owner_type": "o".repeat(65) }),
    ] {
        expect_error(
            user.post_json(CONTENTS, &body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    let response = user
        .request(Method::POST, CONTENTS)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(response, StatusCode::BAD_REQUEST, "bad_request").await;
    expect_error(
        user.get(&format!("{CONTENTS}/not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        user.get(&format!("{CONTENTS}/{NIL}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// PUT 全量替换:没给的可编辑字段被清空;id / owner / status / derivation 不动;持久;边界 422 / 404。
#[tokio::test]
async fn put_full_replace_semantics() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let id = upload_id(&user, "a.txt", "text/plain", b"x").await;
    let before = expect_json(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;

    let updated = expect_json(
        user.put_json(
            &format!("{CONTENTS}/{id}"),
            &json!({ "name": "renamed", "description": "desc" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["name"], "renamed");
    assert_eq!(updated["description"], "desc");
    assert_eq!(updated["id"], before["id"]);
    assert_eq!(updated["owner_id"], before["owner_id"]);
    assert_eq!(updated["status"], "uploaded", "PUT 不改状态");
    assert_eq!(updated["derivation_type"], "original");

    // 再 PUT 只给 name → description 被清空(全量替换,不是 PATCH)
    let updated = expect_json(
        user.put_json(&format!("{CONTENTS}/{id}"), &json!({ "name": "only-name" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(
        updated["description"].is_null(),
        "全量替换应清空未给字段: {updated}"
    );
    let got = expect_json(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["name"], "only-name", "改动应持久");
    assert!(got["description"].is_null());

    expect_error(
        user.put_json(
            &format!("{CONTENTS}/{id}"),
            &json!({ "name": "n".repeat(256) }),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        user.put_json(&format!("{CONTENTS}/{NIL}"), &json!({ "name": "x" }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

// ───────────────────────────── 元数据 ─────────────────────────────

/// PUT /metadata 全量替换 → 204 空 body;GET 反映新值;改名后下载用新文件名;
/// file_size 不给 = 清空(全量替换口径);边界 422 / 400 / 404。
#[tokio::test]
async fn metadata_put_replaces_and_drives_download_name() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let id = upload_id(&user, "a.txt", "text/plain", b"hello").await;
    let path = format!("{CONTENTS}/{id}/metadata");

    let body = expect(
        user.put_json(
            &path,
            &json!({
                "tags": ["x", "y"],
                "file_name": "renamed.txt",
                "checksum": "abc",
                "checksum_algorithm": "sha256",
                "metadata": { "k": 1 }
            }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");

    let metadata = expect_json(user.get(&path).await, StatusCode::OK).await;
    assert_eq!(metadata["tags"], json!(["x", "y"]));
    assert_eq!(metadata["file_name"], "renamed.txt");
    assert_eq!(metadata["checksum"], "abc");
    assert_eq!(metadata["checksum_algorithm"], "sha256");
    assert_eq!(metadata["metadata"], json!({ "k": 1 }));
    assert!(
        metadata["file_size"].is_null(),
        "全量替换:没给 file_size 即清空: {metadata}"
    );
    assert_eq!(metadata["mime_type"], "text/plain", "mime 原样保留");

    let response = user.get(&format!("{CONTENTS}/{id}/download")).await;
    let display_name = header(&response, "content-disposition");
    assert!(
        display_name.starts_with("attachment; filename=\"renamed.txt\""),
        "下载应用元数据里的新名: {display_name}"
    );
    assert_eq!(expect_bytes(response).await, b"hello");

    // tags 超 64 个 / file_name 超长 → 422
    let many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
    expect_error(
        user.put_json(&path, &json!({ "tags": many })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        user.put_json(&path, &json!({ "tags": [], "file_name": "f".repeat(256) }))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    // 缺必填 tags → 400(body 反序列化失败)
    expect_error(
        user.put_json(&path, &json!({ "file_name": "x" })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    // 内容不存在 → 404
    expect_error(
        user.put_json(
            &format!("{CONTENTS}/{NIL}/metadata"),
            &json!({ "tags": [] }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// **mime 是服务端所有物**(防存储型 XSS 的根因闸):以 text/html 上传后,PUT /metadata 带
/// `mime_type: image/png` 也改不动它(请求照常 204,字段被忽略);preview 仍按 html 降级 attachment。
#[tokio::test]
async fn metadata_put_cannot_mutate_server_owned_mime() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let id = upload_id(&user, "evil.html", "text/html", b"<script>x</script>").await;
    expect(
        user.put_json(
            &format!("{CONTENTS}/{id}/metadata"),
            &json!({ "tags": [], "file_name": "evil.html", "mime_type": "image/png" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    let metadata = expect_json(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        metadata["mime_type"], "text/html",
        "mime 必须仍是上传时的值: {metadata}"
    );
    let response = user.get(&format!("{CONTENTS}/{id}/preview")).await;
    assert!(
        header(&response, "content-disposition").starts_with("attachment"),
        "改 mime 不能骗过 inline 闸门"
    );
    assert_eq!(header(&response, "content-type"), "text/html");
    expect_bytes(response).await;
}

/// 只建账(无字节、无元数据行)的内容 PUT /metadata = upsert 建首行:204,mime 为 null(fail-closed)。
#[tokio::test]
async fn metadata_put_upserts_on_created_content_without_mime() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let id = create(&user, json!({ "name": "raw" })).await;
    expect(
        user.put_json(
            &format!("{CONTENTS}/{id}/metadata"),
            &json!({ "tags": ["t"], "file_name": "x.png", "mime_type": "image/png", "file_size": 7 }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    let metadata = expect_json(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["tags"], json!(["t"]));
    assert_eq!(metadata["file_name"], "x.png");
    assert_eq!(metadata["file_size"], 7);
    assert!(
        metadata["mime_type"].is_null(),
        "客户端给不了 mime,没有字节就没有 mime: {metadata}"
    );
}

// ───────────────────────────── 预览(XSS 闸) ─────────────────────────────

/// 内存后端代理回退:惰性类型(栅格图 / 纯文本)inline 渲染,带 `CSP: sandbox` 兜底,字节原样。
#[tokio::test]
async fn preview_inlines_safe_types_with_sandbox_csp() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    for (name, mime, data) in [
        ("a.png", "image/png", b"png-bytes".as_slice()),
        ("a.txt", "text/plain", b"plain".as_slice()),
        ("a.pdf", "application/pdf", b"%PDF".as_slice()),
    ] {
        let id = upload_id(&user, name, mime, data).await;
        let response = user.get(&format!("{CONTENTS}/{id}/preview")).await;
        assert_eq!(header(&response, "content-type"), mime);
        assert!(
            header(&response, "content-disposition").starts_with("inline"),
            "{mime} 应 inline"
        );
        assert_eq!(header(&response, "content-security-policy"), "sandbox");
        assert_eq!(expect_bytes(response).await, data);
    }
}

/// 活动内容(html / svg / xhtml,含带参数的写法)预览**必须降级 attachment**,绝不 inline;
/// CSP sandbox 照样在。下载端点恒为 attachment。
#[tokio::test]
async fn preview_forces_attachment_for_active_content() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    for mime in [
        "text/html",
        "image/svg+xml",
        "image/svg+xml; charset=utf-8",
        "application/xhtml+xml",
        "application/xml",
    ] {
        let id = upload_id(&user, "x", mime, b"<script>alert(1)</script>").await;
        let response = user.get(&format!("{CONTENTS}/{id}/preview")).await;
        assert!(
            header(&response, "content-disposition").starts_with("attachment"),
            "{mime} 必须降级 attachment"
        );
        assert_eq!(
            header(&response, "content-security-policy"),
            "sandbox",
            "{mime}"
        );
        expect_bytes(response).await;

        let response = user.get(&format!("{CONTENTS}/{id}/download")).await;
        assert!(
            header(&response, "content-disposition").starts_with("attachment"),
            "{mime} 下载恒 attachment"
        );
        expect_bytes(response).await;
    }
}

// ───────────────────────────── 行级 ownership ─────────────────────────────

/// 非 owner(有 read/write/delete 但无 :all)对他人内容的**全部**单条读写一律 404(不区分,防泄露存在),
/// 包括图片预览;越权写不生效;列表只含自己的。
#[tokio::test]
async fn cross_user_access_is_404_and_has_no_effect() {
    let server = start_owner_policy().await;
    let alice = new_user(&server);
    let bob = new_user(&server);
    let text = upload_id(&alice, "own.txt", "text/plain", b"secret").await;
    let image = upload_id(&alice, "a.png", "image/png", b"\x89PNG").await;
    let mine = upload_id(&bob, "bob.txt", "text/plain", b"bob").await;

    for id in [&text, &image] {
        let item = format!("{CONTENTS}/{id}");
        for path in [
            item.clone(),
            format!("{item}/download"),
            format!("{item}/preview"),
            format!("{item}/objects"),
            format!("{item}/metadata"),
        ] {
            expect_error(bob.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
        }
        expect_error(
            bob.put_json(&item, &json!({ "name": "pwned" })).await,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
        expect_error(
            bob.put_json(&format!("{item}/metadata"), &json!({ "tags": ["pwned"] }))
                .await,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
        expect_error(
            bob.post_empty(&format!("{item}/confirm-upload")).await,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
        expect_error(bob.delete(&item).await, StatusCode::NOT_FOUND, "not_found").await;
    }

    // 越权写全没生效
    let got = expect_json(
        alice.get(&format!("{CONTENTS}/{text}")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(got["name"], "doc");
    let metadata = expect_json(
        alice.get(&format!("{CONTENTS}/{text}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["tags"], json!(["a", "b"]));
    assert_eq!(
        expect_bytes(alice.get(&format!("{CONTENTS}/{text}/download")).await).await,
        b"secret"
    );

    // 列表按 owner 隔离
    assert_eq!(list_ids(&bob).await, vec![mine.clone()]);
    let alice_ids = list_ids(&alice).await;
    assert_eq!(alice_ids.len(), 2);
    assert!(!alice_ids.contains(&mine));

    // owner 本人可删自己的
    expect(
        alice.delete(&format!("{CONTENTS}/{text}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
}

/// 只读 viewer 看不到别人的(404),也建不了(403)。
#[tokio::test]
async fn viewer_without_all_mode_sees_only_own() {
    let server = start_owner_policy().await;
    let alice = new_user(&server);
    let id = upload_id(&alice, "own.txt", "text/plain", b"x").await;
    let viewer = server.bearer(&mint(
        Uuid::now_v7(),
        "viewer",
        &[],
        Some(http_support::DEFAULT_TENANT),
        &["viewer"],
        vec![],
    ));
    expect_error(
        viewer.get(&format!("{CONTENTS}/{id}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    assert!(list_ids(&viewer).await.is_empty());
    expect_error(
        viewer.post_json(CONTENTS, &json!({})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// `contents:read:all` / `contents:write:all` 是 ownership 的 **mode 开关**:持有者跨用户可读、可改、可删。
/// 列表**不**受 read:all 影响(content 库 list 强制按 owner,routes.rs 的 ponytail 注释明载)。
#[tokio::test]
async fn all_mode_perms_cross_user_but_list_stays_owner_scoped() {
    let server = TestServer::start().await; // seed 策略:admin 含 :all + delete
    let user = server.login(USER, PASSWORD).await;
    let id = upload_id(&user, "u.png", "image/png", b"img").await;
    let admin = server.login(ADMIN, PASSWORD).await;
    let item = format!("{CONTENTS}/{id}");

    expect(admin.get(&item).await, StatusCode::OK).await;
    expect(admin.get(&format!("{item}/metadata")).await, StatusCode::OK).await;
    expect(admin.get(&format!("{item}/objects")).await, StatusCode::OK).await;
    assert_eq!(
        expect_bytes(admin.get(&format!("{item}/download")).await).await,
        b"img"
    );
    assert_eq!(
        expect_bytes(admin.get(&format!("{item}/preview")).await).await,
        b"img"
    );
    assert!(
        !list_ids(&admin).await.contains(&id),
        "列表恒按当前用户过滤(read:all 在列表不生效,刻意设计)"
    );

    let updated = expect_json(
        admin.put_json(&item, &json!({ "name": "by-admin" })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["name"], "by-admin");
    expect(
        admin
            .put_json(&format!("{item}/metadata"), &json!({ "tags": ["adm"] }))
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(admin.delete(&item).await, StatusCode::NO_CONTENT).await;
    expect_error(user.get(&item).await, StatusCode::NOT_FOUND, "not_found").await;
}

/// 测试策略的 auditor(只配 :all,靠 implies 得到底权)同样跨用户可读可删 —— :all 蕴含底权。
#[tokio::test]
async fn all_perms_imply_base_perms() {
    let server = start_owner_policy().await;
    let alice = new_user(&server);
    let id = upload_id(&alice, "own.txt", "text/plain", b"x").await;
    let auditor = server.bearer(&mint(
        Uuid::now_v7(),
        "auditor",
        &[],
        Some(http_support::DEFAULT_TENANT),
        &["auditor"],
        vec![],
    ));
    expect(
        auditor.get(&format!("{CONTENTS}/{id}")).await,
        StatusCode::OK,
    )
    .await;
    expect(
        auditor.delete(&format!("{CONTENTS}/{id}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
}

/// 列表:按建序倒序(新的在前),软删的不出现。
#[tokio::test]
async fn list_is_newest_first() {
    let server = start_owner_policy().await;
    let user = new_user(&server);
    let first = create(&user, json!({ "name": "first" })).await;
    let second = upload_id(&user, "b.txt", "text/plain", b"b").await;
    let third = create(&user, json!({ "name": "third" })).await;
    assert_eq!(
        list_ids(&user).await,
        vec![third.clone(), second.clone(), first.clone()]
    );
    expect(
        user.delete(&format!("{CONTENTS}/{second}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(list_ids(&user).await, vec![third, first]);
}

// ───────────────────────────── 两步上传 ─────────────────────────────

/// 内存后端 prepare:201,`upload_url: null`(回退一步上传的信号),content / object 皆 created;
/// 用户声明的元数据不等销账即可查(size 留空);没传字节就销账 → 409,状态不动。
#[tokio::test]
async fn prepare_upload_on_memory_backend_signals_fallback() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let prepared = expect_json(
        user.post_json(
            &format!("{CONTENTS}/upload-url"),
            &json!({ "name": "two-step", "file_name": "a.txt", "mime_type": "text/plain", "tags": ["t"] }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert!(
        prepared["upload_url"].is_null(),
        "memory 后端应给回退信号: {prepared}"
    );
    assert_eq!(prepared["content"]["status"], "created");
    assert_eq!(prepared["content"]["name"], "two-step");
    assert_eq!(prepared["object"]["status"], "created");
    assert_eq!(prepared["object"]["file_name"], "a.txt");
    let id = string_of(&prepared["content"]["id"]);
    assert!(string_of(&prepared["object"]["object_key"])
        .starts_with(&format!("tenants/{DEFAULT_TENANT}/{id}/")));

    let metadata = expect_json(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["tags"], json!(["t"]));
    assert_eq!(metadata["mime_type"], "text/plain");
    assert_eq!(metadata["file_name"], "a.txt");
    assert!(
        metadata["file_size"].is_null(),
        "size 留给 confirm 从后端补"
    );

    let objects = expect_json(
        user.get(&format!("{CONTENTS}/{id}/objects")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(objects.as_array().unwrap().len(), 1);
    assert_eq!(objects[0]["status"], "created");

    expect_error(
        user.post_empty(&format!("{CONTENTS}/{id}/confirm-upload"))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    let got = expect_json(user.get(&format!("{CONTENTS}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["status"], "created", "销账失败不得翻状态");
    expect_error(
        user.get(&format!("{CONTENTS}/{id}/download")).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    // 空 body 也能 prepare(全可选);超长字段 → 422
    expect(
        user.post_json(&format!("{CONTENTS}/upload-url"), &json!({}))
            .await,
        StatusCode::CREATED,
    )
    .await;
    for body in [
        json!({ "mime_type": "m".repeat(256) }),
        json!({ "file_name": "f".repeat(256) }),
        json!({ "name": "n".repeat(256) }),
        json!({ "tags": (0..65).map(|i| format!("t{i}")).collect::<Vec<_>>() }),
    ] {
        expect_error(
            user.post_json(&format!("{CONTENTS}/upload-url"), &body)
                .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
}

/// confirm 的错误分支:仅建账(无占格对象)→ 404;不存在 → 404;坏 id → 400。
#[tokio::test]
async fn confirm_upload_error_branches() {
    let server = TestServer::start().await;
    let user = new_user(&server);
    let id = create(&user, json!({ "name": "raw" })).await;
    expect_error(
        user.post_empty(&format!("{CONTENTS}/{id}/confirm-upload"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        user.post_empty(&format!("{CONTENTS}/{NIL}/confirm-upload"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        user.post_empty(&format!("{CONTENTS}/nope/confirm-upload"))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 两步上传全流程:prepare → 客户端直写字节(这里直写与服务共享的内存 store,模拟拿凭证 PUT)→
/// confirm 200 uploaded(幂等重试仍 200)→ size 补上、对象翻 uploaded、preview / download 读回字节。
#[tokio::test]
async fn two_step_upload_full_flow() {
    let store = Arc::new(content::InMemoryObjectStore::new());
    let server = start_with_store(store.clone()).await;
    let user = new_user(&server);
    let prepared = expect_json(
        user.post_json(
            &format!("{CONTENTS}/upload-url"),
            &json!({ "file_name": "a.txt", "mime_type": "text/plain", "tags": ["t"] }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    let id = string_of(&prepared["content"]["id"]);
    let key = string_of(&prepared["object"]["object_key"]);

    // 第二步:客户端直传(字节不过 app)
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

    let confirmed = expect_json(
        user.post_empty(&format!("{CONTENTS}/{id}/confirm-upload"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(confirmed["status"], "uploaded");
    assert_eq!(confirmed["id"], id.as_str());
    // 网络抖动重发:幂等 200,不是 409
    let again = expect_json(
        user.post_empty(&format!("{CONTENTS}/{id}/confirm-upload"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(again["status"], "uploaded");

    let metadata = expect_json(
        user.get(&format!("{CONTENTS}/{id}/metadata")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["file_size"], 14, "size 由 confirm 从后端补");
    assert_eq!(metadata["tags"], json!(["t"]), "prepare 写的 tags 不丢");
    let objects = expect_json(
        user.get(&format!("{CONTENTS}/{id}/objects")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(objects[0]["status"], "uploaded");

    let response = user.get(&format!("{CONTENTS}/{id}/preview")).await;
    assert!(header(&response, "content-disposition").starts_with("inline"));
    assert_eq!(expect_bytes(response).await, b"two-step bytes");
    assert_eq!(
        expect_bytes(user.get(&format!("{CONTENTS}/{id}/download")).await).await,
        b"two-step bytes"
    );
}

// ───────────────────────────── presign 后端(307) ─────────────────────────────

/// presign 后端:upload-url 给凭证(签进 key 与 mime);preview → 307 inline 凭证、download → 307 attachment
/// 凭证(文件名取元数据,改名后签新名);两者都 `Cache-Control: no-store`。会话不跟随重定向。
#[tokio::test]
async fn presign_backend_redirects_with_no_store() {
    let server =
        start_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new()))).await;
    let user = new_user(&server);

    let prepared = expect_json(
        user.post_json(
            &format!("{CONTENTS}/upload-url"),
            &json!({ "file_name": "b.png", "mime_type": "image/png" }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    let url = string_of(&prepared["upload_url"]);
    assert!(
        url.contains(&string_of(&prepared["object"]["object_key"])),
        "{url}"
    );
    assert!(url.contains("mime=image/png"), "mime 要签进凭证: {url}");

    let id = upload_id(&user, "a.png", "image/png", b"x").await;
    // 改元数据里的文件名(object 行仍是 a.png):download 凭证必须签新名
    expect(
        user.put_json(
            &format!("{CONTENTS}/{id}/metadata"),
            &json!({ "tags": [], "file_name": "renamed.pdf" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;

    for (path, want) in [
        (format!("{CONTENTS}/{id}/preview"), "?inline"),
        (format!("{CONTENTS}/{id}/download"), "dl=renamed.pdf"),
    ] {
        let response = user.get(&path).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(header(&response, "cache-control"), "no-store", "{path}");
        let location = header(&response, "location");
        assert!(
            location.starts_with("https://cdn.test/"),
            "{path}: {location}"
        );
        assert!(location.contains(want), "{path}: {location}");
    }

    // 跳转前照样过鉴权 / ownership:无凭据 401、非 owner 404(签名 URL 不外泄)
    expect_error(
        server
            .anonymous()
            .get(&format!("{CONTENTS}/{id}/preview"))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    let other = new_user(&server);
    expect_error(
        other.get(&format!("{CONTENTS}/{id}/download")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// presign 分支的 XSS 闸:活动内容的 preview 拿到的是 attachment **下载**凭证,绝不是 inline 预览凭证;
/// 改 mime 也骗不过(mime 不可改)。
#[tokio::test]
async fn presign_preview_of_active_content_gets_download_url() {
    let server =
        start_with_store(Arc::new(PresignStore(content::InMemoryObjectStore::new()))).await;
    let user = new_user(&server);
    let id = upload_id(&user, "evil.html", "text/html", b"<script>x</script>").await;
    expect(
        user.put_json(
            &format!("{CONTENTS}/{id}/metadata"),
            &json!({ "tags": [], "file_name": "evil.html", "mime_type": "image/png" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    let response = user.get(&format!("{CONTENTS}/{id}/preview")).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = header(&response, "location");
    assert!(
        !location.contains("?inline"),
        "活动内容绝不能拿到 inline 凭证: {location}"
    );
    assert!(
        location.contains("dl=evil.html"),
        "应是下载凭证: {location}"
    );
}

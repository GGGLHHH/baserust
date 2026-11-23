//! profile(用户资料 + 头像)的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架
//! (换底座只换 `http_support::serve`)。与 `profile_api.rs`(axum oneshot)覆盖同一组场景并补强:
//! 前台读写 / ownership / scope 收窄 / 头像绑定四查(+ 非本人)/ 头像端点出图与降级,
//! 以及后台(`users:admin`,seed 下仅 superadmin 持有)的读 / 改 / 传头像。
//!
//! 头像 content 走真实上传端点(`contents/upload` 一步 multipart;未 confirm 的用 `contents/upload-url`
//! 只做 prepare)。seed 给**每个** seed 账号都建了初始资料(superadmin / admin 带 display_name,user 的为 null)——
//! 要"还没有资料"的主体,用自铸令牌的新 user(`fresh_user`)。
//!
//! covers: GET /api/v1/frontend/profiles/me
//! covers: GET /api/v1/frontend/profiles/{user_id}
//! covers: PUT /api/v1/frontend/profiles/{user_id}
//! covers: GET /api/v1/frontend/profiles/{user_id}/avatar
//! covers: GET /api/v1/admin/auth/users/{id}/profile
//! covers: PUT /api/v1/admin/auth/users/{id}/profile
//! covers: POST /api/v1/admin/auth/users/{id}/avatar

mod http_support;

use std::sync::Arc;

use baserust::app::adapters::ContentAvatarProbe;
use baserust::features::profile::{InMemoryProfileRepo, ProfileService};
use baserust::kernel::authz::Perm;
use http_support::{
    admin_scoped, expect, expect_error, expect_json, mint, user_token, Client, TestServer, ADMIN,
    PASSWORD, SUPERADMIN, USER,
};
use reqwest::multipart::{Form, Part};
use reqwest::{Method, Response, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const P: &str = "/api/v1/frontend/profiles";
const ME: &str = "/api/v1/frontend/profiles/me";

/// 一张"图片"的字节(PNG 魔数开头;内存后端不嗅探内容,mime 取上传声明)。
const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];

fn profile_path(id: &str) -> String {
    format!("{P}/{id}")
}

fn avatar_path(id: &str) -> String {
    format!("{P}/{id}/avatar")
}

fn admin_profile_path(id: &str) -> String {
    format!("/api/v1/admin/auth/users/{id}/profile")
}

fn admin_avatar_path(id: &str) -> String {
    format!("/api/v1/admin/auth/users/{id}/avatar")
}

/// 会话主体的 user id(经 `/frontend/auth/me`)。
async fn my_id(c: &Client) -> String {
    let v = expect_json(c.get("/api/v1/frontend/auth/me").await, StatusCode::OK).await;
    v["id"].as_str().expect("me 应带 id").to_owned()
}

/// 一个还没有资料的新 `user` 主体(自铸令牌,随机 id)。返回 (会话, user id)。
fn fresh_user(s: &TestServer) -> (Client, String) {
    let (token, id) = user_token();
    (s.bearer(&token), id.to_string())
}

/// 某个 seed 账号的 user id(前台登录后读 me)。
async fn seed_id(s: &TestServer, username: &str) -> String {
    my_id(&s.login(username, PASSWORD).await).await
}

/// 只含一个 `file` 部分的 multipart 表单。
fn file_form(mime: &str, data: &[u8]) -> Form {
    Form::new().part(
        "file",
        Part::bytes(data.to_vec())
            .file_name("avatar.bin")
            .mime_str(mime)
            .unwrap(),
    )
}

/// 一步上传(multipart `contents/upload`)→ 已就绪的 content,owner = 会话主体。返回 content id。
async fn upload(c: &Client, mime: &str) -> String {
    let v = expect_json(
        c.post_multipart("/api/v1/frontend/contents/upload", file_form(mime, PNG))
            .await,
        StatusCode::CREATED,
    )
    .await;
    v["content"]["id"].as_str().unwrap().to_owned()
}

/// 两步上传只做第 ① 步(prepare,不 confirm)→ 未就绪的 content。返回 content id。
async fn prepare_only(c: &Client, mime: &str) -> String {
    let v = expect_json(
        c.post_json(
            "/api/v1/frontend/contents/upload-url",
            &json!({ "name": "avatar-src", "file_name": "a.png", "mime_type": mime }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    v["content"]["id"].as_str().unwrap().to_owned()
}

/// PUT 资料只绑头像(其余字段清空 —— 全量替换)。
async fn put_avatar(c: &Client, user_id: &str, cid: &str) -> Response {
    c.put_json(&profile_path(user_id), &json!({ "avatar_content_id": cid }))
        .await
}

/// 头像端点代理出图(内存后端无 presign):200 + 原字节 + 声明的 mime + inline + CSP sandbox。
async fn expect_avatar_bytes(resp: Response, mime: &str) {
    assert_eq!(resp.status(), StatusCode::OK, "头像端点应出图");
    let headers = resp.headers().clone();
    assert_eq!(headers["content-type"], mime);
    assert_eq!(headers["content-disposition"], "inline");
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("sandbox"), "代理出图要带 CSP sandbox: {csp}");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), PNG, "应原样出上传的字节");
}

// ───────────────────────────── 前台:/profiles/me ─────────────────────────────

/// `/me`:未建 → **200 空资料**(user_id 是本人、其余 null,不是 404);
/// 建后与按 id 读逐字段等值(me 只是身份别名)。
#[tokio::test]
async fn me_blank_before_creation_then_equals_by_id() {
    let s = TestServer::start().await;
    let (user, uid) = fresh_user(&s);

    let blank = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert_eq!(
        blank["user_id"], uid,
        "空资料带本人 id(前端 PUT 要用): {blank}"
    );
    for k in [
        "display_name",
        "phone",
        "avatar_content_id",
        "avatar_url",
        "created_at",
        "updated_at",
    ] {
        assert!(blank[k].is_null(), "未建资料 {k} 应为 null: {blank}");
    }

    let created = expect_json(
        user.put_json(&profile_path(&uid), &json!({ "display_name": "Alice" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert!(created["created_at"].is_string() && created["updated_at"].is_string());

    let me = expect_json(user.get(ME).await, StatusCode::OK).await;
    let by_id = expect_json(user.get(&profile_path(&uid)).await, StatusCode::OK).await;
    assert_eq!(me, by_id, "me 应与按 id 读等值");
    assert_eq!(me["display_name"], "Alice");
}

/// seed 账号的初始资料:建号时连带建行(admin 带 display_name;user 没配 → null 但行在,有时间戳)。
#[tokio::test]
async fn me_returns_seeded_profile() {
    let s = TestServer::start().await;
    let admin = s.login(ADMIN, PASSWORD).await;
    let v = expect_json(admin.get(ME).await, StatusCode::OK).await;
    assert_eq!(v["display_name"], "Admin", "{v}");
    assert_eq!(v["user_id"], my_id(&admin).await);
    assert!(v["created_at"].is_string(), "真行 → 真时间戳: {v}");

    let user = s.login(USER, PASSWORD).await;
    let v = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert!(v["display_name"].is_null(), "{v}");
    assert!(v["created_at"].is_string(), "seed user 也有初始资料行: {v}");
}

/// 四个前台端点都要登录:无凭据 → 401 + 统一错误体。
#[tokio::test]
async fn frontend_endpoints_require_login_401() {
    let s = TestServer::start().await;
    let c = s.anon();
    let id = Uuid::now_v7().to_string();
    expect_error(c.get(ME).await, StatusCode::UNAUTHORIZED, "unauthorized").await;
    expect_error(
        c.get(&profile_path(&id)).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    expect_error(
        c.put_json(&profile_path(&id), &json!({ "display_name": "x" }))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    expect_error(
        c.get(&avatar_path(&id)).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

// ───────────────────────────── 前台:读 / 写 ─────────────────────────────

/// GET 未建 → 404;PUT 建 → 201;再 PUT → 200 且**全量覆盖**(未给字段清空);任意登录用户可读他人。
#[tokio::test]
async fn put_upsert_full_replace_and_anyone_can_read() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let path = profile_path(&uid);

    expect_error(alice.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;

    let v = expect_json(
        alice
            .put_json(&path, &json!({ "display_name": "San", "phone": "138" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["user_id"], uid);
    assert_eq!(v["display_name"], "San");
    assert_eq!(v["phone"], "138");
    assert!(v["avatar_url"].is_null() && v["avatar_content_id"].is_null());

    let v = expect_json(
        alice.put_json(&path, &json!({ "phone": "999" })).await,
        StatusCode::OK,
    )
    .await;
    assert!(v["display_name"].is_null(), "全量替换:未给字段清空: {v}");
    assert_eq!(v["phone"], "999");

    // 另一个普通用户(无 write:all,seed user 登录会话)读 alice → 200,且看到的是持久化后的值
    let bob = s.login(USER, PASSWORD).await;
    let got = expect_json(bob.get(&path).await, StatusCode::OK).await;
    assert_eq!(got["phone"], "999");
    assert!(got["display_name"].is_null());
}

/// 读别人未建的资料 → 404(与 me 的"空资料"刻意不同)。
#[tokio::test]
async fn get_missing_profile_is_404() {
    let s = TestServer::start().await;
    let user = s.login(USER, PASSWORD).await;
    expect_error(
        user.get(&profile_path(&Uuid::now_v7().to_string())).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// ownership:普通用户改别人 → 403(不是 404:资料本就任意可读,存在性不敏感)且不落库;
/// admin(seed 有 `profiles:write:all`)可替任何人建(201)/改(200)。
#[tokio::test]
async fn ownership_gate_403_and_write_all_can_edit_others() {
    let s = TestServer::start().await;
    let user = s.login(USER, PASSWORD).await;
    let admin = s.login(ADMIN, PASSWORD).await;
    let admin_id = my_id(&admin).await;
    let (fresh, fresh_id) = fresh_user(&s);

    expect_error(
        user.put_json(
            &profile_path(&admin_id),
            &json!({ "display_name": "pwned" }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let v = expect_json(admin.get(ME).await, StatusCode::OK).await;
    assert_eq!(v["display_name"], "Admin", "被拒的写不应生效: {v}");

    let v = expect_json(
        admin
            .put_json(
                &profile_path(&fresh_id),
                &json!({ "display_name": "ByAdmin" }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["user_id"], fresh_id);
    let v = expect_json(
        admin
            .put_json(
                &profile_path(&fresh_id),
                &json!({ "display_name": "ByAdminAgain" }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["display_name"], "ByAdminAgain");
    // 本人看到的就是 admin 改后的
    let me = expect_json(fresh.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["display_name"], "ByAdminAgain");
}

/// scope 收窄(降权令牌):缺 read → 读任意人 403,但 me 仍 200(零 perm 的自我操作);
/// 缺 write → PUT 自己 403;scope 没给 write:all 的 admin 改别人 → 403。
#[tokio::test]
async fn scoped_tokens_gate_read_and_write() {
    let s = TestServer::start().await;
    let id = Uuid::now_v7();
    let uid = id.to_string();

    let write_only = s.bearer(&mint(id, "u", &["user"], vec![Perm::ProfileWrite]));
    expect_error(
        write_only.get(&profile_path(&uid)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let me = expect_json(write_only.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["user_id"], uid);
    expect(
        write_only
            .put_json(&profile_path(&uid), &json!({ "display_name": "w" }))
            .await,
        StatusCode::CREATED,
    )
    .await;

    let read_only = s.bearer(&mint(id, "u", &["user"], vec![Perm::ProfileRead]));
    expect_error(
        read_only
            .put_json(&profile_path(&uid), &json!({ "display_name": "r" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let v = expect_json(read_only.get(&profile_path(&uid)).await, StatusCode::OK).await;
    assert_eq!(v["display_name"], "w", "403 的写不应生效");

    // admin 角色够 write:all,但 scope 只给了 write → 改别人仍 403(scope 只收窄不放大)
    let narrowed_admin = s.bearer(&admin_scoped(vec![Perm::ProfileWrite]));
    expect_error(
        narrowed_admin
            .put_json(&profile_path(&uid), &json!({ "display_name": "x" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 校验与边界:超长(>255)→ 422;恰 255 → 通过;路径非 UUID / body 非 JSON → 400(统一错误体)。
#[tokio::test]
async fn put_validation_and_bad_input() {
    let s = TestServer::start().await;
    let (user, uid) = fresh_user(&s);
    let path = profile_path(&uid);

    for body in [
        json!({ "phone": "9".repeat(256) }),
        json!({ "display_name": "n".repeat(256) }),
    ] {
        expect_error(
            user.put_json(&path, &body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(user.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
    expect(
        user.put_json(
            &path,
            &json!({ "display_name": "n".repeat(255), "phone": "9".repeat(255) }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;

    expect_error(
        user.get(&profile_path("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        user.put_json(&profile_path("not-a-uuid"), &json!({})).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let resp = user
        .req(Method::PUT, &path)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(resp, StatusCode::BAD_REQUEST, "bad_request").await;
}

// ───────────────────────────── 前台:头像 ─────────────────────────────

/// 头像全链路:上传 png → 绑定 → avatar_url 富化为头像端点;头像端点本人 + 跨用户都出图;
/// 而 content 本体的 preview 严格按 owner 隔离(非 owner → 404)。
#[tokio::test]
async fn avatar_bind_enrich_and_serve_cross_user() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let cid = upload(&alice, "image/png").await;

    let v = expect_json(put_avatar(&alice, &uid, &cid).await, StatusCode::CREATED).await;
    assert_eq!(v["avatar_content_id"], cid);
    assert_eq!(v["avatar_url"], avatar_path(&uid), "{v}");
    // 读路径同样富化
    let v = expect_json(alice.get(&profile_path(&uid)).await, StatusCode::OK).await;
    assert_eq!(v["avatar_url"], avatar_path(&uid));

    let bob = s.login(USER, PASSWORD).await;
    expect_avatar_bytes(alice.get(&avatar_path(&uid)).await, "image/png").await;
    expect_avatar_bytes(bob.get(&avatar_path(&uid)).await, "image/png").await;

    expect_error(
        bob.get(&format!("/api/v1/frontend/contents/{cid}/preview"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 头像 content 被删(悬空):读资料降级 avatar_url=null、保留原始引用,不炸;头像端点 → 404。
#[tokio::test]
async fn avatar_dangling_after_content_delete_degrades() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let admin = s.login(ADMIN, PASSWORD).await; // seed admin 有 contents:delete + write:all
    let cid = upload(&alice, "image/png").await;
    expect(put_avatar(&alice, &uid, &cid).await, StatusCode::CREATED).await;

    expect(
        admin
            .delete(&format!("/api/v1/frontend/contents/{cid}"))
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;

    let v = expect_json(alice.get(&profile_path(&uid)).await, StatusCode::OK).await;
    assert!(v["avatar_url"].is_null(), "悬空应降级 null: {v}");
    assert_eq!(v["avatar_content_id"], cid, "原始引用保留");
    let me = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert!(me["avatar_url"].is_null());
    expect_error(
        alice.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 绑定五拒 → 422(且一律不落库):不存在 / prepare 未 confirm / 非图片 / SVG(活动内容,防存储型 XSS)/
/// 别人 owner 的图(防把他人私图"洗"成自己的头像)。
#[tokio::test]
async fn avatar_bad_bindings_rejected_422() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let bob = s.login(USER, PASSWORD).await;

    let cases = [
        ("不存在", Uuid::now_v7().to_string()),
        ("未 confirm", prepare_only(&alice, "image/png").await),
        ("非图片", upload(&alice, "text/plain").await),
        ("SVG", upload(&alice, "image/svg+xml").await),
        ("别人的图", upload(&bob, "image/png").await),
    ];
    for (why, cid) in cases {
        let v = expect_json(
            put_avatar(&alice, &uid, &cid).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_eq!(v["code"], "validation", "{why}: {v}");
    }
    expect_error(
        alice.get(&profile_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// write:all 也不能把**自己的** content 绑成别人的头像(owner 必须是目标用户)。
#[tokio::test]
async fn write_all_cannot_bind_foreign_content_to_others() {
    let s = TestServer::start().await;
    let admin = s.login(ADMIN, PASSWORD).await;
    let user_id = seed_id(&s, USER).await;
    let admins_png = upload(&admin, "image/png").await;
    expect_error(
        put_avatar(&admin, &user_id, &admins_png).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

/// 头像端点在无资料 / 有资料但未绑头像时 → 404(不泄露、不炸)。
#[tokio::test]
async fn avatar_endpoint_404_when_unset() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    expect_error(
        alice.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect(
        alice
            .put_json(&profile_path(&uid), &json!({ "display_name": "San" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    expect_error(
        alice.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    // 换绑后解绑(PUT 不带 avatar_content_id = 清空)→ 又回 404
    let cid = upload(&alice, "image/webp").await;
    expect(put_avatar(&alice, &uid, &cid).await, StatusCode::OK).await;
    expect_avatar_bytes(alice.get(&avatar_path(&uid)).await, "image/webp").await;
    let v = expect_json(
        alice
            .put_json(&profile_path(&uid), &json!({ "display_name": "San" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(v["avatar_content_id"].is_null() && v["avatar_url"].is_null());
    expect_error(
        alice.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// presign 部署形态(S3/minio):头像端点 → 307 跳签名 URL,`Cache-Control: no-store`。
/// 起服务时把 content 的字节后端换成"会签 URL"的 store(字节仍在内存),其余全真。
#[tokio::test]
async fn avatar_presign_backend_redirects_307() {
    let s = TestServer::start_with(|st| {
        let contents = content::ContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(PresignStore(content::InMemoryObjectStore::new())),
            "cdn",
        );
        st.profiles = ProfileService::new(
            Arc::new(InMemoryProfileRepo::new()),
            Arc::new(ContentAvatarProbe::new(contents.clone())),
        );
        st.contents = contents;
    })
    .await;
    let alice = s.login(USER, PASSWORD).await;
    let uid = my_id(&alice).await;
    let cid = upload(&alice, "image/png").await;
    expect(put_avatar(&alice, &uid, &cid).await, StatusCode::CREATED).await;

    let resp = s.bearer(&user_token().0).get(&avatar_path(&uid)).await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "presign 后端应 307"
    );
    let location = resp.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with("https://cdn.test/") && location.ends_with("?inline"),
        "Location 应是 inline 签名 URL: {location}"
    );
    assert_eq!(resp.headers()["cache-control"], "no-store");
}

/// 只把 preview_url 覆写成"签名 URL"的测试 store(字节走内存)。
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
    async fn preview_url(&self, k: &str) -> Result<Option<String>, content::ContentError> {
        Ok(Some(format!("https://cdn.test/{k}?inline")))
    }
}

// ───────────────────────────── 后台:/admin/auth/users/{id}/... ─────────────────────────────

/// 后台三端点的闸:无凭据 401;user(无 admin:login)被组闸 403;admin 能进后台但无 users:admin → 403;
/// superadmin → 放行;superadmin 降权令牌(scope 只有 admin:login)→ 403。
#[tokio::test]
async fn admin_endpoints_gate() {
    let s = TestServer::start().await;
    let (target_session, target) = fresh_user(&s);
    let body = json!({ "display_name": "x" });

    async fn all_three(c: &Client, target: &str, body: &Value) -> Vec<Response> {
        vec![
            c.get(&admin_profile_path(target)).await,
            c.put_json(&admin_profile_path(target), body).await,
            c.post_multipart(&admin_avatar_path(target), file_form("image/png", PNG))
                .await,
        ]
    }

    for resp in all_three(&s.anon(), &target, &body).await {
        expect_error(resp, StatusCode::UNAUTHORIZED, "unauthorized").await;
    }
    let user = s.login(USER, PASSWORD).await;
    for resp in all_three(&user, &target, &body).await {
        expect_error(resp, StatusCode::FORBIDDEN, "forbidden").await;
    }
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    for resp in all_three(&admin, &target, &body).await {
        expect_error(resp, StatusCode::FORBIDDEN, "forbidden").await;
    }
    let narrowed = s.bearer(&mint(
        Uuid::now_v7(),
        "sa",
        &["superadmin"],
        vec![Perm::AdminLogin],
    ));
    for resp in all_three(&narrowed, &target, &body).await {
        expect_error(resp, StatusCode::FORBIDDEN, "forbidden").await;
    }
    // 以上全被拒 → 目标用户仍无资料、无 content
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    expect_error(
        sa.get(&admin_profile_path(&target)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let mine = expect_json(
        target_session.get("/api/v1/frontend/contents").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(mine, json!([]), "被拒的头像上传不应落 content: {mine}");
}

/// 后台读资料:seed 的 admin 有初始资料 → 200;未建资料的用户 → 404;路径非 UUID → 400。
#[tokio::test]
async fn admin_get_user_profile() {
    let s = TestServer::start().await;
    let admin_id = seed_id(&s, ADMIN).await;
    let (_, user_id) = fresh_user(&s);
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;

    let v = expect_json(sa.get(&admin_profile_path(&admin_id)).await, StatusCode::OK).await;
    assert_eq!(v["user_id"], admin_id);
    assert_eq!(v["display_name"], "Admin");
    assert!(v["created_at"].is_string());

    expect_error(
        sa.get(&admin_profile_path(&user_id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.get(&admin_profile_path("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 后台改资料:PUT 全量(首建也回 200);本人前台可见;空 body 清空;超长 422;
/// 头像同样四查 —— 绑 superadmin 自己的图给别人 → 422,绑目标本人的图 → 200 且富化。
#[tokio::test]
async fn admin_put_user_profile_full_replace() {
    let s = TestServer::start().await;
    let user = s.login(USER, PASSWORD).await;
    let user_id = my_id(&user).await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    let path = admin_profile_path(&user_id);

    let v = expect_json(
        sa.put_json(
            &path,
            &json!({ "display_name": "Set By SA", "phone": "123" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["user_id"], user_id);
    assert_eq!(v["display_name"], "Set By SA");
    let me = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["display_name"], "Set By SA");
    assert_eq!(me["phone"], "123");

    let v = expect_json(sa.put_json(&path, &json!({})).await, StatusCode::OK).await;
    assert!(
        v["display_name"].is_null() && v["phone"].is_null(),
        "全量替换:空 body 清空: {v}"
    );

    expect_error(
        sa.put_json(&path, &json!({ "phone": "9".repeat(256) }))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    let sa_front = s.login(SUPERADMIN, PASSWORD).await;
    let sa_png = upload(&sa_front, "image/png").await;
    expect_error(
        sa.put_json(&path, &json!({ "avatar_content_id": sa_png }))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    let users_png = upload(&user, "image/gif").await;
    let v = expect_json(
        sa.put_json(&path, &json!({ "avatar_content_id": users_png }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["avatar_content_id"], users_png);
    assert_eq!(v["avatar_url"], avatar_path(&user_id));
    let got = expect_json(sa.get(&path).await, StatusCode::OK).await;
    assert_eq!(got, v, "后台读与写回一致");
}

/// 后台传头像(无资料的用户):上传即绑定 → 200,content owner = 目标用户;本人与他人都能经头像端点看到。
#[tokio::test]
async fn admin_upload_avatar_creates_profile_and_binds() {
    let s = TestServer::start().await;
    let (user, user_id) = fresh_user(&s);
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;

    let v = expect_json(
        sa.post_multipart(&admin_avatar_path(&user_id), file_form("image/jpeg", PNG))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["user_id"], user_id);
    assert!(v["display_name"].is_null() && v["phone"].is_null());
    assert_eq!(v["avatar_url"], avatar_path(&user_id));
    let cid = v["avatar_content_id"]
        .as_str()
        .expect("应绑定 content")
        .to_owned();

    // content 归目标用户:本人能按 owner 读到,且列表里就是它
    let c = expect_json(
        user.get(&format!("/api/v1/frontend/contents/{cid}")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        c["owner_id"], user_id,
        "头像 content 的 owner 应是目标用户: {c}"
    );

    expect_avatar_bytes(user.get(&avatar_path(&user_id)).await, "image/jpeg").await;
    let other = s.login(USER, PASSWORD).await;
    expect_avatar_bytes(other.get(&avatar_path(&user_id)).await, "image/jpeg").await;
    let me = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["avatar_content_id"], cid);
}

/// 后台传头像保留现有 display_name / phone(只换头像);再传一次 → 换成新 content。
#[tokio::test]
async fn admin_upload_avatar_preserves_existing_fields() {
    let s = TestServer::start().await;
    let admin_id = seed_id(&s, ADMIN).await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    expect(
        sa.put_json(
            &admin_profile_path(&admin_id),
            &json!({ "display_name": "Admin", "phone": "555" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;

    let first = expect_json(
        sa.post_multipart(&admin_avatar_path(&admin_id), file_form("image/png", PNG))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        first["display_name"], "Admin",
        "应保留 display_name: {first}"
    );
    assert_eq!(first["phone"], "555", "应保留 phone: {first}");
    assert!(first["avatar_content_id"].is_string());

    let second = expect_json(
        sa.post_multipart(&admin_avatar_path(&admin_id), file_form("image/webp", PNG))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_ne!(
        second["avatar_content_id"], first["avatar_content_id"],
        "应换成新 content"
    );
    assert_eq!(second["display_name"], "Admin");
    let viewer = s.login(USER, PASSWORD).await;
    expect_avatar_bytes(viewer.get(&avatar_path(&admin_id)).await, "image/webp").await;
}

/// 后台传头像的拒绝分支,且**先校验后写**(不留孤儿 content、不建资料):
/// SVG / 非图片 → 422;缺 file 部分 → 422;body 不是 multipart → 400。
#[tokio::test]
async fn admin_upload_avatar_rejects_without_side_effects() {
    let s = TestServer::start().await;
    let (user, user_id) = fresh_user(&s);
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    let path = admin_avatar_path(&user_id);

    for mime in ["image/svg+xml", "text/plain"] {
        expect_error(
            sa.post_multipart(&path, file_form(mime, PNG)).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        sa.post_multipart(&path, Form::new().text("name", "no-file"))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        sa.post_json(&path, &json!({ "file": "not multipart" }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;

    let mine = expect_json(user.get("/api/v1/frontend/contents").await, StatusCode::OK).await;
    assert_eq!(mine, json!([]), "被拒的上传不应落 content: {mine}");
    expect_error(
        sa.get(&admin_profile_path(&user_id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

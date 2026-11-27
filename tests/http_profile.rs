//! profile(用户资料 + 头像)的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架
//! (换底座只换 `http_support::serve`)。与 `profile_api.rs`(axum oneshot)覆盖同一组场景并补强:
//! 前台读写 / ownership / scope 收窄 / 头像绑定四查(+ 非本人)/ 头像端点出图与降级,
//! 以及后台(`users:admin`,seed 下仅 superadmin 持有)的读 / 改 / 传头像。
//!
//! **资料全局一份**(spec §6.2):`profiles:*` 是**平台级**权限(只有平台管理员持有),租户管理员改不了别人的资料;
//! 本人自助走 `/profiles/me`(仅登录)。**头像是个人内容**(`ContentScope::Personal`,spec §4.4):只能经
//! `POST /profiles/me/avatar`(本人)或后台 `POST /admin/auth/users/{id}/avatar`(`users:admin`)上传;
//! 租户作用域的 `contents/*` 端点看不到它,也不能拿租户内容当头像;头像端点对所有已登录用户可读、跨租户可见。
//! seed 给**每个** seed 账号都建了初始资料(superadmin / admin 带 display_name,user 的为 null)——
//! 要"还没有资料"的主体,用自铸令牌的新 user(`fresh_user`)。
//!
//! covers: GET /api/v1/frontend/profiles/me
//! covers: PUT /api/v1/frontend/profiles/me
//! covers: POST /api/v1/frontend/profiles/me/avatar
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
use http_support::DEFAULT_TENANT;
use http_support::{
    expect, expect_error, expect_json, mint, superadmin_token, user_token, Client, TestServer,
    ADMIN, PASSWORD, SUPERADMIN, USER,
};
use reqwest::multipart::{Form, Part};
use reqwest::{Method, Response, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const P: &str = "/api/v1/frontend/profiles";
const ME: &str = "/api/v1/frontend/profiles/me";
const MY_AVATAR: &str = "/api/v1/frontend/profiles/me/avatar";

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

/// 本人传头像(`POST /profiles/me/avatar`,个人内容,上传即绑定)→ 200,返回资料 JSON。
async fn upload_my_avatar(c: &Client, mime: &str) -> Value {
    expect_json(
        c.post_multipart(MY_AVATAR, file_form(mime, PNG)).await,
        StatusCode::OK,
    )
    .await
}

/// 本人传头像,只要绑定上的 content id。
async fn my_avatar_id(c: &Client, mime: &str) -> String {
    upload_my_avatar(c, mime).await["avatar_content_id"]
        .as_str()
        .expect("应绑定 content")
        .to_owned()
}

/// 一步上传到**租户内容**(`contents/upload`)→ 已就绪的租户 content,owner = 会话主体。返回 content id。
async fn upload_tenant_content(c: &Client, mime: &str) -> String {
    let v = expect_json(
        c.post_multipart("/api/v1/frontend/contents/upload", file_form(mime, PNG))
            .await,
        StatusCode::CREATED,
    )
    .await;
    v["content"]["id"].as_str().unwrap().to_owned()
}

/// 本人 PUT 资料只绑头像(其余字段清空 —— 全量替换)。
async fn put_my_avatar_id(c: &Client, cid: &str) -> Response {
    c.put_json(ME, &json!({ "avatar_content_id": cid })).await
}

/// 平台管理员会话(平台角色 superadmin:持 `profiles:*`)。
fn platform_admin(s: &TestServer) -> Client {
    s.bearer(&superadmin_token(Uuid::now_v7(), vec![]))
}

/// 别的租户里的一个成员(随机租户、随机主体)。
fn other_tenant_member(s: &TestServer, roles: &[&str]) -> Client {
    s.bearer(&mint(
        Uuid::now_v7(),
        "other",
        &[],
        Some(Uuid::now_v7()),
        roles,
        vec![],
    ))
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

/// `/me`:未建 → **200 空资料**(user_id 是本人、其余 null,不是 404);PUT /me 建 → 201,
/// 建后 me 与平台管理员按 id 读逐字段等值(me 只是身份别名)。
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
        user.put_json(ME, &json!({ "display_name": "Alice" })).await,
        StatusCode::CREATED,
    )
    .await;
    assert!(created["created_at"].is_string() && created["updated_at"].is_string());

    let me = expect_json(user.get(ME).await, StatusCode::OK).await;
    let by_id = expect_json(
        platform_admin(&s).get(&profile_path(&uid)).await,
        StatusCode::OK,
    )
    .await;
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

/// 前台端点都要登录:无凭据 → 401 + 统一错误体。
#[tokio::test]
async fn frontend_endpoints_require_login_401() {
    let s = TestServer::start().await;
    let c = s.anon();
    let id = Uuid::now_v7().to_string();
    expect_error(c.get(ME).await, StatusCode::UNAUTHORIZED, "unauthorized").await;
    expect_error(
        c.put_json(ME, &json!({ "display_name": "x" })).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    expect_error(
        c.post_multipart(MY_AVATAR, file_form("image/png", PNG))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
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

/// PUT /me:建 → 201;再 PUT → 200 且**全量覆盖**(未给字段清空)。资料全局:不需要当前租户
/// (平台上下文的令牌也能改自己的资料)。
#[tokio::test]
async fn put_me_upsert_full_replace_without_tenant() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);

    let v = expect_json(
        alice
            .put_json(ME, &json!({ "display_name": "San", "phone": "138" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["user_id"], uid);
    assert_eq!(v["display_name"], "San");
    assert_eq!(v["phone"], "138");
    assert!(v["avatar_url"].is_null() && v["avatar_content_id"].is_null());

    let v = expect_json(
        alice.put_json(ME, &json!({ "phone": "999" })).await,
        StatusCode::OK,
    )
    .await;
    assert!(v["display_name"].is_null(), "全量替换:未给字段清空: {v}");
    assert_eq!(v["phone"], "999");
    let got = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert_eq!(got["phone"], "999");

    // 没有当前租户(平台上下文)的令牌:资料是全局的,照样能建 / 改自己的
    let id = Uuid::now_v7();
    let no_tenant = s.bearer(&mint(id, "nt", &[], None, &[], vec![]));
    let v = expect_json(
        no_tenant
            .put_json(ME, &json!({ "display_name": "NoTenant" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["user_id"], id.to_string());
}

/// PUT /me 校验与边界:超长(>255)→ 422 且不落库;恰 255 → 通过;body 非 JSON → 400。
#[tokio::test]
async fn put_me_validation_and_bad_input() {
    let s = TestServer::start().await;
    let (user, _) = fresh_user(&s);

    for body in [
        json!({ "phone": "9".repeat(256) }),
        json!({ "display_name": "n".repeat(256) }),
    ] {
        expect_error(
            user.put_json(ME, &body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    let v = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert!(v["created_at"].is_null(), "被拒的写不应建资料: {v}");
    expect(
        user.put_json(
            ME,
            &json!({ "display_name": "n".repeat(255), "phone": "9".repeat(255) }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    let resp = user
        .req(Method::PUT, ME)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(resp, StatusCode::BAD_REQUEST, "bad_request").await;
}

// ───────────────────────────── 前台:按 id 读 / 写(平台级) ─────────────────────────────

/// 按 id 读 / 写别人的资料是**平台级**权限:租户成员(含租户管理员)读别人 → 403、改别人 → 403(且不落库);
/// 平台管理员可读、可替任何人建(201)/ 改(200)。资料全局一份,租户管理员不能改所有人的资料。
#[tokio::test]
async fn by_id_access_is_platform_only() {
    let s = TestServer::start().await;
    let user = s.login(USER, PASSWORD).await;
    let tenant_admin = s.login(ADMIN, PASSWORD).await;
    let admin_id = my_id(&tenant_admin).await;
    let (fresh, fresh_id) = fresh_user(&s);
    let pa = platform_admin(&s);

    for c in [&user, &tenant_admin] {
        expect_error(
            c.get(&profile_path(&admin_id)).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
        expect_error(
            c.put_json(
                &profile_path(&fresh_id),
                &json!({ "display_name": "pwned" }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    let v = expect_json(fresh.get(ME).await, StatusCode::OK).await;
    assert!(v["created_at"].is_null(), "被拒的写不应生效: {v}");

    let v = expect_json(pa.get(&profile_path(&admin_id)).await, StatusCode::OK).await;
    assert_eq!(v["display_name"], "Admin");
    let v = expect_json(
        pa.put_json(
            &profile_path(&fresh_id),
            &json!({ "display_name": "ByPlatform" }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["user_id"], fresh_id);
    let v = expect_json(
        pa.put_json(
            &profile_path(&fresh_id),
            &json!({ "display_name": "ByPlatformAgain" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["display_name"], "ByPlatformAgain");
    let me = expect_json(fresh.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["display_name"], "ByPlatformAgain");
}

/// 防接管:按 id 改**别人**的资料另要 `platform:roles`(只有 superadmin)。平台管理员(`platform_admin`,持
/// `profiles:write:all` 但没有 `platform:roles`)改 superadmin / 普通账号的资料 → 403 且不落库;改自己(按 id)照常;
/// 改普通账号走后台 `PUT /admin/auth/users/{id}/profile` 照常(那里按目标的平台角色判闸)。superadmin 改别人仍可。
#[tokio::test]
async fn platform_admin_cannot_put_others_profile_by_id() {
    let s = TestServer::start().await;
    let sa = s.login(SUPERADMIN, PASSWORD).await;
    let sa_id = my_id(&sa).await;
    let user_id = seed_id(&s, USER).await;
    let pa_id = Uuid::now_v7();
    let pa = s.bearer(&mint(pa_id, "pa", &["platform_admin"], None, &[], vec![]));

    let before = expect_json(sa.get(ME).await, StatusCode::OK).await;
    for target in [&sa_id, &user_id] {
        expect_error(
            pa.put_json(
                &profile_path(target),
                &json!({ "display_name": "pwned", "phone": "000" }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    let after = expect_json(sa.get(ME).await, StatusCode::OK).await;
    assert_eq!(
        after["display_name"], before["display_name"],
        "被拒的写不应生效"
    );
    assert_eq!(after["phone"], before["phone"], "被拒的写不应生效");

    // 改自己(按 id)不是"改别人",不要 platform:roles
    let v = expect_json(
        pa.put_json(
            &profile_path(&pa_id.to_string()),
            &json!({ "display_name": "Me" }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(v["display_name"], "Me");

    // 平台管理员改普通账号的资料:走后台接口
    let v = expect_json(
        pa.put_json(
            &admin_profile_path(&user_id),
            &json!({ "display_name": "ByAdminRoute" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["display_name"], "ByAdminRoute");
    // …但后台接口改 superadmin 照样 403(guard_platform_account)
    expect_error(
        pa.put_json(
            &admin_profile_path(&sa_id),
            &json!({ "display_name": "pwned" }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;

    // superadmin 改别人仍可
    let v = expect_json(
        sa.put_json(
            &profile_path(&user_id),
            &json!({ "display_name": "BySuper" }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["display_name"], "BySuper");
}

/// superadmin 的降权令牌:scope 里缺 `platform:roles` → 按 id 改别人 403(scope 只收窄不放大)。
#[tokio::test]
async fn put_others_profile_needs_platform_roles_in_scope() {
    let s = TestServer::start().await;
    let (_, target) = fresh_user(&s);
    let narrowed = s.bearer(&superadmin_token(
        Uuid::now_v7(),
        vec![Perm::ProfileWrite, Perm::ProfileWriteAll],
    ));
    expect_error(
        narrowed
            .put_json(&profile_path(&target), &json!({ "display_name": "x" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let full = s.bearer(&superadmin_token(
        Uuid::now_v7(),
        vec![
            Perm::ProfileWrite,
            Perm::ProfileWriteAll,
            Perm::PlatformRoles,
        ],
    ));
    expect(
        full.put_json(&profile_path(&target), &json!({ "display_name": "x" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
}

/// 读别人未建的资料 → 404(与 me 的"空资料"刻意不同)。
#[tokio::test]
async fn get_missing_profile_is_404() {
    let s = TestServer::start().await;
    expect_error(
        platform_admin(&s)
            .get(&profile_path(&Uuid::now_v7().to_string()))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// scope 收窄(降权的平台管理员令牌):缺 read → 按 id 读 403;缺 write:all → 改别人 403(scope 只收窄不放大);
/// me 仍 200(零 perm 的自我操作)。
#[tokio::test]
async fn scoped_platform_tokens_gate_read_and_write() {
    let s = TestServer::start().await;
    let (_, target) = fresh_user(&s);

    let write_only = s.bearer(&superadmin_token(Uuid::now_v7(), vec![Perm::ProfileWrite]));
    expect_error(
        write_only.get(&profile_path(&target)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        write_only
            .put_json(&profile_path(&target), &json!({ "display_name": "x" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect(write_only.get(ME).await, StatusCode::OK).await;

    let read_only = s.bearer(&superadmin_token(Uuid::now_v7(), vec![Perm::ProfileRead]));
    expect_error(
        read_only
            .put_json(&profile_path(&target), &json!({ "display_name": "r" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        read_only.get(&profile_path(&target)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 路径非 UUID → 400(统一错误体)。
#[tokio::test]
async fn by_id_bad_path_is_400() {
    let s = TestServer::start().await;
    let pa = platform_admin(&s);
    expect_error(
        pa.get(&profile_path("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        pa.put_json(&profile_path("not-a-uuid"), &json!({})).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── 前台:头像(个人内容) ─────────────────────────────

/// 头像全链路:本人传 png(上传即绑定)→ avatar_url 富化为头像端点;头像端点本人 + 跨用户都出图;
/// 保留现有 display_name / phone(只换头像)。
#[tokio::test]
async fn my_avatar_upload_binds_enriches_and_serves() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    expect(
        alice
            .put_json(ME, &json!({ "display_name": "Alice", "phone": "1" }))
            .await,
        StatusCode::CREATED,
    )
    .await;

    let v = upload_my_avatar(&alice, "image/png").await;
    assert_eq!(v["user_id"], uid);
    assert_eq!(v["display_name"], "Alice", "应保留 display_name: {v}");
    assert_eq!(v["phone"], "1", "应保留 phone: {v}");
    assert!(v["avatar_content_id"].is_string());
    assert_eq!(v["avatar_url"], avatar_path(&uid), "{v}");
    let me = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["avatar_url"], avatar_path(&uid));

    let bob = s.login(USER, PASSWORD).await;
    expect_avatar_bytes(alice.get(&avatar_path(&uid)).await, "image/png").await;
    expect_avatar_bytes(bob.get(&avatar_path(&uid)).await, "image/png").await;
}

/// 头像跨租户可见:资料全局、头像是个人内容 —— 别的租户的成员、没有当前租户的令牌都能经头像端点看到。
#[tokio::test]
async fn avatar_visible_across_tenants() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    upload_my_avatar(&alice, "image/png").await;

    let other = other_tenant_member(&s, &["user"]);
    expect_avatar_bytes(other.get(&avatar_path(&uid)).await, "image/png").await;
    let no_tenant = s.bearer(&mint(Uuid::now_v7(), "nt", &[], None, &[], vec![]));
    expect_avatar_bytes(no_tenant.get(&avatar_path(&uid)).await, "image/png").await;

    // 头像也能在没有当前租户时上传(资料是全局的)
    let id = Uuid::now_v7();
    let nt_self = s.bearer(&mint(id, "nt", &[], None, &[], vec![]));
    upload_my_avatar(&nt_self, "image/webp").await;
    expect_avatar_bytes(other.get(&avatar_path(&id.to_string())).await, "image/webp").await;
}

/// 头像不进租户内容:本人的 `contents` 列表里没有它,按 id 读 / 预览都 404(本人与租户管理员皆然),
/// 租户管理员删也是 404。
#[tokio::test]
async fn avatar_not_listed_in_tenant_contents() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let cid = my_avatar_id(&alice, "image/png").await;

    let mine = expect_json(alice.get("/api/v1/frontend/contents").await, StatusCode::OK).await;
    assert_eq!(mine, json!([]), "头像不该出现在租户内容列表里: {mine}");
    let tenant_admin = s.login(ADMIN, PASSWORD).await; // 有 contents:read:all / write:all / delete
    for c in [&alice, &tenant_admin] {
        for path in [
            format!("/api/v1/frontend/contents/{cid}"),
            format!("/api/v1/frontend/contents/{cid}/preview"),
        ] {
            expect_error(c.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
        }
    }
    // 删(user 角色没有 contents:delete,只用租户管理员试):同样 404,头像照常出图
    expect_error(
        tenant_admin
            .delete(&format!("/api/v1/frontend/contents/{cid}"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_avatar_bytes(tenant_admin.get(&avatar_path(&uid)).await, "image/png").await;
}

/// 只有本人能换自己的头像:别人(同租户成员 / 租户管理员)改不了按 id 的资料(403)、也不能把别人的头像
/// 绑到自己名下(422);本人再传一次 → 换成新 content。
#[tokio::test]
async fn only_owner_can_replace_avatar() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let first = my_avatar_id(&alice, "image/png").await;

    let (bob, _) = fresh_user(&s);
    let tenant_admin = s.login(ADMIN, PASSWORD).await;
    let tenant_admin_backend = s.login_admin(ADMIN, PASSWORD).await;
    let bobs = my_avatar_id(&bob, "image/png").await;
    for c in [&bob, &tenant_admin] {
        expect_error(
            c.put_json(&profile_path(&uid), &json!({ "avatar_content_id": bobs }))
                .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    for c in [&bob, &tenant_admin_backend] {
        expect_error(
            c.post_multipart(&admin_avatar_path(&uid), file_form("image/png", PNG))
                .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    // bob 把 alice 的头像绑成自己的 → 422(owner 必须是本人)
    expect_error(
        put_my_avatar_id(&bob, &first).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    let v = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert_eq!(v["avatar_content_id"], first, "别人的尝试都不该生效: {v}");

    let second = my_avatar_id(&alice, "image/webp").await;
    assert_ne!(second, first, "应换成新 content");
    expect_avatar_bytes(bob.get(&avatar_path(&uid)).await, "image/webp").await;
}

/// 本人传头像的拒绝分支,且**先校验后写**(不留孤儿 content、不建资料):SVG / 非图片 → 422;
/// 缺 file 部分 → 422;body 不是 multipart → 400。
#[tokio::test]
async fn my_avatar_upload_rejects_without_side_effects() {
    let s = TestServer::start().await;
    let (user, uid) = fresh_user(&s);

    for mime in ["image/svg+xml", "text/plain"] {
        expect_error(
            user.post_multipart(MY_AVATAR, file_form(mime, PNG)).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        user.post_multipart(MY_AVATAR, Form::new().text("name", "no-file"))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        user.post_json(MY_AVATAR, &json!({ "file": "not multipart" }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let v = expect_json(user.get(ME).await, StatusCode::OK).await;
    assert!(v["created_at"].is_null(), "被拒的上传不应建资料: {v}");
    expect_error(
        user.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 头像只认个人内容:租户内容(`contents/upload`,哪怕是本人的 png)、不存在的 id、别人的头像 → 绑定 422,一律不落库。
#[tokio::test]
async fn avatar_bad_bindings_rejected_422() {
    let s = TestServer::start().await;
    let (alice, _) = fresh_user(&s);
    let (bob, _) = fresh_user(&s);

    let cases = [
        ("不存在", Uuid::now_v7().to_string()),
        ("租户内容", upload_tenant_content(&alice, "image/png").await),
        ("别人的头像", my_avatar_id(&bob, "image/png").await),
    ];
    for (why, cid) in cases {
        let v = expect_json(
            put_my_avatar_id(&alice, &cid).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_eq!(v["code"], "validation", "{why}: {v}");
    }
    let v = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert!(v["created_at"].is_null(), "被拒的绑定不应建资料: {v}");
}

/// 显式重新绑定 / 解绑(PUT /me)不删任何头像:解绑(不带 avatar_content_id = 清空 → 头像端点 404)后,
/// 那张头像还在,可以再绑回来。
#[tokio::test]
async fn rebind_and_unbind_own_avatar() {
    let s = TestServer::start().await;
    let (alice, uid) = fresh_user(&s);
    let first = my_avatar_id(&alice, "image/png").await;

    let v = expect_json(
        alice.put_json(ME, &json!({ "display_name": "San" })).await,
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

    let v = expect_json(put_my_avatar_id(&alice, &first).await, StatusCode::OK).await;
    assert_eq!(v["avatar_content_id"], first, "解绑不删,能再绑回来");
    expect_avatar_bytes(alice.get(&avatar_path(&uid)).await, "image/png").await;
}

/// 起服务并留一个 content 服务句柄(个人内容没有 HTTP 读 / 删入口,测试直接经服务查 / 删)。
async fn start_with_contents() -> (TestServer, content::ContentService) {
    let contents = content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    );
    let handle = contents.clone();
    let s = TestServer::start_with(move |st| {
        st.profiles = ProfileService::new(
            Arc::new(InMemoryProfileRepo::new()),
            Arc::new(ContentAvatarProbe::new(contents.clone())),
        );
        st.contents = contents;
    })
    .await;
    (s, handle)
}

/// 个人作用域里这条 content 是否还活着。
async fn personal_alive(contents: &content::ContentService, cid: &str) -> bool {
    match contents
        .get_content(
            content::ContentScope::Personal,
            Uuid::parse_str(cid).unwrap(),
        )
        .await
    {
        Ok(_) => true,
        Err(content::ContentError::NotFound) => false,
        Err(e) => panic!("读个人内容出错: {e}"),
    }
}

/// 上传新头像会回收换下来的旧头像(零权限入口不能无限堆存储):传两次 → 第一张已软删、不能再绑回来;
/// 后台代传同样回收。显式重新绑定(PUT)不删:解绑后传新的,再 PUT 绑回旧的,新传的那张仍在。
#[tokio::test]
async fn uploading_again_soft_deletes_previous_avatar() {
    let (s, contents) = start_with_contents().await;
    let (alice, uid) = fresh_user(&s);
    let first = my_avatar_id(&alice, "image/png").await;
    let second = my_avatar_id(&alice, "image/webp").await;
    assert!(
        !personal_alive(&contents, &first).await,
        "换下来的旧头像应已软删"
    );
    assert!(personal_alive(&contents, &second).await);
    expect_error(
        put_my_avatar_id(&alice, &first).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_avatar_bytes(alice.get(&avatar_path(&uid)).await, "image/webp").await;

    // 后台代传(users:admin)替换 → 同样回收 alice 的上一张
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    let v = expect_json(
        sa.post_multipart(&admin_avatar_path(&uid), file_form("image/png", PNG))
            .await,
        StatusCode::OK,
    )
    .await;
    let third = v["avatar_content_id"].as_str().unwrap().to_owned();
    assert!(
        !personal_alive(&contents, &second).await,
        "后台代传也回收旧头像"
    );
    assert!(personal_alive(&contents, &third).await);

    // 显式重新绑定不删:解绑 → 传新的(此时没有已绑定的旧头像,third 不动)→ PUT 绑回 third → fourth 仍在
    expect(alice.put_json(ME, &json!({})).await, StatusCode::OK).await;
    let fourth = my_avatar_id(&alice, "image/gif").await;
    assert!(
        personal_alive(&contents, &third).await,
        "未绑定的旧头像不在回收范围"
    );
    expect(put_my_avatar_id(&alice, &third).await, StatusCode::OK).await;
    assert!(
        personal_alive(&contents, &fourth).await,
        "PUT 重新绑定不删任何头像"
    );
    assert!(personal_alive(&contents, &third).await);
}

/// 头像 content 被删(悬空):读资料降级 avatar_url=null、保留原始引用,不炸;头像端点 → 404。
/// 个人内容没有 HTTP 删除入口,直接经 content 服务以 `Personal` 作用域软删。
#[tokio::test]
async fn avatar_dangling_after_content_delete_degrades() {
    let (s, handle) = start_with_contents().await;
    let (alice, uid) = fresh_user(&s);
    let cid = my_avatar_id(&alice, "image/png").await;

    handle
        .delete_content(
            content::ContentScope::Personal,
            Uuid::parse_str(&cid).unwrap(),
            None,
        )
        .await
        .unwrap();

    let me = expect_json(alice.get(ME).await, StatusCode::OK).await;
    assert!(me["avatar_url"].is_null(), "悬空应降级 null: {me}");
    assert_eq!(me["avatar_content_id"], cid, "原始引用保留");
    expect_error(
        alice.get(&avatar_path(&uid)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 平台管理员(write:all)也不能把**自己的**头像绑成别人的头像(owner 必须是目标用户)。
#[tokio::test]
async fn write_all_cannot_bind_foreign_content_to_others() {
    let s = TestServer::start().await;
    let pa = platform_admin(&s);
    let user_id = seed_id(&s, USER).await;
    let pas = my_avatar_id(&pa, "image/png").await;
    expect_error(
        pa.put_json(
            &profile_path(&user_id),
            &json!({ "avatar_content_id": pas }),
        )
        .await,
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
        alice.put_json(ME, &json!({ "display_name": "San" })).await,
        StatusCode::CREATED,
    )
    .await;
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
    upload_my_avatar(&alice, "image/png").await;

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
        Some(DEFAULT_TENANT),
        &[ADMIN],
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
/// 头像同样四查 —— 绑 superadmin 自己的头像 / 目标的租户内容 → 422,绑目标本人的个人头像 → 200 且富化。
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

    // 头像四查同样生效:superadmin 自己的头像 / 用户的租户内容 → 422
    let sa_front = s.login(SUPERADMIN, PASSWORD).await;
    let sa_png = my_avatar_id(&sa_front, "image/png").await;
    let users_tenant_png = upload_tenant_content(&user, "image/png").await;
    for cid in [sa_png, users_tenant_png] {
        expect_error(
            sa.put_json(&path, &json!({ "avatar_content_id": cid }))
                .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }

    // 用户本人传过的头像(个人内容)可以由后台重新绑定
    let users_png = my_avatar_id(&user, "image/gif").await;
    expect(sa.put_json(&path, &json!({})).await, StatusCode::OK).await;
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

    // 后台传的头像是个人内容(不属于任何租户):租户作用域的 contents 端点看不到它(本人也一样),
    // 只经头像端点出图。
    expect_error(
        user.get(&format!("/api/v1/frontend/contents/{cid}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

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

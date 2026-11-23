//! widget 的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架
//! (换底座只换 `http_support::serve`)。与 `widget_api.rs`(axum oneshot)覆盖同一组场景并补强。
//!
//! 用测试授权策略:`user` = "用户管理自己的 widget"(read + write + delete,无 `:all`),
//! 这样读侧 / 写侧 / SSE 的 ownership 闸都能打到。
//!
//! covers: GET /api/v1/frontend/widgets
//! covers: POST /api/v1/frontend/widgets
//! covers: GET /api/v1/frontend/widgets/{id}
//! covers: PUT /api/v1/frontend/widgets/{id}
//! covers: DELETE /api/v1/frontend/widgets/{id}
//! covers: GET /api/v1/frontend/widgets/events
//! covers: GET /api/v1/frontend/widgets/my-count
//! covers: GET /api/v1/frontend/widgets/overview
//! covers: GET /api/v1/frontend/widgets/purge-preview
//! covers: GET /api/v1/public/widgets/stats
//! covers: GET /api/v1/admin/widgets

mod http_support;

use std::sync::Arc;

use baserust::kernel::authz::{Perm, Policy};
use http_support::{
    admin_scoped, expect, expect_error, expect_json, mint, next_sse_event, user_token, Client,
    TestServer,
};
use reqwest::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

const W: &str = "/api/v1/frontend/widgets";

fn test_policy() -> Policy {
    Policy::from_roles([
        (
            "superadmin".to_owned(),
            vec![Perm::UsersAdmin, Perm::AdminLogin, Perm::WidgetRead],
        ),
        (
            "admin".to_owned(),
            vec![
                Perm::WidgetRead,
                Perm::WidgetReadAll,
                Perm::WidgetWrite,
                Perm::WidgetWriteAll,
                Perm::WidgetDelete,
            ],
        ),
        (
            "user".to_owned(),
            vec![Perm::WidgetRead, Perm::WidgetWrite, Perm::WidgetDelete],
        ),
    ])
}

/// 起服务 + admin 会话(满权 admin 令牌)。
async fn start() -> (TestServer, Client) {
    let s = TestServer::start_with(|st| st.policy = Arc::new(test_policy())).await;
    let admin = s.bearer(&mint(Uuid::nil(), "admin", &["admin"], vec![]));
    (s, admin)
}

async fn create(c: &Client, name: &str) -> String {
    let v = expect_json(
        c.post_json(W, &json!({ "name": name })).await,
        StatusCode::CREATED,
    )
    .await;
    v["id"].as_str().unwrap().to_owned()
}

/// widget 端点必须登录:无凭据 → 401 + 统一错误体。
#[tokio::test]
async fn widgets_require_auth_401() {
    let (s, _) = start().await;
    expect_error(
        s.anon().get(W).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

#[tokio::test]
async fn create_then_list_offset() {
    let (_s, admin) = start().await;
    let created = expect_json(
        admin.post_json(W, &json!({ "name": "alpha" })).await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["name"], "alpha");
    assert!(created["created_at"].is_string());
    let body = expect_json(admin.get(W).await, StatusCode::OK).await;
    assert_eq!(body["items"][0]["name"], "alpha");
    assert_eq!(body["page_info"]["mode"], "offset");
    assert_eq!(body["page_info"]["total"], 1);
}

/// 空 cursor = cursor 模式首页。
#[tokio::test]
async fn cursor_first_page_ok() {
    let (_s, admin) = start().await;
    create(&admin, "a").await;
    let v = expect_json(
        admin.get(&format!("{W}?cursor=&size=2")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["page_info"]["mode"], "cursor");
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let (_s, admin) = start().await;
    expect_error(
        admin.post_json(W, &json!({ "name": "" })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

/// body 不是合法 JSON → 400 + 统一错误体(不漏框架默认的纯文本)。
#[tokio::test]
async fn malformed_json_is_400_with_error_body() {
    let (_s, admin) = start().await;
    let resp = admin
        .req(Method::POST, W)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(resp, StatusCode::BAD_REQUEST, "bad_request").await;
}

/// 路径参数不是 UUID → 400 + 统一错误体。
#[tokio::test]
async fn bad_path_param_is_400_with_error_body() {
    let (_s, admin) = start().await;
    expect_error(
        admin.get(&format!("{W}/not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let (_s, admin) = start().await;
    expect_error(
        admin.get(&format!("{W}?cursor=!!!bad")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let (_s, admin) = start().await;
    expect_error(
        admin.get(&format!("{W}?page=1&cursor=xxx")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

#[tokio::test]
async fn missing_widget_is_404() {
    let (_s, admin) = start().await;
    expect_error(
        admin
            .get(&format!("{W}/00000000-0000-0000-0000-000000000000"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 重名 → 409。
#[tokio::test]
async fn duplicate_name_is_409() {
    let (_s, admin) = start().await;
    create(&admin, "dup").await;
    expect_error(
        admin.post_json(W, &json!({ "name": "dup" })).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
}

/// PUT 全量替换 → 200,改名持久。
#[tokio::test]
async fn put_full_replace_renames_returns_200() {
    let (_s, admin) = start().await;
    let id = create(&admin, "before").await;
    let v = expect_json(
        admin
            .put_json(&format!("{W}/{id}"), &json!({ "name": "after" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["name"], "after");
    let got = expect_json(admin.get(&format!("{W}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["name"], "after", "改名应持久");
}

/// DELETE 软删 → 204(空 body),删后 GET → 404。
#[tokio::test]
async fn delete_soft_deletes_returns_204_then_404() {
    let (_s, admin) = start().await;
    let id = create(&admin, "doomed").await;
    let body = expect(
        admin.delete(&format!("{W}/{id}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");
    expect(admin.get(&format!("{W}/{id}")).await, StatusCode::NOT_FOUND).await;
}

/// 写侧 ownership:无 write:all 的 user 改不动 / 删不掉别人的(404,同 GET);自己的照常;admin 跨用户可改。
#[tokio::test]
async fn write_ownership_others_widget_is_404() {
    let (s, admin) = start().await;
    let user = s.bearer(&user_token().0);
    let theirs = create(&admin, "admins-widget").await;
    let path = format!("{W}/{theirs}");
    expect(user.get(&path).await, StatusCode::NOT_FOUND).await;
    expect(
        user.put_json(&path, &json!({ "name": "pwned" })).await,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(user.delete(&path).await, StatusCode::NOT_FOUND).await;

    let mine = create(&user, "users-widget").await;
    let path = format!("{W}/{mine}");
    expect(
        user.put_json(&path, &json!({ "name": "renamed-by-owner" }))
            .await,
        StatusCode::OK,
    )
    .await;
    expect(
        admin
            .put_json(&path, &json!({ "name": "renamed-by-admin" }))
            .await,
        StatusCode::OK,
    )
    .await;
}

/// 读侧 ownership:user 的列表只含自己创建的。
#[tokio::test]
async fn list_only_shows_own_widgets_for_user() {
    let (s, admin) = start().await;
    let user = s.bearer(&user_token().0);
    create(&admin, "admins").await;
    create(&user, "users").await;
    let v = expect_json(user.get(W).await, StatusCode::OK).await;
    let names: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("users")]);
}

/// 富化:列表项的 created_by 用户来自 idm(seed 的 admin 登录后建的 widget,带 username)。
#[tokio::test]
async fn list_enriches_created_by_user() {
    let s = TestServer::start().await; // seed 策略:admin 有 widgets:write
    let admin = s.login(http_support::ADMIN, http_support::PASSWORD).await;
    create(&admin, "enriched").await;
    let v = expect_json(admin.get(W).await, StatusCode::OK).await;
    assert_eq!(v["items"][0]["created_by_user"]["username"], "admin", "{v}");
}

/// SSE:开流 → create → 收到 created 事件(`event: created` + widget JSON)。
#[tokio::test]
async fn sse_stream_receives_created_event() {
    let (_s, admin) = start().await;
    let resp = admin.get(&format!("{W}/events")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    create(&admin, "sse-demo").await;
    let event = next_sse_event(&mut stream, &mut buf).await;
    assert!(event.contains("event: created"), "应是 created 帧: {event}");
    assert!(
        event.contains(r#""name":"sse-demo""#),
        "应含 widget JSON: {event}"
    );
}

/// SSE 行级 ownership:user 收不到别人的 widget,照收自己的。
#[tokio::test]
async fn sse_stream_filters_other_users_widgets() {
    let (s, admin) = start().await;
    let user = s.bearer(&user_token().0);
    let resp = user.get(&format!("{W}/events")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    create(&admin, "admins-secret-widget").await;
    create(&user, "users-own-widget").await;
    let event = next_sse_event(&mut stream, &mut buf).await;
    assert!(!event.contains("admins-secret-widget"), "越权泄漏: {event}");
    assert!(
        event.contains("users-own-widget"),
        "自己的必须照收: {event}"
    );
}

#[tokio::test]
async fn sse_requires_auth() {
    let (s, _) = start().await;
    expect(
        s.anon().get(&format!("{W}/events")).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// 降权令牌(scope 只有 write)→ 403。
#[tokio::test]
async fn sse_requires_read_scope() {
    let (s, _) = start().await;
    let scoped = s.bearer(&admin_scoped(vec![Perm::WidgetWrite]));
    expect_error(
        scoped.get(&format!("{W}/events")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 多权限:AND 缺一 403、全有 200;OR 任一支 200、两支皆无 403。
#[tokio::test]
async fn multi_perm_and_or_endpoints() {
    let (s, admin) = start().await;
    let purge = format!("{W}/purge-preview");
    let overview = format!("{W}/overview");
    expect(admin.get(&purge).await, StatusCode::OK).await;
    let read_only = s.bearer(&admin_scoped(vec![Perm::WidgetRead]));
    expect(read_only.get(&purge).await, StatusCode::FORBIDDEN).await;
    expect(read_only.get(&overview).await, StatusCode::OK).await;
    let write_only = s.bearer(&admin_scoped(vec![Perm::WidgetWrite]));
    expect(write_only.get(&overview).await, StatusCode::FORBIDDEN).await;
}

/// 公开 / 仅登录 / superadmin-only 三种形态。
#[tokio::test]
async fn public_login_only_and_admin_only_shapes() {
    let (s, admin) = start().await;
    let user = s.bearer(&user_token().0);
    create(&user, "x").await;

    // public:无凭据也 200
    let v = expect_json(
        s.anon().get("/api/v1/public/widgets/stats").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["total"], 1);

    // 仅登录:无凭据 401,有凭据 200(只算自己的)
    let my = format!("{W}/my-count");
    expect(s.anon().get(&my).await, StatusCode::UNAUTHORIZED).await;
    assert_eq!(
        expect_json(user.get(&my).await, StatusCode::OK).await["total"],
        1
    );

    // superadmin-only:admin 无 admin:login → admin 组闸 403;superadmin 200 且看到全部
    expect(
        admin.get("/api/v1/admin/widgets").await,
        StatusCode::FORBIDDEN,
    )
    .await;
    let sa = s.bearer(&mint(Uuid::now_v7(), "superadmin", &["superadmin"], vec![]));
    let v = expect_json(sa.get("/api/v1/admin/widgets").await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1);
}

/// 排序:offset 下 name asc/desc;cursor + sort_by=name 按 (name, id) keyset 翻页。
#[tokio::test]
async fn list_sort_by_name_offset_and_cursor() {
    let (_s, admin) = start().await;
    for name in ["b", "a"] {
        create(&admin, name).await;
    }
    let first = |v: &serde_json::Value| v["items"][0]["name"].as_str().unwrap().to_owned();
    let get = |q: String| {
        let admin = admin.clone();
        async move { expect_json(admin.get(&format!("{W}?{q}")).await, StatusCode::OK).await }
    };

    assert_eq!(
        first(&get("sort_by=name&order=asc&page=1".into()).await),
        "a"
    );
    assert_eq!(
        first(&get("sort_by=name&order=desc&page=1".into()).await),
        "b"
    );

    let v = get("cursor=&sort_by=name&order=asc&size=1".into()).await;
    assert_eq!(first(&v), "a");
    assert_eq!(v["page_info"]["mode"], "cursor");
    let next = v["page_info"]["next_cursor"].as_str().unwrap().to_owned();
    let v = get(format!("cursor={next}&sort_by=name&order=asc&size=1")).await;
    assert_eq!(first(&v), "b");
}

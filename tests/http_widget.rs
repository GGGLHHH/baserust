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
//! covers: GET /api/v1/frontend/widgets/stats
//! covers: GET /api/v1/admin/widgets

mod http_support;

use baserust::app::router;
use serde_json::Value;
use std::sync::Arc;

use baserust::kernel::authorization::{Permission, Policy};
use http_support::{
    admin_scoped, expect, expect_error, expect_json, mint, next_sse_event, user_token, Client,
    TestServer, ADMIN, DEFAULT_TENANT,
};
use reqwest::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

const WIDGETS: &str = "/api/v1/frontend/widgets";

fn test_policy() -> Policy {
    Policy::new([
        (
            "superadmin".to_owned(),
            vec![
                Permission::UsersAdmin,
                Permission::AdminLogin,
                Permission::WidgetRead,
            ],
        ),
        (
            "admin".to_owned(),
            vec![
                Permission::WidgetRead,
                Permission::WidgetReadAll,
                Permission::WidgetWrite,
                Permission::WidgetWriteAll,
                Permission::WidgetDelete,
                Permission::MembersAdmin,
            ],
        ),
        (
            "user".to_owned(),
            vec![
                Permission::WidgetRead,
                Permission::WidgetWrite,
                Permission::WidgetDelete,
            ],
        ),
    ])
}

/// 起服务 + admin 会话(满权 admin 令牌)。
async fn start() -> (TestServer, Client) {
    let server = TestServer::start_with(|state| state.policy = Arc::new(test_policy())).await;
    let admin = server.bearer(&mint(
        Uuid::nil(),
        "admin",
        &[],
        Some(DEFAULT_TENANT),
        &["admin"],
        vec![],
    ));
    (server, admin)
}

async fn create(client: &Client, name: &str) -> String {
    let widget = expect_json(
        client.post_json(WIDGETS, &json!({ "name": name })).await,
        StatusCode::CREATED,
    )
    .await;
    widget["id"].as_str().unwrap().to_owned()
}

/// widget 端点必须登录:无凭据 → 401 + 统一错误体。
#[tokio::test]
async fn widgets_require_auth_401() {
    let (server, _) = start().await;
    expect_error(
        server.anonymous().get(WIDGETS).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

#[tokio::test]
async fn create_then_list_offset() {
    let (_server, admin) = start().await;
    let created = expect_json(
        admin.post_json(WIDGETS, &json!({ "name": "alpha" })).await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["name"], "alpha");
    assert!(created["created_at"].is_string());
    let body = expect_json(admin.get(WIDGETS).await, StatusCode::OK).await;
    assert_eq!(body["items"][0]["name"], "alpha");
    assert_eq!(body["page_info"]["mode"], "offset");
    assert_eq!(body["page_info"]["total"], 1);
}

/// 空 cursor = cursor 模式首页。
#[tokio::test]
async fn cursor_first_page_ok() {
    let (_server, admin) = start().await;
    create(&admin, "a").await;
    let page = expect_json(
        admin.get(&format!("{WIDGETS}?cursor=&size=2")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(page["page_info"]["mode"], "cursor");
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let (_server, admin) = start().await;
    expect_error(
        admin.post_json(WIDGETS, &json!({ "name": "" })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

/// body 不是合法 JSON → 400 + 统一错误体(不漏框架默认的纯文本)。
#[tokio::test]
async fn malformed_json_is_400_with_error_body() {
    let (_server, admin) = start().await;
    let response = admin
        .request(Method::POST, WIDGETS)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(response, StatusCode::BAD_REQUEST, "bad_request").await;
}

/// 路径参数不是 UUID → 400 + 统一错误体。
#[tokio::test]
async fn bad_path_param_is_400_with_error_body() {
    let (_server, admin) = start().await;
    expect_error(
        admin.get(&format!("{WIDGETS}/not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let (_server, admin) = start().await;
    expect_error(
        admin.get(&format!("{WIDGETS}?cursor=!!!bad")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let (_server, admin) = start().await;
    expect_error(
        admin.get(&format!("{WIDGETS}?page=1&cursor=xxx")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

#[tokio::test]
async fn missing_widget_is_404() {
    let (_server, admin) = start().await;
    expect_error(
        admin
            .get(&format!("{WIDGETS}/00000000-0000-0000-0000-000000000000"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 重名 → 409。
#[tokio::test]
async fn duplicate_name_is_409() {
    let (_server, admin) = start().await;
    create(&admin, "dup").await;
    expect_error(
        admin.post_json(WIDGETS, &json!({ "name": "dup" })).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
}

/// PUT 全量替换 → 200,改名持久。
#[tokio::test]
async fn put_full_replace_renames_returns_200() {
    let (_server, admin) = start().await;
    let id = create(&admin, "before").await;
    let widget = expect_json(
        admin
            .put_json(&format!("{WIDGETS}/{id}"), &json!({ "name": "after" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(widget["name"], "after");
    let got = expect_json(admin.get(&format!("{WIDGETS}/{id}")).await, StatusCode::OK).await;
    assert_eq!(got["name"], "after", "改名应持久");
}

/// DELETE 软删 → 204(空 body),删后 GET → 404。
#[tokio::test]
async fn delete_soft_deletes_returns_204_then_404() {
    let (_server, admin) = start().await;
    let id = create(&admin, "doomed").await;
    let body = expect(
        admin.delete(&format!("{WIDGETS}/{id}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");
    expect(
        admin.get(&format!("{WIDGETS}/{id}")).await,
        StatusCode::NOT_FOUND,
    )
    .await;
}

/// 写侧 ownership:无 write:all 的 user 改不动 / 删不掉别人的(404,同 GET);自己的照常;admin 跨用户可改。
#[tokio::test]
async fn write_ownership_others_widget_is_404() {
    let (server, admin) = start().await;
    let user = server.bearer(&user_token().0);
    let theirs = create(&admin, "admins-widget").await;
    let path = format!("{WIDGETS}/{theirs}");
    expect(user.get(&path).await, StatusCode::NOT_FOUND).await;
    expect(
        user.put_json(&path, &json!({ "name": "pwned" })).await,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(user.delete(&path).await, StatusCode::NOT_FOUND).await;

    let mine = create(&user, "users-widget").await;
    let path = format!("{WIDGETS}/{mine}");
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
    let (server, admin) = start().await;
    let user = server.bearer(&user_token().0);
    create(&admin, "admins").await;
    create(&user, "users").await;
    let page = expect_json(user.get(WIDGETS).await, StatusCode::OK).await;
    let names: Vec<_> = page["items"]
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
    let server = TestServer::start().await; // seed 策略:admin 有 widgets:write
    let admin = server
        .login(http_support::ADMIN, http_support::PASSWORD)
        .await;
    create(&admin, "enriched").await;
    let page = expect_json(admin.get(WIDGETS).await, StatusCode::OK).await;
    assert_eq!(
        page["items"][0]["created_by_user"]["username"], "admin",
        "{page}"
    );
}

/// SSE:开流 → create → 收到 created 事件(`event: created` + widget JSON)。
#[tokio::test]
async fn sse_stream_receives_created_event() {
    let (_server, admin) = start().await;
    let response = admin.get(&format!("{WIDGETS}/events")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    create(&admin, "sse-demo").await;
    let event = next_sse_event(&mut stream, &mut buffer).await;
    assert!(event.contains("event: created"), "应是 created 帧: {event}");
    assert!(
        event.contains(r#""name":"sse-demo""#),
        "应含 widget JSON: {event}"
    );
}

/// SSE 行级 ownership:user 收不到别人的 widget,照收自己的。
#[tokio::test]
async fn sse_stream_filters_other_users_widgets() {
    let (server, admin) = start().await;
    let user = server.bearer(&user_token().0);
    let response = user.get(&format!("{WIDGETS}/events")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    create(&admin, "admins-secret-widget").await;
    create(&user, "users-own-widget").await;
    let event = next_sse_event(&mut stream, &mut buffer).await;
    assert!(!event.contains("admins-secret-widget"), "越权泄漏: {event}");
    assert!(
        event.contains("users-own-widget"),
        "自己的必须照收: {event}"
    );
}

#[tokio::test]
async fn sse_requires_auth() {
    let (server, _) = start().await;
    expect(
        server.anonymous().get(&format!("{WIDGETS}/events")).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// 降权令牌(scope 只有 write)→ 403。
#[tokio::test]
async fn sse_requires_read_scope() {
    let (server, _) = start().await;
    let scoped = server.bearer(&admin_scoped(vec![Permission::WidgetWrite]));
    expect_error(
        scoped.get(&format!("{WIDGETS}/events")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 多权限:AND 缺一 403、全有 200;OR 任一支 200、两支皆无 403。
#[tokio::test]
async fn multi_perm_and_or_endpoints() {
    let (server, admin) = start().await;
    let purge = format!("{WIDGETS}/purge-preview");
    let overview = format!("{WIDGETS}/overview");
    expect(admin.get(&purge).await, StatusCode::OK).await;
    let read_only = server.bearer(&admin_scoped(vec![Permission::WidgetRead]));
    expect(read_only.get(&purge).await, StatusCode::FORBIDDEN).await;
    expect(read_only.get(&overview).await, StatusCode::OK).await;
    let write_only = server.bearer(&admin_scoped(vec![Permission::WidgetWrite]));
    expect(write_only.get(&overview).await, StatusCode::FORBIDDEN).await;
    // OR 的另一支:本组织成员管理员(members:admin,租户级)
    let members_admin = server.bearer(&admin_scoped(vec![Permission::MembersAdmin]));
    expect(members_admin.get(&overview).await, StatusCode::OK).await;
    // 平台级 users:admin 不是这个租户数据接口的来路:平台管理员在本租户没有租户角色 → 403
    let platform_only = server.bearer(&mint(
        Uuid::now_v7(),
        "superadmin",
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[],
        vec![],
    ));
    expect(platform_only.get(&overview).await, StatusCode::FORBIDDEN).await;
}

/// 仅登录(stats / my-count)/ superadmin-only 两种形态。
#[tokio::test]
async fn login_only_and_admin_only_shapes() {
    let (server, admin) = start().await;
    let user = server.bearer(&user_token().0);
    create(&user, "x").await;

    // stats:仅登录、数当前租户全部(不只自己的);无凭据 401
    let stats = format!("{WIDGETS}/stats");
    expect(
        server.anonymous().get(&stats).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    create(&admin, "y").await;
    assert_eq!(
        expect_json(user.get(&stats).await, StatusCode::OK).await["total"],
        2
    );

    // 仅登录:无凭据 401,有凭据 200(只算自己的)
    let my = format!("{WIDGETS}/my-count");
    expect(server.anonymous().get(&my).await, StatusCode::UNAUTHORIZED).await;
    assert_eq!(
        expect_json(user.get(&my).await, StatusCode::OK).await["total"],
        1
    );

    // 后台列表:本文件测试策略里的 admin 没有 admin:login → admin 组闸 403;带后台准入的 superadmin 200 且看到全部
    expect(
        admin.get("/api/v1/admin/widgets").await,
        StatusCode::FORBIDDEN,
    )
    .await;
    let superadmin = server.bearer(&mint(
        Uuid::now_v7(),
        "superadmin",
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    ));
    let page = expect_json(
        superadmin.get("/api/v1/admin/widgets").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        page["page_info"]["total"], 2,
        "本租户 user 的 x + admin 的 y: {page}"
    );
}

/// 排序:offset 下 name asc/desc;cursor + sort_by=name 按 (name, id) keyset 翻页。
#[tokio::test]
async fn list_sort_by_name_offset_and_cursor() {
    let (_server, admin) = start().await;
    for name in ["b", "a"] {
        create(&admin, name).await;
    }
    let first = |v: &Value| v["items"][0]["name"].as_str().unwrap().to_owned();
    let get = |query: String| {
        let admin = admin.clone();
        async move {
            expect_json(
                admin.get(&format!("{WIDGETS}?{query}")).await,
                StatusCode::OK,
            )
            .await
        }
    };

    assert_eq!(
        first(&get("sort_by=name&order=asc&page=1".into()).await),
        "a"
    );
    assert_eq!(
        first(&get("sort_by=name&order=desc&page=1".into()).await),
        "b"
    );

    let page = get("cursor=&sort_by=name&order=asc&size=1".into()).await;
    assert_eq!(first(&page), "a");
    assert_eq!(page["page_info"]["mode"], "cursor");
    let next = page["page_info"]["next_cursor"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = get(format!("cursor={next}&sort_by=name&order=asc&size=1")).await;
    assert_eq!(first(&page), "b");
}

// ───────────────────────────── 多租户隔离 ─────────────────────────────

/// 另一个租户(随机新租户)里的满权 admin 会话。租户只从 token 来:同一个服务、换个 token 就是别的租户。
fn other_tenant_admin(server: &TestServer) -> Client {
    server.bearer(&mint(
        Uuid::now_v7(),
        "other-admin",
        &[],
        Some(Uuid::now_v7()),
        &["admin"],
        vec![],
    ))
}

fn names(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("应有 items: {page}"))
        .iter()
        .map(|w| w["name"].as_str().unwrap().to_owned())
        .collect()
}

/// 跨租户访问资源 ID → 404(不泄露存在),读写删都一样;本租户的行原样不动。
#[tokio::test]
async fn widget_of_other_tenant_is_404() {
    let (server, admin) = start().await;
    let other = other_tenant_admin(&server);
    let id = create(&admin, "tenant-a-widget").await;
    let path = format!("{WIDGETS}/{id}");
    expect_error(other.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
    expect_error(
        other.put_json(&path, &json!({ "name": "pwned" })).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        other.delete(&path).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let got = expect_json(admin.get(&path).await, StatusCode::OK).await;
    assert_eq!(got["name"], "tenant-a-widget", "别的租户改不动、删不掉");
}

/// 列表 / 计数只含当前租户的数据(admin 有 read:all 也一样,read:all 只是「本租户内看全部」)。
#[tokio::test]
async fn widget_list_only_current_tenant() {
    let (server, admin) = start().await;
    let other = other_tenant_admin(&server);
    create(&admin, "a1").await;
    create(&admin, "a2").await;
    create(&other, "b1").await;

    let mine = expect_json(
        admin
            .get(&format!("{WIDGETS}?sort_by=name&order=asc"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(names(&mine), vec!["a1", "a2"]);
    assert_eq!(mine["page_info"]["total"], 2);
    let theirs = expect_json(other.get(WIDGETS).await, StatusCode::OK).await;
    assert_eq!(names(&theirs), vec!["b1"]);
    assert_eq!(theirs["page_info"]["total"], 1);
    // cursor 模式同样只翻本租户
    let cursor = expect_json(
        admin.get(&format!("{WIDGETS}?cursor=&size=10")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(cursor["items"].as_array().unwrap().len(), 2, "{cursor}");

    for (client, expected_total) in [(&admin, 2), (&other, 1)] {
        for endpoint in ["overview", "purge-preview", "my-count"] {
            let count = expect_json(
                client.get(&format!("{WIDGETS}/{endpoint}")).await,
                StatusCode::OK,
            )
            .await;
            // 各自的行都是自己建的:overview(本租户全部)与 my-count / purge-preview(本人)同数
            assert_eq!(count["total"], expected_total, "{endpoint}: {count}");
        }
    }
    // superadmin 专属的「列全部」也只列当前租户
    let superadmin = server.bearer(&mint(
        Uuid::now_v7(),
        "superadmin",
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    ));
    let page = expect_json(
        superadmin.get("/api/v1/admin/widgets").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(page["page_info"]["total"], 2, "{page}");

    // 计数(仅登录)也只数当前租户
    for (client, expected_total) in [(&admin, 2), (&other, 1)] {
        let stats = expect_json(
            client.get(&format!("{WIDGETS}/stats")).await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(stats["total"], expected_total, "stats: {stats}");
    }
}

/// 名字唯一只在租户内:别的租户可以用同名;同租户重名仍 409。
#[tokio::test]
async fn same_name_allowed_in_different_tenants() {
    let (server, admin) = start().await;
    let other = other_tenant_admin(&server);
    create(&admin, "shared").await;
    create(&other, "shared").await;
    expect_error(
        other.post_json(WIDGETS, &json!({ "name": "shared" })).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    // 改名撞名同理:只看本租户
    let id = create(&other, "renamable").await;
    expect_error(
        other
            .put_json(&format!("{WIDGETS}/{id}"), &json!({ "name": "shared" }))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
}

/// SSE 先比租户再比 owner:有 read:all 的 admin 也收不到别的租户的事件。
#[tokio::test]
async fn sse_does_not_leak_other_tenant_events() {
    let (server, admin) = start().await;
    let other = other_tenant_admin(&server);
    let response = admin.get(&format!("{WIDGETS}/events")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    let theirs = create(&other, "other-tenant-secret").await;
    expect(
        other.delete(&format!("{WIDGETS}/{theirs}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    create(&admin, "own-tenant-widget").await;
    let event = next_sse_event(&mut stream, &mut buffer).await;
    assert!(
        !event.contains("other-tenant-secret") && !event.contains(&theirs),
        "跨租户泄漏: {event}"
    );
    assert!(
        event.contains("own-tenant-widget"),
        "本租户的必须照收: {event}"
    );
}

/// 平台上下文令牌(没有当前租户,哪怕是平台管理员)调租户级 widget 接口 → 403 `tenant_required`。
#[tokio::test]
async fn widget_endpoints_require_current_tenant() {
    let (server, _) = start().await;
    let platform = server.bearer(&mint(
        Uuid::now_v7(),
        "superadmin",
        &["superadmin"],
        None,
        &[],
        vec![],
    ));
    for path in [
        WIDGETS.to_owned(),
        format!("{WIDGETS}/events"),
        format!("{WIDGETS}/my-count"),
        format!("{WIDGETS}/stats"),
        format!("{WIDGETS}/overview"),
        format!("{WIDGETS}/{}", Uuid::now_v7()),
        "/api/v1/admin/widgets".to_owned(),
    ] {
        expect_error(
            platform.get(&path).await,
            StatusCode::FORBIDDEN,
            "tenant_required",
        )
        .await;
    }
    expect_error(
        platform.post_json(WIDGETS, &json!({ "name": "x" })).await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
}

/// 平台管理员在某租户里只是 `user` 角色时:`users:admin` 只让他过 superadmin 专属的闸,
/// 「列全部」的可见域仍看租户角色 —— 没有租户级 `read:all`,admin 列表只返回他自己建的。
#[tokio::test]
async fn admin_list_for_platform_admin_with_user_tenant_role_is_own_only() {
    let (server, admin) = start().await;
    let superadmin = server.bearer(&mint(
        Uuid::now_v7(),
        "superadmin",
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &["user"],
        vec![],
    ));
    create(&admin, "someone-elses").await;
    create(&superadmin, "mine").await;
    let page = expect_json(
        superadmin.get("/api/v1/admin/widgets").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(names(&page), vec!["mine"], "{page}");
    assert_eq!(page["page_info"]["total"], 1, "{page}");
}

/// 租户管理员(租户角色 admin:有 `admin:login` + 租户级 widget 读权)经真实后台登录就能看后台 widget 列表
/// —— 闸是租户级 `widgets:read`,不再是平台级 `users:admin`;可见域照旧(admin 有 `read:all` → 本租户全部)。
/// 普通成员没有后台准入 → 组闸 403。文档(前端 access-policies 由它生成)同样不再要求 `users:admin`。
#[tokio::test]
async fn tenant_admin_sees_admin_widget_list() {
    let server = TestServer::start().await; // seed 策略
                                            // 别人(superadmin 在默认租户里也是 admin)建一个,admin 自己建一个
    let other = server
        .login(http_support::SUPERADMIN, http_support::PASSWORD)
        .await;
    create(&other, "others-one").await;
    let admin = server.login_admin(ADMIN, http_support::PASSWORD).await;
    create(&admin, "admins-one").await;

    let page = expect_json(admin.get("/api/v1/admin/widgets").await, StatusCode::OK).await;
    let mut got = names(&page);
    got.sort();
    assert_eq!(got, vec!["admins-one", "others-one"], "{page}");
    let user = server
        .login(http_support::USER, http_support::PASSWORD)
        .await;
    expect(
        user.get("/api/v1/admin/widgets").await,
        StatusCode::FORBIDDEN,
    )
    .await;

    let spec = serde_json::to_value(router::api_spec()).unwrap();
    let security = &spec["paths"]["/api/v1/admin/widgets"]["get"]["security"];
    let requests: Vec<Vec<String>> = security
        .as_array()
        .unwrap_or_else(|| panic!("应有 security: {security}"))
        .iter()
        .map(|requirement| {
            requirement["oauth2"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_owned())
                .collect()
        })
        .collect();
    assert!(
        requests.iter().any(
            |r| r.contains(&"admin:login".to_owned()) && r.contains(&"widgets:read".to_owned())
        ),
        "租户管理员那一支 = admin:login + widgets:read: {security}"
    );
    assert!(
        requests
            .iter()
            .all(|r| r.contains(&"widgets:read".to_owned())),
        "每一支都要租户级读权,不能只凭平台权限: {security}"
    );
}

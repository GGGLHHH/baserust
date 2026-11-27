//! 后台用户管理(users 模块)的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架。
//! 与 `users_api.rs`(axum oneshot)覆盖同一组场景并补强:授权矩阵、列表过滤/排序/双模式分页、
//! 建/查/改/删/设角色/重置密码的正常与错误分支、自锁与提权闸(防越权),以及跨模块行为
//! (管理员建的号能在前台登录、改名/重置密码/删号/改角色后登录与会话的变化)。
//!
//! 大多数测试用 seed 策略(superadmin 满权、admin 只有后台准入无 `users:admin`、user 普通);
//! 提权闸测试另换一份带「中间管理员」`useradmin`(有 `users:admin` 但非满权)的策略。
//!
//! 多租户之后账号管理只授**平台角色**(`user_roles`);admin / user 是租户角色,经租户成员关系授予
//! (seed 账号都在默认租户里),这里的角色目录不列、建号 / 设角色传它们 → 422。
//! 2026-11-26 起 superadmin 不经接口授予 / 撤销(目录不列它),这里授出的平台角色一律用 `platform_admin`;
//! 平台管理员相关的独占 / 防接管场景在 `http_platform_admin.rs`。
//!
//! covers: GET /api/v1/admin/auth/users
//! covers: POST /api/v1/admin/auth/users
//! covers: GET /api/v1/admin/auth/users/{id}
//! covers: PUT /api/v1/admin/auth/users/{id}
//! covers: DELETE /api/v1/admin/auth/users/{id}
//! covers: PUT /api/v1/admin/auth/users/{id}/roles
//! covers: POST /api/v1/admin/auth/users/{id}/password
//! covers: GET /api/v1/admin/auth/roles

mod http_support;

use idm::RoleScope;
use std::collections::HashSet;
use std::sync::Arc;

use baserust::kernel::authorization::{Permission, Policy, RoleName};
use http_support::{
    expect, expect_error, expect_json, mint, Client, TestServer, ADMIN, DEFAULT_TENANT, PASSWORD,
    SUPERADMIN, USER,
};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const USERS: &str = "/api/v1/admin/auth/users";
const ROLES: &str = "/api/v1/admin/auth/roles";
const FRONT_ME: &str = "/api/v1/frontend/auth/me";
const LOGIN: &str = "/api/v1/public/auth/login";
const ADMIN_LOGIN: &str = "/api/v1/admin/auth/login";
const REFRESH: &str = "/api/v1/public/auth/refresh";

/// 一个合法 UUID 但不对应任何用户 / 角色。
const NIL: &str = "00000000-0000-0000-0000-000000000000";

// ───────────────────────────── 帮手 ─────────────────────────────

/// 起服务(seed 策略)+ 已登录后台的 superadmin 会话(cookie)。
async fn start() -> (TestServer, Client) {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    (server, superadmin)
}

/// 角色名 → 角色 id(经 `GET /roles` 目录解析;角色按 id 提交)。
async fn role_ids(client: &Client, names: &[&str]) -> Vec<String> {
    let catalog = expect_json(client.get(ROLES).await, StatusCode::OK).await;
    let items = catalog["items"].as_array().expect("items 应是数组");
    names
        .iter()
        .map(|name| {
            items
                .iter()
                .find(|r| r["name"] == *name)
                .unwrap_or_else(|| panic!("角色目录缺 {name}: {catalog}"))["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// 建号(断言 201),返回响应体。`roles` 是角色**名**,内部解析成 id。
async fn create(
    client: &Client,
    username: &str,
    email: Option<&str>,
    password: &str,
    roles: &[&str],
) -> Value {
    let ids = role_ids(client, roles).await;
    expect_json(
        client.post_json(
            USERS,
            &json!({ "username": username, "email": email, "password": password, "roles": ids }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await
}

/// 建号(无 email,密码 `password123`),返回新 id。
async fn create_id(client: &Client, username: &str, roles: &[&str]) -> String {
    let created = create(client, username, None, "password123", roles).await;
    created["id"].as_str().unwrap().to_owned()
}

/// `GET /users?{query}` → 200 的 JSON。
async fn list(client: &Client, query: &str) -> Value {
    expect_json(
        client.get(&format!("{USERS}?{query}")).await,
        StatusCode::OK,
    )
    .await
}

/// 列表项的 username 序列(保序)。
fn usernames(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items 应是数组: {page}"))
        .iter()
        .map(|i| i["username"].as_str().unwrap().to_owned())
        .collect()
}

/// 按**精确**用户名查 id(列表 username 过滤是子串,这里再精确匹配一遍)。
async fn find_id(client: &Client, username: &str) -> String {
    let page = list(client, &format!("username={username}&size=100")).await;
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["username"] == username)
        .unwrap_or_else(|| panic!("列表里找不到 {username}: {page}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// 响应体 roles 数组排序后(角色比较不看顺序)。
fn sorted_roles(user: &Value) -> Vec<String> {
    let mut roles: Vec<String> = user["roles"]
        .as_array()
        .unwrap_or_else(|| panic!("roles 应是数组: {user}"))
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    roles.sort();
    roles
}

/// 前台登录的状态码(不断言,用来验「登不进去」)。
async fn front_login_status(server: &TestServer, identifier: &str, password: &str) -> StatusCode {
    server
        .anonymous()
        .post_json(
            LOGIN,
            &json!({ "identifier": identifier, "password": password }),
        )
        .await
        .status()
}

fn user_url(id: &str) -> String {
    format!("{USERS}/{id}")
}

// ───────────────────────────── 1. 授权矩阵 ─────────────────────────────

/// 全部 8 个端点:无凭据 → 401;user(无 admin:login)→ 组闸 403;admin(有 admin:login
/// 无 users:admin)→ 端点闸 403;都是统一错误体。请求体都合法,确保打到的是授权而非解析。
#[tokio::test]
async fn authz_matrix_all_endpoints() {
    let (server, superadmin) = start().await;
    let target = create_id(&superadmin, "matrix-target", &["platform_admin"]).await;
    let id_url = user_url(&target);
    let endpoints: Vec<(Method, String, Option<Value>)> = vec![
        (Method::GET, USERS.to_owned(), None),
        (
            Method::POST,
            USERS.to_owned(),
            Some(json!({ "username": "x", "email": null, "password": "secret1", "roles": [] })),
        ),
        (Method::GET, id_url.clone(), None),
        (
            Method::PUT,
            id_url.clone(),
            Some(json!({ "username": "x", "email": null })),
        ),
        (Method::DELETE, id_url.clone(), None),
        (
            Method::PUT,
            format!("{id_url}/roles"),
            Some(json!({ "roles": [] })),
        ),
        (
            Method::POST,
            format!("{id_url}/password"),
            Some(json!({ "new_password": "secret1" })),
        ),
        (Method::GET, ROLES.to_owned(), None),
    ];

    let anonymous = server.anonymous();
    let user = server.login(USER, PASSWORD).await;
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    for (client, status, code) in [
        (&anonymous, StatusCode::UNAUTHORIZED, "unauthorized"),
        (&user, StatusCode::FORBIDDEN, "forbidden"),
        (&admin, StatusCode::FORBIDDEN, "forbidden"),
    ] {
        for (method, path, body) in &endpoints {
            let mut request = client.request(method.clone(), path);
            if let Some(payload) = body {
                request = request.json(payload);
            }
            expect_error(request.send().await.unwrap(), status, code).await;
        }
    }

    // 以上都被拒 → 目标毫发无损
    let detail = expect_json(superadmin.get(&id_url).await, StatusCode::OK).await;
    assert_eq!(detail["username"], "matrix-target");
    assert_eq!(sorted_roles(&detail), vec!["platform_admin"]);
}

/// superadmin 能用;Bearer 令牌也行(不止 cookie)。
#[tokio::test]
async fn superadmin_cookie_and_bearer_both_work() {
    let (server, superadmin) = start().await;
    expect(superadmin.get(USERS).await, StatusCode::OK).await;
    let bearer = server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &[SUPERADMIN],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    ));
    expect(bearer.get(USERS).await, StatusCode::OK).await;
    expect(bearer.get(ROLES).await, StatusCode::OK).await;
}

/// 降权令牌:scope 只收窄不放大。缺 users:admin → 端点 403;后台准入凭 admin:login **或**平台级权限
/// (users:admin 本身就是平台级,单给它也能过组闸);两样都没有 → 组闸 403。
#[tokio::test]
async fn scoped_token_needs_users_admin_and_an_admin_entry() {
    let server = TestServer::start().await;
    let superadmin_token = |scope| {
        mint(
            Uuid::now_v7(),
            SUPERADMIN,
            &[SUPERADMIN],
            Some(DEFAULT_TENANT),
            &[ADMIN],
            scope,
        )
    };
    let only_login = server.bearer(&superadmin_token(vec![Permission::AdminLogin]));
    expect_error(
        only_login.get(USERS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        only_login.get(ROLES).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 平台管理员:users:admin 是平台级权限 → 自身即后台准入
    let only_users = server.bearer(&superadmin_token(vec![Permission::UsersAdmin]));
    expect(only_users.get(USERS).await, StatusCode::OK).await;
    // 准入权限一个都不在 scope 里 → 组闸 403
    let neither = server.bearer(&superadmin_token(vec![Permission::WidgetRead]));
    expect_error(neither.get(USERS).await, StatusCode::FORBIDDEN, "forbidden").await;
    let both = server.bearer(&superadmin_token(vec![
        Permission::AdminLogin,
        Permission::UsersAdmin,
    ]));
    expect(both.get(USERS).await, StatusCode::OK).await;
}

// ───────────────────────────── 2. 角色目录 ─────────────────────────────

/// 角色目录:闭集里**能经接口授出的平台角色**(id + 机器码 + 展示名),单页 cursor 包络(has_more=false)。
/// 租户角色(admin / user)经租户成员关系授予,不在账号管理的目录里;superadmin 只由 seed 声明,也不在。
#[tokio::test]
async fn list_roles_returns_platform_roles_single_page() {
    let (_server, superadmin) = start().await;
    let catalog = expect_json(superadmin.get(ROLES).await, StatusCode::OK).await;
    let items = catalog["items"].as_array().unwrap();
    let platform: Vec<RoleName> = RoleName::ALL
        .into_iter()
        .filter(|r| r.scope() == RoleScope::Platform && *r != RoleName::Superadmin)
        .collect();
    assert_eq!(items.len(), platform.len(), "{catalog}");
    assert!(
        !items
            .iter()
            .any(|i| i["name"] == "admin" || i["name"] == "user" || i["name"] == "superadmin"),
        "租户角色 / superadmin 不进目录: {catalog}"
    );
    for role in platform {
        let item = items
            .iter()
            .find(|i| i["name"] == role.as_str())
            .unwrap_or_else(|| panic!("目录缺 {}: {catalog}", role.as_str()));
        assert!(
            Uuid::parse_str(item["id"].as_str().unwrap()).is_ok(),
            "id 应是 uuid: {item}"
        );
        assert_eq!(item["display_name"], role.display_name());
    }
    assert_eq!(catalog["page_info"]["mode"], "cursor");
    assert_eq!(catalog["page_info"]["has_more"], false);
    assert_eq!(catalog["page_info"]["next_cursor"], Value::Null);

    // 带分页参数也照返全量(参数被接受但不真分页)
    let paged_catalog = expect_json(
        superadmin.get(&format!("{ROLES}?size=1")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        paged_catalog["items"].as_array().unwrap().len(),
        items.len()
    );
}

// ───────────────────────────── 3. 建号 ─────────────────────────────

/// 建号 → 201 + 完整视图;新号 display_name/avatar 为 null、email 未验证;
/// 之后 GET 详情一致,且能用这组凭据在**前台登录**(跨模块:管理员建号 → 认证)。
#[tokio::test]
async fn create_user_then_front_login_with_new_password() {
    let (server, superadmin) = start().await;
    let created = create(&superadmin, "neo", Some("neo@x.test"), "matrix123", &[]).await;
    let id = created["id"].as_str().unwrap().to_owned();
    assert!(Uuid::parse_str(&id).is_ok(), "{created}");
    assert_eq!(created["username"], "neo");
    assert_eq!(created["email"], "neo@x.test");
    assert_eq!(created["email_verified"], false);
    assert_eq!(created["roles"], json!([]));
    assert_eq!(created["display_name"], Value::Null);
    assert_eq!(created["avatar_url"], Value::Null);
    assert!(created["created_at"].is_string(), "{created}");
    assert!(
        created.get("password").is_none() && created.get("password_hash").is_none(),
        "不应回显密码: {created}"
    );

    let got = expect_json(superadmin.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(got["username"], "neo");
    assert_eq!(got["roles"], json!([]));

    // 前台登录:用户名 / 邮箱都行;错密码 401
    let client = server.login("neo", "matrix123").await;
    let me = expect_json(client.get(FRONT_ME).await, StatusCode::OK).await;
    assert_eq!(me["username"], "neo");
    assert_eq!(me["roles"], json!([]));
    server.login("neo@x.test", "matrix123").await;
    assert_eq!(
        front_login_status(&server, "neo", "wrong-password").await,
        StatusCode::UNAUTHORIZED
    );
    // 没有平台级权限、也不在任何租户里(管理员建的号不自动入租户)→ 后台登录 403 `tenant_required`
    // (前端据此显示「还没加入任何组织」)
    expect_error(
        server
            .anonymous()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "neo", "password": "matrix123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
}

/// 建带平台角色(platform_admin)的号 → 不属于任何租户也能登后台(平台管理员凭平台级权限准入)、能管账号,
/// 但够不到租户级接口(tenant_required);不带角色(roles=[])→ roles 为空、前台照常能登。
#[tokio::test]
async fn create_with_platform_role_can_login_admin_and_no_roles_is_empty() {
    let (server, superadmin) = start().await;
    create(&superadmin, "ops", None, "opspass", &["platform_admin"]).await;
    let ops = server.login_admin("ops", "opspass").await;
    let me = expect_json(ops.get("/api/v1/admin/auth/me").await, StatusCode::OK).await;
    assert_eq!(me["username"], "ops");
    expect(ops.get(USERS).await, StatusCode::OK).await;
    expect_error(
        ops.get("/api/v1/frontend/widgets").await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;

    let created = create(&superadmin, "bare", None, "barepass", &[]).await;
    assert_eq!(created["roles"], json!([]));
    let client = server.login("bare", "barepass").await;
    assert_eq!(
        expect_json(client.get(FRONT_ME).await, StatusCode::OK).await["roles"],
        json!([])
    );
}

/// 重复的角色 id 去重(响应与落库一致,不回显两份)。
#[tokio::test]
async fn create_dedups_repeated_role_ids() {
    let (_server, superadmin) = start().await;
    let ids = role_ids(&superadmin, &["platform_admin", "platform_admin"]).await;
    let created = expect_json(
        superadmin.post_json(
            USERS,
            &json!({ "username": "dup-roles", "email": null, "password": "secret1", "roles": ids }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(sorted_roles(&created), vec!["platform_admin"], "{created}");
    let id = created["id"].as_str().unwrap();
    let got = expect_json(superadmin.get(&user_url(id)).await, StatusCode::OK).await;
    assert_eq!(sorted_roles(&got), vec!["platform_admin"], "{got}");
}

/// 建号错误分支:重名 / 重邮箱 409;未知角色 id、空用户名、超长用户名、非法邮箱、短密码 422;
/// 缺字段 / 非法 JSON 400 —— 全是统一错误体,且失败不留半态(不会建出号)。
#[tokio::test]
async fn create_user_error_cases() {
    let (server, superadmin) = start().await;
    let body = |username: &str, email: Value, password: &str, roles: Value| json!({ "username": username, "email": email, "password": password, "roles": roles });
    // 409:与 seed 账号撞名;与 seed superadmin 撞邮箱
    expect_error(
        superadmin
            .post_json(USERS, &body(USER, Value::Null, "secret1", json!([])))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        superadmin
            .post_json(
                USERS,
                &body("fresh", json!("superadmin@local"), "secret1", json!([])),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    // 422
    let long_name = "x".repeat(101);
    let cases = [
        body("ghost", Value::Null, "secret1", json!([NIL])),
        body("", Value::Null, "secret1", json!([])),
        body(&long_name, Value::Null, "secret1", json!([])),
        body("bad-mail", json!("not-an-email"), "secret1", json!([])),
        body("shortpw", Value::Null, "ab", json!([])),
    ];
    for case in &cases {
        expect_error(
            superadmin.post_json(USERS, case).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    // 未知角色 id 夹在合法 id 中间也整单拒(原子)
    let mut mixed = role_ids(&superadmin, &[]).await;
    mixed.push(NIL.to_owned());
    expect_error(
        superadmin
            .post_json(USERS, &body("half", Value::Null, "secret1", json!(mixed)))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    // 400:缺 roles 字段、roles 里不是 uuid、非法 JSON
    expect_error(
        superadmin
            .post_json(
                USERS,
                &json!({ "username": "noroles", "email": null, "password": "secret1" }),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin
            .post_json(
                USERS,
                &body("badid", Value::Null, "secret1", json!(["admin"])),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let response = superadmin
        .request(Method::POST, USERS)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(response, StatusCode::BAD_REQUEST, "bad_request").await;

    // 以上全部失败 → 只剩 seed 的 3 个号;失败的用户名也登不进
    let page = list(&superadmin, "").await;
    assert_eq!(
        page["page_info"]["total"], 3,
        "失败的建号不应留下数据: {page}"
    );
    for name in ["ghost", "half", "shortpw", "fresh"] {
        assert_eq!(
            front_login_status(&server, name, "secret1").await,
            StatusCode::UNAUTHORIZED,
            "{name} 不应被建出来"
        );
    }
}

// ───────────────────────────── 4. 列表 ─────────────────────────────

/// 默认:offset 第 1 页、size 20、带 total;只有 seed 的 3 个号;按 created_at 倒序(新的在前);
/// 富化 display_name(seed 给 superadmin / admin 建了初始资料,user 没有 → null)。
#[tokio::test]
async fn list_default_offset_desc_and_enriched() {
    let (_server, superadmin) = start().await;
    let page = list(&superadmin, "").await;
    assert_eq!(page["page_info"]["mode"], "offset");
    assert_eq!(page["page_info"]["page"], 1);
    assert_eq!(page["page_info"]["size"], 20);
    assert_eq!(page["page_info"]["total"], 3);
    assert_eq!(page["page_info"]["total_pages"], 1);
    let names: HashSet<String> = usernames(&page).into_iter().collect();
    let expected: HashSet<String> = [SUPERADMIN, ADMIN, USER]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(names, expected);
    let row = |name: &str| {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["username"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(row(SUPERADMIN)["display_name"], "Super Admin");
    assert_eq!(row(SUPERADMIN)["email"], "superadmin@local");
    assert_eq!(row(SUPERADMIN)["roles"], json!(["superadmin"]));
    assert_eq!(row(ADMIN)["display_name"], "Admin");
    assert_eq!(row(USER)["display_name"], Value::Null);
    assert_eq!(row(USER)["email"], Value::Null);

    // 新建的号排最前(默认 created_at desc);order=asc 时排最后
    create_id(&superadmin, "newest", &[]).await;
    assert_eq!(usernames(&list(&superadmin, "").await)[0], "newest");
    let ascending = usernames(&list(&superadmin, "order=asc").await);
    assert_eq!(ascending.last().unwrap(), "newest");
}

/// username 过滤:子串 + 大小写不敏感;无命中 → 空页 total 0。
/// 多租户:`GET /users` 是**平台账号列表** —— 不论后台会话在哪个租户,都列全部账号:平台管理员新建、
/// 不属于任何租户的账号也在里面;角色列是平台角色(租户角色不出现)。租户成员列表是另外的接口。
#[tokio::test]
async fn list_is_platform_account_list_including_accounts_in_no_tenant() {
    let (_server, superadmin) = start().await;
    let lonely = create_id(&superadmin, "lonely_acct", &[]).await;

    let page = list(&superadmin, "size=100").await;
    let names = usernames(&page);
    for expected in ["lonely_acct", SUPERADMIN, ADMIN, USER] {
        assert!(
            names.iter().any(|n| n == expected),
            "{expected} 应在平台账号列表里(不属于任何租户的账号也在): {names:?}"
        );
    }
    let item = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == lonely.as_str())
        .expect("新账号在列表里");
    assert_eq!(item["roles"], json!([]), "不属于任何租户、没有平台角色");
    // seed 的 admin / user 是租户角色:平台账号列表的角色列不显示它们。
    let admin = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["username"] == ADMIN)
        .unwrap();
    assert_eq!(
        admin["roles"],
        json!([]),
        "租户角色不进平台账号列表的角色列"
    );
}

#[tokio::test]
async fn list_filter_username_substring_case_insensitive() {
    let (_server, superadmin) = start().await;
    for name in ["alice", "bob", "carol"] {
        create_id(&superadmin, name, &[]).await;
    }
    let page = list(&superadmin, "username=A&sort_by=username&order=asc").await;
    assert_eq!(
        usernames(&page),
        vec!["admin", "alice", "carol", "superadmin"]
    );
    assert_eq!(page["page_info"]["total"], 4);
    let page = list(&superadmin, "username=ADMIN&sort_by=username&order=asc").await;
    assert_eq!(usernames(&page), vec!["admin", "superadmin"]);
    let page = list(&superadmin, "username=zzz").await;
    assert!(usernames(&page).is_empty(), "{page}");
    assert_eq!(page["page_info"]["total"], 0);
}

/// 角色过滤:正选 role(重复 key = 任一)/ 反选 role_not / 二者组合 / 与 username 组合。
#[tokio::test]
async fn list_filter_roles_any_none_and_combined() {
    let (_server, superadmin) = start().await;
    // 账号管理只授平台角色(经接口能授的只有 platform_admin;superadmin 只有 seed 的那一个);
    // seed 的 admin / user 只在默认租户里有租户角色,user_roles 里没有 → 按角色过滤时算「无角色」。
    create_id(&superadmin, "alice", &["platform_admin"]).await;
    create_id(&superadmin, "bob", &["platform_admin"]).await;
    create_id(&superadmin, "nobody", &[]).await;
    let sorted = |filter: &str| format!("{filter}&sort_by=username&order=asc");

    assert_eq!(
        usernames(&list(&superadmin, &sorted("role=platform_admin")).await),
        vec!["alice", "bob"]
    );
    assert_eq!(
        usernames(&list(&superadmin, &sorted("role=platform_admin&role=superadmin")).await),
        vec!["alice", "bob", "superadmin"],
        "重复 key = 任一"
    );
    assert_eq!(
        usernames(
            &list(
                &superadmin,
                &sorted("role_not=platform_admin&role_not=superadmin")
            )
            .await
        ),
        vec!["admin", "nobody", "user"]
    );
    assert_eq!(
        usernames(&list(&superadmin, &sorted("role=platform_admin&username=o")).await),
        vec!["bob"]
    );
    let page = list(&superadmin, "role=platform_admin").await;
    assert_eq!(page["page_info"]["total"], 2);

    // 不在闭集的角色名 → 400(query 反序列化失败,统一错误体)
    expect_error(
        superadmin.get(&format!("{USERS}?role=editor")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 创建时间区间过滤(RFC3339,闭区间)。
#[tokio::test]
async fn list_filter_created_range() {
    let (_server, superadmin) = start().await;
    let page = list(&superadmin, "created_from=2000-01-01T00:00:00Z").await;
    assert_eq!(page["page_info"]["total"], 3);
    let page = list(&superadmin, "created_from=2999-01-01T00:00:00Z").await;
    assert_eq!(page["page_info"]["total"], 0);
    let page = list(&superadmin, "created_to=2000-01-01T00:00:00Z").await;
    assert_eq!(page["page_info"]["total"], 0);
    let page = list(
        &superadmin,
        "created_from=2000-01-01T00:00:00Z&created_to=2999-01-01T00:00:00Z",
    )
    .await;
    assert_eq!(page["page_info"]["total"], 3);

    // 用某个号自己的 created_at 当两端 → 恰好命中它(闭区间)
    let created = create(&superadmin, "pinpoint", None, "secret1", &[]).await;
    let at = created["created_at"].as_str().unwrap().replace('+', "%2B");
    let page = list(&superadmin, &format!("created_from={at}&created_to={at}")).await;
    assert_eq!(usernames(&page), vec!["pinpoint"], "{page}");

    // 非法时间 → 400
    expect_error(
        superadmin
            .get(&format!("{USERS}?created_from=yesterday"))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 排序:username asc/desc、email asc(null 排在有值之后)、created_at;未知排序字段 → 400。
#[tokio::test]
async fn list_sort_by_username_email_created_at() {
    let (_server, superadmin) = start().await;
    create(&superadmin, "zed", Some("a@x.test"), "secret1", &[]).await;
    create(&superadmin, "amy", Some("z@x.test"), "secret1", &[]).await;

    assert_eq!(
        usernames(&list(&superadmin, "sort_by=username&order=asc").await),
        vec!["admin", "amy", "superadmin", "user", "zed"]
    );
    assert_eq!(
        usernames(&list(&superadmin, "sort_by=username&order=desc").await),
        vec!["zed", "user", "superadmin", "amy", "admin"]
    );

    let page = list(&superadmin, "sort_by=email&order=asc").await;
    let emails: Vec<Value> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["email"].clone())
        .collect();
    assert_eq!(
        emails[..3],
        [
            json!("a@x.test"),
            json!("superadmin@local"),
            json!("z@x.test")
        ],
        "{page}"
    );
    assert!(
        emails[3..].iter().all(Value::is_null),
        "无邮箱的排后: {page}"
    );
    let page = list(&superadmin, "sort_by=email&order=desc").await;
    assert_eq!(page["items"][0]["email"], "z@x.test", "{page}");

    // created_at 显式 asc:最早的是 seed 账号,最后建的 amy 在末尾
    let ascending = usernames(&list(&superadmin, "sort_by=created_at&order=asc").await);
    assert_eq!(ascending.last().unwrap(), "amy");
    assert_eq!(ascending[3], "zed");

    expect_error(
        superadmin.get(&format!("{USERS}?sort_by=password")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin.get(&format!("{USERS}?order=sideways")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// offset 分页:page/size/total/total_pages;越界页空;with_total=false 不算 total;size 越界 clamp。
#[tokio::test]
async fn list_offset_pagination() {
    let (_server, superadmin) = start().await;
    for name in ["u1", "u2"] {
        create_id(&superadmin, name, &[]).await;
    }
    // 共 5 个号,按 username 升序:admin, superadmin, u1, u2, user
    let query = "sort_by=username&order=asc&size=2";
    let first_page = list(&superadmin, &format!("{query}&page=1")).await;
    assert_eq!(usernames(&first_page), vec!["admin", "superadmin"]);
    assert_eq!(first_page["page_info"]["total"], 5);
    assert_eq!(first_page["page_info"]["total_pages"], 3);
    assert_eq!(first_page["page_info"]["size"], 2);
    let second_page = list(&superadmin, &format!("{query}&page=2")).await;
    assert_eq!(usernames(&second_page), vec!["u1", "u2"]);
    assert_eq!(second_page["page_info"]["page"], 2);
    let third_page = list(&superadmin, &format!("{query}&page=3")).await;
    assert_eq!(usernames(&third_page), vec!["user"]);
    let out_of_range_page = list(&superadmin, &format!("{query}&page=9")).await;
    assert!(
        usernames(&out_of_range_page).is_empty(),
        "{out_of_range_page}"
    );
    assert_eq!(out_of_range_page["page_info"]["total"], 5);

    let no_total = list(&superadmin, &format!("{query}&page=1&with_total=false")).await;
    assert_eq!(no_total["page_info"]["total"], Value::Null);
    assert_eq!(usernames(&no_total).len(), 2);

    // size clamp 到 [1,100];page=0 视为第 1 页
    let page = list(&superadmin, "size=0").await;
    assert_eq!(page["page_info"]["size"], 1);
    assert_eq!(usernames(&page).len(), 1);
    let page = list(&superadmin, "size=1000").await;
    assert_eq!(page["page_info"]["size"], 100);
    let page = list(&superadmin, "page=0&size=2&sort_by=username&order=asc").await;
    assert_eq!(page["page_info"]["page"], 1);
    assert_eq!(usernames(&page), vec!["admin", "superadmin"]);

    // 类型不对 → 400
    expect_error(
        superadmin.get(&format!("{USERS}?page=abc")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// cursor 分页(默认排序):空 cursor = 首页;逐页走完覆盖全部、无重复、末页 has_more=false;可与过滤组合。
#[tokio::test]
async fn list_cursor_pagination_walks_all() {
    let (_server, superadmin) = start().await;
    for name in ["c1", "c2", "c3", "c4"] {
        create_id(&superadmin, name, &["platform_admin"]).await;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;
    loop {
        let page = list(&superadmin, &format!("cursor={cursor}&size=3")).await;
        assert_eq!(page["page_info"]["mode"], "cursor", "{page}");
        assert_eq!(page["page_info"]["limit"], 3);
        assert!(
            page["page_info"].get("total").is_none(),
            "cursor 模式不带 total: {page}"
        );
        seen.extend(usernames(&page));
        pages += 1;
        if page["page_info"]["has_more"] == true {
            cursor = page["page_info"]["next_cursor"]
                .as_str()
                .unwrap()
                .to_owned();
        } else {
            assert_eq!(page["page_info"]["next_cursor"], Value::Null);
            break;
        }
        assert!(pages < 10, "cursor 翻页不收敛");
    }
    assert_eq!(pages, 3, "7 个号每页 3 → 3 页");
    assert_eq!(seen.len(), 7);
    let unique: HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 7, "不应重复: {seen:?}");
    assert_eq!(seen[0], "c4", "默认 created_at desc:最新的在首页首位");

    // 与过滤组合:role=platform_admin 共 4 个(c1..c4),size=3 → 首页 3 条且 has_more
    let page = list(&superadmin, "cursor=&size=3&role=platform_admin").await;
    assert_eq!(usernames(&page).len(), 3);
    assert_eq!(page["page_info"]["has_more"], true);
    let next = page["page_info"]["next_cursor"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = list(
        &superadmin,
        &format!("cursor={next}&size=3&role=platform_admin"),
    )
    .await;
    assert_eq!(usernames(&page).len(), 1);
    assert_eq!(page["page_info"]["has_more"], false);
}

/// 分页参数冲突 / 非法:cursor + 非默认排序 → 422;page + cursor → 422;坏 cursor → 400。
#[tokio::test]
async fn list_pagination_param_errors() {
    let (_server, superadmin) = start().await;
    for query in [
        "cursor=&sort_by=username",
        "cursor=&order=asc",
        "cursor=&sort_by=created_at&order=asc",
        "page=1&cursor=",
        "page=1&cursor=xxx",
    ] {
        expect_error(
            superadmin.get(&format!("{USERS}?{query}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    // 显式写出默认排序(created_at desc)可以配 cursor
    let page = list(&superadmin, "cursor=&sort_by=created_at&order=desc").await;
    assert_eq!(page["page_info"]["mode"], "cursor");

    expect_error(
        superadmin.get(&format!("{USERS}?cursor=!!!bad")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 内存模式无 search 投影后端:q(非空白)/ sort_by=display_name → 422;纯空白 q 视为未搜索 → 200。
#[tokio::test]
async fn list_without_search_backend_rejects_q_and_display_name_sort() {
    let (_server, superadmin) = start().await;
    for query in ["q=admin", "sort_by=display_name", "q=a&sort_by=username"] {
        expect_error(
            superadmin.get(&format!("{USERS}?{query}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    let page = list(&superadmin, "q=%20%20").await;
    assert_eq!(page["page_info"]["total"], 3);
    let page = list(&superadmin, "q=").await;
    assert_eq!(page["page_info"]["total"], 3);
}

// ───────────────────────────── 5. 详情 ─────────────────────────────

/// 详情:200 带富化;不存在 404;路径不是 uuid → 400。
#[tokio::test]
async fn get_user_found_missing_and_bad_id() {
    let (_server, superadmin) = start().await;
    let id = find_id(&superadmin, SUPERADMIN).await;
    let user = expect_json(superadmin.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(user["id"], id.as_str());
    assert_eq!(user["username"], SUPERADMIN);
    assert_eq!(user["email"], "superadmin@local");
    assert_eq!(user["roles"], json!(["superadmin"]));
    assert_eq!(user["display_name"], "Super Admin");
    assert!(user["created_at"].is_string());

    expect_error(
        superadmin.get(&user_url(&Uuid::now_v7().to_string())).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin.get(&user_url("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── 6. 改身份 ─────────────────────────────

/// PUT 全量:改名 + 邮箱 → 200 且持久;email=null 清空;改名后新名能登、旧名不能(会话凭据跟着变)。
#[tokio::test]
async fn update_user_full_replace_and_relogin_by_new_name() {
    let (server, superadmin) = start().await;
    let id = create_id(&superadmin, "gina", &["platform_admin"]).await;
    let url = user_url(&id);
    let updated = expect_json(
        superadmin
            .put_json(&url, &json!({ "username": "gina2", "email": "g@x.test" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["id"], id.as_str());
    assert_eq!(updated["username"], "gina2");
    assert_eq!(updated["email"], "g@x.test");
    assert_eq!(updated["email_verified"], false);
    assert_eq!(
        updated["roles"],
        json!(["platform_admin"]),
        "改身份不动角色"
    );
    let got = expect_json(superadmin.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], "gina2");
    assert_eq!(got["email"], "g@x.test");

    server.login("gina2", "password123").await;
    server.login("g@x.test", "password123").await;
    assert_eq!(
        front_login_status(&server, "gina", "password123").await,
        StatusCode::UNAUTHORIZED
    );

    // email=null 清空;同名同邮箱(自己的)不算冲突
    let updated = expect_json(
        superadmin
            .put_json(&url, &json!({ "username": "gina2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["email"], Value::Null);
    expect(
        superadmin
            .put_json(&url, &json!({ "username": "gina2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
}

/// 改身份错误分支:撞名 / 撞邮箱 409;空名 / 非法邮箱 422;缺字段 400;不存在 404;坏 id 400。
#[tokio::test]
async fn update_user_error_cases() {
    let (_server, superadmin) = start().await;
    let id = create_id(&superadmin, "hank", &[]).await;
    let url = user_url(&id);
    expect_error(
        superadmin
            .put_json(&url, &json!({ "username": ADMIN, "email": null }))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        superadmin
            .put_json(
                &url,
                &json!({ "username": "hank", "email": "superadmin@local" }),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    for body in [
        json!({ "username": "", "email": null }),
        json!({ "username": "x".repeat(101), "email": null }),
        json!({ "username": "hank", "email": "nope" }),
    ] {
        expect_error(
            superadmin.put_json(&url, &body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        superadmin.put_json(&url, &json!({ "email": null })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin
            .put_json(
                &user_url(&Uuid::now_v7().to_string()),
                &json!({ "username": "ghost", "email": null }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .put_json(&user_url("123"), &json!({ "username": "x", "email": null }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    // 全部失败 → 原样
    let got = expect_json(superadmin.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], "hank");
    assert_eq!(got["email"], Value::Null);
}

// ───────────────────────────── 7. 删号 ─────────────────────────────

/// 软删 → 204 空 body;之后详情 404、再删 404、列表里没了、登录 401、旧会话 refresh 401;
/// 用户名释放(可再建同名号)。
#[tokio::test]
async fn delete_user_soft_deletes_and_kills_login() {
    let (server, superadmin) = start().await;
    let id = create_id(&superadmin, "doomed", &[]).await;
    let session = server.login("doomed", "password123").await;
    expect(session.post_empty(REFRESH).await, StatusCode::OK).await;

    let body = expect(
        superadmin.delete(&user_url(&id)).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");

    expect_error(
        superadmin.get(&user_url(&id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin.delete(&user_url(&id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let page = list(&superadmin, "").await;
    assert!(!usernames(&page).contains(&"doomed".to_owned()), "{page}");
    assert_eq!(page["page_info"]["total"], 3);

    assert_eq!(
        front_login_status(&server, "doomed", "password123").await,
        StatusCode::UNAUTHORIZED
    );
    expect(session.post_empty(REFRESH).await, StatusCode::UNAUTHORIZED).await;

    // 已删号的其它写操作也是 404
    expect_error(
        superadmin
            .put_json(
                &user_url(&id),
                &json!({ "username": "zombie", "email": null }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .put_json(&format!("{}/roles", user_url(&id)), &json!({ "roles": [] }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .post_json(
                &format!("{}/password", user_url(&id)),
                &json!({ "new_password": "revive1" }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

    // 用户名释放:再建同名号是个新 id
    let again = create_id(&superadmin, "doomed", &[]).await;
    assert_ne!(again, id);
}

/// 删号错误分支:不存在 404;坏 id 400;**删自己** 409(自锁)。
#[tokio::test]
async fn delete_user_missing_bad_id_and_self_is_409() {
    let (server, superadmin) = start().await;
    expect_error(
        superadmin
            .delete(&user_url(&Uuid::now_v7().to_string()))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin.delete(&user_url("nope")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;

    let me = find_id(&superadmin, SUPERADMIN).await;
    expect_error(
        superadmin.delete(&user_url(&me)).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    // 自己还在、还能登
    expect(superadmin.get(&user_url(&me)).await, StatusCode::OK).await;
    server.login_admin(SUPERADMIN, PASSWORD).await;
}

// ───────────────────────────── 8. 设角色 ─────────────────────────────

/// 全量替换角色:设 [platform_admin] → 200;再设 [] 清空;改动反映在后续登录(能否进后台)。
#[tokio::test]
async fn set_roles_full_replace_affects_next_login() {
    let (server, superadmin) = start().await;
    let id = create_id(&superadmin, "promo", &[]).await;
    let url = format!("{}/roles", user_url(&id));
    // 还没平台角色(也不在任何租户里)→ 后台登录 403
    expect(
        server
            .anonymous()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "promo", "password": "password123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
    )
    .await;

    let ids = role_ids(&superadmin, &["platform_admin"]).await;
    let updated = expect_json(
        superadmin.put_json(&url, &json!({ "roles": ids })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["id"], id.as_str());
    assert_eq!(sorted_roles(&updated), vec!["platform_admin"]);
    let got = expect_json(superadmin.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(sorted_roles(&got), vec!["platform_admin"]);
    server.login_admin("promo", "password123").await;
    assert!(
        usernames(&list(&superadmin, "role=platform_admin").await).contains(&"promo".to_owned())
    );

    // 全量替换(不是追加):清空
    let updated = expect_json(
        superadmin.put_json(&url, &json!({ "roles": [] })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["roles"], json!([]));
    expect(
        server
            .anonymous()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "promo", "password": "password123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
    )
    .await;
    // 列表的角色过滤也跟着变
    assert!(
        !usernames(&list(&superadmin, "role=platform_admin").await).contains(&"promo".to_owned())
    );
}

/// 设角色错误分支:未知角色 id 422(原子,不留半态);不存在 404;坏 body 400。
#[tokio::test]
async fn set_roles_error_cases() {
    let (_server, superadmin) = start().await;
    let id = create_id(&superadmin, "roleuser", &["platform_admin"]).await;
    let url = format!("{}/roles", user_url(&id));
    let mut ids = role_ids(&superadmin, &["platform_admin"]).await;
    ids.push(NIL.to_owned());
    expect_error(
        superadmin.put_json(&url, &json!({ "roles": ids })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    let got = expect_json(superadmin.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!(["platform_admin"]), "失败不应留半态");

    expect_error(
        superadmin
            .put_json(
                &format!("{}/roles", user_url(&Uuid::now_v7().to_string())),
                &json!({ "roles": [] }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .put_json(&url, &json!({ "roles": "admin" }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin.put_json(&url, &json!({})).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 改**自己**的角色:superadmin 去掉自己的 superadmin → 403(superadmin 不经接口撤销;它先于「不能丢 users:admin」
/// 的 409 自锁 —— 那道自锁仍在,只对闭集外的自定义平台角色还够得着,见 routes 单测);
/// 未知角色 id 先报 422(不被 403 / 409 抢先)。保留 superadmin 的改动见 `http_platform_admin.rs`。
#[tokio::test]
async fn set_own_roles_cannot_drop_superadmin() {
    let (server, superadmin) = start().await;
    let me = find_id(&superadmin, SUPERADMIN).await;
    let url = format!("{}/roles", user_url(&me));
    expect_error(
        superadmin.put_json(&url, &json!({ "roles": [] })).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        superadmin.put_json(&url, &json!({ "roles": [NIL] })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    let got = expect_json(superadmin.get(&user_url(&me)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!(["superadmin"]), "被拒后角色不变");
    // 仍是超管
    let again = server.login_admin(SUPERADMIN, PASSWORD).await;
    expect(again.get(USERS).await, StatusCode::OK).await;
}

// ───────────────────────────── 9. 重置密码 ─────────────────────────────

/// 重置密码 → 204;旧密码登不进、新密码能登;**既有会话被撤**(refresh 401)。
#[tokio::test]
async fn reset_password_switches_password_and_revokes_sessions() {
    let (server, superadmin) = start().await;
    let user_id = find_id(&superadmin, USER).await;
    let old_session = server.login(USER, PASSWORD).await;
    expect(old_session.post_empty(REFRESH).await, StatusCode::OK).await;

    let body = expect(
        superadmin
            .post_json(
                &format!("{}/password", user_url(&user_id)),
                &json!({ "new_password": "brand-new-1" }),
            )
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");

    assert_eq!(
        front_login_status(&server, USER, PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );
    let fresh = server.login(USER, "brand-new-1").await;
    assert_eq!(
        expect_json(fresh.get(FRONT_ME).await, StatusCode::OK).await["username"],
        USER
    );
    expect_error(
        old_session.post_empty(REFRESH).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    // 新会话不受影响
    expect(fresh.post_empty(REFRESH).await, StatusCode::OK).await;
}

/// 管理员给**自己**重置密码也允许(无自锁);之后旧密码失效。
#[tokio::test]
async fn reset_own_password_is_allowed() {
    let (server, superadmin) = start().await;
    let me = find_id(&superadmin, SUPERADMIN).await;
    expect(
        superadmin
            .post_json(
                &format!("{}/password", user_url(&me)),
                &json!({ "new_password": "rotated-1" }),
            )
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    server.login_admin(SUPERADMIN, "rotated-1").await;
    assert_eq!(
        front_login_status(&server, SUPERADMIN, PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );
}

/// 重置密码错误分支:短密码 422(且旧密码仍有效);不存在 404;缺字段 400;坏 id 400。
#[tokio::test]
async fn reset_password_error_cases() {
    let (server, superadmin) = start().await;
    let user_id = find_id(&superadmin, USER).await;
    let url = format!("{}/password", user_url(&user_id));
    expect_error(
        superadmin
            .post_json(&url, &json!({ "new_password": "ab" }))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    server.login(USER, PASSWORD).await; // 没改成

    expect_error(
        superadmin
            .post_json(
                &format!("{}/password", user_url(&Uuid::now_v7().to_string())),
                &json!({ "new_password": "secret1" }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .post_json(&url, &json!({ "password": "secret1" }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin
            .post_json(
                &format!("{}/password", user_url("zzz")),
                &json!({ "new_password": "secret1" }),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── 10. 提权闸(防越权) ─────────────────────────────

/// 带「中间管理员」的策略:`useradmin` 有 users:admin + admin:login 但非满权。
/// user 角色不带权限 → 中间管理员够得着它(打「同级/更低权目标」照常放行)。
fn escalation_policy() -> Policy {
    Policy::new([
        ("superadmin".to_owned(), Permission::ALL.to_vec()),
        ("admin".to_owned(), vec![Permission::AdminLogin]),
        ("user".to_owned(), vec![]),
        (
            "useradmin".to_owned(),
            vec![Permission::AdminLogin, Permission::UsersAdmin],
        ),
    ])
}

/// 中间管理员策略下起好的服务和两个会话。
struct EscalationSetup {
    server: TestServer,
    superadmin: Client,
    /// 中间管理员(`useradmin`)会话。
    user_admin: Client,
}

/// 起服务(中间管理员策略)并登好 superadmin 与中间管理员会话。
async fn start_escalation() -> EscalationSetup {
    let server = TestServer::start_with(|state| state.policy = Arc::new(escalation_policy())).await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let user_admin = server.bearer(&mint(
        Uuid::now_v7(),
        "useradmin",
        &["useradmin"],
        Some(DEFAULT_TENANT),
        &["useradmin"],
        vec![],
    ));
    EscalationSetup {
        server,
        superadmin,
        user_admin,
    }
}

/// 中间管理员能读(列表 / 详情 / 角色目录),但对 superadmin 的四个写操作全 403,
/// 且 superadmin 毫发无损(原密码能登、名字/角色不变、没被删)。
#[tokio::test]
async fn intermediate_admin_cannot_touch_superadmin() {
    let EscalationSetup {
        server,
        superadmin,
        user_admin,
    } = start_escalation().await;
    expect(user_admin.get(USERS).await, StatusCode::OK).await;
    expect(user_admin.get(ROLES).await, StatusCode::OK).await;
    let victim = find_id(&user_admin, SUPERADMIN).await;
    let url = user_url(&victim);
    expect(user_admin.get(&url).await, StatusCode::OK).await;

    expect_error(
        user_admin
            .post_json(
                &format!("{url}/password"),
                &json!({ "new_password": "pwned123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        user_admin
            .put_json(&url, &json!({ "username": "hijacked", "email": null }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        user_admin
            .put_json(&format!("{url}/roles"), &json!({ "roles": [] }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        user_admin.delete(&url).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;

    let got = expect_json(superadmin.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], SUPERADMIN);
    assert_eq!(got["roles"], json!(["superadmin"]));
    server.login_admin(SUPERADMIN, PASSWORD).await;
}

/// 对同级/更低权目标,中间管理员四个写操作照常放行(闸别收成谁都改不了)。
#[tokio::test]
async fn intermediate_admin_can_manage_lower_users() {
    let EscalationSetup {
        server,
        superadmin,
        user_admin,
    } = start_escalation().await;
    let plain = create_id(&superadmin, "plain", &[]).await;
    let url = user_url(&plain);
    let updated = expect_json(
        user_admin
            .put_json(&url, &json!({ "username": "plain2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["username"], "plain2");
    let updated = expect_json(
        user_admin
            .put_json(&format!("{url}/roles"), &json!({ "roles": [] }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(sorted_roles(&updated).is_empty(), "{updated}");
    expect(
        user_admin
            .post_json(
                &format!("{url}/password"),
                &json!({ "new_password": "reset-ok" }),
            )
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    server.login("plain2", "reset-ok").await;
    expect(user_admin.delete(&url).await, StatusCode::NO_CONTENT).await;
    expect(superadmin.get(&url).await, StatusCode::NOT_FOUND).await;
}

/// 授出去的角色也闸:中间管理员(无 platform:roles)不能建平台管理员号、不能把别人升成平台管理员(403,不落库);
/// 目录里也看不到可授的平台角色(id 取自 superadmin 的目录)。superadmin 授出后,中间管理员反过来动不了那个号。
#[tokio::test]
async fn intermediate_admin_cannot_grant_platform_admin() {
    let EscalationSetup {
        superadmin,
        user_admin,
        ..
    } = start_escalation().await;
    let catalog = expect_json(user_admin.get(ROLES).await, StatusCode::OK).await;
    assert_eq!(catalog["items"], json!([]), "无 platform:roles → 目录为空");
    let super_role = role_ids(&superadmin, &["platform_admin"]).await;
    expect_error(
        user_admin.post_json(
            USERS,
            &json!({ "username": "sneaky", "email": null, "password": "secret1", "roles": super_role }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    assert!(
        !usernames(&list(&superadmin, "username=sneaky").await).contains(&"sneaky".to_owned()),
        "被拒的建号不应落库"
    );

    let plain = create_id(&user_admin, "plain", &[]).await;
    let with_super = super_role.clone();
    expect_error(
        user_admin
            .put_json(
                &format!("{}/roles", user_url(&plain)),
                &json!({ "roles": with_super }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let got = expect_json(superadmin.get(&user_url(&plain)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!([]), "被拒后角色不变");

    // superadmin(持 platform:roles)授平台管理员照常
    let updated = expect_json(
        superadmin
            .put_json(
                &format!("{}/roles", user_url(&plain)),
                &json!({ "roles": super_role }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["roles"], json!(["platform_admin"]));
    // 现在 plain 是平台管理员了 → 中间管理员反过来动不了它
    expect_error(
        user_admin.delete(&user_url(&plain)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// seed 策略下的提权闸(scope 收窄的超管令牌 = 非满权主体):授 / 动带权限的角色 → 403,
/// 不带权限的操作照常。验证闸看的是 role ∩ scope,而不只是 role。
#[tokio::test]
async fn scoped_superadmin_token_cannot_grant_or_touch_beyond_scope() {
    let (server, superadmin) = start().await;
    let narrow = server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &[SUPERADMIN],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![Permission::AdminLogin, Permission::UsersAdmin],
    ));
    // scope 只给了 admin:login + users:admin,没给 platform:roles / tenants:admin
    let super_role = role_ids(&superadmin, &["platform_admin"]).await;
    // 授平台管理员(要 platform:roles,且含 tenants:admin,都在 scope 外)→ 403
    expect_error(
        narrow
            .post_json(
                USERS,
                &json!({ "username": "scoped", "email": null, "password": "secret1", "roles": super_role }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 不授角色 → 201
    let created = expect_json(
        narrow
            .post_json(
                USERS,
                &json!({ "username": "scoped", "email": null, "password": "secret1", "roles": [] }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    let bare = created["id"].as_str().unwrap().to_owned();
    // 目标持平台角色(平台管理员,要 platform:roles,scope 外)→ 改密 403;无角色的号 → 204
    let boss = create_id(&superadmin, "boss", &["platform_admin"]).await;
    expect_error(
        narrow
            .post_json(
                &format!("{}/password", user_url(&boss)),
                &json!({ "new_password": "pwned123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    server.login("boss", "password123").await; // 没被改
    expect(
        narrow
            .post_json(
                &format!("{}/password", user_url(&bare)),
                &json!({ "new_password": "fine123" }),
            )
            .await,
        StatusCode::NO_CONTENT,
    )
    .await;
}

/// 账号管理只给平台管理员(`users:admin` 是平台级权限):租户管理员(默认租户 admin)能进后台,
/// 但账号的列 / 建 / 查 / 改 / 删 / 设平台角色 / 重置密码 / 角色目录一律 403 —— 账号是全局的,可能也属于别的租户。
#[tokio::test]
async fn tenant_admin_cannot_manage_accounts() {
    let (server, superadmin) = start().await;
    let target = create_id(&superadmin, "victim", &[]).await;
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    let requests: Vec<(Method, String, Option<Value>)> = vec![
        (Method::GET, USERS.to_owned(), None),
        (
            Method::POST,
            USERS.to_owned(),
            Some(json!({ "username": "x", "password": "pwd123", "roles": [] })),
        ),
        (Method::GET, format!("{USERS}/{target}"), None),
        (
            Method::PUT,
            format!("{USERS}/{target}"),
            Some(json!({ "username": "victim2", "email": null })),
        ),
        (Method::DELETE, format!("{USERS}/{target}"), None),
        (
            Method::PUT,
            format!("{USERS}/{target}/roles"),
            Some(json!({ "roles": [] })),
        ),
        (
            Method::POST,
            format!("{USERS}/{target}/password"),
            Some(json!({ "new_password": "hijack1" })),
        ),
        (Method::GET, ROLES.to_owned(), None),
    ];
    for (method, path, body) in requests {
        let mut request = admin.request(method.clone(), &path);
        if let Some(payload) = &body {
            request = request.json(payload);
        }
        expect_error(
            request.send().await.unwrap(),
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    // 账号原样:没被改名 / 删除 / 改密
    let user = expect_json(
        superadmin.get(&format!("{USERS}/{target}")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(user["username"], "victim");
    server.login("victim", "password123").await;
}

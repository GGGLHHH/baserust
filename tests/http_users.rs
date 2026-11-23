//! 后台用户管理(users 模块)的**黑盒 HTTP 验收测试**:真实端口 + reqwest,测试体不 import 任何 web 框架。
//! 与 `users_api.rs`(axum oneshot)覆盖同一组场景并补强:授权矩阵、列表过滤/排序/双模式分页、
//! 建/查/改/删/设角色/重置密码的正常与错误分支、自锁与提权闸(防越权),以及跨模块行为
//! (管理员建的号能在前台登录、改名/重置密码/删号/改角色后登录与会话的变化)。
//!
//! 大多数测试用 seed 策略(superadmin 满权、admin 只有后台准入无 `users:admin`、user 普通);
//! 提权闸测试另换一份带「中间管理员」`useradmin`(有 `users:admin` 但非满权)的策略。
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

use std::collections::HashSet;
use std::sync::Arc;

use baserust::kernel::authz::{Perm, Policy, RoleName};
use http_support::{
    expect, expect_error, expect_json, mint, Client, TestServer, ADMIN, PASSWORD, SUPERADMIN, USER,
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
    let s = TestServer::start().await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    (s, sa)
}

/// 角色名 → 角色 id(经 `GET /roles` 目录解析;角色按 id 提交)。
async fn role_ids(c: &Client, names: &[&str]) -> Vec<String> {
    let v = expect_json(c.get(ROLES).await, StatusCode::OK).await;
    let items = v["items"].as_array().expect("items 应是数组");
    names
        .iter()
        .map(|n| {
            items
                .iter()
                .find(|r| r["name"] == *n)
                .unwrap_or_else(|| panic!("角色目录缺 {n}: {v}"))["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// 建号(断言 201),返回响应体。`roles` 是角色**名**,内部解析成 id。
async fn create(
    c: &Client,
    username: &str,
    email: Option<&str>,
    password: &str,
    roles: &[&str],
) -> Value {
    let ids = role_ids(c, roles).await;
    expect_json(
        c.post_json(
            USERS,
            &json!({ "username": username, "email": email, "password": password, "roles": ids }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await
}

/// 建号(无 email,密码 `password123`),返回新 id。
async fn create_id(c: &Client, username: &str, roles: &[&str]) -> String {
    let v = create(c, username, None, "password123", roles).await;
    v["id"].as_str().unwrap().to_owned()
}

/// `GET /users?{query}` → 200 的 JSON。
async fn list(c: &Client, query: &str) -> Value {
    expect_json(c.get(&format!("{USERS}?{query}")).await, StatusCode::OK).await
}

/// 列表项的 username 序列(保序)。
fn usernames(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items 应是数组: {v}"))
        .iter()
        .map(|i| i["username"].as_str().unwrap().to_owned())
        .collect()
}

/// 按**精确**用户名查 id(列表 username 过滤是子串,这里再精确匹配一遍)。
async fn find_id(c: &Client, username: &str) -> String {
    let v = list(c, &format!("username={username}&size=100")).await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["username"] == username)
        .unwrap_or_else(|| panic!("列表里找不到 {username}: {v}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// 响应体 roles 数组排序后(角色比较不看顺序)。
fn sorted_roles(v: &Value) -> Vec<String> {
    let mut r: Vec<String> = v["roles"]
        .as_array()
        .unwrap_or_else(|| panic!("roles 应是数组: {v}"))
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    r.sort();
    r
}

/// 前台登录的状态码(不断言,用来验「登不进去」)。
async fn front_login_status(s: &TestServer, identifier: &str, password: &str) -> StatusCode {
    s.anon()
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
    let (s, sa) = start().await;
    let target = create_id(&sa, "matrix-target", &["user"]).await;
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

    let anon = s.anon();
    let user = s.login(USER, PASSWORD).await;
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    for (c, status, code) in [
        (&anon, StatusCode::UNAUTHORIZED, "unauthorized"),
        (&user, StatusCode::FORBIDDEN, "forbidden"),
        (&admin, StatusCode::FORBIDDEN, "forbidden"),
    ] {
        for (m, path, body) in &endpoints {
            let mut req = c.req(m.clone(), path);
            if let Some(b) = body {
                req = req.json(b);
            }
            expect_error(req.send().await.unwrap(), status, code).await;
        }
    }

    // 以上都被拒 → 目标毫发无损
    let v = expect_json(sa.get(&id_url).await, StatusCode::OK).await;
    assert_eq!(v["username"], "matrix-target");
    assert_eq!(sorted_roles(&v), vec!["user"]);
}

/// superadmin 能用;Bearer 令牌也行(不止 cookie)。
#[tokio::test]
async fn superadmin_cookie_and_bearer_both_work() {
    let (s, sa) = start().await;
    expect(sa.get(USERS).await, StatusCode::OK).await;
    let bearer = s.bearer(&mint(Uuid::now_v7(), SUPERADMIN, &[SUPERADMIN], vec![]));
    expect(bearer.get(USERS).await, StatusCode::OK).await;
    expect(bearer.get(ROLES).await, StatusCode::OK).await;
}

/// 降权令牌:scope 只收窄不放大。缺 users:admin → 端点 403;缺 admin:login → 组闸 403。
#[tokio::test]
async fn scoped_token_needs_both_admin_login_and_users_admin() {
    let s = TestServer::start().await;
    let sa_token = |scope| mint(Uuid::now_v7(), SUPERADMIN, &[SUPERADMIN], scope);
    let only_login = s.bearer(&sa_token(vec![Perm::AdminLogin]));
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
    let only_users = s.bearer(&sa_token(vec![Perm::UsersAdmin]));
    expect_error(
        only_users.get(USERS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let both = s.bearer(&sa_token(vec![Perm::AdminLogin, Perm::UsersAdmin]));
    expect(both.get(USERS).await, StatusCode::OK).await;
}

// ───────────────────────────── 2. 角色目录 ─────────────────────────────

/// 角色目录:全量闭集角色(id + 机器码 + 展示名),单页 cursor 包络(has_more=false)。
#[tokio::test]
async fn list_roles_returns_closed_set_single_page() {
    let (_s, sa) = start().await;
    let v = expect_json(sa.get(ROLES).await, StatusCode::OK).await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), RoleName::ALL.len(), "{v}");
    for r in RoleName::ALL {
        let item = items
            .iter()
            .find(|i| i["name"] == r.as_str())
            .unwrap_or_else(|| panic!("目录缺 {}: {v}", r.as_str()));
        assert!(
            Uuid::parse_str(item["id"].as_str().unwrap()).is_ok(),
            "id 应是 uuid: {item}"
        );
        assert_eq!(item["display_name"], r.display_name());
    }
    assert_eq!(v["page_info"]["mode"], "cursor");
    assert_eq!(v["page_info"]["has_more"], false);
    assert_eq!(v["page_info"]["next_cursor"], Value::Null);

    // 带分页参数也照返全量(参数被接受但不真分页)
    let v2 = expect_json(sa.get(&format!("{ROLES}?size=1")).await, StatusCode::OK).await;
    assert_eq!(v2["items"].as_array().unwrap().len(), RoleName::ALL.len());
}

// ───────────────────────────── 3. 建号 ─────────────────────────────

/// 建号 → 201 + 完整视图;新号 display_name/avatar 为 null、email 未验证;
/// 之后 GET 详情一致,且能用这组凭据在**前台登录**(跨模块:管理员建号 → 认证)。
#[tokio::test]
async fn create_user_then_front_login_with_new_password() {
    let (s, sa) = start().await;
    let v = create(&sa, "neo", Some("neo@x.test"), "matrix123", &["user"]).await;
    let id = v["id"].as_str().unwrap().to_owned();
    assert!(Uuid::parse_str(&id).is_ok(), "{v}");
    assert_eq!(v["username"], "neo");
    assert_eq!(v["email"], "neo@x.test");
    assert_eq!(v["email_verified"], false);
    assert_eq!(v["roles"], json!(["user"]));
    assert_eq!(v["display_name"], Value::Null);
    assert_eq!(v["avatar_url"], Value::Null);
    assert!(v["created_at"].is_string(), "{v}");
    assert!(
        v.get("password").is_none() && v.get("password_hash").is_none(),
        "不应回显密码: {v}"
    );

    let got = expect_json(sa.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(got["username"], "neo");
    assert_eq!(got["roles"], json!(["user"]));

    // 前台登录:用户名 / 邮箱都行;错密码 401
    let c = s.login("neo", "matrix123").await;
    let me = expect_json(c.get(FRONT_ME).await, StatusCode::OK).await;
    assert_eq!(me["username"], "neo");
    assert_eq!(me["roles"], json!(["user"]));
    s.login("neo@x.test", "matrix123").await;
    assert_eq!(
        front_login_status(&s, "neo", "wrong-password").await,
        StatusCode::UNAUTHORIZED
    );
    // user 角色没有 admin:login → 后台登录 403
    expect_error(
        s.anon()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "neo", "password": "matrix123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 建带 admin 角色的号 → 能登后台;不带角色(roles=[])→ roles 为空、前台照常能登。
#[tokio::test]
async fn create_with_admin_role_can_login_admin_and_no_roles_is_empty() {
    let (s, sa) = start().await;
    create(&sa, "ops", None, "opspass", &["admin"]).await;
    let ops = s.login_admin("ops", "opspass").await;
    let me = expect_json(ops.get("/api/v1/admin/auth/me").await, StatusCode::OK).await;
    assert_eq!(me["username"], "ops");
    // 但 admin 角色仍够不到用户管理
    expect(ops.get(USERS).await, StatusCode::FORBIDDEN).await;

    let v = create(&sa, "bare", None, "barepass", &[]).await;
    assert_eq!(v["roles"], json!([]));
    let c = s.login("bare", "barepass").await;
    assert_eq!(
        expect_json(c.get(FRONT_ME).await, StatusCode::OK).await["roles"],
        json!([])
    );
}

/// 重复的角色 id 去重(响应与落库一致,不回显两份)。
#[tokio::test]
async fn create_dedups_repeated_role_ids() {
    let (_s, sa) = start().await;
    let ids = role_ids(&sa, &["admin", "admin", "user"]).await;
    let v = expect_json(
        sa.post_json(
            USERS,
            &json!({ "username": "dup-roles", "email": null, "password": "secret1", "roles": ids }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(sorted_roles(&v), vec!["admin", "user"], "{v}");
    let id = v["id"].as_str().unwrap();
    let got = expect_json(sa.get(&user_url(id)).await, StatusCode::OK).await;
    assert_eq!(sorted_roles(&got), vec!["admin", "user"], "{got}");
}

/// 建号错误分支:重名 / 重邮箱 409;未知角色 id、空用户名、超长用户名、非法邮箱、短密码 422;
/// 缺字段 / 非法 JSON 400 —— 全是统一错误体,且失败不留半态(不会建出号)。
#[tokio::test]
async fn create_user_error_cases() {
    let (s, sa) = start().await;
    let body = |username: &str, email: Value, password: &str, roles: Value| json!({ "username": username, "email": email, "password": password, "roles": roles });
    // 409:与 seed 账号撞名;与 seed superadmin 撞邮箱
    expect_error(
        sa.post_json(USERS, &body(USER, Value::Null, "secret1", json!([])))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        sa.post_json(
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
    for b in &cases {
        expect_error(
            sa.post_json(USERS, b).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    // 未知角色 id 夹在合法 id 中间也整单拒(原子)
    let mut mixed = role_ids(&sa, &["user"]).await;
    mixed.push(NIL.to_owned());
    expect_error(
        sa.post_json(USERS, &body("half", Value::Null, "secret1", json!(mixed)))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    // 400:缺 roles 字段、roles 里不是 uuid、非法 JSON
    expect_error(
        sa.post_json(
            USERS,
            &json!({ "username": "noroles", "email": null, "password": "secret1" }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.post_json(
            USERS,
            &body("badid", Value::Null, "secret1", json!(["admin"])),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let resp = sa
        .req(Method::POST, USERS)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    expect_error(resp, StatusCode::BAD_REQUEST, "bad_request").await;

    // 以上全部失败 → 只剩 seed 的 3 个号;失败的用户名也登不进
    let v = list(&sa, "").await;
    assert_eq!(v["page_info"]["total"], 3, "失败的建号不应留下数据: {v}");
    for name in ["ghost", "half", "shortpw", "fresh"] {
        assert_eq!(
            front_login_status(&s, name, "secret1").await,
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
    let (_s, sa) = start().await;
    let v = list(&sa, "").await;
    assert_eq!(v["page_info"]["mode"], "offset");
    assert_eq!(v["page_info"]["page"], 1);
    assert_eq!(v["page_info"]["size"], 20);
    assert_eq!(v["page_info"]["total"], 3);
    assert_eq!(v["page_info"]["total_pages"], 1);
    let names: HashSet<String> = usernames(&v).into_iter().collect();
    assert_eq!(
        names,
        [SUPERADMIN, ADMIN, USER]
            .iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>()
    );
    let row = |name: &str| {
        v["items"]
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
    create_id(&sa, "newest", &[]).await;
    assert_eq!(usernames(&list(&sa, "").await)[0], "newest");
    let asc = usernames(&list(&sa, "order=asc").await);
    assert_eq!(asc.last().unwrap(), "newest");
}

/// username 过滤:子串 + 大小写不敏感;无命中 → 空页 total 0。
#[tokio::test]
async fn list_filter_username_substring_case_insensitive() {
    let (_s, sa) = start().await;
    for n in ["alice", "bob", "carol"] {
        create_id(&sa, n, &["user"]).await;
    }
    let v = list(&sa, "username=A&sort_by=username&order=asc").await;
    assert_eq!(usernames(&v), vec!["admin", "alice", "carol", "superadmin"]);
    assert_eq!(v["page_info"]["total"], 4);
    let v = list(&sa, "username=ADMIN&sort_by=username&order=asc").await;
    assert_eq!(usernames(&v), vec!["admin", "superadmin"]);
    let v = list(&sa, "username=zzz").await;
    assert_eq!(usernames(&v), Vec::<String>::new());
    assert_eq!(v["page_info"]["total"], 0);
}

/// 角色过滤:正选 role(重复 key = 任一)/ 反选 role_not / 二者组合 / 与 username 组合。
#[tokio::test]
async fn list_filter_roles_any_none_and_combined() {
    let (_s, sa) = start().await;
    create_id(&sa, "alice", &["user"]).await;
    create_id(&sa, "bob", &["user", "admin"]).await;
    create_id(&sa, "carol", &["admin"]).await;
    create_id(&sa, "nobody", &[]).await;
    let q = |f: &str| format!("{f}&sort_by=username&order=asc");

    assert_eq!(
        usernames(&list(&sa, &q("role=user")).await),
        vec!["alice", "bob", "user"]
    );
    assert_eq!(
        usernames(&list(&sa, &q("role=admin&role=superadmin")).await),
        vec!["admin", "bob", "carol", "superadmin"]
    );
    assert_eq!(
        usernames(&list(&sa, &q("role_not=user")).await),
        vec!["admin", "carol", "nobody", "superadmin"]
    );
    assert_eq!(
        usernames(&list(&sa, &q("role_not=user&role_not=admin&role_not=superadmin")).await),
        vec!["nobody"],
        "全反选只剩无角色的号"
    );
    assert_eq!(
        usernames(&list(&sa, &q("role=user&role_not=admin")).await),
        vec!["alice", "user"]
    );
    assert_eq!(
        usernames(&list(&sa, &q("role=admin&username=o")).await),
        vec!["bob", "carol"]
    );
    let v = list(&sa, "role=superadmin").await;
    assert_eq!(v["page_info"]["total"], 1);

    // 不在闭集的角色名 → 400(query 反序列化失败,统一错误体)
    expect_error(
        sa.get(&format!("{USERS}?role=editor")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 创建时间区间过滤(RFC3339,闭区间)。
#[tokio::test]
async fn list_filter_created_range() {
    let (_s, sa) = start().await;
    let v = list(&sa, "created_from=2000-01-01T00:00:00Z").await;
    assert_eq!(v["page_info"]["total"], 3);
    let v = list(&sa, "created_from=2999-01-01T00:00:00Z").await;
    assert_eq!(v["page_info"]["total"], 0);
    let v = list(&sa, "created_to=2000-01-01T00:00:00Z").await;
    assert_eq!(v["page_info"]["total"], 0);
    let v = list(
        &sa,
        "created_from=2000-01-01T00:00:00Z&created_to=2999-01-01T00:00:00Z",
    )
    .await;
    assert_eq!(v["page_info"]["total"], 3);

    // 用某个号自己的 created_at 当两端 → 恰好命中它(闭区间)
    let created = create(&sa, "pinpoint", None, "secret1", &[]).await;
    let at = created["created_at"].as_str().unwrap().replace('+', "%2B");
    let v = list(&sa, &format!("created_from={at}&created_to={at}")).await;
    assert_eq!(usernames(&v), vec!["pinpoint"], "{v}");

    // 非法时间 → 400
    expect_error(
        sa.get(&format!("{USERS}?created_from=yesterday")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 排序:username asc/desc、email asc(null 排在有值之后)、created_at;未知排序字段 → 400。
#[tokio::test]
async fn list_sort_by_username_email_created_at() {
    let (_s, sa) = start().await;
    create(&sa, "zed", Some("a@x.test"), "secret1", &[]).await;
    create(&sa, "amy", Some("z@x.test"), "secret1", &[]).await;

    assert_eq!(
        usernames(&list(&sa, "sort_by=username&order=asc").await),
        vec!["admin", "amy", "superadmin", "user", "zed"]
    );
    assert_eq!(
        usernames(&list(&sa, "sort_by=username&order=desc").await),
        vec!["zed", "user", "superadmin", "amy", "admin"]
    );

    let v = list(&sa, "sort_by=email&order=asc").await;
    let emails: Vec<Value> = v["items"]
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
        "{v}"
    );
    assert!(emails[3..].iter().all(Value::is_null), "无邮箱的排后: {v}");
    let v = list(&sa, "sort_by=email&order=desc").await;
    assert_eq!(v["items"][0]["email"], "z@x.test", "{v}");

    // created_at 显式 asc:最早的是 seed 账号,最后建的 amy 在末尾
    let asc = usernames(&list(&sa, "sort_by=created_at&order=asc").await);
    assert_eq!(asc.last().unwrap(), "amy");
    assert_eq!(asc[3], "zed");

    expect_error(
        sa.get(&format!("{USERS}?sort_by=password")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.get(&format!("{USERS}?order=sideways")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// offset 分页:page/size/total/total_pages;越界页空;with_total=false 不算 total;size 越界 clamp。
#[tokio::test]
async fn list_offset_pagination() {
    let (_s, sa) = start().await;
    for n in ["u1", "u2"] {
        create_id(&sa, n, &[]).await;
    }
    // 共 5 个号,按 username 升序:admin, superadmin, u1, u2, user
    let q = "sort_by=username&order=asc&size=2";
    let p1 = list(&sa, &format!("{q}&page=1")).await;
    assert_eq!(usernames(&p1), vec!["admin", "superadmin"]);
    assert_eq!(p1["page_info"]["total"], 5);
    assert_eq!(p1["page_info"]["total_pages"], 3);
    assert_eq!(p1["page_info"]["size"], 2);
    let p2 = list(&sa, &format!("{q}&page=2")).await;
    assert_eq!(usernames(&p2), vec!["u1", "u2"]);
    assert_eq!(p2["page_info"]["page"], 2);
    let p3 = list(&sa, &format!("{q}&page=3")).await;
    assert_eq!(usernames(&p3), vec!["user"]);
    let p9 = list(&sa, &format!("{q}&page=9")).await;
    assert_eq!(usernames(&p9), Vec::<String>::new());
    assert_eq!(p9["page_info"]["total"], 5);

    let no_total = list(&sa, &format!("{q}&page=1&with_total=false")).await;
    assert_eq!(no_total["page_info"]["total"], Value::Null);
    assert_eq!(usernames(&no_total).len(), 2);

    // size clamp 到 [1,100];page=0 视为第 1 页
    let v = list(&sa, "size=0").await;
    assert_eq!(v["page_info"]["size"], 1);
    assert_eq!(usernames(&v).len(), 1);
    let v = list(&sa, "size=1000").await;
    assert_eq!(v["page_info"]["size"], 100);
    let v = list(&sa, "page=0&size=2&sort_by=username&order=asc").await;
    assert_eq!(v["page_info"]["page"], 1);
    assert_eq!(usernames(&v), vec!["admin", "superadmin"]);

    // 类型不对 → 400
    expect_error(
        sa.get(&format!("{USERS}?page=abc")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// cursor 分页(默认排序):空 cursor = 首页;逐页走完覆盖全部、无重复、末页 has_more=false;可与过滤组合。
#[tokio::test]
async fn list_cursor_pagination_walks_all() {
    let (_s, sa) = start().await;
    for n in ["c1", "c2", "c3", "c4"] {
        create_id(&sa, n, &["user"]).await;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;
    loop {
        let v = list(&sa, &format!("cursor={cursor}&size=3")).await;
        assert_eq!(v["page_info"]["mode"], "cursor", "{v}");
        assert_eq!(v["page_info"]["limit"], 3);
        assert!(
            v["page_info"].get("total").is_none(),
            "cursor 模式不带 total: {v}"
        );
        seen.extend(usernames(&v));
        pages += 1;
        if v["page_info"]["has_more"] == true {
            cursor = v["page_info"]["next_cursor"].as_str().unwrap().to_owned();
        } else {
            assert_eq!(v["page_info"]["next_cursor"], Value::Null);
            break;
        }
        assert!(pages < 10, "cursor 翻页不收敛");
    }
    assert_eq!(pages, 3, "7 个号每页 3 → 3 页");
    assert_eq!(seen.len(), 7);
    assert_eq!(
        seen.iter().collect::<HashSet<_>>().len(),
        7,
        "不应重复: {seen:?}"
    );
    assert_eq!(seen[0], "c4", "默认 created_at desc:最新的在首页首位");

    // 与过滤组合:role=user 共 5 个,size=4 → 首页 4 条且 has_more
    let v = list(&sa, "cursor=&size=4&role=user").await;
    assert_eq!(usernames(&v).len(), 4);
    assert_eq!(v["page_info"]["has_more"], true);
    let next = v["page_info"]["next_cursor"].as_str().unwrap().to_owned();
    let v = list(&sa, &format!("cursor={next}&size=4&role=user")).await;
    assert_eq!(usernames(&v).len(), 1);
    assert_eq!(v["page_info"]["has_more"], false);
}

/// 分页参数冲突 / 非法:cursor + 非默认排序 → 422;page + cursor → 422;坏 cursor → 400。
#[tokio::test]
async fn list_pagination_param_errors() {
    let (_s, sa) = start().await;
    for q in [
        "cursor=&sort_by=username",
        "cursor=&order=asc",
        "cursor=&sort_by=created_at&order=asc",
        "page=1&cursor=",
        "page=1&cursor=xxx",
    ] {
        expect_error(
            sa.get(&format!("{USERS}?{q}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    // 显式写出默认排序(created_at desc)可以配 cursor
    let v = list(&sa, "cursor=&sort_by=created_at&order=desc").await;
    assert_eq!(v["page_info"]["mode"], "cursor");

    expect_error(
        sa.get(&format!("{USERS}?cursor=!!!bad")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 内存模式无 search 投影后端:q(非空白)/ sort_by=display_name → 422;纯空白 q 视为未搜索 → 200。
#[tokio::test]
async fn list_without_search_backend_rejects_q_and_display_name_sort() {
    let (_s, sa) = start().await;
    for q in ["q=admin", "sort_by=display_name", "q=a&sort_by=username"] {
        expect_error(
            sa.get(&format!("{USERS}?{q}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    let v = list(&sa, "q=%20%20").await;
    assert_eq!(v["page_info"]["total"], 3);
    let v = list(&sa, "q=").await;
    assert_eq!(v["page_info"]["total"], 3);
}

// ───────────────────────────── 5. 详情 ─────────────────────────────

/// 详情:200 带富化;不存在 404;路径不是 uuid → 400。
#[tokio::test]
async fn get_user_found_missing_and_bad_id() {
    let (_s, sa) = start().await;
    let id = find_id(&sa, SUPERADMIN).await;
    let v = expect_json(sa.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(v["id"], id.as_str());
    assert_eq!(v["username"], SUPERADMIN);
    assert_eq!(v["email"], "superadmin@local");
    assert_eq!(v["roles"], json!(["superadmin"]));
    assert_eq!(v["display_name"], "Super Admin");
    assert!(v["created_at"].is_string());

    expect_error(
        sa.get(&user_url(&Uuid::now_v7().to_string())).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.get(&user_url("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── 6. 改身份 ─────────────────────────────

/// PUT 全量:改名 + 邮箱 → 200 且持久;email=null 清空;改名后新名能登、旧名不能(会话凭据跟着变)。
#[tokio::test]
async fn update_user_full_replace_and_relogin_by_new_name() {
    let (s, sa) = start().await;
    let id = create_id(&sa, "gina", &["user"]).await;
    let url = user_url(&id);
    let v = expect_json(
        sa.put_json(&url, &json!({ "username": "gina2", "email": "g@x.test" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["id"], id.as_str());
    assert_eq!(v["username"], "gina2");
    assert_eq!(v["email"], "g@x.test");
    assert_eq!(v["email_verified"], false);
    assert_eq!(v["roles"], json!(["user"]), "改身份不动角色");
    let got = expect_json(sa.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], "gina2");
    assert_eq!(got["email"], "g@x.test");

    s.login("gina2", "password123").await;
    s.login("g@x.test", "password123").await;
    assert_eq!(
        front_login_status(&s, "gina", "password123").await,
        StatusCode::UNAUTHORIZED
    );

    // email=null 清空;同名同邮箱(自己的)不算冲突
    let v = expect_json(
        sa.put_json(&url, &json!({ "username": "gina2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["email"], Value::Null);
    expect(
        sa.put_json(&url, &json!({ "username": "gina2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
}

/// 改身份错误分支:撞名 / 撞邮箱 409;空名 / 非法邮箱 422;缺字段 400;不存在 404;坏 id 400。
#[tokio::test]
async fn update_user_error_cases() {
    let (_s, sa) = start().await;
    let id = create_id(&sa, "hank", &["user"]).await;
    let url = user_url(&id);
    expect_error(
        sa.put_json(&url, &json!({ "username": ADMIN, "email": null }))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        sa.put_json(
            &url,
            &json!({ "username": "hank", "email": "superadmin@local" }),
        )
        .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    for b in [
        json!({ "username": "", "email": null }),
        json!({ "username": "x".repeat(101), "email": null }),
        json!({ "username": "hank", "email": "nope" }),
    ] {
        expect_error(
            sa.put_json(&url, &b).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        sa.put_json(&url, &json!({ "email": null })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.put_json(
            &user_url(&Uuid::now_v7().to_string()),
            &json!({ "username": "ghost", "email": null }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.put_json(&user_url("123"), &json!({ "username": "x", "email": null }))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    // 全部失败 → 原样
    let got = expect_json(sa.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], "hank");
    assert_eq!(got["email"], Value::Null);
}

// ───────────────────────────── 7. 删号 ─────────────────────────────

/// 软删 → 204 空 body;之后详情 404、再删 404、列表里没了、登录 401、旧会话 refresh 401;
/// 用户名释放(可再建同名号)。
#[tokio::test]
async fn delete_user_soft_deletes_and_kills_login() {
    let (s, sa) = start().await;
    let id = create_id(&sa, "doomed", &["user"]).await;
    let session = s.login("doomed", "password123").await;
    expect(session.post_empty(REFRESH).await, StatusCode::OK).await;

    let body = expect(sa.delete(&user_url(&id)).await, StatusCode::NO_CONTENT).await;
    assert!(body.is_empty(), "204 不应有 body: {body}");

    expect_error(
        sa.get(&user_url(&id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.delete(&user_url(&id)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let v = list(&sa, "").await;
    assert!(!usernames(&v).contains(&"doomed".to_owned()), "{v}");
    assert_eq!(v["page_info"]["total"], 3);

    assert_eq!(
        front_login_status(&s, "doomed", "password123").await,
        StatusCode::UNAUTHORIZED
    );
    expect(session.post_empty(REFRESH).await, StatusCode::UNAUTHORIZED).await;

    // 已删号的其它写操作也是 404
    expect_error(
        sa.put_json(
            &user_url(&id),
            &json!({ "username": "zombie", "email": null }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.put_json(&format!("{}/roles", user_url(&id)), &json!({ "roles": [] }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.post_json(
            &format!("{}/password", user_url(&id)),
            &json!({ "new_password": "revive1" }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

    // 用户名释放:再建同名号是个新 id
    let again = create_id(&sa, "doomed", &[]).await;
    assert_ne!(again, id);
}

/// 删号错误分支:不存在 404;坏 id 400;**删自己** 409(自锁)。
#[tokio::test]
async fn delete_user_missing_bad_id_and_self_is_409() {
    let (s, sa) = start().await;
    expect_error(
        sa.delete(&user_url(&Uuid::now_v7().to_string())).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.delete(&user_url("nope")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;

    let me = find_id(&sa, SUPERADMIN).await;
    expect_error(
        sa.delete(&user_url(&me)).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    // 自己还在、还能登
    expect(sa.get(&user_url(&me)).await, StatusCode::OK).await;
    s.login_admin(SUPERADMIN, PASSWORD).await;
}

// ───────────────────────────── 8. 设角色 ─────────────────────────────

/// 全量替换角色:设 [admin,user] → 200;再设 [] 清空;改动反映在后续登录(能否进后台)。
#[tokio::test]
async fn set_roles_full_replace_affects_next_login() {
    let (s, sa) = start().await;
    let id = create_id(&sa, "promo", &["user"]).await;
    let url = format!("{}/roles", user_url(&id));
    // 还没 admin 角色 → 后台登录 403
    expect(
        s.anon()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "promo", "password": "password123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
    )
    .await;

    let ids = role_ids(&sa, &["admin", "user"]).await;
    let v = expect_json(
        sa.put_json(&url, &json!({ "roles": ids })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["id"], id.as_str());
    assert_eq!(sorted_roles(&v), vec!["admin", "user"]);
    let got = expect_json(sa.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(sorted_roles(&got), vec!["admin", "user"]);
    s.login_admin("promo", "password123").await;

    // 全量替换(不是追加):只给 admin → user 角色没了
    let ids = role_ids(&sa, &["admin"]).await;
    let v = expect_json(
        sa.put_json(&url, &json!({ "roles": ids })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(sorted_roles(&v), vec!["admin"]);

    // 清空
    let v = expect_json(
        sa.put_json(&url, &json!({ "roles": [] })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["roles"], json!([]));
    expect(
        s.anon()
            .post_json(
                ADMIN_LOGIN,
                &json!({ "identifier": "promo", "password": "password123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
    )
    .await;
    // 列表的角色过滤也跟着变
    assert!(!usernames(&list(&sa, "role=admin").await).contains(&"promo".to_owned()));
}

/// 设角色错误分支:未知角色 id 422(原子,不留半态);不存在 404;坏 body 400。
#[tokio::test]
async fn set_roles_error_cases() {
    let (_s, sa) = start().await;
    let id = create_id(&sa, "roleuser", &["user"]).await;
    let url = format!("{}/roles", user_url(&id));
    let mut ids = role_ids(&sa, &["admin"]).await;
    ids.push(NIL.to_owned());
    expect_error(
        sa.put_json(&url, &json!({ "roles": ids })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    let got = expect_json(sa.get(&user_url(&id)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!(["user"]), "失败不应留半态");

    expect_error(
        sa.put_json(
            &format!("{}/roles", user_url(&Uuid::now_v7().to_string())),
            &json!({ "roles": [] }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.put_json(&url, &json!({ "roles": "admin" })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.put_json(&url, &json!({})).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

/// 自锁:改**自己**的角色不能丢 users:admin(409);保留 superadmin 再加别的可以;
/// 未知角色 id 先报 422(不被自锁 409 抢先)。
#[tokio::test]
async fn set_own_roles_must_keep_users_admin() {
    let (s, sa) = start().await;
    let me = find_id(&sa, SUPERADMIN).await;
    let url = format!("{}/roles", user_url(&me));
    let admin_only = role_ids(&sa, &["admin"]).await;
    expect_error(
        sa.put_json(&url, &json!({ "roles": admin_only })).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        sa.put_json(&url, &json!({ "roles": [] })).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        sa.put_json(&url, &json!({ "roles": [NIL] })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    let got = expect_json(sa.get(&user_url(&me)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!(["superadmin"]), "被拒后角色不变");

    let keep = role_ids(&sa, &["superadmin", "user"]).await;
    let v = expect_json(
        sa.put_json(&url, &json!({ "roles": keep })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(sorted_roles(&v), vec!["superadmin", "user"]);
    // 仍是超管
    let again = s.login_admin(SUPERADMIN, PASSWORD).await;
    expect(again.get(USERS).await, StatusCode::OK).await;
}

// ───────────────────────────── 9. 重置密码 ─────────────────────────────

/// 重置密码 → 204;旧密码登不进、新密码能登;**既有会话被撤**(refresh 401)。
#[tokio::test]
async fn reset_password_switches_password_and_revokes_sessions() {
    let (s, sa) = start().await;
    let user_id = find_id(&sa, USER).await;
    let old_session = s.login(USER, PASSWORD).await;
    expect(old_session.post_empty(REFRESH).await, StatusCode::OK).await;

    let body = expect(
        sa.post_json(
            &format!("{}/password", user_url(&user_id)),
            &json!({ "new_password": "brand-new-1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(body.is_empty(), "204 不应有 body: {body}");

    assert_eq!(
        front_login_status(&s, USER, PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );
    let fresh = s.login(USER, "brand-new-1").await;
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
    let (s, sa) = start().await;
    let me = find_id(&sa, SUPERADMIN).await;
    expect(
        sa.post_json(
            &format!("{}/password", user_url(&me)),
            &json!({ "new_password": "rotated-1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.login_admin(SUPERADMIN, "rotated-1").await;
    assert_eq!(
        front_login_status(&s, SUPERADMIN, PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );
}

/// 重置密码错误分支:短密码 422(且旧密码仍有效);不存在 404;缺字段 400;坏 id 400。
#[tokio::test]
async fn reset_password_error_cases() {
    let (s, sa) = start().await;
    let user_id = find_id(&sa, USER).await;
    let url = format!("{}/password", user_url(&user_id));
    expect_error(
        sa.post_json(&url, &json!({ "new_password": "ab" })).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    s.login(USER, PASSWORD).await; // 没改成

    expect_error(
        sa.post_json(
            &format!("{}/password", user_url(&Uuid::now_v7().to_string())),
            &json!({ "new_password": "secret1" }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        sa.post_json(&url, &json!({ "password": "secret1" })).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.post_json(
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
    Policy::from_roles([
        ("superadmin".to_owned(), Perm::ALL.to_vec()),
        ("admin".to_owned(), vec![Perm::AdminLogin]),
        ("user".to_owned(), vec![]),
        (
            "useradmin".to_owned(),
            vec![Perm::AdminLogin, Perm::UsersAdmin],
        ),
    ])
}

/// 起服务(中间管理员策略)→ (服务, superadmin 会话, 中间管理员会话)。
async fn start_escalation() -> (TestServer, Client, Client) {
    let s = TestServer::start_with(|st| st.policy = Arc::new(escalation_policy())).await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    let ua = s.bearer(&mint(Uuid::now_v7(), "useradmin", &["useradmin"], vec![]));
    (s, sa, ua)
}

/// 中间管理员能读(列表 / 详情 / 角色目录),但对 superadmin 的四个写操作全 403,
/// 且 superadmin 毫发无损(原密码能登、名字/角色不变、没被删)。
#[tokio::test]
async fn intermediate_admin_cannot_touch_superadmin() {
    let (s, sa, ua) = start_escalation().await;
    expect(ua.get(USERS).await, StatusCode::OK).await;
    expect(ua.get(ROLES).await, StatusCode::OK).await;
    let victim = find_id(&ua, SUPERADMIN).await;
    let url = user_url(&victim);
    expect(ua.get(&url).await, StatusCode::OK).await;

    let user_role = role_ids(&ua, &["user"]).await;
    expect_error(
        ua.post_json(
            &format!("{url}/password"),
            &json!({ "new_password": "pwned123" }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        ua.put_json(&url, &json!({ "username": "hijacked", "email": null }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        ua.put_json(&format!("{url}/roles"), &json!({ "roles": user_role }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(ua.delete(&url).await, StatusCode::FORBIDDEN, "forbidden").await;

    let got = expect_json(sa.get(&url).await, StatusCode::OK).await;
    assert_eq!(got["username"], SUPERADMIN);
    assert_eq!(got["roles"], json!(["superadmin"]));
    s.login_admin(SUPERADMIN, PASSWORD).await;
}

/// 对同级/更低权目标,中间管理员四个写操作照常放行(闸别收成谁都改不了)。
#[tokio::test]
async fn intermediate_admin_can_manage_lower_users() {
    let (s, sa, ua) = start_escalation().await;
    let plain = create_id(&sa, "plain", &["user"]).await;
    let url = user_url(&plain);
    let v = expect_json(
        ua.put_json(&url, &json!({ "username": "plain2", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["username"], "plain2");
    let ids = role_ids(&ua, &["user", "admin"]).await;
    let v = expect_json(
        ua.put_json(&format!("{url}/roles"), &json!({ "roles": ids }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(sorted_roles(&v), vec!["admin", "user"]);
    expect(
        ua.post_json(
            &format!("{url}/password"),
            &json!({ "new_password": "reset-ok" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.login("plain2", "reset-ok").await;
    expect(ua.delete(&url).await, StatusCode::NO_CONTENT).await;
    expect(sa.get(&url).await, StatusCode::NOT_FOUND).await;
}

/// 授出去的角色也闸:中间管理员不能建 superadmin 号、不能把别人升成 superadmin(403,不落库);
/// 建 / 授自己够得着的角色照常。
#[tokio::test]
async fn intermediate_admin_cannot_grant_superadmin() {
    let (_s, sa, ua) = start_escalation().await;
    let super_role = role_ids(&ua, &["superadmin"]).await;
    expect_error(
        ua.post_json(
            USERS,
            &json!({ "username": "sneaky", "email": null, "password": "secret1", "roles": super_role }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    assert!(
        !usernames(&list(&sa, "username=sneaky").await).contains(&"sneaky".to_owned()),
        "被拒的建号不应落库"
    );

    let plain = create_id(&ua, "plain", &["user"]).await;
    let mut with_super = role_ids(&ua, &["user"]).await;
    with_super.extend(super_role.clone());
    expect_error(
        ua.put_json(
            &format!("{}/roles", user_url(&plain)),
            &json!({ "roles": with_super }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let got = expect_json(sa.get(&user_url(&plain)).await, StatusCode::OK).await;
    assert_eq!(got["roles"], json!(["user"]), "被拒后角色不变");

    // superadmin 自己授 superadmin 恒过
    let v = expect_json(
        sa.put_json(
            &format!("{}/roles", user_url(&plain)),
            &json!({ "roles": super_role }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["roles"], json!(["superadmin"]));
    // 现在 plain 是超管了 → 中间管理员反过来动不了它
    expect_error(
        ua.delete(&user_url(&plain)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// seed 策略下的提权闸(scope 收窄的超管令牌 = 非满权主体):授 / 动带权限的角色 → 403,
/// 不带权限的操作照常。验证闸看的是 role ∩ scope,而不只是 role。
#[tokio::test]
async fn scoped_superadmin_token_cannot_grant_or_touch_beyond_scope() {
    let (s, sa) = start().await;
    let narrow = s.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &[SUPERADMIN],
        vec![Perm::AdminLogin, Perm::UsersAdmin],
    ));
    let user_role = role_ids(&sa, &["user"]).await;
    // 授 user 角色(含 widgets:read 等,scope 外)→ 403
    expect_error(
        narrow
            .post_json(
                USERS,
                &json!({ "username": "scoped", "email": null, "password": "secret1", "roles": user_role }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 不授角色 → 201
    let v = expect_json(
        narrow
            .post_json(
                USERS,
                &json!({ "username": "scoped", "email": null, "password": "secret1", "roles": [] }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    let bare = v["id"].as_str().unwrap().to_owned();
    // 目标 seed user 持 scope 外的权 → 改密 403;无角色的号 → 204
    let seed_user = find_id(&sa, USER).await;
    expect_error(
        narrow
            .post_json(
                &format!("{}/password", user_url(&seed_user)),
                &json!({ "new_password": "pwned123" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    s.login(USER, PASSWORD).await; // 没被改
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

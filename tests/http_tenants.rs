//! 平台租户管理 + 租户成员管理的**黑盒 HTTP 验收测试**(spec §4.5 / §4.6 / §4.3):
//! 平台管理员(平台角色 superadmin → `tenants:admin`)建 / 改名 / 停用租户、管理任意租户的成员;
//! 租户管理员(当前租户里有 `members:read` / `members:admin`)按用户名把已有账号加进本租户、设租户角色、移出;
//! 停用租户 / 移出成员立即吊销相关会话(refresh 401);别的租户的成员一律 404。
//!
//! covers: GET /api/v1/admin/platform/tenants
//! covers: POST /api/v1/admin/platform/tenants
//! covers: GET /api/v1/admin/platform/tenants/{id}
//! covers: PUT /api/v1/admin/platform/tenants/{id}
//! covers: GET /api/v1/admin/platform/tenants/{id}/members
//! covers: PUT /api/v1/admin/platform/tenants/{id}/members/{user_id}
//! covers: DELETE /api/v1/admin/platform/tenants/{id}/members/{user_id}
//! covers: GET /api/v1/admin/auth/members
//! covers: POST /api/v1/admin/auth/members
//! covers: PUT /api/v1/admin/auth/members/{user_id}/roles
//! covers: DELETE /api/v1/admin/auth/members/{user_id}

mod http_support;

use http_support::{
    expect, expect_error, expect_json, member_token, Client, TestServer, ADMIN, DEFAULT_TENANT,
    PASSWORD, SUPERADMIN, USER,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

const TENANTS: &str = "/api/v1/admin/platform/tenants";
const MEMBERS: &str = "/api/v1/admin/auth/members";
const USERS: &str = "/api/v1/admin/auth/users";
const REFRESH: &str = "/api/v1/public/auth/refresh";
const SWITCH: &str = "/api/v1/frontend/auth/switch-tenant";
const PERMS_ME: &str = "/api/v1/frontend/permissions/me";

// ───────────────────────────── 帮手 ─────────────────────────────

/// 平台管理员建租户(断言 201),返回租户 id。
async fn create_tenant(superadmin: &Client, slug: &str, name: &str) -> Uuid {
    let tenant = expect_json(
        superadmin
            .post_json(TENANTS, &json!({ "slug": slug, "name": name }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(tenant["slug"], slug, "{tenant}");
    assert_eq!(tenant["name"], name, "{tenant}");
    assert_eq!(tenant["status"], "active", "{tenant}");
    tenant["id"].as_str().unwrap().parse().unwrap()
}

/// 平台管理员建账号(不授平台角色,密码 `pwd123`),返回 user id。
async fn create_account(superadmin: &Client, username: &str, email: Option<&str>) -> Uuid {
    let account = expect_json(
        superadmin
            .post_json(
                USERS,
                &json!({ "username": username, "email": email, "password": "pwd123", "roles": [] }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    account["id"].as_str().unwrap().parse().unwrap()
}

fn member_path(tenant: Uuid, user: Uuid) -> String {
    format!("{TENANTS}/{tenant}/members/{user}")
}

/// 成员列表(`items`)里的用户名(排序后)。
fn member_names(list: &Value) -> Vec<String> {
    let mut names: Vec<String> = list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items 应是数组: {list}"))
        .iter()
        .map(|m| m["username"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

/// 成员列表里某人那一行。
fn member_row<'a>(list: &'a Value, username: &str) -> &'a Value {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["username"] == username)
        .unwrap_or_else(|| panic!("成员列表里没有 {username}: {list}"))
}

// ───────────────────────────── 平台:租户 ─────────────────────────────

/// 平台管理员:建租户 → 列表 / 详情可见 → PUT 全量(改名 + 停用)→ 恢复;slug 重复 409、不合法 422、
/// 不存在 404;租户管理员碰不到平台接口(403)。
#[tokio::test]
async fn platform_admin_creates_and_suspends_tenant() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;

    let id = create_tenant(&superadmin, "acme", "Acme").await;
    let list = expect_json(superadmin.get(TENANTS).await, StatusCode::OK).await;
    let slugs: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["slug"].as_str().unwrap())
        .collect();
    assert!(
        slugs.contains(&"default") && slugs.contains(&"acme"),
        "{list}"
    );

    let got = expect_json(
        superadmin.get(&format!("{TENANTS}/{id}")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(got["id"], id.to_string());
    assert_eq!(got["slug"], "acme");

    // PUT 全量:改名 + 停用
    let tenant = expect_json(
        superadmin
            .put_json(
                &format!("{TENANTS}/{id}"),
                &json!({ "name": "Acme Inc", "status": "suspended" }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(tenant["name"], "Acme Inc");
    assert_eq!(tenant["status"], "suspended");
    assert_eq!(tenant["slug"], "acme", "slug 不可改");
    // 恢复
    let tenant = expect_json(
        superadmin
            .put_json(
                &format!("{TENANTS}/{id}"),
                &json!({ "name": "Acme Inc", "status": "active" }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(tenant["status"], "active");

    // slug 已占用 → 409;不合法 → 422;状态不在闭集 → 4xx
    expect_error(
        superadmin
            .post_json(TENANTS, &json!({ "slug": "acme", "name": "Dup" }))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    for bad in ["Bad Slug", "", "-x", "UPPER"] {
        expect_error(
            superadmin
                .post_json(TENANTS, &json!({ "slug": bad, "name": "x" }))
                .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    let response = superadmin
        .put_json(
            &format!("{TENANTS}/{id}"),
            &json!({ "name": "x", "status": "deleted" }),
        )
        .await;
    assert!(response.status().is_client_error(), "{}", response.status());

    // 不存在 → 404
    let ghost = Uuid::now_v7();
    expect_error(
        superadmin.get(&format!("{TENANTS}/{ghost}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .put_json(
                &format!("{TENANTS}/{ghost}"),
                &json!({ "name": "x", "status": "active" }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

    // 租户管理员(默认租户 admin,无平台角色)→ 平台接口一律 403
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    expect_error(admin.get(TENANTS).await, StatusCode::FORBIDDEN, "forbidden").await;
    expect_error(
        admin
            .post_json(TENANTS, &json!({ "slug": "mine", "name": "Mine" }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        admin.get(&format!("{TENANTS}/{id}/members")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 平台管理员管理任意租户的成员:PUT 不存在则加入 / 存在则全量设角色,平台角色 422,
/// 列表只列该租户的成员,DELETE 移出(再删 404),租户不存在 404。
#[tokio::test]
async fn platform_admin_manages_any_tenant_members() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let acme = create_tenant(&superadmin, "acme", "Acme").await;
    let carol = create_account(&superadmin, "carol", None).await;

    // 新租户还没有成员
    let members = expect_json(
        superadmin.get(&format!("{TENANTS}/{acme}/members")).await,
        StatusCode::OK,
    )
    .await;
    assert!(member_names(&members).is_empty(), "{members}");

    // 指定第一个管理员:不存在则加入
    let member = expect_json(
        superadmin
            .put_json(&member_path(acme, carol), &json!({ "roles": ["admin"] }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member["id"], carol.to_string());
    assert_eq!(member["username"], "carol");
    assert_eq!(member["roles"], json!(["admin"]));
    assert_eq!(member["status"], "active");
    // 已是成员:全量替换角色
    let member = expect_json(
        superadmin
            .put_json(&member_path(acme, carol), &json!({ "roles": ["user"] }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member["roles"], json!(["user"]));
    // 平台角色不能经成员关系授予 → 422
    expect_error(
        superadmin
            .put_json(
                &member_path(acme, carol),
                &json!({ "roles": ["superadmin"] }),
            )
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    let members = expect_json(
        superadmin.get(&format!("{TENANTS}/{acme}/members")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member_names(&members), vec!["carol"]);
    // 默认租户的成员列表里没有 carol(各租户各管各的)
    let members = expect_json(
        superadmin
            .get(&format!("{TENANTS}/{DEFAULT_TENANT}/members"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member_names(&members), vec!["admin", "superadmin", "user"]);

    // 移出;再移 → 404
    expect(
        superadmin.delete(&member_path(acme, carol)).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect_error(
        superadmin.delete(&member_path(acme, carol)).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    // 不存在的账号 / 租户 → 404
    expect_error(
        superadmin
            .put_json(&member_path(acme, Uuid::now_v7()), &json!({ "roles": [] }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let ghost = Uuid::now_v7();
    expect_error(
        superadmin.get(&format!("{TENANTS}/{ghost}/members")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        superadmin
            .put_json(&member_path(ghost, carol), &json!({ "roles": [] }))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 停用租户 → 该租户里的会话**立即吊销**(spec §4.6):停用期间 refresh 401;**恢复租户后**停用前的旧会话
/// 仍然 refresh 401(只有真吊销了才会这样 —— refresh 本身会重查成员关系和租户状态,恢复后那道检查已经放行);
/// 同一个人在别的租户的会话不受影响。
#[tokio::test]
async fn suspended_tenant_member_cannot_refresh() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let beta = create_tenant(&superadmin, "beta", "Beta").await;
    let user_id = {
        let me = expect_json(
            server
                .login(USER, PASSWORD)
                .await
                .get("/api/v1/frontend/auth/me")
                .await,
            StatusCode::OK,
        )
        .await;
        let id: Uuid = me["id"].as_str().unwrap().parse().unwrap();
        id
    };
    expect(
        superadmin
            .put_json(&member_path(beta, user_id), &json!({ "roles": ["user"] }))
            .await,
        StatusCode::OK,
    )
    .await;

    // 两个会话在 beta(in_beta 停用期间不碰,专门验恢复后旧会话仍失效;probe 验停用期间 401),一个留在默认租户
    let in_beta = server.login(USER, PASSWORD).await;
    expect(
        in_beta
            .post_json(SWITCH, &json!({ "tenant_id": beta }))
            .await,
        StatusCode::OK,
    )
    .await;
    let probe = server.login(USER, PASSWORD).await; // 登录默认进最近用过的 beta
    assert_eq!(
        expect_json(probe.get(PERMS_ME).await, StatusCode::OK).await["tenant"]["id"],
        beta.to_string()
    );
    // 登录默认进最近用过的租户(刚切过的 beta)→ 显式切回默认租户
    let in_default = server.login(USER, PASSWORD).await;
    expect(
        in_default
            .post_json(SWITCH, &json!({ "tenant_id": DEFAULT_TENANT }))
            .await,
        StatusCode::OK,
    )
    .await;
    expect(in_beta.post_empty(REFRESH).await, StatusCode::OK).await;

    expect(
        superadmin
            .put_json(
                &format!("{TENANTS}/{beta}"),
                &json!({ "name": "Beta", "status": "suspended" }),
            )
            .await,
        StatusCode::OK,
    )
    .await;

    expect_error(
        probe.post_empty(REFRESH).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    // 默认租户里的会话照常
    expect(in_default.post_empty(REFRESH).await, StatusCode::OK).await;
    let permissions = expect_json(in_default.get(PERMS_ME).await, StatusCode::OK).await;
    assert_eq!(permissions["tenant"]["id"], DEFAULT_TENANT.to_string());
    // 停用的租户切不进去
    expect_error(
        in_default
            .post_json(SWITCH, &json!({ "tenant_id": beta }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;

    // 恢复租户:成员关系和租户状态都又有效了,但停用前发出的会话已被吊销 → 旧 refresh 仍 401
    expect(
        superadmin
            .put_json(
                &format!("{TENANTS}/{beta}"),
                &json!({ "name": "Beta", "status": "active" }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    expect_error(
        in_beta.post_empty(REFRESH).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    // 对照:恢复后新进入 beta 是可以的(401 只能是吊销造成的)
    expect(
        in_default
            .post_json(SWITCH, &json!({ "tenant_id": beta }))
            .await,
        StatusCode::OK,
    )
    .await;
    expect(in_default.post_empty(REFRESH).await, StatusCode::OK).await;
}

// ───────────────────────────── 租户管理员:成员 ─────────────────────────────

/// 租户管理员按**完整用户名**把已有账号加进本租户(精确匹配,邮箱不算),授租户角色;
/// 加进来的人登录就在这个租户里;重复加 409;授平台角色 422;改角色 PUT 全量。
#[tokio::test]
async fn tenant_admin_adds_member_by_username() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    // 账号由平台管理员建(建号时不属于任何租户)
    let carol = create_account(&superadmin, "carol", Some("carol@example.com")).await;

    let admin = server.login_admin(ADMIN, PASSWORD).await;
    let before = expect_json(admin.get(MEMBERS).await, StatusCode::OK).await;
    assert_eq!(member_names(&before), vec!["admin", "superadmin", "user"]);
    assert_eq!(member_row(&before, "user")["roles"], json!(["user"]));

    // 邮箱不算用户名:精确匹配用户名才行
    expect_error(
        admin
            .post_json(
                MEMBERS,
                &json!({ "username": "carol@example.com", "roles": ["user"] }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "account_not_found",
    )
    .await;
    // 平台角色不能经成员关系授予 → 422
    expect_error(
        admin
            .post_json(
                MEMBERS,
                &json!({ "username": "carol", "roles": ["superadmin"] }),
            )
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    let member = expect_json(
        admin
            .post_json(MEMBERS, &json!({ "username": "carol", "roles": ["user"] }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(member["id"], carol.to_string());
    assert_eq!(member["username"], "carol");
    assert_eq!(member["email"], "carol@example.com");
    assert_eq!(member["roles"], json!(["user"]));
    assert_eq!(member["status"], "active");

    // 已是成员 → 409
    expect_error(
        admin
            .post_json(MEMBERS, &json!({ "username": "carol", "roles": [] }))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    let after = expect_json(admin.get(MEMBERS).await, StatusCode::OK).await;
    assert_eq!(
        member_names(&after),
        vec!["admin", "carol", "superadmin", "user"]
    );

    // carol 登录直接进默认租户,角色 user
    let carol_client = server.login("carol", "pwd123").await;
    let permissions = expect_json(carol_client.get(PERMS_ME).await, StatusCode::OK).await;
    assert_eq!(
        permissions["tenant"]["id"],
        DEFAULT_TENANT.to_string(),
        "{permissions}"
    );
    assert_eq!(permissions["tenant_roles"], json!(["user"]));

    // PUT 全量设角色
    let member = expect_json(
        admin
            .put_json(
                &format!("{MEMBERS}/{carol}/roles"),
                &json!({ "roles": ["admin"] }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member["roles"], json!(["admin"]));
    // 刷新后 carol 拿到新角色
    expect(carol_client.post_empty(REFRESH).await, StatusCode::OK).await;
    let permissions = expect_json(carol_client.get(PERMS_ME).await, StatusCode::OK).await;
    assert_eq!(permissions["tenant_roles"], json!(["admin"]));

    // 改自己的角色不能把自己的成员管理权弄没(锁死)→ 409
    let me = member_row(&after, ADMIN)["id"].as_str().unwrap().to_owned();
    expect_error(
        admin
            .put_json(
                &format!("{MEMBERS}/{me}/roles"),
                &json!({ "roles": ["user"] }),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    // 无搜索后端(内存模式)时 q → 422(同账号列表口径)
    expect_error(
        admin.get(&format!("{MEMBERS}?q=car")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;

    // 普通成员(无 members:read、无 admin:login)→ 403
    let user_token = member_token(Uuid::now_v7(), USER, &[USER], vec![]);
    expect_error(
        server.bearer(&user_token).get(MEMBERS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 查不到的用户名 → 404 `account_not_found`(不建号:租户管理员不能新建账号)。
#[tokio::test]
async fn unknown_username_is_404() {
    let server = TestServer::start().await;
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    expect_error(
        admin
            .post_json(MEMBERS, &json!({ "username": "nobody", "roles": ["user"] }))
            .await,
        StatusCode::NOT_FOUND,
        "account_not_found",
    )
    .await;
    // 没有因此多出账号 / 成员
    let members = expect_json(admin.get(MEMBERS).await, StatusCode::OK).await;
    assert_eq!(member_names(&members), vec!["admin", "superadmin", "user"]);
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let users = expect_json(
        superadmin.get(&format!("{USERS}?username=nobody")).await,
        StatusCode::OK,
    )
    .await;
    assert!(users["items"].as_array().unwrap().is_empty(), "{users}");
}

/// 租户管理员只管本租户:别的租户的成员(id 存在)改角色 / 移出一律 404,也不出现在本租户列表里;
/// 同时属于两个租户的人,从本租户移出不影响他在另一个租户的成员关系。
#[tokio::test]
async fn tenant_admin_cannot_touch_other_tenant_members() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let other = create_tenant(&superadmin, "other", "Other").await;
    let dave = create_account(&superadmin, "dave", None).await;
    let erin = create_account(&superadmin, "erin", None).await;
    for who in [dave, erin] {
        expect(
            superadmin
                .put_json(&member_path(other, who), &json!({ "roles": ["admin"] }))
                .await,
            StatusCode::OK,
        )
        .await;
    }

    let admin = server.login_admin(ADMIN, PASSWORD).await;
    let members = expect_json(admin.get(MEMBERS).await, StatusCode::OK).await;
    assert!(
        !member_names(&members).contains(&"dave".to_owned()),
        "{members}"
    );
    expect_error(
        admin
            .put_json(
                &format!("{MEMBERS}/{dave}/roles"),
                &json!({ "roles": ["user"] }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        admin.delete(&format!("{MEMBERS}/{dave}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

    // erin 也加进默认租户,再从默认租户移出:other 里的成员关系不动
    expect(
        admin
            .post_json(MEMBERS, &json!({ "username": "erin", "roles": ["user"] }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    expect(
        admin.delete(&format!("{MEMBERS}/{erin}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    let members = expect_json(
        superadmin.get(&format!("{TENANTS}/{other}/members")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(member_names(&members), vec!["dave", "erin"]);
    assert_eq!(
        member_row(&members, "dave")["roles"],
        json!(["admin"]),
        "other 里 dave 的角色没被改"
    );

    // 请求里塞 tenant_id 也没用:租户只从 token 来
    expect_error(
        admin
            .delete(&format!("{MEMBERS}/{dave}?tenant_id={other}"))
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 移出成员 → 他在该租户的会话**立即吊销**(spec §4.6):移出期间 refresh 401;**重新加回后**移出前的旧会话
/// 仍然 refresh 401(refresh 会重查成员关系,加回后那道检查已放行,只有真吊销了才会 401);不能移出自己(409)。
#[tokio::test]
async fn removed_member_sessions_revoked() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    let carol = create_account(&superadmin, "carol", None).await;
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    expect(
        admin
            .post_json(MEMBERS, &json!({ "username": "carol", "roles": ["user"] }))
            .await,
        StatusCode::CREATED,
    )
    .await;

    // carol_client 在移出期间不碰(专门验加回后旧会话仍失效);probe 验移出期间 401
    let carol_client = server.login("carol", "pwd123").await;
    expect(carol_client.post_empty(REFRESH).await, StatusCode::OK).await;
    let probe = server.login("carol", "pwd123").await;

    expect(
        admin.delete(&format!("{MEMBERS}/{carol}")).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect_error(
        probe.post_empty(REFRESH).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    let members = expect_json(admin.get(MEMBERS).await, StatusCode::OK).await;
    assert!(
        !member_names(&members).contains(&"carol".to_owned()),
        "{members}"
    );
    // 再移 → 404
    expect_error(
        admin.delete(&format!("{MEMBERS}/{carol}")).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;

    // 不能把自己移出本租户
    let me = member_row(&members, ADMIN)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    expect_error(
        admin.delete(&format!("{MEMBERS}/{me}")).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    // 重新加回:成员关系又有效了,但移出前的旧会话已被吊销 → 旧 refresh 仍 401
    expect(
        admin
            .post_json(MEMBERS, &json!({ "username": "carol", "roles": ["user"] }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    expect_error(
        carol_client.post_empty(REFRESH).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    // 对照:重新登录可以进默认租户(401 只能是吊销造成的)
    let again = server.login("carol", "pwd123").await;
    assert_eq!(
        expect_json(again.get(PERMS_ME).await, StatusCode::OK).await["tenant"]["id"],
        DEFAULT_TENANT.to_string()
    );
}

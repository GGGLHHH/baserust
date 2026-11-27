//! 多租户认证边界的**黑盒 HTTP 验收测试**:登录进默认租户、我的租户列表、切换租户、
//! 缺租户 → 403 `tenant_required`、平台角色不给租户级权限、`/permissions/me` 带当前租户、注册加入默认租户、
//! 后台登录挑有后台权限的租户(没有 → 平台上下文 / 403)。
//!
//! covers: GET /api/v1/frontend/auth/tenants
//! covers: POST /api/v1/frontend/auth/switch-tenant

mod http_support;

use http_support::{
    expect, expect_error, expect_json, mint, superadmin_token, Client, TestServer, ADMIN,
    DEFAULT_TENANT, PASSWORD, SUPERADMIN, USER,
};
use reqwest::{Response, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;

const PERMS_ME: &str = "/api/v1/frontend/permissions/me";
const TENANTS: &str = "/api/v1/frontend/auth/tenants";
const SWITCH: &str = "/api/v1/frontend/auth/switch-tenant";
const WIDGETS: &str = "/api/v1/frontend/widgets";
const ADMIN_LOGIN: &str = "/api/v1/admin/auth/login";
const ACCOUNTS: &str = "/api/v1/admin/auth/users";
const MEMBERS: &str = "/api/v1/admin/auth/members";

async fn permissions_me(client: &Client) -> Value {
    expect_json(client.get(PERMS_ME).await, StatusCode::OK).await
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("应是数组: {value}"))
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

/// 我的租户列表里按 slug 找租户 id。
async fn tenant_id(client: &Client, slug: &str) -> Uuid {
    let list = expect_json(client.get(TENANTS).await, StatusCode::OK).await;
    let tenant = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["slug"] == slug)
        .unwrap_or_else(|| panic!("我的租户里没有 {slug}: {list}"));
    tenant["id"].as_str().unwrap().parse().unwrap()
}

/// seed 账号登录直接进默认租户(单租户项目登录不多一步):token 带默认租户和其中的租户角色。
#[tokio::test]
async fn login_enters_default_tenant() {
    let server = TestServer::start().await;
    for (who, role) in [(USER, "user"), (ADMIN, "admin"), (SUPERADMIN, "admin")] {
        let client = server.login(who, PASSWORD).await;
        let me = permissions_me(&client).await;
        assert_eq!(
            me["tenant"]["id"],
            DEFAULT_TENANT.to_string(),
            "{who}: {me}"
        );
        assert_eq!(me["tenant_roles"], json!([role]), "{who}: {me}");
        // 租户级业务接口照常可用
        expect(client.get(WIDGETS).await, StatusCode::OK).await;
    }
    // 后台登录同样进默认租户,准入看有效权限(默认租户 admin 有 admin:login)
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    expect(admin.get("/api/v1/admin/auth/me").await, StatusCode::OK).await;
}

/// `GET /permissions/me` 带当前租户 { id, slug, name };平台上下文 → null。
#[tokio::test]
async fn permissions_me_includes_tenant() {
    let server = TestServer::start().await;
    let client = server.login(USER, PASSWORD).await;
    let me = permissions_me(&client).await;
    assert_eq!(
        me["tenant"],
        json!({ "id": DEFAULT_TENANT, "slug": "default", "name": "默认组织" })
    );
    assert_eq!(me["roles"], json!([]), "user 没有平台角色");
    assert!(strings(&me["permissions"]).contains(&"widgets:read".to_owned()));

    // 平台上下文令牌:tenant = null,租户角色为空
    let platform = server.bearer(&mint(Uuid::now_v7(), "p", &[], None, &[], vec![]));
    let me = permissions_me(&platform).await;
    assert!(me["tenant"].is_null(), "{me}");
    assert_eq!(me["tenant_roles"], json!([]));
    assert_eq!(me["permissions"], json!([]));
}

/// 我的租户:列出有效成员关系(id / slug / name / 我的角色 / 是否当前),单租户账号只有一条。
#[tokio::test]
async fn tenants_lists_my_memberships() {
    let server = TestServer::start_with_mock("tenancy_mock.toml").await;
    let client = server.login(USER, PASSWORD).await;
    let list = expect_json(client.get(TENANTS).await, StatusCode::OK).await;
    let mut items: Vec<(String, String, Vec<String>, bool)> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|tenant| {
            (
                tenant["slug"].as_str().unwrap().to_owned(),
                tenant["name"].as_str().unwrap().to_owned(),
                strings(&tenant["roles"]),
                tenant["current"].as_bool().unwrap(),
            )
        })
        .collect();
    items.sort();
    assert_eq!(
        items,
        vec![
            ("acme".into(), "Acme".into(), vec!["admin".into()], false),
            (
                "default".into(),
                "默认组织".into(),
                vec!["user".into()],
                true
            ),
        ]
    );

    // 只属于默认租户的账号只有一条(前端据此隐藏切换器)
    let admin = server.login(ADMIN, PASSWORD).await;
    let list = expect_json(admin.get(TENANTS).await, StatusCode::OK).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["id"], DEFAULT_TENANT.to_string());

    // 未登录 → 401
    expect_error(
        server.anonymous().get(TENANTS).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

/// 切换租户:换会话、写新 cookie,token 的当前租户和租户角色跟着变;refresh 沿用新租户;
/// 下次登录默认进最近用过的那个。
#[tokio::test]
async fn switch_tenant_changes_token_tenant() {
    let server = TestServer::start_with_mock("tenancy_mock.toml").await;
    let client = server.login(USER, PASSWORD).await;
    let acme = tenant_id(&client, "acme").await;

    let response = client
        .post_json(SWITCH, &json!({ "tenant_id": acme }))
        .await;
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("access_token=")),
        "切换应写新 access cookie"
    );
    let switched = expect_json(response, StatusCode::OK).await;
    assert_eq!(switched["username"], USER);

    let me = permissions_me(&client).await;
    assert_eq!(me["tenant"]["id"], acme.to_string());
    assert_eq!(me["tenant"]["slug"], "acme");
    assert_eq!(me["tenant_roles"], json!(["admin"]));
    assert!(
        strings(&me["permissions"]).contains(&"admin:login".to_owned()),
        "在 acme 是 admin → 有后台准入: {me}"
    );
    let list = expect_json(client.get(TENANTS).await, StatusCode::OK).await;
    let current: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["current"] == true)
        .map(|t| t["slug"].as_str().unwrap())
        .collect();
    assert_eq!(current, vec!["acme"]);

    // refresh 沿用会话上的租户
    expect(
        client.post_empty("/api/v1/public/auth/refresh").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        permissions_me(&client).await["tenant"]["id"],
        acme.to_string()
    );

    // 重新登录:进最近用过的 acme;后台登录按 acme 里的 admin 角色准入
    let again = server.login(USER, PASSWORD).await;
    assert_eq!(
        permissions_me(&again).await["tenant"]["id"],
        acme.to_string()
    );
    server.login_admin(USER, PASSWORD).await;

    // 切回默认租户
    expect(
        client
            .post_json(SWITCH, &json!({ "tenant_id": DEFAULT_TENANT }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        permissions_me(&client).await["tenant_roles"],
        json!(["user"])
    );
}

/// 切到自己不是成员的租户 → 403(平台管理员也一样),原会话不动;没有 refresh cookie → 401。
#[tokio::test]
async fn switch_to_foreign_tenant_is_403() {
    let server = TestServer::start_with_mock("tenancy_mock.toml").await;
    let user = server.login(USER, PASSWORD).await;
    let acme = tenant_id(&user, "acme").await;

    for who in [ADMIN, SUPERADMIN] {
        let client = server.login(who, PASSWORD).await;
        expect_error(
            client
                .post_json(SWITCH, &json!({ "tenant_id": acme }))
                .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
        // 原会话照常:仍在默认租户,refresh 也还能用
        assert_eq!(
            permissions_me(&client).await["tenant"]["id"],
            DEFAULT_TENANT.to_string()
        );
        expect(
            client.post_empty("/api/v1/public/auth/refresh").await,
            StatusCode::OK,
        )
        .await;
    }
    // 不存在的租户 → 同样 403(不区分「不存在」和「不是成员」)
    expect_error(
        user.post_json(SWITCH, &json!({ "tenant_id": Uuid::now_v7() }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // Bearer 令牌没有 refresh cookie → 401(切换是换会话)
    let bearer = server.bearer(&superadmin_token(Uuid::now_v7(), vec![]));
    expect_error(
        bearer
            .post_json(SWITCH, &json!({ "tenant_id": acme }))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    // body 不合法 → 422 / 400
    let response = user
        .post_json(SWITCH, &json!({ "tenant_id": "nope" }))
        .await;
    assert!(response.status().is_client_error(), "{}", response.status());
}

/// token 没有当前租户(平台上下文)访问租户级接口 → 403 `tenant_required`(不落默认租户、不是 404)。
#[tokio::test]
async fn tenant_route_without_tenant_is_403_tenant_required() {
    let server = TestServer::start().await;
    // 有租户角色名、但没有当前租户:租户角色不算
    let no_tenant = server.bearer(&mint(Uuid::now_v7(), "u", &[], None, &["admin"], vec![]));
    for path in [
        WIDGETS,
        "/api/v1/frontend/contents",
        "/api/v1/frontend/profiles/me",
    ] {
        let response = no_tenant.get(path).await;
        if path.ends_with("/profiles/me") {
            // 读自己资料是「仅登录」接口,不要求租户
            expect(response, StatusCode::OK).await;
        } else {
            expect_error(response, StatusCode::FORBIDDEN, "tenant_required").await;
        }
    }
    // 后台组闸(admin:login 是租户级)同样 tenant_required
    expect_error(
        no_tenant.get("/api/v1/admin/auth/me").await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
    // 仅登录、与租户无关的接口照常
    expect(no_tenant.get(TENANTS).await, StatusCode::OK).await;
}

/// 平台角色(superadmin)不自动获得任何租户级权限:不在租户里时只有平台级权限,
/// 租户级接口 403 `tenant_required`;在租户里但没有租户角色 → 403。
#[tokio::test]
async fn platform_role_grants_no_tenant_perms() {
    let server = TestServer::start().await;
    let platform_only = server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &[SUPERADMIN],
        None,
        &[],
        vec![],
    ));
    let me = permissions_me(&platform_only).await;
    assert_eq!(me["roles"], json!(["superadmin"]));
    assert_eq!(
        me["permissions"],
        json!([
            "audit:read",
            "ops:read",
            "platform:roles",
            "profiles:read",
            "profiles:write",
            "profiles:write:all",
            "tenants:admin",
            "users:admin"
        ]),
        "只有平台级(资料全局一份,profiles:* 也是平台级;含 superadmin 独占的 ops / audit / platform:roles): {me}"
    );
    expect_error(
        platform_only.get(WIDGETS).await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;

    // 在默认租户里、但没有任何租户角色:平台角色不顶替租户角色
    let in_tenant_no_role = server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &[SUPERADMIN],
        Some(DEFAULT_TENANT),
        &[],
        vec![],
    ));
    expect_error(
        in_tenant_no_role.get(WIDGETS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let me = permissions_me(&in_tenant_no_role).await;
    assert_eq!(
        me["permissions"],
        json!([
            "audit:read",
            "ops:read",
            "platform:roles",
            "profiles:read",
            "profiles:write",
            "profiles:write:all",
            "tenants:admin",
            "users:admin"
        ]),
        "{me}"
    );
    // 平台管理员不属于任何租户也能进后台(凭平台级权限),但后台里的租户级接口照样 tenant_required
    expect(
        platform_only.get("/api/v1/admin/auth/users").await,
        StatusCode::OK,
    )
    .await;

    // 反过来:租户角色 admin 拿不到平台级 users:admin
    let tenant_admin = server.bearer(&mint(
        Uuid::now_v7(),
        ADMIN,
        &[],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    ));
    let me = permissions_me(&tenant_admin).await;
    assert!(!strings(&me["permissions"]).contains(&"users:admin".to_owned()));
    // 把租户角色名塞进平台角色也没用(有没有当前租户都一样)
    let smuggled = server.bearer(&mint(Uuid::now_v7(), ADMIN, &[ADMIN], None, &[], vec![]));
    assert_eq!(permissions_me(&smuggled).await["permissions"], json!([]));
    let smuggled_in_tenant = server.bearer(&mint(
        Uuid::now_v7(),
        ADMIN,
        &[ADMIN],
        Some(DEFAULT_TENANT),
        &[],
        vec![],
    ));
    assert_eq!(
        permissions_me(&smuggled_in_tenant).await["permissions"],
        json!([])
    );
    expect_error(
        smuggled_in_tenant.get(WIDGETS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

/// 公开注册:自动加入默认租户、角色 user,注册完就在默认租户里(spec §4.5)。
#[tokio::test]
async fn register_joins_default_tenant() {
    let server = TestServer::start().await;
    let client = server.anonymous();
    expect(
        client
            .post_json(
                "/api/v1/public/auth/register",
                &json!({ "username": "newbie", "password": "secret1" }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    let me = permissions_me(&client).await;
    assert_eq!(me["tenant"]["id"], DEFAULT_TENANT.to_string());
    assert_eq!(me["tenant_roles"], json!(["user"]));
    expect(client.get(WIDGETS).await, StatusCode::OK).await;
}

/// 切换租户只认**同一个人**的会话:refresh cookie 属于 A、当前身份(access token)是 B → 401,
/// A 的会话不动(防拿别人的 refresh cookie 借道切换)。
#[tokio::test]
async fn switch_tenant_rejects_refresh_session_of_another_user() {
    let server = TestServer::start_with_mock("tenancy_mock.toml").await;
    // A = user:拿到它的 refresh cookie 原值
    let login = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/api/v1/public/auth/login", server.base))
        .json(&json!({ "identifier": USER, "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    let refresh = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix("refresh_token="))
        .map(|v| v.split(';').next().unwrap().to_owned())
        .expect("登录应写 refresh cookie");
    expect(login, StatusCode::OK).await;
    let client_a = server.login(USER, PASSWORD).await;
    let acme = tenant_id(&client_a, "acme").await;

    // B = admin 的 access token(Bearer)+ A 的 refresh cookie(无 access cookie,身份取 Bearer)
    let b_token = mint(
        Uuid::now_v7(),
        ADMIN,
        &[],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    );
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}{SWITCH}", server.base))
        .bearer_auth(&b_token)
        .header("cookie", format!("refresh_token={refresh}"))
        .json(&json!({ "tenant_id": acme }))
        .send()
        .await
        .unwrap();
    expect_error(response, StatusCode::UNAUTHORIZED, "unauthorized").await;

    // A 的那个会话没被吊销:拿同一个 refresh cookie 还能续
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/api/v1/public/auth/refresh", server.base))
        .header("cookie", format!("refresh_token={refresh}"))
        .send()
        .await
        .unwrap();
    expect(response, StatusCode::OK).await;
}

// ── 后台登录挑租户(spec §4.2:准入看「当前租户角色或平台角色里有后台权限」)──

/// 后台登录请求(不断言状态),返回原始响应。
async fn post_admin_login(client: &Client, who: &str, password: &str) -> Response {
    client
        .post_json(
            ADMIN_LOGIN,
            &json!({ "identifier": who, "password": password }),
        )
        .await
}

/// 平台管理员建一个全局账号(不属于任何租户),`platform_roles` 是平台角色名,密码 `secret1`。
async fn create_account(superadmin: &Client, username: &str, platform_roles: &[&str]) {
    let catalog = expect_json(
        superadmin.get("/api/v1/admin/auth/roles").await,
        StatusCode::OK,
    )
    .await;
    let ids: Vec<Value> = platform_roles
        .iter()
        .map(|name| {
            catalog["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == *name)
                .unwrap_or_else(|| panic!("角色目录缺 {name}: {catalog}"))["id"]
                .clone()
        })
        .collect();
    expect(
        superadmin
            .post_json(
                ACCOUNTS,
                &json!({ "username": username, "password": "secret1", "roles": ids }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
}

/// 最近用过的租户里没有后台权限、别的租户里有 → 后台登录进有后台权限的那个(按 last_used_at 倒序挑第一个);
/// 前台登录不受影响,仍进最近用过的租户。
#[tokio::test]
async fn admin_login_picks_tenant_with_admin_access() {
    let server = TestServer::start_with_mock("tenancy_mock.toml").await;
    // user:默认租户里是 user(无 admin:login),acme 里是 admin。切回默认租户 → 最近用过的 = 默认租户。
    let client = server.login(USER, PASSWORD).await;
    let acme = tenant_id(&client, "acme").await;
    expect(
        client
            .post_json(SWITCH, &json!({ "tenant_id": DEFAULT_TENANT }))
            .await,
        StatusCode::OK,
    )
    .await;
    let front = server.login(USER, PASSWORD).await;
    assert_eq!(
        permissions_me(&front).await["tenant"]["id"],
        DEFAULT_TENANT.to_string(),
        "前台登录仍进最近用过的租户"
    );

    let admin_session = server.anonymous();
    expect(
        post_admin_login(&admin_session, USER, PASSWORD).await,
        StatusCode::OK,
    )
    .await;
    let me = permissions_me(&admin_session).await;
    assert_eq!(me["tenant"]["id"], acme.to_string(), "{me}");
    assert_eq!(me["tenant_roles"], json!(["admin"]), "{me}");
    expect(
        admin_session.get("/api/v1/admin/auth/me").await,
        StatusCode::OK,
    )
    .await;
}

/// 没有任何有效成员关系、也没有平台权限的账号后台登录 → 403 `tenant_required`(前端据此显示「还没加入任何组织」),
/// 不发 cookie。前台登录照常(平台上下文)。
#[tokio::test]
async fn admin_login_without_any_membership_is_tenant_required() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    create_account(&superadmin, "lonely", &[]).await;

    let client = server.anonymous();
    let response = post_admin_login(&client, "lonely", "secret1").await;
    assert!(
        response.headers().get("set-cookie").is_none(),
        "被拒不应发 cookie"
    );
    expect_error(response, StatusCode::FORBIDDEN, "tenant_required").await;
    expect(
        client.get("/api/v1/admin/auth/me").await,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let front = server.login("lonely", "secret1").await;
    assert!(permissions_me(&front).await["tenant"].is_null());
}

/// 有成员关系、但哪个租户里都没有后台权限(也没有平台权限)→ 403 `forbidden`,不发 cookie。
#[tokio::test]
async fn admin_login_member_without_admin_anywhere_is_forbidden() {
    let server = TestServer::start().await;
    let client = server.anonymous();
    let response = post_admin_login(&client, USER, PASSWORD).await;
    assert!(
        response.headers().get("set-cookie").is_none(),
        "被拒不应发 cookie"
    );
    expect_error(response, StatusCode::FORBIDDEN, "forbidden").await;
    expect(
        client.get("/api/v1/admin/auth/me").await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// 平台管理员不属于任何租户 → 后台登录进平台上下文(tenant 为空);他所在的租户里都没有后台权限时同样进平台上下文,
/// 平台接口可用、租户级接口 `tenant_required`。
#[tokio::test]
async fn platform_admin_without_membership_enters_platform_context() {
    let server = TestServer::start().await;
    let superadmin = server.login_admin(SUPERADMIN, PASSWORD).await;
    create_account(&superadmin, "ops", &["platform_admin"]).await;

    let client = server.anonymous();
    expect(
        post_admin_login(&client, "ops", "secret1").await,
        StatusCode::OK,
    )
    .await;
    let me = permissions_me(&client).await;
    assert!(me["tenant"].is_null(), "{me}");
    assert_eq!(me["roles"], json!(["platform_admin"]), "{me}");
    expect(client.get(ACCOUNTS).await, StatusCode::OK).await;
    expect_error(
        client.get("/api/v1/admin/widgets").await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;

    // 加进默认租户当普通成员(user 没有 admin:login):仍进平台上下文,不进那个没有后台权限的租户
    expect(
        superadmin
            .post_json(MEMBERS, &json!({ "username": "ops", "roles": ["user"] }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    let client = server.anonymous();
    expect(
        post_admin_login(&client, "ops", "secret1").await,
        StatusCode::OK,
    )
    .await;
    assert!(permissions_me(&client).await["tenant"].is_null());
}

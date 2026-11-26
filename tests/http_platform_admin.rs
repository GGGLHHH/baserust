//! 平台管理员(`platform_admin`)与 superadmin 独占权限的**黑盒 HTTP 验收测试**(2026-11-26 角色补充):
//! - superadmin 独占:运维(系统监控 `ops:read`)、认证审计(`audit:read`)、任命 / 撤销平台管理员(`platform:roles`);
//! - 平台管理员:组织管理 + 普通账号管理都能做,但碰不到持有平台角色的账号(superadmin / 其他平台管理员);
//! - superadmin 只由 seed 声明:任何接口都授不出、也撤不掉;
//! - 防接管:组织成员接口(平台 / 组织内)改角色 / 移出持平台角色的账号同样要 `platform:roles`。
//!
//! 平台管理员都经真实接口产生:superadmin 后台登录 → 角色目录取 `platform_admin` → 建号授予 → 该账号后台登录。

mod http_support;

use std::sync::{Arc, Mutex};

use baserust::features::users::UserAdminService;
use http_support::{
    expect, expect_error, expect_json, Client, TestServer, ADMIN, PASSWORD, SUPERADMIN, USER,
};
use reqwest::StatusCode;
use serde_json::json;

const USERS: &str = "/api/v1/admin/auth/users";
const ROLES: &str = "/api/v1/admin/auth/roles";
const TENANTS: &str = "/api/v1/admin/platform/tenants";
const MEMBERS: &str = "/api/v1/admin/auth/members";
const PERMS_ME: &str = "/api/v1/frontend/permissions/me";
const DEFAULT_TENANT: &str = "00000000-0000-0000-0000-000000000001";

// ───────────────────────────── 帮手 ─────────────────────────────

/// 起服务 + superadmin 后台会话。
async fn start() -> (TestServer, Client) {
    let s = TestServer::start().await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    (s, sa)
}

/// 角色目录(`GET /roles`)里的角色名。
async fn catalog_names(c: &Client) -> Vec<String> {
    let v = expect_json(c.get(ROLES).await, StatusCode::OK).await;
    v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items 应是数组: {v}"))
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect()
}

/// 目录里某角色的 id(目录里没有 → panic)。
async fn role_id(c: &Client, name: &str) -> String {
    let v = expect_json(c.get(ROLES).await, StatusCode::OK).await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("角色目录缺 {name}: {v}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// 建号(断言 201),返回 id。`role_ids` 是角色 id。
async fn create_account(c: &Client, username: &str, role_ids: &[String]) -> String {
    let v = expect_json(
        c.post_json(
            USERS,
            &json!({ "username": username, "email": null, "password": "pwd123", "roles": role_ids }),
        )
        .await,
        StatusCode::CREATED,
    )
    .await;
    v["id"].as_str().unwrap().to_owned()
}

/// superadmin 任命一个平台管理员(建号授 platform_admin),返回 (id, 该账号的后台会话)。
async fn appoint(s: &TestServer, sa: &Client, username: &str) -> (String, Client) {
    let pa_role = role_id(sa, "platform_admin").await;
    let id = create_account(sa, username, &[pa_role]).await;
    let c = s.login_admin(username, "pwd123").await;
    (id, c)
}

/// 按精确用户名查账号 id。
async fn find_id(c: &Client, username: &str) -> String {
    let v = expect_json(
        c.get(&format!("{USERS}?username={username}&size=100"))
            .await,
        StatusCode::OK,
    )
    .await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["username"] == username)
        .unwrap_or_else(|| panic!("找不到 {username}: {v}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn perms(c: &Client) -> Vec<String> {
    let v = expect_json(c.get(PERMS_ME).await, StatusCode::OK).await;
    v["permissions"]
        .as_array()
        .unwrap_or_else(|| panic!("permissions 应是数组: {v}"))
        .iter()
        .map(|p| p.as_str().unwrap().to_owned())
        .collect()
}

/// 1×1 PNG(后台代传头像用)。
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn avatar_form() -> reqwest::multipart::Form {
    reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(PNG.to_vec())
            .file_name("a.png")
            .mime_str("image/png")
            .unwrap(),
    )
}

fn user_url(id: &str) -> String {
    format!("{USERS}/{id}")
}

/// 对某账号的全部账号管理写操作(改账号信息 / 改资料 / 改角色 / 重置密码 / 删除)都应 403。
async fn assert_account_writes_forbidden(c: &Client, target: &str) {
    let url = user_url(target);
    let cases: Vec<(&str, reqwest::Response)> = vec![
        (
            "改账号信息",
            c.put_json(&url, &json!({ "username": "hijacked", "email": null }))
                .await,
        ),
        (
            "改资料",
            c.put_json(
                &format!("{url}/profile"),
                &json!({ "display_name": "hijacked", "phone": null, "avatar_content_id": null }),
            )
            .await,
        ),
        (
            "改角色",
            c.put_json(&format!("{url}/roles"), &json!({ "roles": [] }))
                .await,
        ),
        (
            "重置密码",
            c.post_json(
                &format!("{url}/password"),
                &json!({ "new_password": "hijacked1" }),
            )
            .await,
        ),
        (
            "代传头像",
            c.post_multipart(&format!("{url}/avatar"), avatar_form())
                .await,
        ),
        ("删除", c.delete(&url).await),
    ];
    for (what, resp) in cases {
        let got = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert_eq!(got, StatusCode::FORBIDDEN, "{what} 应 403,body: {body}");
    }
}

// ───────────────────────────── 测试 ─────────────────────────────

/// 平台管理员:组织管理(建 / 改名 / 停用、指定成员与组织管理员、移出)、普通账号管理(建号 / 改 / 重置密码 / 删除)都能做;
/// 不属于任何组织也能进后台(平台上下文);角色目录里没有可授的平台角色。
#[tokio::test]
async fn platform_admin_can_manage_orgs_and_plain_accounts() {
    let (s, sa) = start().await;
    let (_pa_id, pa) = appoint(&s, &sa, "pa1").await;

    // 平台上下文(不是任何组织的成员)
    let me = expect_json(pa.get(PERMS_ME).await, StatusCode::OK).await;
    assert!(me["tenant"].is_null(), "{me}");

    // 组织:建 / 改名 / 停用 / 恢复
    let v = expect_json(
        pa.post_json(TENANTS, &json!({ "slug": "pa-org", "name": "PA Org" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    let org = v["id"].as_str().unwrap().to_owned();
    for status in ["suspended", "active"] {
        let v = expect_json(
            pa.put_json(
                &format!("{TENANTS}/{org}"),
                &json!({ "name": "PA Org 2", "status": status }),
            )
            .await,
            StatusCode::OK,
        )
        .await;
        assert_eq!(v["status"], status);
    }

    // 普通账号:建号(不带角色)→ 指定为组织管理员 → 改角色 → 移出
    let plain = create_account(&pa, "plain1", &[]).await;
    let member = format!("{TENANTS}/{org}/members/{plain}");
    let v = expect_json(
        pa.put_json(&member, &json!({ "roles": ["admin"] })).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["roles"], json!(["admin"]), "{v}");
    expect_json(
        pa.put_json(&member, &json!({ "roles": ["user"] })).await,
        StatusCode::OK,
    )
    .await;
    expect(pa.delete(&member).await, StatusCode::NO_CONTENT).await;

    // 普通账号的账号管理:读 / 改 / 改资料 / 重置密码 / 设角色(空)/ 删除
    expect_json(pa.get(&user_url(&plain)).await, StatusCode::OK).await;
    expect_json(
        pa.put_json(
            &user_url(&plain),
            &json!({ "username": "plain1b", "email": null }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    expect_json(
        pa.put_json(
            &format!("{}/profile", user_url(&plain)),
            &json!({ "display_name": "Plain", "phone": null, "avatar_content_id": null }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    expect_json(
        pa.post_multipart(&format!("{}/avatar", user_url(&plain)), avatar_form())
            .await,
        StatusCode::OK,
    )
    .await;
    expect(
        pa.post_json(
            &format!("{}/password", user_url(&plain)),
            &json!({ "new_password": "newpass1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect_json(
        pa.put_json(
            &format!("{}/roles", user_url(&plain)),
            &json!({ "roles": [] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    expect(pa.delete(&user_url(&plain)).await, StatusCode::NO_CONTENT).await;

    // seed 的 admin(只在默认组织里是 admin,没有平台角色)= 普通账号:平台管理员能管
    let admin_id = find_id(&pa, ADMIN).await;
    expect(
        pa.post_json(
            &format!("{}/password", user_url(&admin_id)),
            &json!({ "new_password": "newpass1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.login_admin(ADMIN, "newpass1").await;

    // 角色目录:平台管理员没有 platform:roles → 没有可授的平台角色
    assert!(catalog_names(&pa).await.is_empty());
}

/// 系统监控与认证审计是 superadmin 独占:平台管理员 403,且 /permissions/me 里没有 ops:read / audit:read / platform:roles。
#[tokio::test]
async fn platform_admin_cannot_see_monitoring_or_audit() {
    let (s, sa) = start().await;
    let (pa_id, pa) = appoint(&s, &sa, "pa1").await;

    for path in [
        "/api/v1/admin/monitoring".to_owned(),
        "/api/v1/admin/monitoring/history".to_owned(),
        "/api/v1/admin/monitoring/logs".to_owned(),
        "/api/v1/admin/auth/auth-events".to_owned(),
        "/api/v1/admin/auth/auth-events/stats".to_owned(),
        "/api/v1/admin/auth/auth-events/stream".to_owned(),
        format!("{USERS}/{pa_id}/auth-events"),
    ] {
        expect_error(pa.get(&path).await, StatusCode::FORBIDDEN, "forbidden").await;
        // 对照:superadmin 能看(stream 是 SSE 长连接,只看状态码)
        let resp = sa.get(&path).await;
        assert_eq!(resp.status(), StatusCode::OK, "superadmin 应能读 {path}");
    }

    let p = perms(&pa).await;
    for absent in ["ops:read", "audit:read", "platform:roles"] {
        assert!(
            !p.contains(&absent.to_owned()),
            "平台管理员不该有 {absent}: {p:?}"
        );
    }
    for present in ["users:admin", "tenants:admin"] {
        assert!(
            p.contains(&present.to_owned()),
            "平台管理员应有 {present}: {p:?}"
        );
    }
    let p = perms(&sa).await;
    for present in [
        "ops:read",
        "audit:read",
        "platform:roles",
        "users:admin",
        "tenants:admin",
    ] {
        assert!(
            p.contains(&present.to_owned()),
            "superadmin 应有 {present}: {p:?}"
        );
    }
}

/// 平台管理员碰不到 superadmin:改账号信息 / 改资料 / 改角色 / 重置密码 / 删除 → 403;
/// 也不能把 superadmin 移出组织或改他在组织里的角色。superadmin 原样可登录。
#[tokio::test]
async fn platform_admin_cannot_touch_superadmin() {
    let (s, sa) = start().await;
    let (_pa, pa) = appoint(&s, &sa, "pa1").await;
    let sa_id = find_id(&pa, SUPERADMIN).await;

    assert_account_writes_forbidden(&pa, &sa_id).await;
    let member = format!("{TENANTS}/{DEFAULT_TENANT}/members/{sa_id}");
    expect_error(
        pa.put_json(&member, &json!({ "roles": ["user"] })).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(pa.delete(&member).await, StatusCode::FORBIDDEN, "forbidden").await;

    // 什么都没变:superadmin 照旧用原密码登录,仍是默认组织 admin
    let again = s.login_admin(SUPERADMIN, PASSWORD).await;
    let me = expect_json(again.get(PERMS_ME).await, StatusCode::OK).await;
    assert_eq!(me["tenant_roles"], json!(["admin"]), "{me}");
    let v = expect_json(sa.get(&user_url(&sa_id)).await, StatusCode::OK).await;
    assert_eq!(v["username"], SUPERADMIN);
    assert_eq!(v["roles"], json!(["superadmin"]));
}

/// 平台管理员之间互相也碰不到(只有 superadmin 能管平台管理员)。
#[tokio::test]
async fn platform_admin_cannot_touch_other_platform_admin() {
    let (s, sa) = start().await;
    let (_pa1, pa1) = appoint(&s, &sa, "pa1").await;
    let (pa2_id, _pa2) = appoint(&s, &sa, "pa2").await;

    assert_account_writes_forbidden(&pa1, &pa2_id).await;

    // 组织成员接口:pa2 在某组织里时,pa1 改不了他的角色、移不走他
    let v = expect_json(
        sa.post_json(TENANTS, &json!({ "slug": "org2", "name": "Org2" }))
            .await,
        StatusCode::CREATED,
    )
    .await;
    let org = v["id"].as_str().unwrap().to_owned();
    let member = format!("{TENANTS}/{org}/members/{pa2_id}");
    expect_json(
        sa.put_json(&member, &json!({ "roles": ["admin"] })).await,
        StatusCode::OK,
    )
    .await;
    expect_error(
        pa1.put_json(&member, &json!({ "roles": ["user"] })).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        pa1.delete(&member).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;

    // pa2 仍可用原密码登录
    s.login_admin("pa2", "pwd123").await;
}

/// 平台管理员授不出平台管理员(建号带、改角色带都 403);目录里也看不到它。
#[tokio::test]
async fn platform_admin_cannot_grant_platform_admin() {
    let (s, sa) = start().await;
    let (_pa, pa) = appoint(&s, &sa, "pa1").await;
    let pa_role = role_id(&sa, "platform_admin").await; // 拿 superadmin 看得到的 id 去试

    assert!(!catalog_names(&pa)
        .await
        .contains(&"platform_admin".to_owned()));
    expect_error(
        pa.post_json(
            USERS,
            &json!({ "username": "sneaky", "email": null, "password": "pwd123", "roles": [pa_role] }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let plain = create_account(&pa, "plain1", &[]).await;
    expect_error(
        pa.put_json(
            &format!("{}/roles", user_url(&plain)),
            &json!({ "roles": [pa_role] }),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    let v = expect_json(sa.get(&user_url(&plain)).await, StatusCode::OK).await;
    assert_eq!(v["roles"], json!([]), "角色没被改: {v}");
}

/// superadmin 任命 / 撤销平台管理员;被任命的人能进后台管组织,撤销后就没有平台权限了。
#[tokio::test]
async fn superadmin_can_appoint_and_revoke_platform_admin() {
    let (s, sa) = start().await;
    // 目录:superadmin 看得到 platform_admin,看不到 superadmin
    let names = catalog_names(&sa).await;
    assert!(names.contains(&"platform_admin".to_owned()), "{names:?}");
    assert!(!names.contains(&"superadmin".to_owned()), "{names:?}");

    // 任命:先建普通号,再改角色
    let id = create_account(&sa, "cand", &[]).await;
    let pa_role = role_id(&sa, "platform_admin").await;
    let v = expect_json(
        sa.put_json(
            &format!("{}/roles", user_url(&id)),
            &json!({ "roles": [pa_role] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["roles"], json!(["platform_admin"]), "{v}");
    let c = s.login_admin("cand", "pwd123").await;
    expect_json(c.get(TENANTS).await, StatusCode::OK).await;

    // superadmin 能管平台管理员:重置密码
    expect(
        sa.post_json(
            &format!("{}/password", user_url(&id)),
            &json!({ "new_password": "newpass1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;

    // 撤销
    let v = expect_json(
        sa.put_json(&format!("{}/roles", user_url(&id)), &json!({ "roles": [] }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["roles"], json!([]), "{v}");
    // 不是任何组织成员、也没有平台权限 → 后台登录 403 tenant_required
    expect_error(
        s.anon()
            .post_json(
                "/api/v1/admin/auth/login",
                &json!({ "identifier": "cand", "password": "newpass1" }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "tenant_required",
    )
    .await;
    // superadmin 也能删平台管理员
    let (pa2, _) = appoint(&s, &sa, "pa2").await;
    expect(sa.delete(&user_url(&pa2)).await, StatusCode::NO_CONTENT).await;
}

/// superadmin 角色不经任何接口授出 / 撤销(只由 seed 声明):
/// 目录里没有它;拿到它的 id 建号 / 改角色也 403(superadmin 本人去授给别人也一样);superadmin 去掉自己的也 403;
/// 组织成员接口里它不是组织角色 → 422。superadmin 本人能改自己的资料 / 密码,不能删自己。
#[tokio::test]
async fn superadmin_role_never_grantable_via_api() {
    // 从组合根拿到账号管理服务:目录接口不列 superadmin,只有服务层的平台角色目录里查得到它的 id
    let slot: Arc<Mutex<Option<UserAdminService>>> = Arc::default();
    let s = {
        let slot = slot.clone();
        TestServer::start_with(move |st| *slot.lock().unwrap() = Some(st.user_admin.clone())).await
    };
    let svc = slot.lock().unwrap().clone().unwrap();
    let sa_role = svc
        .list_roles()
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name.as_str() == "superadmin")
        .expect("服务层平台角色目录应有 superadmin")
        .id
        .to_string();
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await;
    let (_pa, pa) = appoint(&s, &sa, "pa1").await;

    assert!(!catalog_names(&sa).await.contains(&"superadmin".to_owned()));

    // 建号带 superadmin:superadmin 本人、平台管理员都 403
    for c in [&sa, &pa] {
        expect_error(
            c.post_json(
                USERS,
                &json!({ "username": "second-root", "email": null, "password": "pwd123", "roles": [sa_role] }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    // 改角色授 superadmin:403
    let plain = create_account(&sa, "plain1", &[]).await;
    for c in [&sa, &pa] {
        expect_error(
            c.put_json(
                &format!("{}/roles", user_url(&plain)),
                &json!({ "roles": [sa_role] }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    // superadmin 去掉自己的 superadmin(清空 / 换成平台管理员都不行):403
    let sa_id = find_id(&sa, SUPERADMIN).await;
    let pa_role = role_id(&sa, "platform_admin").await;
    for roles in [json!([]), json!([pa_role])] {
        expect_error(
            sa.put_json(
                &format!("{}/roles", user_url(&sa_id)),
                &json!({ "roles": roles }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    // 保留 superadmin 的改动(再加个平台管理员)不算授出 / 撤销
    expect_json(
        sa.put_json(
            &format!("{}/roles", user_url(&sa_id)),
            &json!({ "roles": [sa_role, pa_role] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    // superadmin 本人可以改自己的资料 / 密码,但不能删自己
    expect_json(
        sa.put_json(
            &format!("{}/profile", user_url(&sa_id)),
            &json!({ "display_name": "Root", "phone": null, "avatar_content_id": null }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    expect(
        sa.post_json(
            &format!("{}/password", user_url(&sa_id)),
            &json!({ "new_password": "newroot1" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    let sa = s.login_admin(SUPERADMIN, "newroot1").await;
    expect_error(
        sa.delete(&user_url(&sa_id)).await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;

    // 组织成员接口:superadmin 不是组织角色 → 422(平台 PUT 与组织内加成员都一样)
    expect_error(
        sa.put_json(
            &format!("{TENANTS}/{DEFAULT_TENANT}/members/{plain}"),
            &json!({ "roles": ["superadmin"] }),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        sa.post_json(
            MEMBERS,
            &json!({ "username": "plain1", "roles": ["superadmin"] }),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

/// 组织成员接口防接管:组织管理员(默认组织 admin)不能把 superadmin 移出组织、也不能改他在组织里的角色
/// (superadmin 在默认组织里也只是 admin,按组织角色比较本来拦不住)。普通成员照常能管。
#[tokio::test]
async fn tenant_admin_cannot_remove_superadmin_from_org() {
    let (s, sa) = start().await;
    let sa_id = find_id(&sa, SUPERADMIN).await;
    let user_id = find_id(&sa, USER).await;
    let admin = s.login_admin(ADMIN, PASSWORD).await;

    expect_error(
        admin
            .put_json(
                &format!("{MEMBERS}/{sa_id}/roles"),
                &json!({ "roles": ["user"] }),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    expect_error(
        admin.delete(&format!("{MEMBERS}/{sa_id}")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 平台管理员在组织里同样受保护;组织管理员也不能按用户名把持平台角色的账号加进来(加进来就移不走)
    let (pa_id, _) = appoint(&s, &sa, "pa1").await;
    expect_error(
        admin
            .post_json(MEMBERS, &json!({ "username": "pa1", "roles": ["user"] }))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
    // 对照:加普通账号照常;查不到的用户名仍是 404(不因闸改变)
    create_account(&sa, "plain-joiner", &[]).await;
    expect_json(
        admin
            .post_json(
                MEMBERS,
                &json!({ "username": "plain-joiner", "roles": ["user"] }),
            )
            .await,
        StatusCode::CREATED,
    )
    .await;
    expect_error(
        admin
            .post_json(
                MEMBERS,
                &json!({ "username": "nobody-here", "roles": ["user"] }),
            )
            .await,
        StatusCode::NOT_FOUND,
        "account_not_found",
    )
    .await;
    // 平台 PUT 成员「加入新组织」仍放行(平台管理员 / superadmin 可以把平台账号加进组织)
    expect_json(
        sa.put_json(
            &format!("{TENANTS}/{DEFAULT_TENANT}/members/{pa_id}"),
            &json!({ "roles": ["user"] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    expect_error(
        admin.delete(&format!("{MEMBERS}/{pa_id}")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;

    // 对照:普通成员照常能改
    expect_json(
        admin
            .put_json(
                &format!("{MEMBERS}/{user_id}/roles"),
                &json!({ "roles": ["admin"] }),
            )
            .await,
        StatusCode::OK,
    )
    .await;
    // superadmin 自己(持 platform:roles)可以改组织里持平台角色的成员
    expect_json(
        sa.put_json(
            &format!("{MEMBERS}/{pa_id}/roles"),
            &json!({ "roles": ["admin"] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    let me = expect_json(
        s.login_admin(SUPERADMIN, PASSWORD)
            .await
            .get(PERMS_ME)
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        me["tenant_roles"],
        json!(["admin"]),
        "superadmin 仍是默认组织 admin: {me}"
    );
}

/// 两个成员列表接口都标出「持平台角色」的成员(看原始平台角色名),前端据此隐藏改角色 / 移出;
/// 写操作的成员响应同样带这个标记。
#[tokio::test]
async fn member_lists_flag_platform_role_holders() {
    let (s, sa) = start().await;
    let (pa_id, _) = appoint(&s, &sa, "pa1").await;
    // 平台管理员加进默认组织(响应即带标记)
    let v = expect_json(
        sa.put_json(
            &format!("{TENANTS}/{DEFAULT_TENANT}/members/{pa_id}"),
            &json!({ "roles": ["user"] }),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["holds_platform_role"], true, "{v}");

    let flags = |v: &serde_json::Value| -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = v["items"]
            .as_array()
            .unwrap_or_else(|| panic!("items 应是数组: {v}"))
            .iter()
            .map(|m| {
                (
                    m["username"].as_str().unwrap().to_owned(),
                    m["holds_platform_role"]
                        .as_bool()
                        .unwrap_or_else(|| panic!("缺 holds_platform_role: {m}")),
                )
            })
            .collect();
        out.sort();
        out
    };
    let expected = vec![
        (ADMIN.to_owned(), false),
        ("pa1".to_owned(), true),
        (SUPERADMIN.to_owned(), true),
        (USER.to_owned(), false),
    ];
    // 平台接口
    let v = expect_json(
        sa.get(&format!("{TENANTS}/{DEFAULT_TENANT}/members?size=100"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(flags(&v), expected);
    // 组织内接口(组织管理员看本组织)
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    let v = expect_json(
        admin.get(&format!("{MEMBERS}?size=100")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(flags(&v), expected);
}

//! 租户管理端点的**黑盒验收**(P6)—— 平台开通 + 租户内成员管理。
//!
//! 用真实 `AppState::new(Mount::Both)`(内存,进程内 seed):seed.toml 给了 acme/globex,
//! `user` 是 Acme 的 tn:admin,`admin`/`superadmin` 是 Acme 的 tn:member。真实 `authenticate`
//! 中间件 + 真实组闸 + 真实端点。
//!
//! 两条授权线各自钉死:
//! - 平台开通(`/admin/auth/tenants`):gate `Perm::TenantsAdmin`(superadmin 专属)——
//!   `admin` 有 admin:login 能进后台,但没 TenantsAdmin → 403。
//! - 自助成员(`/frontend/auth/tenants/members`):gate 活的 tn:admin 检查 ——
//!   `user`(Acme admin)能管;`admin`(Acme member)→ 403。**提权口保持关闭的实证。**

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use tower::ServiceExt;

use baserust::app::{build_router, AppState, Mount};
use baserust::infra::config::Config;

async fn app() -> Router {
    let (state, _bg) = AppState::new(&Config::default(), Mount::Both)
        .await
        .expect("内存模式 AppState(含进程内 seed 租户 + 成员)");
    build_router(state, &Config::default(), Mount::Both)
}

fn set_cookie(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            v.to_str()
                .ok()?
                .strip_prefix(&format!("{name}="))
                .map(|r| r.split(';').next().unwrap().to_owned())
        })
}

/// 登录一个 seed 账号,返回 (access, refresh) cookie。
async fn login(app: &Router, who: &str) -> (String, String) {
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"identifier":"{who}","password":"pwd"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{who} 应能登录");
    (
        set_cookie(&res, "access_token").unwrap(),
        set_cookie(&res, "refresh_token").unwrap(),
    )
}

async fn req(
    app: &Router,
    method: &str,
    uri: &str,
    access: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("access_token={access}"));
    let body = match body {
        Some(json) => {
            b = b.header("content-type", "application/json");
            Body::from(json.to_owned())
        }
        None => Body::empty(),
    };
    let res = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

// ─────────────────────────── 平台开通 ───────────────────────────

/// superadmin 开通一个租户 + 交钥匙给初始 admin,然后能列、能停用。
#[tokio::test]
async fn superadmin_provisions_a_tenant_with_first_admin() {
    let app = app().await;
    let (sa, _) = login(&app, "superadmin").await;

    // 开通 "newco",把 admin 设为它的第一个 tn:admin。
    let (status, tenant) = req(
        &app,
        "POST",
        "/api/v1/admin/auth/tenants",
        &sa,
        Some(r#"{"name":"newco","display_name":"New Co","admin_identifier":"admin"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "开通应 201:{tenant}");
    assert_eq!(tenant["name"], "newco");
    assert_eq!(tenant["status"], "active");
    let new_id = tenant["id"].as_str().unwrap().to_owned();

    // 重名 → 409
    let (dup, _) = req(
        &app,
        "POST",
        "/api/v1/admin/auth/tenants",
        &sa,
        Some(r#"{"name":"newco","display_name":"Dup"}"#),
    )
    .await;
    assert_eq!(dup, StatusCode::CONFLICT, "重名 slug 应 409");

    // 列表含 newco
    let (ls, list) = req(&app, "GET", "/api/v1/admin/auth/tenants", &sa, None).await;
    assert_eq!(ls, StatusCode::OK);
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "newco"),
        "列表应含新开通的租户"
    );

    // 停用(PUT status=suspended)
    let (up, updated) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/auth/tenants/{new_id}"),
        &sa,
        Some(r#"{"display_name":"New Co (paused)","status":"suspended"}"#),
    )
    .await;
    assert_eq!(up, StatusCode::OK);
    assert_eq!(updated["status"], "suspended");
    assert_eq!(updated["display_name"], "New Co (paused)");

    // 交钥匙生效:admin 现在是 newco 的成员 —— 登录后能切进去
    // (member_role 用 membership,它过滤停用租户;newco 已停用 ⇒ 切换会 404。
    //  这条不测切换,只确认开通 + 停用链路;交钥匙的正例在 service 单测里。)
}

/// **平台开通的授权**:`admin` 有 admin:login(能进后台),但没 `tenants:admin` → 403。
/// 这正是 op 层 perm 闸的钉力(不是组闸)。
#[tokio::test]
async fn admin_without_tenants_admin_cannot_provision() {
    let app = app().await;
    let (admin, _) = login(&app, "admin").await;
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/auth/tenants",
        &admin,
        Some(r#"{"name":"sneaky","display_name":"Sneaky"}"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "admin 无 tenants:admin → 403(平台开通是 superadmin 专属)"
    );
}

// ─────────────────────── 租户内成员管理(自助)───────────────────────

/// `user` 是 Acme 的 tn:admin → 能列/邀/移成员。
#[tokio::test]
async fn tenant_admin_manages_own_members() {
    let app = app().await;
    let (user, _) = login(&app, "user").await; // Acme admin(seed)

    // 列成员:Acme 有 user(admin)+ admin + superadmin(都是 seed 放进去的成员)
    let (ls, members) = req(
        &app,
        "GET",
        "/api/v1/frontend/auth/tenants/members",
        &user,
        None,
    )
    .await;
    assert_eq!(ls, StatusCode::OK, "Acme admin 应能列本租户成员:{members}");
    let names: Vec<&str> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["username"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"user"), "自己在成员里");

    // 邀请一个不存在的人 → 404
    let (nf, _) = req(
        &app,
        "POST",
        "/api/v1/frontend/auth/tenants/members",
        &user,
        Some(r#"{"identifier":"ghost","role":"member"}"#),
    )
    .await;
    assert_eq!(nf, StatusCode::NOT_FOUND, "邀请不存在的人 → 404");

    // 先注册一个新账号(0 租户是常规状态),再邀请进来
    app.clone()
        .oneshot(
            Request::post("/api/v1/public/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"newhire","password":"pwd12345"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (add, _) = req(
        &app,
        "POST",
        "/api/v1/frontend/auth/tenants/members",
        &user,
        Some(r#"{"identifier":"newhire","role":"member"}"#),
    )
    .await;
    assert_eq!(add, StatusCode::CREATED, "邀请已有账号 → 201");

    // 成员列表现在含 newhire
    let (_, members2) = req(
        &app,
        "GET",
        "/api/v1/frontend/auth/tenants/members",
        &user,
        None,
    )
    .await;
    let newhire = members2
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["username"] == "newhire")
        .expect("newhire 应已在成员里");
    let newhire_id = newhire["user_id"].as_str().unwrap().to_owned();
    assert_eq!(newhire["role"], "member");

    // 移除
    let (del, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/frontend/auth/tenants/members/{newhire_id}"),
        &user,
        None,
    )
    .await;
    assert_eq!(del, StatusCode::NO_CONTENT, "移除成员 → 204");

    // 再移除同一人 → 404
    let (del2, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/frontend/auth/tenants/members/{newhire_id}"),
        &user,
        None,
    )
    .await;
    assert_eq!(del2, StatusCode::NOT_FOUND, "移除非成员 → 404");
}

/// **提权口关闭的实证**:`admin` 是 Acme 的 tn:member(不是 admin)→ 管不了成员。
///
/// 授权靠**活的 `tenant_members.role`**,不靠 claim 里的平台角色 —— admin 的平台角色再大
/// (admin),在租户内只是个 member,就管不了人。403,不是 404(他知道 Acme 存在,无泄露)。
#[tokio::test]
async fn tenant_member_who_is_not_admin_gets_403() {
    let app = app().await;
    let (admin, _) = login(&app, "admin").await; // Acme member(seed),非 admin

    for (method, uri, body) in [
        ("GET", "/api/v1/frontend/auth/tenants/members", None),
        (
            "POST",
            "/api/v1/frontend/auth/tenants/members",
            Some(r#"{"identifier":"user","role":"member"}"#),
        ),
    ] {
        let (status, _) = req(&app, method, uri, &admin, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri}:租户内 member 管不了成员 → 403(授权靠活的 tenant_members.role)"
        );
    }
}

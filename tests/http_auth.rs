//! 认证的**黑盒 HTTP 验收测试**:注册 / 登录 / 刷新 / 登出 / 个人信息 / 改密 / 注销 / 后台登录。
//! 用浏览器式会话(httponly cookie),不碰任何 web 框架类型。
//!
//! covers: POST /api/v1/public/auth/register
//! covers: POST /api/v1/public/auth/login
//! covers: POST /api/v1/public/auth/refresh
//! covers: POST /api/v1/public/auth/logout
//! covers: POST /api/v1/frontend/auth/logout-all
//! covers: GET /api/v1/frontend/auth/me
//! covers: PUT /api/v1/frontend/auth/me
//! covers: DELETE /api/v1/frontend/auth/me
//! covers: POST /api/v1/frontend/auth/me/password
//! covers: POST /api/v1/admin/auth/login
//! covers: GET /api/v1/admin/auth/me

mod http_support;

use http_support::{
    expect, expect_error, expect_json, TestServer, ADMIN, PASSWORD, SUPERADMIN, USER,
};
use reqwest::StatusCode;
use serde_json::json;

const ME: &str = "/api/v1/frontend/auth/me";

/// 注册 → 201 + httponly cookie(token 不进 body);注册后同一会话即已登录。
#[tokio::test]
async fn register_sets_httponly_cookies_and_logs_in() {
    let s = TestServer::start().await;
    let c = s.anon();
    let resp = c
        .post_json(
            "/api/v1/public/auth/register",
            &json!({ "username": "newbie", "email": "newbie@x.test", "password": "secret1" }),
        )
        .await;
    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let v = expect_json(resp, StatusCode::CREATED).await;
    assert_eq!(v["username"], "newbie");
    assert!(v.get("access_token").is_none(), "token 不进响应体: {v}");
    let access = cookies
        .iter()
        .find(|c| c.starts_with("access_token="))
        .expect("应下发 access_token cookie");
    assert!(access.contains("HttpOnly"), "{access}");
    assert!(cookies.iter().any(|c| c.starts_with("refresh_token=")));

    let me = expect_json(c.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["username"], "newbie");
    assert_eq!(
        me["roles"],
        json!([]),
        "自助注册的新用户不带角色(授权由管理员分配)"
    );
}

#[tokio::test]
async fn register_duplicate_username_is_409_and_bad_input_422() {
    let s = TestServer::start().await;
    let c = s.anon();
    expect_error(
        c.post_json(
            "/api/v1/public/auth/register",
            &json!({ "username": USER, "password": "secret1" }),
        )
        .await,
        StatusCode::CONFLICT,
        "conflict",
    )
    .await;
    expect_error(
        c.post_json(
            "/api/v1/public/auth/register",
            &json!({ "username": "", "password": "secret1" }),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
}

/// 登录:对 → 200 + 会话可用;错密码 / 不存在的用户 → 401(不区分,防枚举)。
#[tokio::test]
async fn login_ok_and_wrong_password_401() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    let me = expect_json(c.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["username"], USER);

    for (id, pw) in [(USER, "wrong"), ("nobody", PASSWORD)] {
        expect_error(
            s.anon()
                .post_json(
                    "/api/v1/public/auth/login",
                    &json!({ "identifier": id, "password": pw }),
                )
                .await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }
}

/// 登录可用 email 作标识。
#[tokio::test]
async fn login_by_email() {
    let s = TestServer::start().await;
    let c = s.login("superadmin@local", PASSWORD).await;
    let me = expect_json(c.get(ME).await, StatusCode::OK).await;
    assert_eq!(me["username"], SUPERADMIN);
}

/// 未登录访问 me → 401。
#[tokio::test]
async fn me_requires_login() {
    let s = TestServer::start().await;
    expect_error(
        s.anon().get(ME).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

/// 刷新:带 refresh cookie → 200(换新 cookie);无 cookie → 401。
#[tokio::test]
async fn refresh_with_cookie_ok_without_401() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    let v = expect_json(
        c.post_empty("/api/v1/public/auth/refresh").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["username"], USER);
    expect(c.get(ME).await, StatusCode::OK).await;

    expect_error(
        s.anon().post_empty("/api/v1/public/auth/refresh").await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
}

/// 登出 → 204 + 清 cookie,之后 me 401、refresh 401;幂等(未登录也 204)。
#[tokio::test]
async fn logout_clears_session() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    expect(
        c.post_empty("/api/v1/public/auth/logout").await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(c.get(ME).await, StatusCode::UNAUTHORIZED).await;
    expect(
        c.post_empty("/api/v1/public/auth/refresh").await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    expect(
        s.anon().post_empty("/api/v1/public/auth/logout").await,
        StatusCode::NO_CONTENT,
    )
    .await;
}

/// 登出全部:另一个会话的 refresh 也失效。
#[tokio::test]
async fn logout_all_revokes_other_sessions() {
    let s = TestServer::start().await;
    let a = s.login(USER, PASSWORD).await;
    let b = s.login(USER, PASSWORD).await;
    expect(
        a.post_empty("/api/v1/frontend/auth/logout-all").await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(
        b.post_empty("/api/v1/public/auth/refresh").await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    expect(
        s.anon()
            .post_empty("/api/v1/frontend/auth/logout-all")
            .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// PUT me 全量替换:改用户名 + 邮箱;邮箱给 null = 清空。
#[tokio::test]
async fn update_me_full_replace() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    let v = expect_json(
        c.put_json(ME, &json!({ "username": "renamed", "email": "r@x.test" }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["username"], "renamed");
    assert_eq!(v["email"], "r@x.test");
    let v = expect_json(
        c.put_json(ME, &json!({ "username": "renamed", "email": null }))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["email"], serde_json::Value::Null);
    // 改名撞已有用户 → 409
    expect(
        c.put_json(ME, &json!({ "username": ADMIN, "email": null }))
            .await,
        StatusCode::CONFLICT,
    )
    .await;
}

/// 改密:旧密码错 → 4xx;对 → 204 + 清 cookie,新密码能登、旧密码不能。
#[tokio::test]
async fn change_password_then_relogin() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    let wrong = c
        .post_json(
            "/api/v1/frontend/auth/me/password",
            &json!({ "current_password": "wrong", "new_password": "newpwd123" }),
        )
        .await;
    assert!(
        wrong.status().is_client_error(),
        "旧密码错应拒: {}",
        wrong.status()
    );

    expect(
        c.post_json(
            "/api/v1/frontend/auth/me/password",
            &json!({ "current_password": PASSWORD, "new_password": "newpwd123" }),
        )
        .await,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.login(USER, "newpwd123").await;
    expect(
        s.anon()
            .post_json(
                "/api/v1/public/auth/login",
                &json!({ "identifier": USER, "password": PASSWORD }),
            )
            .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// 注销账号:要密码确认;之后无法登录。
#[tokio::test]
async fn delete_me_requires_password_then_account_gone() {
    let s = TestServer::start().await;
    let c = s.login(USER, PASSWORD).await;
    let wrong = c.delete_json(ME, &json!({ "password": "wrong" })).await;
    assert!(
        wrong.status().is_client_error(),
        "密码错应拒: {}",
        wrong.status()
    );
    expect(
        c.delete_json(ME, &json!({ "password": PASSWORD })).await,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(
        s.anon()
            .post_json(
                "/api/v1/public/auth/login",
                &json!({ "identifier": USER, "password": PASSWORD }),
            )
            .await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

/// 后台登录:无 admin:login 的 user → 403 且不发 cookie;admin → 200,后台 me 可用。
#[tokio::test]
async fn admin_login_gate_and_admin_me() {
    let s = TestServer::start().await;
    let c = s.anon();
    let resp = c
        .post_json(
            "/api/v1/admin/auth/login",
            &json!({ "identifier": USER, "password": PASSWORD }),
        )
        .await;
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "被拒不应发 cookie"
    );
    expect_error(resp, StatusCode::FORBIDDEN, "forbidden").await;
    expect(
        c.get("/api/v1/admin/auth/me").await,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let admin = s.login_admin(ADMIN, PASSWORD).await;
    let me = expect_json(admin.get("/api/v1/admin/auth/me").await, StatusCode::OK).await;
    assert_eq!(me["username"], ADMIN);
}

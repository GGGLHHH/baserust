//! 租户切换端点的**契约测试**(spec §4.9)。断言只看状态码 / JSON 字段 / Set-Cookie / claim,
//! 不 import DTO 类型 —— 契约是"线上形状"。
//!
//! # 为什么这个文件必须存在
//!
//! P2 第一版把这两个端点连同「安全支点」一起发了出去,**零黑盒覆盖**:所有 `*_api` 夹具都写
//! `tenants: None`,于是端点恒 500,没有任何测试到得了 handler 体内。后果是
//! `.is_none()` 反写成 `.is_some()`(= 任何人可切进任何租户)全仓照样绿。
//!
//! 所以这里装的是**整条真链**:内存 TenantRepo → InProcessTenantDirectory(auth 的端口)
//! → AuthService + TenantClaimsExtender(铸币时填 tenant claim)。不用 `StaticTenantDirectory`
//! ——它的 `set_active` 是 no-op,测不出「切了之后新 token 真的换了租户」这唯一要紧的事。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt;
use uuid::Uuid;

use baserust::app::adapters::{InProcessTenantDirectory, TenantClaimsExtender};
use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier, TenantDirectory};
use baserust::features::tenants::{InMemoryTenantRepo, TenantRepo, TenantRole, TenantStatus};
use baserust::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 建一个装好租户的测试 app,返回 (router, tenant_repo, acme_id, globex_id, notmine_id)。
/// 返回仓储句柄是为了让测试能改成员资格 —— 有些不变量只有在「时间线」上才看得见。
///
/// `alice` 是 acme 与 globex 的成员(按此顺序加入);`notmine` 存在但她不是成员 ——
/// 「非成员」与「不存在」必须对外无法区分,得有个真存在的租户才测得了。
async fn test_app() -> (Router, Arc<InMemoryTenantRepo>, Uuid, Uuid, Uuid) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());
    let users = Arc::new(InMemoryUserRepo::new());
    let roles = Arc::new(InMemoryRoleRepo::sharing_with(&users));
    let tenant_repo = Arc::new(InMemoryTenantRepo::new());

    // 三家公司 + alice 的两份成员资格。**顺序即 seq**:acme 先加入 ⇒ 没显式选过时回退到它。
    let (acme, globex, notmine) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    for (id, name) in [(acme, "acme"), (globex, "globex"), (notmine, "notmine")] {
        tenant_repo
            .upsert_tenant(id, name, name, TenantStatus::Active, None)
            .await
            .unwrap();
    }

    let auth = AuthService::builder(users.clone(), Arc::new(InMemorySessionRepo::new()), roles)
        .hasher(Arc::new(FakeHasher))
        .signer(signer.clone())
        .verifier(verifier.clone())
        // 没有它,铸出的 token 就不带 tenant claim —— 整个功能是死的。
        .claims_extender(Arc::new(TenantClaimsExtender::new(tenant_repo.clone())))
        .build();

    let alice = auth
        .register(
            idm::RegisterInput {
                username: "alice".into(),
                email: None,
                password: "pwd12345".into(),
            },
            None,
        )
        .await
        .unwrap()
        .user
        .id;
    for (t, role) in [(acme, TenantRole::Admin), (globex, TenantRole::Member)] {
        tenant_repo
            .upsert_member(alice, t, role, None)
            .await
            .unwrap();
    }

    let bus: Arc<dyn baserust::features::widget::EventBus> =
        Arc::new(baserust::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: baserust::features::profile::ProfileService::new(
            Arc::new(baserust::features::profile::InMemoryProfileRepo::new()),
            Arc::new(baserust::features::profile::StaticAvatarProbe::empty()),
        ),
        contents: content::ContentService::new(
            Arc::new(content::InMemoryContentRepo::new()),
            Arc::new(content::InMemoryObjectRepo::new()),
            Arc::new(content::InMemoryObjectStore::new()),
            "memory",
        ),
        auth,
        user_admin: baserust::features::users::UserAdminService::new(
            users.clone(),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(baserust::features::users::StaticProfileDirectory::empty()),
            None,
        ),
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(baserust::infra::authz::Policy::default()),
        token_signer: Some(signer),
        token_verifier: verifier,
        tenants: Some(Arc::new(InProcessTenantDirectory::new(tenant_repo.clone()))
            as Arc<dyn TenantDirectory>),
        tenant_admin: Some(baserust::features::tenants::TenantAdminService::new(
            tenant_repo.clone(),
            users.clone(),
        )),
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
    };
    let router = build_router(
        state,
        &baserust::infra::config::Config::default(),
        Mount::Both,
    );
    (router, tenant_repo, acme, globex, notmine)
}

// ── 小工具:cookie / claim ──

fn cookies_of(res: &Response) -> Vec<String> {
    res.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

/// 从 Set-Cookie 里抠出某个 cookie 的值。
fn cookie_value(res: &Response, name: &str) -> Option<String> {
    cookies_of(res).iter().find_map(|c| {
        c.strip_prefix(&format!("{name}="))
            .map(|rest| rest.split(';').next().unwrap().to_owned())
    })
}

/// 解 JWT 中段 —— **读线上字节**,不走 verifier:要证明的正是「token 里到底有什么」。
fn tenant_claim(access: &str) -> Option<Uuid> {
    use base64::Engine;
    let mid = access.split('.').nth(1).unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mid)
            .unwrap(),
    )
    .unwrap();
    json.get("tenant")?.as_str()?.parse().ok()
}

fn roles_claim(access: &str) -> Vec<String> {
    use base64::Engine;
    let mid = access.split('.').nth(1).unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mid)
            .unwrap(),
    )
    .unwrap();
    json["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

async fn login(app: &Router) -> (String, String) {
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"identifier":"alice","password":"pwd12345"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    (
        cookie_value(&res, "access_token").unwrap(),
        cookie_value(&res, "refresh_token").unwrap(),
    )
}

async fn body_json(res: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn switch(app: &Router, access: &str, refresh: &str, tenant: Uuid) -> Response {
    app.clone()
        .oneshot(
            Request::put("/api/v1/frontend/auth/active-tenant")
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!("access_token={access}; refresh_token={refresh}"),
                )
                .body(Body::from(format!(r#"{{"tenant_id":"{tenant}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ── 测试 ──

/// **回退**:从没切过的用户(即每个人的初始状态)登录后落在**最早加入**的那家,
/// 且列表里恰好那一条 `is_active`。
#[tokio::test]
async fn login_falls_back_to_earliest_tenant_and_list_marks_it_active() {
    let (app, _repo, acme, globex, _) = test_app().await;
    let (access, _) = login(&app).await;
    assert_eq!(tenant_claim(&access), Some(acme), "该回退到最早加入的 acme");

    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/auth/tenants")
                .header("cookie", format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let items = body_json(res).await;
    assert_eq!(items.as_array().unwrap().len(), 2);
    assert_eq!(items[0]["id"], acme.to_string());
    assert_eq!(items[0]["is_active"], true, "claim 落在 acme ⇒ 它该被选中");
    assert_eq!(items[1]["id"], globex.to_string());
    assert_eq!(items[1]["is_active"], false);
}

/// **切换成功**:新 token 带新租户、cookie 整条轮换、平台角色不受影响。
#[tokio::test]
async fn switch_remints_token_with_new_tenant_and_rotates_cookies() {
    let (app, _repo, _acme, globex, _) = test_app().await;
    let (access, refresh) = login(&app).await;

    let res = switch(&app, &access, &refresh, globex).await;
    assert_eq!(res.status(), StatusCode::OK);

    let new_access = cookie_value(&res, "access_token").expect("必须下发新 access");
    let new_refresh = cookie_value(&res, "refresh_token").expect("必须下发新 refresh");
    assert_eq!(
        tenant_claim(&new_access),
        Some(globex),
        "新 token 必须带新租户 —— 否则「切了等于没切」"
    );
    assert_ne!(
        new_refresh, refresh,
        "**refresh 必须整条轮换** —— 旧的已被 idm 撤销,前端留着下次必 401"
    );
    // 切租户**不该动 roles** —— 它只该动 tenant claim。
    assert_eq!(
        roles_claim(&new_access),
        roles_claim(&access),
        "切租户不该改平台角色"
    );
    // 且 roles 里绝不该出现租户的任何痕迹。v0.5.0 时代 tenant 靠 `t:{uuid}` 混在 roles 里
    // 走私、租户角色是 `tn:admin` —— 两者都已随 idm v0.6.0 的 `extra` 正门删除。
    // 这条钉死别走回去:租户走 tenant claim,roles 只装平台角色闭集。
    for r in roles_claim(&new_access) {
        assert!(
            !r.starts_with("t:") && !r.starts_with("tn:"),
            "roles 里出现了租户痕迹 `{r}` —— 那是已删除的走私通道"
        );
    }
}

/// **安全支点**:非成员 → 404。
///
/// 且与「租户根本不存在」**同码同形**:403 等于承认「它存在,只是你不在里面」,
/// 那本身就是跨租户的信息泄漏。
#[tokio::test]
async fn non_member_and_nonexistent_tenant_are_both_404() {
    let (app, _repo, _, _, notmine) = test_app().await;
    let (access, refresh) = login(&app).await;

    let a = switch(&app, &access, &refresh, notmine).await;
    assert_eq!(a.status(), StatusCode::NOT_FOUND, "非成员必须 404,不是 403");

    let (access2, refresh2) = login(&app).await;
    let b = switch(&app, &access2, &refresh2, Uuid::now_v7()).await;
    assert_eq!(b.status(), StatusCode::NOT_FOUND);

    assert_eq!(
        body_json(a).await,
        body_json(b).await,
        "「非成员」与「不存在」的响应体必须逐字节相同 —— 有任何差别都能被用来枚举租户"
    );
}

/// **失败的切换不得埋雷**:成员资格校验必须在 `set_active` **之前**。
///
/// # 为什么这条测试要走「时间线」
///
/// 直觉写法是「切非成员租户 → 404 → 重新登录 → 断言还在 acme」。**那个写法测不出东西**:
/// 即便 `set_active` 抢在校验前把 active 写成了 notmine,`memberships` 也会把非成员租户
/// 过滤掉 ⇒ 没有任何一条 `is_active` ⇒ 回退到第一个 = acme。**回退把污染盖住了**,
/// 测试照绿 —— 实测过:把校验挪到 set_active 之后,那个写法 7/7 全过。
///
/// 真正的失败模式是**延时地雷**:脏 active 当天无症状;等这人哪天真被邀请进那家公司,
/// 那行突然生效 —— 她下次登录落进 notmine 而不是 acme,而她从没选过它。这里把雷引爆。
#[tokio::test]
async fn failed_switch_must_not_arm_a_landmine_for_later() {
    let (app, repo, acme, _, notmine) = test_app().await;
    let (access, refresh) = login(&app).await;

    // ① 切进一家她不是成员的公司 → 404。若实现顺序错了,此刻 active 已被写成 notmine。
    assert_eq!(
        switch(&app, &access, &refresh, notmine).await.status(),
        StatusCode::NOT_FOUND
    );

    // ② 她后来被正式邀请进了那家公司 —— 上面那行脏 active 此刻会活过来。
    let alice = alice_id(&app).await;
    repo.upsert_member(alice, notmine, TenantRole::Member, None)
        .await
        .unwrap();

    // ③ 重新登录:她该仍然落在 acme(她从没选过 notmine —— 那次切换是 404)。
    let (access2, _) = login(&app).await;
    assert_eq!(
        tenant_claim(&access2),
        Some(acme),
        "那次失败的切换在 user_active_tenant 里留了行;加入该租户后它生效了 —— \
         人被静默挪进了一家她从没主动选过的公司"
    );
}

/// 从 `/auth/me` 拿 alice 的 id(测试不直接持有它)。
async fn alice_id(app: &Router) -> Uuid {
    let (access, _) = login(app).await;
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/auth/me")
                .header("cookie", format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// **凭证混用**:access token 与 refresh cookie 必须是同一个人。
///
/// `authenticate` 接受 cookie **或** `Authorization: Bearer`,而 idm 的 `refresh()` 只按
/// refresh 的哈希认人 —— 不交叉核对就会「按 A 校验、改 A 的租户、按 B 铸币、记在 B 头上」。
#[tokio::test]
async fn access_token_and_refresh_cookie_must_be_the_same_person() {
    let (app, _repo, acme, _, _) = test_app().await;
    let (alice_access, _) = login(&app).await;

    // bob:另一个真实用户,拿自己的 refresh
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"bob","password":"pwd12345"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bob_refresh = cookie_value(&res, "refresh_token").unwrap();

    // alice 的 access(走 Bearer)+ bob 的 refresh(走 cookie)
    let res = app
        .clone()
        .oneshot(
            Request::put("/api/v1/frontend/auth/active-tenant")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {alice_access}"))
                .header("cookie", format!("refresh_token={bob_refresh}"))
                .body(Body::from(format!(r#"{{"tenant_id":"{acme}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "两枚凭证不同源必须拒 —— 否则能拿 A 的身份改状态、按 B 发新会话"
    );
}

/// **0 租户不是错误**:没有任何成员资格的人 → 空数组 + 200(不是 401)。
/// 这是 register 的常规出口(spec §1.1),前端据此渲染「你还没有租户」。
#[tokio::test]
async fn zero_tenant_user_gets_empty_list_not_401() {
    let (app, _repo, _, _, _) = test_app().await;
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"carol","password":"pwd12345"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let access = cookie_value(&res, "access_token").unwrap();
    assert_eq!(tenant_claim(&access), None, "0 租户 ⇒ token 里没有 tenant");

    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/auth/tenants")
                .header("cookie", format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "0 租户必须 200 不是 401");
    assert_eq!(body_json(res).await, serde_json::json!([]));
}

/// 未登录 → 401(两个端点都是)。
#[tokio::test]
async fn unauthenticated_is_401() {
    let (app, _repo, acme, _, _) = test_app().await;
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/auth/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = app
        .clone()
        .oneshot(
            Request::put("/api/v1/frontend/auth/active-tenant")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"tenant_id":"{acme}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

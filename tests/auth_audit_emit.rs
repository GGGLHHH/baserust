//! auth handler 发射审计事件到 idm.outbox —— 黑盒集成测试(内存模式,无 DB/NATS)。
//! harness 镜像 `tests/auth_api.rs`(HTTP-only 风格,真实 register/login)+ `tests/users_api.rs`
//! 的角色目录写法(admin_login 用例需要真实授角色)。`AppState.idm_outbox` 装
//! `idm::InMemoryOutboxRepo`,断言各生命周期端点确实把对应事件落进发件箱。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use baserust::app::adapters::InProcessProfileDirectory;
use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::profile::{InMemoryProfileRepo, ProfileService, StaticAvatarProbe};
use baserust::features::users::UserAdminService;
use baserust::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory, WidgetService,
};
use baserust::kernel::authz::{Perm, Policy};
use baserust::kernel::tenant::DEFAULT_TENANT_ID;
use idm::{
    AuthService, FakeHasher, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo,
    InMemoryUserRepo, OutboxRecord, OutboxRepo, RoleRepo,
};

const PASSWORD: &str = "password123";

/// 内存 app:auth 用**共享** idm user/role repo(admin_login 用例要直接授角色,无 HTTP 授角色端点
/// 可用);`AppState.idm_outbox` 装 `InMemoryOutboxRepo`(与 user repo 共享存储,镜像
/// `idm::InMemoryOutboxRepo::sharing_with` 的既有约定)。`policy`:租户角色 "admin" → `AdminLogin`,平台角色 "ops" → `UsersAdmin`。
async fn test_app() -> (Router, Arc<InMemoryOutboxRepo>, Arc<dyn RoleRepo>) {
    test_app_with_config(baserust::infra::config::Config::default()).await
}

/// 同 [`test_app`],但可传入自定义 `Config`(用于验证 `trusted_proxy_hops` 等真从 config 接线到
/// router,而非只是巧合等于提取器的硬编码兜底值)。
async fn test_app_with_config(
    config: baserust::infra::config::Config,
) -> (Router, Arc<InMemoryOutboxRepo>, Arc<dyn RoleRepo>) {
    let t = tenancy_app(config).await;
    (t.app, t.outbox, t.roles)
}

/// 完整 harness:多带租户 / 成员仓储(与用户仓储共享存储),多租户用例自己建租户、加成员。
struct Harness {
    app: Router,
    outbox: Arc<InMemoryOutboxRepo>,
    roles: Arc<dyn RoleRepo>,
    tenants: Arc<dyn idm::TenantRepo>,
    members: Arc<dyn idm::MemberRepo>,
}

async fn tenancy_app(config: baserust::infra::config::Config) -> Harness {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());

    let mem_users = InMemoryUserRepo::new();
    let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
    let outbox = Arc::new(InMemoryOutboxRepo::sharing_with(&mem_users));
    let members_repo: Arc<dyn idm::MemberRepo> =
        Arc::new(idm::InMemoryMemberRepo::sharing_with(&mem_users));
    let sessions_repo: Arc<dyn idm::SessionRepo> =
        Arc::new(InMemorySessionRepo::sharing_with(&mem_users));
    let tenants_repo: Arc<dyn idm::TenantRepo> =
        Arc::new(idm::InMemoryTenantRepo::sharing_with(&mem_users));

    let users_repo: Arc<dyn idm::UserRepo> = Arc::new(mem_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(mem_roles);
    // 注册加入默认租户并授租户角色 user:目录里要有它(否则注册响亮失败)。
    roles_repo
        .upsert("user", "User", idm::RoleScope::Tenant, None)
        .await
        .unwrap();

    let auth = AuthService::builder(
        users_repo.clone(),
        sessions_repo,
        roles_repo.clone(),
        members_repo.clone(),
    )
    .hasher(Arc::new(FakeHasher))
    .signer(signer.clone())
    .verifier(verifier.clone())
    .access_ttl_secs(900)
    .refresh_ttl_secs(604_800)
    .build();

    let profile_repo: Arc<dyn baserust::features::profile::ProfileRepo> =
        Arc::new(InMemoryProfileRepo::new());
    // user_admin 不是本套断言对象,给独立内存 session repo 占位即可(同 tests/auth_api.rs 的写法)。
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo.clone(),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );

    // admin(租户角色)→ admin:login;ops(平台角色)→ users:admin(平台管理员凭平台级权限进后台)。
    let policy = Policy::from_roles([
        ("admin".to_owned(), vec![Perm::AdminLogin]),
        ("ops".to_owned(), vec![Perm::UsersAdmin]),
    ]);
    let bus: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: ProfileService::new(profile_repo, Arc::new(StaticAvatarProbe::empty())),
        contents: test_contents(),
        auth,
        user_admin,
        tenant_admin: baserust::features::tenants::TenantAdminService::new(
            std::sync::Arc::new(idm::InMemoryTenantRepo::new()),
            std::sync::Arc::new(idm::InMemoryMemberRepo::new()),
            std::sync::Arc::new(idm::InMemoryUserRepo::new()),
            std::sync::Arc::new(idm::InMemoryRoleRepo::new()),
            std::sync::Arc::new(idm::InMemorySessionRepo::new()),
            std::sync::Arc::new(baserust::features::tenants::StaticMemberProfiles::empty()),
            None,
        ),
        probes: Default::default(),
        monitoring: Default::default(),
        cookie_secure: false,
        policy: Arc::new(policy),
        token_signer: Some(signer),
        token_verifier: verifier,
        idm_outbox: Some(outbox.clone() as Arc<dyn OutboxRepo>),
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(state, &config, Mount::Both);
    Harness {
        app,
        outbox,
        roles: roles_repo,
        tenants: tenants_repo,
        members: members_repo,
    }
}

fn test_contents() -> content::ContentService {
    content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

// ── 请求小工具(镜像 tests/auth_api.rs) ──

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn post_json(uri: &str, json: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_owned()))
        .unwrap()
}

fn req_with_cookie(method: &str, uri: &str, cookie: &str, json: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie);
    let body = if let Some(j) = json {
        b = b.header("content-type", "application/json");
        Body::from(j.to_owned())
    } else {
        Body::empty()
    };
    b.body(body).unwrap()
}

fn cookie_value(resp: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.strip_prefix(&prefix)
                .map(|rest| rest.split(';').next().unwrap_or("").to_owned())
        })
}

async fn register(app: &Router, username: &str, password: &str) -> Response {
    app.clone()
        .oneshot(post_json(
            "/api/v1/public/auth/register",
            &format!(r#"{{"username":"{username}","password":"{password}"}}"#),
        ))
        .await
        .unwrap()
}

async fn login(app: &Router, uri: &str, identifier: &str, password: &str) -> Response {
    app.clone()
        .oneshot(post_json(
            uri,
            &format!(r#"{{"identifier":"{identifier}","password":"{password}"}}"#),
        ))
        .await
        .unwrap()
}

/// outbox 里第一条匹配 `event_type` 的行(不假设它是唯一/首行:setup 步骤可能已产生别的事件)。
async fn find_event(outbox: &InMemoryOutboxRepo, event_type: &str) -> Option<OutboxRecord> {
    outbox
        .poll_unpublished(100)
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.event_type == event_type)
}

// ── register ──

#[tokio::test]
async fn register_emits_registered() {
    let (app, outbox, _roles) = test_app().await;
    let resp = register(&app, "alice", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let ev = find_event(&outbox, "auth.registered")
        .await
        .expect("应发 auth.registered");
    assert_eq!(ev.payload["channel"], "public");
    assert_eq!(ev.payload["outcome"], "success");
}

// ── login(public) ──

#[tokio::test]
async fn login_success_emits_login_succeeded() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "alice", PASSWORD).await;

    let resp = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(ev.payload["channel"], "public");
    assert_eq!(ev.payload["outcome"], "success");
}

#[tokio::test]
async fn login_bad_password_emits_login_failed_with_reason() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "alice", PASSWORD).await;

    let resp = login(&app, "/api/v1/public/auth/login", "alice", "wrong").await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "失败仍统一 401(防枚举)"
    );

    let ev = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert_eq!(ev.payload["failure_reason"], "bad_password");
    assert_eq!(
        ev.aggregate_id,
        uuid::Uuid::nil(),
        "失败登录无确定用户 → aggregate_id 应是 nil 哨兵"
    );
}

#[tokio::test]
async fn login_unknown_user_emits_login_failed_with_unknown_user_reason() {
    let (app, outbox, _roles) = test_app().await;

    let resp = login(&app, "/api/v1/public/auth/login", "nobody", "whatever").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let ev = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert_eq!(ev.payload["failure_reason"], "unknown_user");
    assert_eq!(
        ev.aggregate_id,
        uuid::Uuid::nil(),
        "未知用户无确定用户 → aggregate_id 应是 nil 哨兵"
    );
}

// ── refresh / logout / logout-all ──

#[tokio::test]
async fn refresh_emits_refreshed() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "alice", PASSWORD).await;
    let login_resp = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let refresh_cookie =
        cookie_value(&login_resp, "refresh_token").expect("login 应发 refresh cookie");

    let resp = app
        .clone()
        .oneshot(req_with_cookie(
            "POST",
            "/api/v1/public/auth/refresh",
            &format!("refresh_token={refresh_cookie}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&outbox, "auth.refreshed")
        .await
        .expect("应发 auth.refreshed");
    assert_eq!(ev.payload["outcome"], "success");
}

#[tokio::test]
async fn logout_emits_logged_out_only_when_session_found() {
    let (app, outbox, _roles) = test_app().await;

    // 无 cookie 登出:幂等 204,但没找到活跃会话 → 不发事件。
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        find_event(&outbox, "auth.logged_out").await.is_none(),
        "无会话登出不应发事件"
    );

    // 有 refresh cookie 登出 → 发 auth.logged_out,且带 user_id(按用户查审计历史要用到)。
    let reg = register(&app, "alice", PASSWORD).await;
    let user_id = serde_json::from_str::<serde_json::Value>(&body_string(reg).await).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let login_resp = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let refresh_cookie = cookie_value(&login_resp, "refresh_token").unwrap();
    let resp = app
        .clone()
        .oneshot(req_with_cookie(
            "POST",
            "/api/v1/public/auth/logout",
            &format!("refresh_token={refresh_cookie}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let ev = find_event(&outbox, "auth.logged_out")
        .await
        .expect("有会话登出应发事件");
    assert_eq!(ev.payload["user_id"], user_id, "logged_out 应带 user_id");
    assert_eq!(
        ev.aggregate_id.to_string(),
        user_id,
        "aggregate_id 应是 user_id 而非 session_id"
    );
}

#[tokio::test]
async fn logout_all_emits_logout_all() {
    let (app, outbox, _roles) = test_app().await;
    let reg = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&reg, "access_token").unwrap()
    );

    let resp = app
        .clone()
        .oneshot(req_with_cookie(
            "POST",
            "/api/v1/frontend/auth/logout-all",
            &cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.logout_all").await.is_some());
}

// ── change_password / delete_me ──

#[tokio::test]
async fn change_password_emits_password_changed() {
    let (app, outbox, _roles) = test_app().await;
    let reg = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&reg, "access_token").unwrap()
    );

    let resp = app
        .clone()
        .oneshot(req_with_cookie(
            "POST",
            "/api/v1/frontend/auth/me/password",
            &cookie,
            Some(r#"{"current_password":"password123","new_password":"newpass456"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.password_changed").await.is_some());
}

#[tokio::test]
async fn delete_me_emits_account_deleted() {
    let (app, outbox, _roles) = test_app().await;
    let reg = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&reg, "access_token").unwrap()
    );

    let resp = app
        .clone()
        .oneshot(req_with_cookie(
            "DELETE",
            "/api/v1/frontend/auth/me",
            &cookie,
            Some(r#"{"password":"password123"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.account_deleted").await.is_some());
}

// ── admin_login ──

#[tokio::test]
async fn admin_login_success_emits_login_succeeded_admin_channel() {
    let (app, outbox, roles_repo) = test_app().await;
    let reg = register(&app, "boss", PASSWORD).await;
    let id: uuid::Uuid = serde_json::from_str::<serde_json::Value>(&body_string(reg).await)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    // 平台角色 ops(有平台级权限)→ 后台准入(不依赖租户角色)
    let ops_role_id = roles_repo
        .upsert("ops", "Ops", idm::RoleScope::Platform, None)
        .await
        .unwrap();
    roles_repo.grant(id, ops_role_id, None).await.unwrap();

    let resp = login(&app, "/api/v1/admin/auth/login", "boss", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded(admin channel)");
    assert_eq!(ev.payload["channel"], "admin");
}

#[tokio::test]
async fn admin_login_no_admin_perm_emits_admin_access_denied() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "eve", PASSWORD).await; // 无 admin 角色

    let resp = login(&app, "/api/v1/admin/auth/login", "eve", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let ev = find_event(&outbox, "auth.admin_access_denied")
        .await
        .expect("应发 auth.admin_access_denied");
    assert_eq!(ev.payload["failure_reason"], "no_admin_perm");
    assert!(ev.payload["user_id"].is_string(), "已知用户应带 user_id");
}

#[tokio::test]
async fn admin_login_bad_password_emits_login_failed_admin_channel() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "carl", PASSWORD).await;

    let resp = login(&app, "/api/v1/admin/auth/login", "carl", "wrong").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let ev = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed(admin channel)");
    assert_eq!(ev.payload["channel"], "admin");
    assert_eq!(ev.payload["failure_reason"], "bad_password");
}

// ── HTTP 头透传(回归护栏:resolve_client_ip off-by-one + TrustedHops 未接线,见 Fix B/C) ──

#[tokio::test]
async fn login_headers_resolve_through_wired_trusted_hops() {
    let (app, outbox, _roles) = test_app().await;
    register(&app, "alice", PASSWORD).await;

    // test_app() 的 build_router 走默认 Config(trusted_proxy_hops=1);单条 XFF 即客户端真实 IP。
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.9")
                .header("user-agent", "SmokeTest/1.0")
                .header("x-request-id", "req-abc")
                .body(Body::from(format!(
                    r#"{{"identifier":"alice","password":"{PASSWORD}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        ev.payload["ip"], "203.0.113.9",
        "1 跳可信 → XFF 唯一条即真实 IP"
    );
    assert_eq!(ev.payload["user_agent"], "SmokeTest/1.0");
    assert_eq!(ev.payload["request_id"], "req-abc");
    assert_eq!(ev.payload["forwarded_chain"], "203.0.113.9");
}

/// 回归护栏(Finding B):上面那条测试用默认 `trusted_proxy_hops=1`,与提取器硬编码兜底
/// `.unwrap_or(1)`(见 client_context.rs)数值重合,测不出"config 有没有真接线到 router"。
/// 这里故意配 `trusted_proxy_hops=2`(非默认值、非兜底值),XFF 两跳:
/// "203.0.113.9(真实客户端), 10.0.0.1(nginx 追加)"。若 TrustedHops 接线被删掉,提取器会静默
/// 退回兜底的 1 跳,解出 XFF[len-1]="10.0.0.1"(错),断言会失败——这条测试才真正证明配置的跳数
/// 传到了提取器,而不只是巧合对上。
#[tokio::test]
async fn login_headers_use_configured_trusted_hops_not_extractor_default() {
    let config = baserust::infra::config::Config {
        trusted_proxy_hops: 2,
        ..baserust::infra::config::Config::default()
    };
    let (app, outbox, _roles) = test_app_with_config(config).await;
    register(&app, "alice", PASSWORD).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.9, 10.0.0.1")
                .body(Body::from(format!(
                    r#"{{"identifier":"alice","password":"{PASSWORD}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        ev.payload["ip"], "203.0.113.9",
        "trusted_hops=2 须从 config 接线到提取器 → 取 XFF[len-2];\
         若只是巧合/兜底值 1,会解成 XFF[len-1]=\"10.0.0.1\""
    );
}

// ── 多租户:事件 payload 带 tenant_id(outbox 信封据此抄出,auth_event 据此记租户) ──

/// 建好默认租户的 harness:注册即加入默认租户(角色 user),登录进入默认租户。
async fn tenancy_harness() -> Harness {
    let h = tenancy_app(baserust::infra::config::Config::default()).await;
    h.tenants
        .upsert_fixed(DEFAULT_TENANT_ID.as_uuid(), "default", "Default", None)
        .await
        .unwrap();
    h
}

async fn all_events(outbox: &InMemoryOutboxRepo) -> Vec<OutboxRecord> {
    outbox.poll_unpublished(1000).await.unwrap()
}

#[tokio::test]
async fn login_success_event_carries_tenant_id() {
    let h = tenancy_harness().await;
    register(&h.app, "alice", PASSWORD).await;
    let resp = login(&h.app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let ev = find_event(&h.outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        ev.payload["tenant_id"],
        DEFAULT_TENANT_ID.as_uuid().to_string(),
        "登录进入的租户记在 payload 上"
    );
}

#[tokio::test]
async fn login_failure_event_has_no_tenant_id() {
    let h = tenancy_harness().await;
    register(&h.app, "alice", PASSWORD).await;
    let resp = login(&h.app, "/api/v1/public/auth/login", "alice", "wrong").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let ev = find_event(&h.outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert!(ev.payload["tenant_id"].is_null(), "登录失败没有租户");
}

#[tokio::test]
async fn switch_tenant_emits_tenant_switched_only_on_success() {
    let h = tenancy_harness().await;
    let reg = register(&h.app, "alice", PASSWORD).await;
    let user_id: uuid::Uuid = serde_json::from_str::<serde_json::Value>(&body_string(reg).await)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let second = h.tenants.create("second", "Second", None).await.unwrap();
    h.members.add(second.id, user_id, &[], None).await.unwrap();
    let stranger = h
        .tenants
        .create("stranger", "Stranger", None)
        .await
        .unwrap();

    let login_resp = login(&h.app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}; refresh_token={}",
        cookie_value(&login_resp, "access_token").unwrap(),
        cookie_value(&login_resp, "refresh_token").unwrap()
    );
    let switch = |cookie: String, tenant: uuid::Uuid| {
        let app = h.app.clone();
        async move {
            app.oneshot(req_with_cookie(
                "POST",
                "/api/v1/frontend/auth/switch-tenant",
                &cookie,
                Some(&format!(r#"{{"tenant_id":"{tenant}"}}"#)),
            ))
            .await
            .unwrap()
        }
    };

    // 失败:不是该租户的成员 → 403,不发事件(原会话不动)。
    let resp = switch(cookie.clone(), stranger.id).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        find_event(&h.outbox, "auth.tenant_switched")
            .await
            .is_none(),
        "切换失败不该发 auth.tenant_switched"
    );

    // 成功:发 auth.tenant_switched,payload 的 tenant_id = 切换后的租户。
    let resp = switch(cookie, second.id).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let switched: Vec<OutboxRecord> = all_events(&h.outbox)
        .await
        .into_iter()
        .filter(|r| r.event_type == "auth.tenant_switched")
        .collect();
    assert_eq!(switched.len(), 1, "成功切换恰好发一条");
    let ev = &switched[0];
    assert_eq!(ev.payload["tenant_id"], second.id.to_string());
    assert_eq!(ev.payload["user_id"], user_id.to_string());
    assert_eq!(ev.payload["outcome"], "success");
    assert!(ev.payload["session_id"].is_string(), "带新会话 id");
    assert_eq!(ev.aggregate_id, user_id);
}

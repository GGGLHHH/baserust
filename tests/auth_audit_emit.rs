//! auth handler 发射审计事件到 idm.outbox —— 黑盒集成测试(内存模式,无 DB/NATS)。
//! harness 镜像 `tests/auth_api.rs`(HTTP-only 风格,真实 register/login)+ `tests/users_api.rs`
//! 的角色目录写法(admin_login 用例需要真实授角色)。`AppState.idm_outbox` 装
//! `idm::InMemoryOutboxRepo`,断言各生命周期端点确实把对应事件落进发件箱。

use axum::body;
use baserust::app::{AppAuthService, AppContentService};
use baserust::features::profile::ProfileRepo;
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::infra::config::Config;
use idm::{
    InMemoryMemberRepo, InMemoryTenantRepo, MemberKey, MemberRepo, NewRole, NewTenant, RoleGrant,
    RoleScope, SessionRepo, TenantRepo, UserRepo,
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

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
use baserust::kernel::authorization::{Permission, Policy};
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use idm::{
    FakeHasher, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo,
    OutboxRecord, OutboxRepo, RoleRepo,
};

const PASSWORD: &str = "password123";

/// 内存 app:auth 用**共享** idm user/role repo(admin_login 用例要直接授角色,无 HTTP 授角色端点
/// 可用);`AppState.idm_outbox` 装 `InMemoryOutboxRepo`(与 user repo 共享存储,镜像
/// `idm::InMemoryOutboxRepo::new_shared_with` 的既有约定)。`policy`:租户角色 "admin" → `AdminLogin`,平台角色 "ops" → `UsersAdmin`。
async fn test_app() -> Harness {
    test_app_with_config(Config::default()).await
}

/// 同 [`test_app`],但可传入自定义 `Config`(用于验证 `trusted_proxy_hops` 等真从 config 接线到
/// router,而非只是巧合等于提取器的硬编码兜底值)。
async fn test_app_with_config(config: Config) -> Harness {
    tenancy_app(config).await
}

/// 完整 harness:多带租户 / 成员仓储(与用户仓储共享存储),多租户用例自己建租户、加成员。
struct Harness {
    app: Router,
    outbox: Arc<InMemoryOutboxRepo>,
    roles: Arc<dyn RoleRepo>,
    tenants: Arc<dyn TenantRepo>,
    members: Arc<dyn MemberRepo>,
}

async fn tenancy_app(config: Config) -> Harness {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());

    let memory_users = InMemoryUserRepo::new();
    let memory_roles = InMemoryRoleRepo::new_shared_with(&memory_users);
    let outbox = Arc::new(InMemoryOutboxRepo::new_shared_with(&memory_users));
    let members_repo: Arc<dyn MemberRepo> =
        Arc::new(InMemoryMemberRepo::new_shared_with(&memory_users));
    let sessions_repo: Arc<dyn SessionRepo> =
        Arc::new(InMemorySessionRepo::new_shared_with(&memory_users));
    let tenants_repo: Arc<dyn TenantRepo> =
        Arc::new(InMemoryTenantRepo::new_shared_with(&memory_users));

    let users_repo: Arc<dyn UserRepo> = Arc::new(memory_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(memory_roles);
    // 注册加入默认租户并授租户角色 user:目录里要有它(否则注册响亮失败)。
    roles_repo
        .upsert(
            NewRole {
                name: "user",
                display_name: "User",
                scope: RoleScope::Tenant,
            },
            None,
        )
        .await
        .unwrap();

    let auth = Arc::new(
        AppAuthService::builder(
            users_repo.clone(),
            sessions_repo,
            roles_repo.clone(),
            members_repo.clone(),
        )
        .hasher(FakeHasher)
        .signer(signer.clone())
        .verifier(verifier.clone())
        .access_ttl(time::Duration::seconds(900))
        .refresh_ttl(time::Duration::seconds(604_800))
        .build(),
    );

    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
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
    let policy = Policy::new([
        ("admin".to_owned(), vec![Permission::AdminLogin]),
        ("ops".to_owned(), vec![Permission::UsersAdmin]),
    ]);
    let bus: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: ProfileService::new(profile_repo, Arc::new(StaticAvatarProbe::new())),
        contents: test_contents(),
        auth,
        user_admin,
        tenant_admin: TenantAdminService::new(
            Arc::new(InMemoryTenantRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(StaticMemberProfiles::new()),
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

fn test_contents() -> AppContentService {
    AppContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

// ── 请求小工具(镜像 tests/auth_api.rs) ──

async fn body_string(response: Response) -> String {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
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

fn request_with_cookie(method: &str, uri: &str, cookie: &str, json: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie);
    let body = if let Some(json_body) = json {
        builder = builder.header("content-type", "application/json");
        Body::from(json_body.to_owned())
    } else {
        Body::empty()
    };
    builder.body(body).unwrap()
}

fn cookie_value(response: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix(&prefix)
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
    let Harness { app, outbox, .. } = test_app().await;
    let response = register(&app, "alice", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let event = find_event(&outbox, "auth.registered")
        .await
        .expect("应发 auth.registered");
    assert_eq!(event.payload["channel"], "public");
    assert_eq!(event.payload["outcome"], "success");
}

// ── login(public) ──

#[tokio::test]
async fn login_success_emits_login_succeeded() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "alice", PASSWORD).await;

    let response = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(event.payload["channel"], "public");
    assert_eq!(event.payload["outcome"], "success");
}

#[tokio::test]
async fn login_bad_password_emits_login_failed_with_reason() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "alice", PASSWORD).await;

    let response = login(&app, "/api/v1/public/auth/login", "alice", "wrong").await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "失败仍统一 401(防枚举)"
    );

    let event = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert_eq!(event.payload["failure_reason"], "bad_password");
    assert_eq!(
        event.aggregate_id,
        Uuid::nil(),
        "失败登录无确定用户 → aggregate_id 应是 nil 哨兵"
    );
}

#[tokio::test]
async fn login_unknown_user_emits_login_failed_with_unknown_user_reason() {
    let Harness { app, outbox, .. } = test_app().await;

    let response = login(&app, "/api/v1/public/auth/login", "nobody", "whatever").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let event = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert_eq!(event.payload["failure_reason"], "unknown_user");
    assert_eq!(
        event.aggregate_id,
        Uuid::nil(),
        "未知用户无确定用户 → aggregate_id 应是 nil 哨兵"
    );
}

// ── refresh / logout / logout-all ──

#[tokio::test]
async fn refresh_emits_refreshed() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "alice", PASSWORD).await;
    let login_response = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let refresh_cookie =
        cookie_value(&login_response, "refresh_token").expect("login 应发 refresh cookie");

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "POST",
            "/api/v1/public/auth/refresh",
            &format!("refresh_token={refresh_cookie}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&outbox, "auth.refreshed")
        .await
        .expect("应发 auth.refreshed");
    assert_eq!(event.payload["outcome"], "success");
}

#[tokio::test]
async fn logout_emits_logged_out_only_when_session_found() {
    let Harness { app, outbox, .. } = test_app().await;

    // 无 cookie 登出:幂等 204,但没找到活跃会话 → 不发事件。
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        find_event(&outbox, "auth.logged_out").await.is_none(),
        "无会话登出不应发事件"
    );

    // 有 refresh cookie 登出 → 发 auth.logged_out,且带 user_id(按用户查审计历史要用到)。
    let registered = register(&app, "alice", PASSWORD).await;
    let body: Value = serde_json::from_str(&body_string(registered).await).unwrap();
    let user_id = body["id"].as_str().unwrap().to_owned();
    let login_response = login(&app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let refresh_cookie = cookie_value(&login_response, "refresh_token").unwrap();
    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "POST",
            "/api/v1/public/auth/logout",
            &format!("refresh_token={refresh_cookie}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let event = find_event(&outbox, "auth.logged_out")
        .await
        .expect("有会话登出应发事件");
    assert_eq!(event.payload["user_id"], user_id, "logged_out 应带 user_id");
    assert_eq!(
        event.aggregate_id.to_string(),
        user_id,
        "aggregate_id 应是 user_id 而非 session_id"
    );
}

#[tokio::test]
async fn logout_all_emits_logout_all() {
    let Harness { app, outbox, .. } = test_app().await;
    let registered = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "POST",
            "/api/v1/frontend/auth/logout-all",
            &cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.logout_all").await.is_some());
}

// ── change_password / delete_me ──

#[tokio::test]
async fn change_password_emits_password_changed() {
    let Harness { app, outbox, .. } = test_app().await;
    let registered = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "POST",
            "/api/v1/frontend/auth/me/password",
            &cookie,
            Some(r#"{"current_password":"password123","new_password":"newpass456"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.password_changed").await.is_some());
}

#[tokio::test]
async fn delete_me_emits_account_deleted() {
    let Harness { app, outbox, .. } = test_app().await;
    let registered = register(&app, "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}",
        cookie_value(&registered, "access_token").unwrap()
    );

    let response = app
        .clone()
        .oneshot(request_with_cookie(
            "DELETE",
            "/api/v1/frontend/auth/me",
            &cookie,
            Some(r#"{"password":"password123"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(find_event(&outbox, "auth.account_deleted").await.is_some());
}

// ── admin_login ──

#[tokio::test]
async fn admin_login_success_emits_login_succeeded_admin_channel() {
    let Harness {
        app,
        outbox,
        roles: roles_repo,
        ..
    } = test_app().await;
    let registered = register(&app, "boss", PASSWORD).await;
    let body: Value = serde_json::from_str(&body_string(registered).await).unwrap();
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    // 平台角色 ops(有平台级权限)→ 后台准入(不依赖租户角色)
    let ops_role_id = roles_repo
        .upsert(
            NewRole {
                name: "ops",
                display_name: "Ops",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();
    roles_repo
        .grant(
            RoleGrant {
                user_id: id,
                role_id: ops_role_id,
            },
            None,
        )
        .await
        .unwrap();

    let response = login(&app, "/api/v1/admin/auth/login", "boss", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded(admin channel)");
    assert_eq!(event.payload["channel"], "admin");
}

#[tokio::test]
async fn admin_login_no_admin_perm_emits_admin_access_denied() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "eve", PASSWORD).await; // 无 admin 角色

    let response = login(&app, "/api/v1/admin/auth/login", "eve", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let event = find_event(&outbox, "auth.admin_access_denied")
        .await
        .expect("应发 auth.admin_access_denied");
    assert_eq!(event.payload["failure_reason"], "no_admin_perm");
    assert!(event.payload["user_id"].is_string(), "已知用户应带 user_id");
}

#[tokio::test]
async fn admin_login_bad_password_emits_login_failed_admin_channel() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "carl", PASSWORD).await;

    let response = login(&app, "/api/v1/admin/auth/login", "carl", "wrong").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let event = find_event(&outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed(admin channel)");
    assert_eq!(event.payload["channel"], "admin");
    assert_eq!(event.payload["failure_reason"], "bad_password");
}

// ── HTTP 头透传(回归护栏:resolve_client_ip off-by-one + TrustedHops 未接线,见 Fix B/C) ──

#[tokio::test]
async fn login_headers_resolve_through_wired_trusted_hops() {
    let Harness { app, outbox, .. } = test_app().await;
    register(&app, "alice", PASSWORD).await;

    // test_app() 的 build_router 走默认 Config(trusted_proxy_hops=1);单条 XFF 即客户端真实 IP。
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        event.payload["ip"], "203.0.113.9",
        "1 跳可信 → XFF 唯一条即真实 IP"
    );
    assert_eq!(event.payload["user_agent"], "SmokeTest/1.0");
    assert_eq!(event.payload["request_id"], "req-abc");
    assert_eq!(event.payload["forwarded_chain"], "203.0.113.9");
}

/// 回归护栏(Finding B):上面那条测试用默认 `trusted_proxy_hops=1`,与提取器硬编码兜底
/// `.unwrap_or(1)`(见 client_context.rs)数值重合,测不出"config 有没有真接线到 router"。
/// 这里故意配 `trusted_proxy_hops=2`(非默认值、非兜底值),XFF 两跳:
/// "203.0.113.9(真实客户端), 10.0.0.1(nginx 追加)"。若 TrustedHops 接线被删掉,提取器会静默
/// 退回兜底的 1 跳,解出 XFF[len-1]="10.0.0.1"(错),断言会失败——这条测试才真正证明配置的跳数
/// 传到了提取器,而不只是巧合对上。
#[tokio::test]
async fn login_headers_use_configured_trusted_hops_not_extractor_default() {
    let config = Config {
        trusted_proxy_hops: 2,
        ..Config::default()
    };
    let Harness { app, outbox, .. } = test_app_with_config(config).await;
    register(&app, "alice", PASSWORD).await;

    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        event.payload["ip"], "203.0.113.9",
        "trusted_hops=2 须从 config 接线到提取器 → 取 XFF[len-2];\
         若只是巧合/兜底值 1,会解成 XFF[len-1]=\"10.0.0.1\""
    );
}

// ── 多租户:事件 payload 带 tenant_id(outbox 信封据此抄出,auth_event 据此记租户) ──

/// 建好默认租户的 harness:注册即加入默认租户(角色 user),登录进入默认租户。
async fn tenancy_harness() -> Harness {
    let harness = tenancy_app(Config::default()).await;
    harness
        .tenants
        .upsert_fixed(
            DEFAULT_TENANT_ID.as_uuid(),
            NewTenant {
                slug: "default",
                name: "Default",
            },
            None,
        )
        .await
        .unwrap();
    harness
}

async fn all_events(outbox: &InMemoryOutboxRepo) -> Vec<OutboxRecord> {
    outbox.poll_unpublished(1000).await.unwrap()
}

#[tokio::test]
async fn login_success_event_carries_tenant_id() {
    let harness = tenancy_harness().await;
    register(&harness.app, "alice", PASSWORD).await;
    let response = login(&harness.app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::OK);

    let event = find_event(&harness.outbox, "auth.login_succeeded")
        .await
        .expect("应发 auth.login_succeeded");
    assert_eq!(
        event.payload["tenant_id"],
        DEFAULT_TENANT_ID.as_uuid().to_string(),
        "登录进入的租户记在 payload 上"
    );
}

#[tokio::test]
async fn login_failure_event_has_no_tenant_id() {
    let harness = tenancy_harness().await;
    register(&harness.app, "alice", PASSWORD).await;
    let response = login(&harness.app, "/api/v1/public/auth/login", "alice", "wrong").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let event = find_event(&harness.outbox, "auth.login_failed")
        .await
        .expect("应发 auth.login_failed");
    assert!(event.payload["tenant_id"].is_null(), "登录失败没有租户");
}

#[tokio::test]
async fn switch_tenant_emits_tenant_switched_only_on_success() {
    let harness = tenancy_harness().await;
    let registered = register(&harness.app, "alice", PASSWORD).await;
    let body: Value = serde_json::from_str(&body_string(registered).await).unwrap();
    let user_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let second = harness
        .tenants
        .create(
            NewTenant {
                slug: "second",
                name: "Second",
            },
            None,
        )
        .await
        .unwrap();
    harness
        .members
        .add(
            MemberKey {
                tenant_id: second.id,
                user_id,
            },
            &[],
            None,
        )
        .await
        .unwrap();
    let stranger = harness
        .tenants
        .create(
            NewTenant {
                slug: "stranger",
                name: "Stranger",
            },
            None,
        )
        .await
        .unwrap();

    let login_response = login(&harness.app, "/api/v1/public/auth/login", "alice", PASSWORD).await;
    let cookie = format!(
        "access_token={}; refresh_token={}",
        cookie_value(&login_response, "access_token").unwrap(),
        cookie_value(&login_response, "refresh_token").unwrap()
    );
    let switch = |cookie: String, tenant: Uuid| {
        let app = harness.app.clone();
        async move {
            app.oneshot(request_with_cookie(
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
    let response = switch(cookie.clone(), stranger.id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        find_event(&harness.outbox, "auth.tenant_switched")
            .await
            .is_none(),
        "切换失败不该发 auth.tenant_switched"
    );

    // 成功:发 auth.tenant_switched,payload 的 tenant_id = 切换后的租户。
    let response = switch(cookie, second.id).await;
    assert_eq!(response.status(), StatusCode::OK);
    let switched: Vec<OutboxRecord> = all_events(&harness.outbox)
        .await
        .into_iter()
        .filter(|r| r.event_type == "auth.tenant_switched")
        .collect();
    assert_eq!(switched.len(), 1, "成功切换恰好发一条");
    let event = &switched[0];
    assert_eq!(event.payload["tenant_id"], second.id.to_string());
    assert_eq!(event.payload["user_id"], user_id.to_string());
    assert_eq!(event.payload["outcome"], "success");
    assert!(event.payload["session_id"].is_string(), "带新会话 id");
    assert_eq!(event.aggregate_id, user_id);
}

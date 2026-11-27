//! auth_audit admin 查询端点 —— 黑盒集成测试(内存模式)。harness 镜像 `tests/users_api.rs`:
//! struct 直建 `AppState` + mint 令牌(不走真实登录);`AppState.auth_events` 装
//! `InMemoryAuthEventRepo`(手插几行数据,不依赖真实 projector 链)。

use axum::body;
use baserust::app::{AppAuthService, AppContentService, Mount};
use baserust::features::auth::ScopedTenant;
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::infra::config::Config;
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use idm::{InMemoryMemberRepo, InMemoryTenantRepo, NewRole, RoleScope, SessionRepo, UserRepo};
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use uuid::Uuid;

use baserust::app::adapters::InProcessProfileDirectory;
use baserust::app::{build_router, AppState};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::auth_audit::{
    AuthAuditService, AuthEventRepo, InMemoryAuthEventRepo, NewAuthEvent,
};
use baserust::features::profile::{
    InMemoryProfileRepo, ProfileRepo, ProfileService, StaticAvatarProbe,
};
use baserust::features::users::UserAdminService;
use baserust::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory, WidgetService,
};
use baserust::kernel::authorization::{Permission, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, RoleRepo};

/// 内存 app + 两个令牌(镜像 `tests/users_api.rs::test_app`):`superadmin`(满权,含 audit:read)
/// 与 `admin`(只有 admin:login)。`AppState.auth_events` 装 `InMemoryAuthEventRepo`,手插数据。
async fn test_app() -> TestApp {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());

    let memory_users = InMemoryUserRepo::new();
    let memory_roles = InMemoryRoleRepo::new_shared_with(&memory_users);
    for (name, display) in [("superadmin", "Super"), ("admin", "Admin")] {
        memory_roles
            .upsert(
                NewRole {
                    name,
                    display_name: display,
                    scope: RoleScope::Platform,
                },
                None,
            )
            .await
            .unwrap();
    }
    let users_repo: Arc<dyn UserRepo> = Arc::new(memory_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(memory_roles);
    let sessions_repo: Arc<dyn SessionRepo> = Arc::new(InMemorySessionRepo::new());

    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo,
        sessions_repo,
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );

    let policy = Policy::new([
        ("superadmin".to_owned(), Permission::ALL.to_vec()),
        ("admin".to_owned(), vec![Permission::AdminLogin]),
    ]);

    let auth_events = Arc::new(InMemoryAuthEventRepo::new());
    // 手插一行,供 200 断言看到非空列表。
    auth_events
        .insert(&NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: "auth.login_succeeded".into(),
            occurred_at: OffsetDateTime::now_utc(),
            channel: "public".into(),
            auth_method: "password".into(),
            user_id: Some(Uuid::now_v7()),
            identifier_attempted: None,
            session_id: Some(Uuid::now_v7()),
            actor: None,
            outcome: "success".into(),
            failure_reason: None,
            ip: None,
            forwarded_chain: None,
            user_agent: None,
            request_id: None,
            tenant_id: None,
            event_sequence: 1,
        })
        .await
        .unwrap();

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
        auth: test_auth(signer.clone(), verifier.clone()),
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
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: Some(AuthAuditService::new(
            auth_events.clone() as Arc<dyn AuthEventRepo>
        )),
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(state, &Config::default(), Mount::Both);

    let superadmin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "superadmin",
            vec!["superadmin".to_owned()],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["admin".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
    let admin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "admin",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["admin".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
    TestApp {
        app,
        events: auth_events,
        superadmin,
        admin,
    }
}

/// 内存 app、它的审计读模型仓储和两枚令牌(见 [`test_app`])。
struct TestApp {
    app: Router,
    /// 审计读模型(手插数据用)。
    events: Arc<InMemoryAuthEventRepo>,
    /// superadmin 的令牌(满权,含 audit:read)。
    superadmin: String,
    /// admin 的令牌(只有 admin:login)。
    admin: String,
}

fn test_contents() -> AppContentService {
    AppContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

fn test_auth(signer: Arc<AppTokenSigner>, verifier: Arc<AppTokenVerifier>) -> Arc<AppAuthService> {
    let auth = AppAuthService::builder(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(InMemoryRoleRepo::new()),
        Arc::new(InMemoryMemberRepo::new()),
    )
    .hasher(FakeHasher)
    // 独立的空角色仓储:注册不授租户角色(配置了目录里没有的角色会响亮失败)
    .signup_roles(Vec::<String>::new())
    .signer(signer)
    .verifier(verifier)
    .access_ttl(time::Duration::seconds(900))
    .refresh_ttl(time::Duration::seconds(604_800))
    .build();
    Arc::new(auth)
}

async fn body_string(response: Response) -> String {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_str(&body_string(response).await).unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ── 授权矩阵:GET /admin/auth-events ──

#[tokio::test]
async fn auth_events_authz_matrix() {
    let TestApp {
        app,
        superadmin,
        admin,
        ..
    } = test_app().await;

    // 无 token → 组闸 401
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/auth/auth-events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "无 token 应 401"
    );

    // admin(admin:login,无 audit:read)→ 403
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/auth-events", &admin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin 无 audit:read 应 403"
    );

    // superadmin → 200 + 命中手插行
    let response = app
        .oneshot(get("/api/v1/admin/auth/auth-events", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "superadmin 应 200");
    let page = json_body(response).await;
    assert_eq!(
        page["items"].as_array().unwrap().len(),
        1,
        "应命中手插的 1 行"
    );
}

// ── q 联合模糊搜(actor + identifier_attempted + ip 子串)下推到库,全历史检索(取代前端内存过滤)──
#[tokio::test]
async fn list_q_searches_actor_ip_identifier_server_side() {
    let TestApp {
        app,
        events: repo,
        superadmin,
        ..
    } = test_app().await;
    let make_event =
        |sequence: i64, actor: &str, ip: &str, identifier: Option<&str>| NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: "auth.login_succeeded".into(),
            occurred_at: OffsetDateTime::now_utc(),
            channel: "public".into(),
            auth_method: "password".into(),
            user_id: Some(Uuid::now_v7()),
            identifier_attempted: identifier.map(str::to_owned),
            session_id: None,
            actor: Some(actor.to_owned()),
            outcome: "success".into(),
            failure_reason: None,
            ip: ip.parse().ok(),
            forwarded_chain: None,
            user_agent: None,
            request_id: None,
            tenant_id: None,
            event_sequence: sequence,
        };
    repo.insert(&make_event(10, "alice", "10.1.1.1", None))
        .await
        .unwrap();
    repo.insert(&make_event(11, "bob", "10.2.2.2", Some("bob@example.com")))
        .await
        .unwrap();

    let actors = |page: Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["actor"].as_str().map(str::to_owned))
            .collect()
    };

    // actor 子串
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/auth-events?q=alic", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        actors(json_body(response).await),
        vec!["alice".to_owned()],
        "q=alic → 命中 actor 子串"
    );

    // ip 子串
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/auth-events?q=10.2", &superadmin))
        .await
        .unwrap();
    assert_eq!(
        actors(json_body(response).await),
        vec!["bob".to_owned()],
        "q=10.2 → 命中 ip 子串"
    );

    // identifier_attempted 子串
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/auth-events?q=example", &superadmin))
        .await
        .unwrap();
    assert_eq!(
        actors(json_body(response).await),
        vec!["bob".to_owned()],
        "q=example → 命中 identifier_attempted 子串"
    );
}

// ── 授权矩阵 + 响应体形状:GET /admin/auth-events/stats ──

#[tokio::test]
async fn stats_endpoint_returns_shape_and_gates() {
    let TestApp {
        app,
        superadmin,
        admin,
        ..
    } = test_app().await;

    // 无 token → 401
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/auth/auth-events/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "无 token 应 401"
    );

    // admin(admin:login,无 audit:read)→ 403
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/auth-events/stats", &admin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin 无 audit:read 应 403"
    );

    // superadmin → 200 + 响应形状(手插的 1 行落在默认 24h 窗口内)
    let response = app
        .oneshot(get("/api/v1/admin/auth/auth-events/stats", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "superadmin 应 200");
    let stats = json_body(response).await;
    assert!(
        !stats["activity"].as_array().unwrap().is_empty(),
        "默认 24h 窗口应零填充出小时桶,即便手插行都不在内"
    );
    assert!(stats["reasons"].is_array(), "应有 reasons 字段");
    assert!(stats["types"].is_array(), "应有 types 字段");
    assert!(stats["top_ips"].is_array(), "应有 top_ips 字段");
    assert!(
        stats["kpi"]["total_events"].is_number(),
        "kpi.total_events 应是数字"
    );
    assert!(
        stats["kpi"]["success_rate"].is_number(),
        "kpi.success_rate 应是数字"
    );
}

// ── 授权矩阵:GET /admin/users/{id}/auth-events ──

#[tokio::test]
async fn user_auth_events_authz_matrix() {
    let TestApp {
        app,
        superadmin,
        admin,
        ..
    } = test_app().await;
    let uri = format!("/api/v1/admin/auth/users/{}/auth-events", Uuid::now_v7());

    let response = app
        .clone()
        .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app.clone().oneshot(get(&uri, &admin)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app.oneshot(get(&uri, &superadmin)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // 随机 uuid,手插行的 user_id 不匹配 → 空列表(非 404,过滤本就允许空结果)。
    let page = json_body(response).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 0);
}

/// `AppState.auth_events = None`(非 needs_idm 进程 / 无 search pool)时,端点应 404 而非 panic ——
/// 授权闸依然先跑(闸在 `repo.ok_or(NotFound)` 之前),故仍是"过闸后业务层缺依赖"的诚实降级。
#[tokio::test]
async fn no_auth_events_backend_is_404_not_panic() {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());
    let memory_users = InMemoryUserRepo::new();
    let memory_roles = InMemoryRoleRepo::new_shared_with(&memory_users);
    memory_roles
        .upsert(
            NewRole {
                name: "superadmin",
                display_name: "Super",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();
    let users_repo: Arc<dyn UserRepo> = Arc::new(memory_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(memory_roles);
    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo,
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );
    let policy = Policy::new([("superadmin".to_owned(), Permission::ALL.to_vec())]);
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
        auth: test_auth(signer.clone(), verifier.clone()),
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
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(state, &Config::default(), Mount::Both);
    let superadmin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "superadmin",
            vec!["superadmin".to_owned()],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["admin".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();

    let response = app
        .oneshot(get("/api/v1/admin/auth/auth-events", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

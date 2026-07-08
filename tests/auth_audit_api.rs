//! auth_audit admin 查询端点 —— 黑盒集成测试(内存模式)。harness 镜像 `tests/users_api.rs`:
//! struct 直建 `AppState` + mint 令牌(不走真实登录);`AppState.auth_events` 装
//! `InMemoryAuthEventRepo`(手插几行数据,不依赖真实 projector 链)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use uuid::Uuid;

use baserust::app::adapters::InProcessProfileDirectory;
use baserust::app::{build_router, AppState};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::auth_audit::{AuthEventRepo, InMemoryAuthEventRepo, NewAuthEvent};
use baserust::features::profile::{
    InMemoryProfileRepo, ProfileRepo, ProfileService, StaticAvatarProbe,
};
use baserust::features::users::UserAdminService;
use baserust::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory, WidgetService,
};
use baserust::infra::authz::{Perm, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, RoleRepo};

/// 内存 app + 两个令牌(镜像 `tests/users_api.rs::test_app`):`superadmin`(users:admin,满权)
/// 与 `admin`(只有 admin:login)。`AppState.auth_events` 装 `InMemoryAuthEventRepo`,手插数据。
async fn test_app() -> (Router, Arc<InMemoryAuthEventRepo>, String, String) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());

    let mem_users = InMemoryUserRepo::new();
    let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
    for (name, display) in [("superadmin", "Super"), ("admin", "Admin")] {
        mem_roles.upsert(name, display, None).await.unwrap();
    }
    let users_repo: Arc<dyn idm::UserRepo> = Arc::new(mem_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(mem_roles);
    let sessions_repo: Arc<dyn idm::SessionRepo> = Arc::new(InMemorySessionRepo::new());

    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo,
        sessions_repo,
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );

    let policy = Policy::from_roles([
        ("superadmin".to_owned(), Perm::ALL.to_vec()),
        ("admin".to_owned(), vec![Perm::AdminLogin]),
    ]);

    let auth_events = Arc::new(InMemoryAuthEventRepo::new());
    // 手插一行,供 200 断言看到非空列表。
    auth_events
        .insert(&NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: "auth.login_succeeded".into(),
            occurred_at: time::OffsetDateTime::now_utc(),
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
            event_seq: 1,
        })
        .await
        .unwrap();

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
        auth: test_auth(signer.clone(), verifier.clone()),
        user_admin,
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(policy),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_events: Some(auth_events.clone() as Arc<dyn AuthEventRepo>),
    };
    let app = build_router(
        state,
        &baserust::infra::config::Config::default(),
        baserust::app::Mount::Both,
    );

    let superadmin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "superadmin",
            vec!["superadmin".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    let admin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "admin",
            vec!["admin".to_owned()],
            vec![],
            900,
        )
        .unwrap();
    (app, auth_events, superadmin, admin)
}

fn test_contents() -> content::ContentService {
    content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

fn test_auth(signer: Arc<AppTokenSigner>, verifier: Arc<AppTokenVerifier>) -> idm::AuthService {
    idm::AuthService::builder(
        Arc::new(InMemoryUserRepo::new()),
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(InMemoryRoleRepo::new()),
    )
    .hasher(Arc::new(FakeHasher))
    .signer(signer)
    .verifier(verifier)
    .access_ttl_secs(900)
    .refresh_ttl_secs(604_800)
    .build()
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn json_body(resp: Response) -> serde_json::Value {
    serde_json::from_str(&body_string(resp).await).unwrap()
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
    let (app, _events, superadmin, admin) = test_app().await;

    // 无 token → 组闸 401
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/auth-events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "无 token 应 401");

    // admin(admin:login,无 users:admin)→ 403
    let r = app
        .clone()
        .oneshot(get("/api/v1/admin/auth-events", &admin))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "admin 无 users:admin 应 403"
    );

    // superadmin → 200 + 命中手插行
    let r = app
        .oneshot(get("/api/v1/admin/auth-events", &superadmin))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "superadmin 应 200");
    let v = json_body(r).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "应命中手插的 1 行");
}

// ── 授权矩阵:GET /admin/users/{id}/auth-events ──

#[tokio::test]
async fn user_auth_events_authz_matrix() {
    let (app, _events, superadmin, admin) = test_app().await;
    let uri = format!("/api/v1/admin/users/{}/auth-events", Uuid::now_v7());

    let r = app
        .clone()
        .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let r = app.clone().oneshot(get(&uri, &admin)).await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    let r = app.oneshot(get(&uri, &superadmin)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // 随机 uuid,手插行的 user_id 不匹配 → 空列表(非 404,过滤本就允许空结果)。
    let v = json_body(r).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 0);
}

/// `AppState.auth_events = None`(非 needs_idm 进程 / 无 search pool)时,端点应 404 而非 panic ——
/// 授权闸依然先跑(闸在 `repo.ok_or(NotFound)` 之前),故仍是"过闸后业务层缺依赖"的诚实降级。
#[tokio::test]
async fn no_auth_events_backend_is_404_not_panic() {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());
    let mem_users = InMemoryUserRepo::new();
    let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
    mem_roles.upsert("superadmin", "Super", None).await.unwrap();
    let users_repo: Arc<dyn idm::UserRepo> = Arc::new(mem_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(mem_roles);
    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo,
        Arc::new(InMemorySessionRepo::new()),
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );
    let policy = Policy::from_roles([("superadmin".to_owned(), Perm::ALL.to_vec())]);
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
        auth: test_auth(signer.clone(), verifier.clone()),
        user_admin,
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(policy),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_events: None,
    };
    let app = build_router(
        state,
        &baserust::infra::config::Config::default(),
        baserust::app::Mount::Both,
    );
    let superadmin = signer
        .mint_scoped(
            Uuid::now_v7(),
            "superadmin",
            vec!["superadmin".to_owned()],
            vec![],
            900,
        )
        .unwrap();

    let r = app
        .oneshot(get("/api/v1/admin/auth-events", &superadmin))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

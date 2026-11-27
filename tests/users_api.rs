//! admin user CRUD 黑盒集成测试 —— 内存模式(无 DB)、单进程 `Both`,oneshot 打真实端点。
//! harness 镜像 `tests/widget_api.rs`:struct 直建 `AppState` + mint 令牌(不走真实登录)。
//! 与 widget 不同处:idm user/role repo **共享**(new_shared_with)且预置角色,profile repo 与
//! `profiles` 服务和富化端口(InProcessProfileDirectory)**同一实例** —— 才能端到端验富化。

use axum::body;
use baserust::app::{AppAuthService, AppContentService, Mount};
use baserust::features::auth::ScopedTenant;
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::infra::config::Config;
use baserust::kernel::authorization::PermissionScope;
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use idm::{InMemoryMemberRepo, InMemoryTenantRepo, NewRole, RoleScope, SessionRepo, UserRepo};
use serde_json::Value;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
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
use baserust::features::profile::{
    InMemoryProfileRepo, ProfileRepo, ProfileService, StaticAvatarProbe,
};
use baserust::features::users::UserAdminService;
use baserust::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory, WidgetService,
};
use baserust::kernel::authorization::{Permission, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, RoleRepo};

/// 内存 app + 两个令牌:`superadmin`(有 users:admin,满权)与 `admin`(只有 admin:login)。
/// idm user/role repo 共享并预置角色(superadmin/platform_admin/admin/user,即 RoleName 闭集;目录接口不列 superadmin,
/// 目标高权账号用 platform_admin —— 动持平台角色的账号要 platform:roles,中间管理员没有);profile repo 三方共享 →
/// 富化可端到端断言。auth 服务用独立占位 repo(本套不测真实登录)。
async fn test_app() -> TestApp {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());

    // idm 身份 repo:user 与 role **共享** RoleStore + 预置可分配角色(建号/设角色靠它解析名→id)。
    let memory_users = InMemoryUserRepo::new();
    let memory_roles = InMemoryRoleRepo::new_shared_with(&memory_users);
    for (name, display) in [
        ("superadmin", "Super"),
        ("platform_admin", "Platform Admin"),
        ("admin", "Admin"),
        ("user", "User"),
    ] {
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

    // profile repo 三方共享:profiles 服务写、富化端口读 —— 同实例才能验 display_name 富化。
    let profile_repo: Arc<dyn ProfileRepo> = Arc::new(InMemoryProfileRepo::new());
    let user_admin = UserAdminService::new(
        users_repo,
        roles_repo,
        sessions_repo,
        Arc::new(FakeHasher),
        Arc::new(InProcessProfileDirectory::new(profile_repo.clone())),
        None,
    );

    // policy(归 app):superadmin 满权(含 users:admin + profiles:write:all);admin 仅后台准入。
    // `useradmin` = **中间管理员**:有 users:admin 但非满权 —— 提权闸真正要拦的那类主体
    // (见 users/adapters/http/routes.rs 头注)。线上 seed 里没有这个角色,但 role→perms 是运行期可改的
    // (`role_permissions` 表),superadmin 随时能造出这类主体,故闸必须对它成立。
    // 多租户:superadmin(平台角色)只取平台级权限(含 users:admin、profiles:write:all);超管令牌在默认租户里
    // 兼任的 `tenant_all` 租户角色给全部租户级权限 —— 合起来仍是「满权」。
    let policy = Policy::new([
        ("superadmin".to_owned(), Permission::ALL.to_vec()),
        (
            "tenant_all".to_owned(),
            Permission::ALL
                .into_iter()
                .filter(|p| p.scope() == PermissionScope::Tenant)
                .collect(),
        ),
        ("admin".to_owned(), vec![Permission::AdminLogin]),
        (
            "useradmin".to_owned(),
            vec![Permission::AdminLogin, Permission::UsersAdmin],
        ),
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
                roles: vec!["tenant_all".to_owned()],
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
        superadmin,
        admin,
    }
}

/// 内存 app 及其两枚令牌(见 [`test_app`])。
struct TestApp {
    app: Router,
    /// superadmin 的令牌(满权)。
    superadmin: String,
    /// admin 的令牌(只有 admin:login)。
    admin: String,
}

/// 测试用 content 服务:全内存(repo + ObjectStore),不碰 DB/minio。
fn test_contents() -> AppContentService {
    AppContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

/// 测试用 AuthService:FakeHasher + 独立内存 repo(本套不测登录/refresh) + 生产同款签验。
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

// ── 请求/响应小工具(镜像 widget_api) ──

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

fn post_json(uri: &str, json: &str, token: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json.to_owned()))
        .unwrap()
}

fn put_json(uri: &str, json: &str, token: &str) -> Request<Body> {
    Request::put(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json.to_owned()))
        .unwrap()
}

fn delete_req(uri: &str, token: &str) -> Request<Body> {
    Request::delete(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// 取角色目录(GET /admin/roles),把角色名映射成其 id,返回可嵌进 body 的 JSON 数组串
/// 如 `["<uuid>"]`(角色现按 id 传;存活名唯一,映射无歧义)。
async fn role_ids_json(app: &Router, token: &str, names: &[&str]) -> String {
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/roles", token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "取角色目录应 200");
    let catalog = json_body(response).await;
    let items = catalog["items"].as_array().unwrap();
    let ids: Vec<&str> = names
        .iter()
        .map(|name| {
            items
                .iter()
                .find(|r| r["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("角色目录缺 {name}"))["id"]
                .as_str()
                .unwrap()
        })
        .collect();
    serde_json::to_string(&ids).unwrap()
}

/// 建号(superadmin),断言 201,返回新 id。`roles` 是角色**名**,内部解析成 id 提交。
async fn create_user(app: &Router, token: &str, username: &str, roles: &[&str]) -> String {
    let ids = role_ids_json(app, token, roles).await;
    let body = format!(
        r#"{{"username":"{username}","email":null,"password":"password123","roles":{ids}}}"#
    );
    let response = app
        .clone()
        .oneshot(post_json("/api/v1/admin/auth/users", &body, token))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "建 {username} 应 201"
    );
    let user = json_body(response).await;
    user["id"].as_str().unwrap().to_owned()
}

/// 收集响应体里的 roles 数组为排序后的 Vec(角色比较 order-insensitive)。
fn sorted_roles(user: &Value) -> Vec<String> {
    let mut roles: Vec<String> = user["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    roles.sort();
    roles
}

// ── 1. 授权矩阵 ──

/// 无 token → 401;`admin`(admin:login 无 users:admin)→ 403;`superadmin` → 200。
#[tokio::test]
async fn authz_matrix() {
    let TestApp {
        app,
        superadmin,
        admin,
    } = test_app().await;

    // 无 token → 组闸 require_admin_login 401
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/auth/users")
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

    // admin 过组闸(有 admin:login)但 handler require_scoped(users:admin) → 403
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users", &admin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin 无 users:admin 应 403"
    );

    // superadmin → 200
    let response = app
        .oneshot(get("/api/v1/admin/auth/users", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "superadmin 应 200");
}

// ── 2. 建号 ──

#[tokio::test]
async fn create_user_cases() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let user_ids = role_ids_json(&app, &superadmin, &["user"]).await;

    // 合法建号 → 201 + roles 命中(响应 roles 仍是名字)
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            &format!(
                r#"{{"username":"neo","email":"neo@example.com","password":"password123","roles":{user_ids}}}"#
            ),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let user = json_body(response).await;
    assert_eq!(
        user["roles"].as_array().unwrap(),
        &vec![serde_json::json!("user")]
    );
    // created_at 存在且可解析(单查是占位值,只断言 present/parseable,不断言精确值)
    assert!(
        OffsetDateTime::parse(user["created_at"].as_str().unwrap(), &Rfc3339,).is_ok(),
        "created_at 应是可解析的 rfc3339"
    );

    // 重名 → 409
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            &format!(
                r#"{{"username":"neo","email":null,"password":"password123","roles":{user_ids}}}"#
            ),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT, "重名应 409");

    // 未知角色 id → 422(合法 uuid 但不在目录)
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            r#"{"username":"ghosty","email":null,"password":"password123","roles":["00000000-0000-0000-0000-000000000000"]}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "未知角色应 422"
    );

    // 空 username → 422(garde length(min=1))
    let response = app
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            r#"{"username":"","email":null,"password":"password123","roles":[]}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "空 username 应 422"
    );
}

// ── 3. 列表:过滤 / 排序 / 分页 / 正反选 / cursor 拒排序 ──

#[tokio::test]
async fn list_filter_sort_page() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    // alice/bob 带 user 角色,carol 带 admin 角色(令正反选有区分度)。
    create_user(&app, &superadmin, "alice", &["user"]).await;
    create_user(&app, &superadmin, "bob", &["user"]).await;
    create_user(&app, &superadmin, "carol", &["admin"]).await;

    // username=a(子串)+ 按 username 升序 + offset 首页 + total:命中 alice、carol(bob 无 'a')。
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/admin/auth/users?username=a&sort_by=username&order=asc&page=1&with_total=true",
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = json_body(response).await;
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["username"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["alice", "carol"],
        "username=a 升序应为 [alice, carol]"
    );
    assert_eq!(page["page_info"]["total"].as_u64(), Some(2), "total 应为 2");

    // 正选 role=user → alice、bob 命中,carol(admin)不在。
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?role=user", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = json_body(response).await;
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["username"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"alice") && names.contains(&"bob"),
        "role=user 应含 alice/bob: {names:?}"
    );
    assert!(
        !names.contains(&"carol"),
        "role=user 不应含 carol: {names:?}"
    );

    // 反选 role_not=user → 排除 alice/bob,仅 carol。
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?role_not=user", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = json_body(response).await;
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["username"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"carol"),
        "role_not=user 应含 carol: {names:?}"
    );
    assert!(
        !names.contains(&"alice") && !names.contains(&"bob"),
        "role_not=user 不应含 alice/bob: {names:?}"
    );

    // cursor 模式(空 cursor = 首页)+ 非默认 sort_by → 422(keyset 恒按 id,排序仅 offset)。
    let response = app
        .oneshot(get(
            "/api/v1/admin/auth/users?cursor=&sort_by=username",
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "cursor + 非默认 sort_by 应 422"
    );
}

// ── 3b. 内存回退(无 search 后端):q / sort_by=display_name → 422;plain/空白 q → 200 ──

/// 本套 harness(`test_app`)装的 `UserAdminService::search = None`(无 search 投影后端)→
/// `list()` 走 idm 直查回退路,`q`/`sort_by=display_name` 因回退路不具备搜索能力而 422
/// (纯空白 q trim 后视为"未搜索",仍走回退且 200)。
#[tokio::test]
async fn list_memory_fallback_rejects_q_and_display_name_sort() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;

    // q=alice → 422(无 search 后端无法提供跨字段搜索)
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?q=alice", &superadmin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "无 search 后端时 q 应 422"
    );

    // sort_by=display_name → 422(回退路无法排 display_name)
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/admin/auth/users?sort_by=display_name",
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "无 search 后端时 sort_by=display_name 应 422"
    );

    // q=（纯空白,url-encoded）→ 200(trim 后为空,不算"要搜索",落回 idm 直查)
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?q=%20%20", &superadmin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "纯空白 q 应落回 idm 直查,200"
    );

    // plain(无 q、默认 sort)→ 200,回退 idm 直查照常
    let response = app
        .oneshot(get("/api/v1/admin/auth/users", &superadmin))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "plain 请求应 200(回退 idm 直查照常)"
    );
}

// ── 4. 富化:PUT profile 后 list 该行 display_name 命中 ──

#[tokio::test]
async fn list_enriches_display_name_from_profile() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let id = create_user(&app, &superadmin, "erin", &["user"]).await;

    // superadmin(有 profiles:write:all)替 erin 建资料
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/profiles/{id}"),
            r#"{"display_name":"Alice A","phone":null,"avatar_content_id":null}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "PUT profile 应成功,得 {}",
        response.status()
    );

    // list erin → display_name 富化命中(内存模式,富化端口读同一 profile repo)
    let response = app
        .oneshot(get("/api/v1/admin/auth/users?username=erin", &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = json_body(response).await;
    assert_eq!(
        page["items"][0]["display_name"].as_str(),
        Some("Alice A"),
        "list 应富化 display_name"
    );
}

// ── 5. 查 / 改 / 删 ──

#[tokio::test]
async fn get_update_delete() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let id = create_user(&app, &superadmin, "gina", &["user"]).await;
    create_user(&app, &superadmin, "taken", &["user"]).await;

    // GET 存在 → 200,created_at 可解析
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/admin/auth/users/{id}"), &superadmin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let user = json_body(response).await;
    assert!(
        OffsetDateTime::parse(user["created_at"].as_str().unwrap(), &Rfc3339,).is_ok(),
        "created_at 应可解析"
    );

    // GET 随机 uuid → 404
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/auth/users/{}", Uuid::now_v7()),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "不存在应 404");

    // PUT 改 username → 200
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}"),
            r#"{"username":"gina2","email":null}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["username"].as_str(),
        Some("gina2")
    );

    // PUT 改名撞已有 username → 409
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}"),
            r#"{"username":"taken","email":null}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT, "撞名应 409");

    // DELETE → 204,再 DELETE → 404
    let response = app
        .clone()
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{id}"),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "软删应 204");
    let response = app
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{id}"),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "再删应 404");
}

// ── 6. 设角色(全量替换) ──

#[tokio::test]
async fn set_roles_full_replace() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let id = create_user(&app, &superadmin, "roleuser", &["user"]).await;
    let admin_user = role_ids_json(&app, &superadmin, &["admin", "user"]).await;

    // 全量设 [admin, user] → 200 + roles 集 == {admin, user}(响应仍是名字,order-insensitive)
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/roles"),
            &format!(r#"{{"roles":{admin_user}}}"#),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        sorted_roles(&json_body(response).await),
        vec!["admin".to_owned(), "user".to_owned()]
    );

    // 含未知角色 id → 422(全量原子,不留半态)
    let response = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/roles"),
            r#"{"roles":["00000000-0000-0000-0000-000000000000"]}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "未知角色应 422"
    );
}

// ── 7. 重置密码 ──

#[tokio::test]
async fn reset_password_204() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let id = create_user(&app, &superadmin, "pwuser", &["user"]).await;

    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{id}/password"),
            r#"{"new_password":"newpass123"}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "重置密码应 204");
    // 撤会话是 best-effort 且本套 auth 用独立 repo,不测 refresh 撤销(harness 不共享登录态)。
}

// ── 8. 用户资料(纳入 users:admin) ──

/// 后台改/读用户资料走 users:admin(不再需要 profiles:write:all)。avatar 上传路径由
/// openapi_authz 契约钉 gate;此处验 GET/PUT display_name/phone 的往返 + admin(无 users:admin)403。
#[tokio::test]
async fn admin_profile_get_put_under_users_admin() {
    let TestApp {
        app,
        superadmin,
        admin,
    } = test_app().await;
    let id = create_user(&app, &superadmin, "profiled", &["user"]).await;

    // superadmin PUT 资料 → 200
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/profile"),
            r#"{"display_name":"Ada Admin","phone":"123","avatar_content_id":null}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "改资料应 200");
    assert_eq!(json_body(response).await["display_name"], "Ada Admin");

    // superadmin GET 资料 → 200 命中
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/auth/users/{id}/profile"),
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["display_name"], "Ada Admin");

    // admin(只有 admin:login,无 users:admin)→ 403
    let response = app
        .oneshot(get(
            &format!("/api/v1/admin/auth/users/{id}/profile"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "无 users:admin 应 403"
    );
}

// ── 9. 提权闸:对**目标现有角色**的闸(改密码 / 删号) ──

/// 中间管理员(users:admin 但非满权)的令牌。`dev()` 是固定内嵌密钥对,独立签的令牌 app 侧照验。
fn useradmin_token() -> String {
    AppTokenSigner::new_with_development_key()
        .mint_scoped(
            Uuid::now_v7(),
            "useradmin",
            vec!["useradmin".to_owned()],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["useradmin".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap()
}

/// **改密码 = 能以对方身份登录**,所以必须闸目标现有角色:中间管理员改不动持平台角色账号(平台管理员 / superadmin)的密码。
/// 没这道闸,本模块辛苦建的提权闸(set_roles 挡着授不出 superadmin)就被这个端点整个绕过 ——
/// 把 superadmin 密码改成自己知道的,登进去就是 Permission::ALL。
#[tokio::test]
async fn intermediate_admin_cannot_reset_a_platform_admin_password() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let user_admin_token = useradmin_token();
    let victim = create_user(&app, &superadmin, "target-sa", &["platform_admin"]).await;
    let plain = create_user(&app, &superadmin, "target-user", &["user"]).await;

    // 打更高权目标 → 403
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{victim}/password"),
            r#"{"new_password":"pwned123456"}"#,
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能改平台管理员的密码(改了就能登进去接管)"
    );

    // 打同级/更低权目标 → 照常放行(别把闸收成谁都改不了)
    let response = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{plain}/password"),
            r#"{"new_password":"newpass123"}"#,
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "改普通用户密码是 users:admin 的正常职权"
    );

    // superadmin 自己打平台管理员 → 过(持 platform:roles + 目标全部权)
    let response = app
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{victim}/password"),
            r#"{"new_password":"newpass123"}"#,
            &superadmin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "superadmin 恒过闸"
    );
}

/// 删号同理:中间管理员删不掉平台管理员(破坏而非接管,但同属"对更高权目标动手")。
#[tokio::test]
async fn intermediate_admin_cannot_delete_a_platform_admin() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let user_admin_token = useradmin_token();
    let victim = create_user(&app, &superadmin, "del-target-sa", &["platform_admin"]).await;
    let plain = create_user(&app, &superadmin, "del-target-user", &["user"]).await;

    let response = app
        .clone()
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{victim}"),
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能删平台管理员"
    );

    let response = app
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{plain}"),
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "删普通用户是正常职权"
    );
}

/// 全量替换角色也得闸**目标现有角色**:中间管理员不能把平台管理员降权/清空。
/// 被授角色闸只管"授出去的",自锁闸只护 actor 自己 —— 少了这道,传一组"自己也有的角色"
/// 就能剥掉 superadmin 的权;若那是唯一的 superadmin,系统再无人能改回来。
#[tokio::test]
async fn intermediate_admin_cannot_strip_a_platform_admin_roles() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let user_admin_token = useradmin_token();
    let victim = create_user(&app, &superadmin, "roles-target-sa", &["platform_admin"]).await;
    let plain = create_user(&app, &superadmin, "roles-target-user", &["user"]).await;
    let user_ids = role_ids_json(&app, &superadmin, &["user"]).await;

    // 把平台管理员降成 user(被授角色 `user` 中间管理员自己够得着 → 只能靠目标闸拦)
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{victim}/roles"),
            &format!(r#"{{"roles":{user_ids}}}"#),
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能剥掉平台管理员的角色"
    );

    // 改同级/更低权目标 → 照常放行
    let response = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{plain}/roles"),
            &format!(r#"{{"roles":{user_ids}}}"#),
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "改普通用户角色是正常职权"
    );
}

/// 改身份字段同样闸目标现有角色:改掉平台管理员的 username 就等于把它锁在门外(登录靠 username)。
/// 本模块四个写端点(update/delete/reset_password/set_roles)口径必须一致。
#[tokio::test]
async fn intermediate_admin_cannot_rename_a_platform_admin() {
    let TestApp {
        app, superadmin, ..
    } = test_app().await;
    let user_admin_token = useradmin_token();
    let victim = create_user(&app, &superadmin, "rename-target-sa", &["platform_admin"]).await;
    let plain = create_user(&app, &superadmin, "rename-target-user", &["user"]).await;

    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{victim}"),
            r#"{"username":"hijacked","email":null}"#,
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能改平台管理员的身份字段"
    );

    let response = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{plain}"),
            r#"{"username":"renamed-ok","email":null}"#,
            &user_admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "改普通用户是正常职权");
}

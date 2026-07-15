//! admin user CRUD 黑盒集成测试 —— 内存模式(无 DB)、单进程 `Both`,oneshot 打真实端点。
//! harness 镜像 `tests/widget_api.rs`:struct 直建 `AppState` + mint 令牌(不走真实登录)。
//! 与 widget 不同处:idm user/role repo **共享**(sharing_with)且预置角色,profile repo 与
//! `profiles` 服务和富化端口(InProcessProfileDirectory)**同一实例** —— 才能端到端验富化。

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
use baserust::features::profile::{
    InMemoryProfileRepo, ProfileRepo, ProfileService, StaticAvatarProbe,
};
use baserust::features::users::UserAdminService;
use baserust::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, StaticUserDirectory, WidgetService,
};
use baserust::infra::authz::{Perm, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, RoleRepo};

/// 内存 app + 两个令牌:`superadmin`(有 users:admin,满权)与 `admin`(只有 admin:login)。
/// idm user/role repo 共享并预置角色(superadmin/admin/user,即 RoleName 闭集);profile repo 三方共享 →
/// 富化可端到端断言。auth 服务用独立占位 repo(本套不测真实登录)。
async fn test_app() -> (Router, String, String) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());

    // idm 身份 repo:user 与 role **共享** RoleStore + 预置可分配角色(建号/设角色靠它解析名→id)。
    let mem_users = InMemoryUserRepo::new();
    let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
    for (name, display) in [
        ("superadmin", "Super"),
        ("admin", "Admin"),
        ("user", "User"),
    ] {
        mem_roles.upsert(name, display, None).await.unwrap();
    }
    let users_repo: Arc<dyn idm::UserRepo> = Arc::new(mem_users);
    let roles_repo: Arc<dyn RoleRepo> = Arc::new(mem_roles);
    let sessions_repo: Arc<dyn idm::SessionRepo> = Arc::new(InMemorySessionRepo::new());

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
    // (见 users/routes.rs 头注)。线上 seed 里没有这个角色,但 role→perms 是运行期可改的
    // (`role_permissions` 表),superadmin 随时能造出这类主体,故闸必须对它成立。
    let policy = Policy::from_roles([
        ("superadmin".to_owned(), Perm::ALL.to_vec()),
        ("admin".to_owned(), vec![Perm::AdminLogin]),
        (
            "useradmin".to_owned(),
            vec![Perm::AdminLogin, Perm::UsersAdmin],
        ),
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
        auth: test_auth(signer.clone(), verifier.clone()),
        user_admin,
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(policy),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
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
    (app, superadmin, admin)
}

/// 测试用 content 服务:全内存(repo + ObjectStore),不碰 DB/minio。
fn test_contents() -> content::ContentService {
    content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        Arc::new(content::InMemoryObjectStore::new()),
        "memory",
    )
}

/// 测试用 AuthService:FakeHasher + 独立内存 repo(本套不测登录/refresh) + 生产同款签验。
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

// ── 请求/响应小工具(镜像 widget_api) ──

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
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/roles", token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "取角色目录应 200");
    let v = json_body(resp).await;
    let items = v["items"].as_array().unwrap();
    let ids: Vec<&str> = names
        .iter()
        .map(|n| {
            items
                .iter()
                .find(|r| r["name"].as_str() == Some(n))
                .unwrap_or_else(|| panic!("角色目录缺 {n}"))["id"]
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
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/admin/auth/users", &body, token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "建 {username} 应 201");
    let v = json_body(resp).await;
    v["id"].as_str().unwrap().to_owned()
}

/// 收集响应体里的 roles 数组为排序后的 Vec(角色比较 order-insensitive)。
fn sorted_roles(v: &serde_json::Value) -> Vec<String> {
    let mut r: Vec<String> = v["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    r.sort();
    r
}

// ── 1. 授权矩阵 ──

/// 无 token → 401;`admin`(admin:login 无 users:admin)→ 403;`superadmin` → 200。
#[tokio::test]
async fn authz_matrix() {
    let (app, superadmin, admin) = test_app().await;

    // 无 token → 组闸 require_admin_login 401
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/auth/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "无 token 应 401");

    // admin 过组闸(有 admin:login)但 handler require_scoped(users:admin) → 403
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users", &admin))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "admin 无 users:admin 应 403"
    );

    // superadmin → 200
    let resp = app
        .oneshot(get("/api/v1/admin/auth/users", &superadmin))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "superadmin 应 200");
}

// ── 2. 建号 ──

#[tokio::test]
async fn create_user_cases() {
    let (app, sa, _admin) = test_app().await;
    let user_ids = role_ids_json(&app, &sa, &["user"]).await;

    // 合法建号 → 201 + roles 命中(响应 roles 仍是名字)
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            &format!(
                r#"{{"username":"neo","email":"neo@example.com","password":"password123","roles":{user_ids}}}"#
            ),
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = json_body(resp).await;
    assert_eq!(
        v["roles"].as_array().unwrap(),
        &vec![serde_json::json!("user")]
    );
    // created_at 存在且可解析(单查是占位值,只断言 present/parseable,不断言精确值)
    assert!(
        time::OffsetDateTime::parse(
            v["created_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok(),
        "created_at 应是可解析的 rfc3339"
    );

    // 重名 → 409
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            &format!(
                r#"{{"username":"neo","email":null,"password":"password123","roles":{user_ids}}}"#
            ),
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "重名应 409");

    // 未知角色 id → 422(合法 uuid 但不在目录)
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            r#"{"username":"ghosty","email":null,"password":"password123","roles":["00000000-0000-0000-0000-000000000000"]}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "未知角色应 422"
    );

    // 空 username → 422(garde length(min=1))
    let resp = app
        .oneshot(post_json(
            "/api/v1/admin/auth/users",
            r#"{"username":"","email":null,"password":"password123","roles":[]}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "空 username 应 422"
    );
}

// ── 3. 列表:过滤 / 排序 / 分页 / 正反选 / cursor 拒排序 ──

#[tokio::test]
async fn list_filter_sort_page() {
    let (app, sa, _admin) = test_app().await;
    // alice/bob 带 user 角色,carol 带 admin 角色(令正反选有区分度)。
    create_user(&app, &sa, "alice", &["user"]).await;
    create_user(&app, &sa, "bob", &["user"]).await;
    create_user(&app, &sa, "carol", &["admin"]).await;

    // username=a(子串)+ 按 username 升序 + offset 首页 + total:命中 alice、carol(bob 无 'a')。
    let resp = app
        .clone()
        .oneshot(get(
            "/api/v1/admin/auth/users?username=a&sort_by=username&order=asc&page=1&with_total=true",
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    let names: Vec<&str> = v["items"]
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
    assert_eq!(v["page_info"]["total"].as_u64(), Some(2), "total 应为 2");

    // 正选 role=user → alice、bob 命中,carol(admin)不在。
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?role=user", &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    let names: Vec<&str> = v["items"]
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
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?role_not=user", &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    let names: Vec<&str> = v["items"]
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
    let resp = app
        .oneshot(get(
            "/api/v1/admin/auth/users?cursor=&sort_by=username",
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
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
    let (app, sa, _admin) = test_app().await;

    // q=alice → 422(无 search 后端无法提供跨字段搜索)
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?q=alice", &sa))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "无 search 后端时 q 应 422"
    );

    // sort_by=display_name → 422(回退路无法排 display_name)
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?sort_by=display_name", &sa))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "无 search 后端时 sort_by=display_name 应 422"
    );

    // q=（纯空白,url-encoded）→ 200(trim 后为空,不算"要搜索",落回 idm 直查)
    let resp = app
        .clone()
        .oneshot(get("/api/v1/admin/auth/users?q=%20%20", &sa))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "纯空白 q 应落回 idm 直查,200"
    );

    // plain(无 q、默认 sort)→ 200,回退 idm 直查照常
    let resp = app
        .oneshot(get("/api/v1/admin/auth/users", &sa))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "plain 请求应 200(回退 idm 直查照常)"
    );
}

// ── 4. 富化:PUT profile 后 list 该行 display_name 命中 ──

#[tokio::test]
async fn list_enriches_display_name_from_profile() {
    let (app, sa, _admin) = test_app().await;
    let id = create_user(&app, &sa, "erin", &["user"]).await;

    // superadmin(有 profiles:write:all)替 erin 建资料
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/profiles/{id}"),
            r#"{"display_name":"Alice A","phone":null,"avatar_content_id":null}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "PUT profile 应成功,得 {}",
        resp.status()
    );

    // list erin → display_name 富化命中(内存模式,富化端口读同一 profile repo)
    let resp = app
        .oneshot(get("/api/v1/admin/auth/users?username=erin", &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(
        v["items"][0]["display_name"].as_str(),
        Some("Alice A"),
        "list 应富化 display_name"
    );
}

// ── 5. 查 / 改 / 删 ──

#[tokio::test]
async fn get_update_delete() {
    let (app, sa, _admin) = test_app().await;
    let id = create_user(&app, &sa, "gina", &["user"]).await;
    create_user(&app, &sa, "taken", &["user"]).await;

    // GET 存在 → 200,created_at 可解析
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/admin/auth/users/{id}"), &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert!(
        time::OffsetDateTime::parse(
            v["created_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok(),
        "created_at 应可解析"
    );

    // GET 随机 uuid → 404
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/auth/users/{}", Uuid::now_v7()),
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "不存在应 404");

    // PUT 改 username → 200
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}"),
            r#"{"username":"gina2","email":null}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["username"].as_str(), Some("gina2"));

    // PUT 改名撞已有 username → 409
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}"),
            r#"{"username":"taken","email":null}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "撞名应 409");

    // DELETE → 204,再 DELETE → 404
    let resp = app
        .clone()
        .oneshot(delete_req(&format!("/api/v1/admin/auth/users/{id}"), &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "软删应 204");
    let resp = app
        .oneshot(delete_req(&format!("/api/v1/admin/auth/users/{id}"), &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "再删应 404");
}

// ── 6. 设角色(全量替换) ──

#[tokio::test]
async fn set_roles_full_replace() {
    let (app, sa, _admin) = test_app().await;
    let id = create_user(&app, &sa, "roleuser", &["user"]).await;
    let admin_user = role_ids_json(&app, &sa, &["admin", "user"]).await;

    // 全量设 [admin, user] → 200 + roles 集 == {admin, user}(响应仍是名字,order-insensitive)
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/roles"),
            &format!(r#"{{"roles":{admin_user}}}"#),
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        sorted_roles(&json_body(resp).await),
        vec!["admin".to_owned(), "user".to_owned()]
    );

    // 含未知角色 id → 422(全量原子,不留半态)
    let resp = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/roles"),
            r#"{"roles":["00000000-0000-0000-0000-000000000000"]}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "未知角色应 422"
    );
}

// ── 7. 重置密码 ──

#[tokio::test]
async fn reset_password_204() {
    let (app, sa, _admin) = test_app().await;
    let id = create_user(&app, &sa, "pwuser", &["user"]).await;

    let resp = app
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{id}/password"),
            r#"{"new_password":"newpass123"}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "重置密码应 204");
    // 撤会话是 best-effort 且本套 auth 用独立 repo,不测 refresh 撤销(harness 不共享登录态)。
}

// ── 8. 用户资料(纳入 users:admin) ──

/// 后台改/读用户资料走 users:admin(不再需要 profiles:write:all)。avatar 上传路径由
/// openapi_authz 契约钉 gate;此处验 GET/PUT display_name/phone 的往返 + admin(无 users:admin)403。
#[tokio::test]
async fn admin_profile_get_put_under_users_admin() {
    let (app, sa, admin) = test_app().await;
    let id = create_user(&app, &sa, "profiled", &["user"]).await;

    // superadmin PUT 资料 → 200
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{id}/profile"),
            r#"{"display_name":"Ada Admin","phone":"123","avatar_content_id":null}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "改资料应 200");
    assert_eq!(json_body(resp).await["display_name"], "Ada Admin");

    // superadmin GET 资料 → 200 命中
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/admin/auth/users/{id}/profile"), &sa))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["display_name"], "Ada Admin");

    // admin(只有 admin:login,无 users:admin)→ 403
    let resp = app
        .oneshot(get(
            &format!("/api/v1/admin/auth/users/{id}/profile"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "无 users:admin 应 403"
    );
}

// ── 9. 提权闸:对**目标现有角色**的闸(改密码 / 删号) ──

/// 中间管理员(users:admin 但非满权)的令牌。`dev()` 是固定内嵌密钥对,独立签的令牌 app 侧照验。
fn useradmin_token() -> String {
    AppTokenSigner::dev()
        .mint_scoped(
            Uuid::now_v7(),
            "useradmin",
            vec!["useradmin".to_owned()],
            vec![],
            900,
        )
        .unwrap()
}

/// **改密码 = 能以对方身份登录**,所以必须闸目标现有角色:中间管理员改不动 superadmin 的密码。
/// 没这道闸,本模块辛苦建的提权闸(set_roles 挡着授不出 superadmin)就被这个端点整个绕过 ——
/// 把 superadmin 密码改成自己知道的,登进去就是 Perm::ALL。
#[tokio::test]
async fn intermediate_admin_cannot_reset_a_superadmin_password() {
    let (app, sa, _admin) = test_app().await;
    let ua = useradmin_token();
    let victim = create_user(&app, &sa, "target-sa", &["superadmin"]).await;
    let plain = create_user(&app, &sa, "target-user", &["user"]).await;

    // 打更高权目标 → 403
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{victim}/password"),
            r#"{"new_password":"pwned123456"}"#,
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能改 superadmin 的密码(改了就能登进去接管)"
    );

    // 打同级/更低权目标 → 照常放行(别把闸收成谁都改不了)
    let resp = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{plain}/password"),
            r#"{"new_password":"newpass123"}"#,
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "改普通用户密码是 users:admin 的正常职权"
    );

    // superadmin 自己打 superadmin → 恒过(满权者持有目标全部权)
    let resp = app
        .oneshot(post_json(
            &format!("/api/v1/admin/auth/users/{victim}/password"),
            r#"{"new_password":"newpass123"}"#,
            &sa,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "superadmin 恒过闸");
}

/// 删号同理:中间管理员删不掉 superadmin(破坏而非接管,但同属"对更高权目标动手")。
#[tokio::test]
async fn intermediate_admin_cannot_delete_a_superadmin() {
    let (app, sa, _admin) = test_app().await;
    let ua = useradmin_token();
    let victim = create_user(&app, &sa, "del-target-sa", &["superadmin"]).await;
    let plain = create_user(&app, &sa, "del-target-user", &["user"]).await;

    let resp = app
        .clone()
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{victim}"),
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能删 superadmin"
    );

    let resp = app
        .oneshot(delete_req(
            &format!("/api/v1/admin/auth/users/{plain}"),
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "删普通用户是正常职权"
    );
}

/// 全量替换角色也得闸**目标现有角色**:中间管理员不能把 superadmin 降权/清空。
/// 被授角色闸只管"授出去的",自锁闸只护 actor 自己 —— 少了这道,传一组"自己也有的角色"
/// 就能剥掉 superadmin 的权;若那是唯一的 superadmin,系统再无人能改回来。
#[tokio::test]
async fn intermediate_admin_cannot_strip_a_superadmin_roles() {
    let (app, sa, _admin) = test_app().await;
    let ua = useradmin_token();
    let victim = create_user(&app, &sa, "roles-target-sa", &["superadmin"]).await;
    let plain = create_user(&app, &sa, "roles-target-user", &["user"]).await;
    let user_ids = role_ids_json(&app, &sa, &["user"]).await;

    // 把 superadmin 降成 user(被授角色 `user` 中间管理员自己够得着 → 只能靠目标闸拦)
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{victim}/roles"),
            &format!(r#"{{"roles":{user_ids}}}"#),
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能剥掉 superadmin 的角色"
    );

    // 改同级/更低权目标 → 照常放行
    let resp = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{plain}/roles"),
            &format!(r#"{{"roles":{user_ids}}}"#),
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "改普通用户角色是正常职权");
}

/// 改身份字段同样闸目标现有角色:改掉 superadmin 的 username 就等于把它锁在门外(登录靠 username)。
/// 本模块四个写端点(update/delete/reset_password/set_roles)口径必须一致。
#[tokio::test]
async fn intermediate_admin_cannot_rename_a_superadmin() {
    let (app, sa, _admin) = test_app().await;
    let ua = useradmin_token();
    let victim = create_user(&app, &sa, "rename-target-sa", &["superadmin"]).await;
    let plain = create_user(&app, &sa, "rename-target-user", &["user"]).await;

    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{victim}"),
            r#"{"username":"hijacked","email":null}"#,
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "中间管理员不该能改 superadmin 的身份字段"
    );

    let resp = app
        .oneshot(put_json(
            &format!("/api/v1/admin/auth/users/{plain}"),
            r#"{"username":"renamed-ok","email":null}"#,
            &ua,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "改普通用户是正常职权");
}

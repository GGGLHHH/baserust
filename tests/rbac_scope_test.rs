//! RBAC + scope 授权**契约测试** —— 用同一套 seed 数据(admin/user/superadmin,见 `seed.toml`)。
//!
//! 范式演示:授权归 app。这里把几个 **mock 端点** gate 在 `Perm` 上(`state.policy.require_scoped`),
//! 过**真实** `authenticate` 中间件 + 真实 `AppState::new`(进程内 seed,内存仓储,无 DB):
//! - **RBAC**:role→权限来自 seed.toml;admin 能写、user 只读、users:admin 仅 superadmin。
//! - **scope**:`mint_scoped` 签的降权令牌即便 role 够,scope 没给也拒(有效权限 = role 权限 ∩ scope)。
//!
//! 401(没认证)vs 403(认证了但无权限)严格区分。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::Router;
use tower::ServiceExt; // oneshot
use uuid::Uuid;

use idm::{AuthOutcome, LoginInput};
use xchangeai::app::{build_router, AppState, Mount};
use xchangeai::features::auth::authenticate;
use xchangeai::infra::audit::CurrentUser;
use xchangeai::infra::authz::{Perm, TokenScope};
use xchangeai::infra::config::Config;
use xchangeai::infra::error::AppError;
use xchangeai::infra::pagination::PageQuery;

// ── mock 端点:每个 gate 在一个 Perm 上(范式:require_scoped 同时管 RBAC 与 scope)──

async fn demo_read(
    axum::extract::State(s): axum::extract::State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<StatusCode, AppError> {
    s.policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    Ok(StatusCode::OK)
}

async fn demo_write(
    axum::extract::State(s): axum::extract::State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<StatusCode, AppError> {
    s.policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetWrite)?;
    Ok(StatusCode::OK)
}

async fn demo_admin(
    axum::extract::State(s): axum::extract::State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<StatusCode, AppError> {
    s.policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(StatusCode::NO_CONTENT)
}

/// 真实 AppState(内存,进程内 seed 出 admin/user/superadmin)+ mock 端点 + 真实鉴权中间件。
async fn setup() -> (AppState, Router) {
    let state = AppState::new(&Config::default(), Mount::Both)
        .await
        .expect("内存模式 AppState 应可建(含进程内 seed)");
    let app = Router::new()
        .route("/demo/read", get(demo_read))
        .route("/demo/write", post(demo_write))
        .route("/demo/admin", delete(demo_admin))
        .layer(from_fn_with_state(state.clone(), authenticate))
        .with_state(state.clone());
    (state, app)
}

async fn login(state: &AppState, who: &str) -> AuthOutcome {
    state
        .auth
        .login(LoginInput {
            identifier: who.to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap_or_else(|_| panic!("seed 用户 {who}:pwd 应能登录"))
}

fn req(method: &str, uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

async fn status(app: &Router, method: &str, uri: &str, bearer: Option<&str>) -> StatusCode {
    app.clone()
        .oneshot(req(method, uri, bearer))
        .await
        .unwrap()
        .status()
}

// ── RBAC ──

#[tokio::test]
async fn rbac_admin_writes_user_cannot_but_user_reads() {
    let (state, app) = setup().await;
    let admin = login(&state, "admin").await.access_token;
    let user = login(&state, "user").await.access_token;

    // admin 有 widgets:write → 200;user 没有 → 403(认证了但无权限,非 401)
    assert_eq!(
        status(&app, "POST", "/demo/write", Some(&admin)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&app, "POST", "/demo/write", Some(&user)).await,
        StatusCode::FORBIDDEN
    );
    // 两者都有 widgets:read → 200
    assert_eq!(
        status(&app, "GET", "/demo/read", Some(&admin)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&app, "GET", "/demo/read", Some(&user)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rbac_users_admin_perm_is_superadmin_only() {
    let (state, app) = setup().await;
    let admin = login(&state, "admin").await.access_token;
    let superadmin = login(&state, "superadmin").await.access_token;

    // users:admin 只给了 superadmin;admin 没有 → 403
    assert_eq!(
        status(&app, "DELETE", "/demo/admin", Some(&admin)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&app, "DELETE", "/demo/admin", Some(&superadmin)).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn unauthenticated_is_401_not_403() {
    let (_state, app) = setup().await;
    // 无 token → CurrentUser 提取失败 → 401(区别于"认证了但没权限"的 403)
    assert_eq!(
        status(&app, "GET", "/demo/read", None).await,
        StatusCode::UNAUTHORIZED
    );
}

// ── scope:降权令牌 ──

#[tokio::test]
async fn scope_downscopes_below_role_grant() {
    let (state, app) = setup().await;
    let admin = login(&state, "admin").await;

    // 给 admin 签一个**只含 widgets:read** 的降权令牌(模拟 PAT / 第三方授权)
    let scoped = state
        .tokens
        .mint_scoped(
            admin.user.id,
            &admin.user.username,
            admin.user.roles.clone(),
            vec![Perm::WidgetRead],
            900,
        )
        .unwrap();

    // 满权令牌:admin 能写;降权令牌:role 够但 scope 没给 write → 403
    assert_eq!(
        status(&app, "POST", "/demo/write", Some(&admin.access_token)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&app, "POST", "/demo/write", Some(&scoped)).await,
        StatusCode::FORBIDDEN
    );
    // 降权令牌仍可读(scope 含 widgets:read,role 也有)
    assert_eq!(
        status(&app, "GET", "/demo/read", Some(&scoped)).await,
        StatusCode::OK
    );
}

// ── 数据所有权(ownership,行级):打**真实** /api/v1/frontend/widgets 端点(已 gate),数据来自 mock.toml seed ──
//
// 三轴扣点:RBAC∩scope 在边缘判"能不能读"+ data_access 推"看全部 or 自己",
// 过滤在查询层按 created_by 执行(repo)。superadmin/admin 有 read:all → 全见;user 无 → 只见自己的。

fn page_query() -> PageQuery {
    PageQuery {
        page: None,
        cursor: None,
        size: Some(100),
        with_total: None,
    }
}

/// 真实全量 app(含 widget 路由 + 鉴权中间件 + 三轴 gate)。
fn real_app(state: &AppState) -> Router {
    build_router(state.clone(), &Config::default(), Mount::Both)
}

async fn body_of(app: &Router, method: &str, uri: &str, bearer: Option<&str>) -> String {
    let resp = app.clone().oneshot(req(method, uri, bearer)).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// 经 service 直查某 mock widget 的 id(owner=None 看全部;id 运行期生成,按 name 找)。
async fn widget_id(state: &AppState, name: &str) -> Uuid {
    state
        .widgets
        .list(page_query(), None)
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("mock.toml 应 seed 出 widget {name}"))
        .id
}

#[tokio::test]
async fn ownership_user_sees_own_others_see_all() {
    // AppState::new 已从 mock.toml 幂等 seed:admin 拥 admin-w1/w2,user 拥 user-w1。
    let (state, _) = setup().await;
    let app = real_app(&state);
    let admin = login(&state, "admin").await.access_token;
    let user = login(&state, "user").await.access_token;
    let superadmin = login(&state, "superadmin").await.access_token;

    // user(无 read:all)→ /widgets 只列自己的 user-w1
    let u = body_of(&app, "GET", "/api/v1/frontend/widgets", Some(&user)).await;
    assert!(u.contains("user-w1"), "user 应见自己的: {u}");
    assert!(
        !u.contains("admin-w1") && !u.contains("admin-w2"),
        "user 不该见别人的: {u}"
    );
    // admin(read:all)→ 见全部三个
    let a = body_of(&app, "GET", "/api/v1/frontend/widgets", Some(&admin)).await;
    assert!(
        a.contains("admin-w1") && a.contains("admin-w2") && a.contains("user-w1"),
        "admin 应见全部: {a}"
    );
    // superadmin(read:all)→ 见全部
    let s = body_of(&app, "GET", "/api/v1/frontend/widgets", Some(&superadmin)).await;
    assert!(
        s.contains("admin-w1") && s.contains("user-w1"),
        "superadmin 应见全部: {s}"
    );
}

#[tokio::test]
async fn ownership_get_others_widget_is_404_not_403() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    let user = login(&state, "user").await.access_token;
    let admin = login(&state, "admin").await.access_token;
    let others = format!(
        "/api/v1/frontend/widgets/{}",
        widget_id(&state, "admin-w1").await
    ); // admin 的
    let own = format!(
        "/api/v1/frontend/widgets/{}",
        widget_id(&state, "user-w1").await
    ); // user 自己的

    // user 取别人的 → 404(不泄露"这行存在",区别于 403)
    assert_eq!(
        status(&app, "GET", &others, Some(&user)).await,
        StatusCode::NOT_FOUND
    );
    // user 取自己的 → 200
    assert_eq!(status(&app, "GET", &own, Some(&user)).await, StatusCode::OK);
    // admin(read:all)取别人的 → 200
    assert_eq!(
        status(&app, "GET", &others, Some(&admin)).await,
        StatusCode::OK
    );
}

/// 跨模块富化**成功主路径** e2e:真实 `InProcessUserDirectory`(非内存桩)把 created_by 填成用户 brief。
/// user 列自己的 user-w1(created_by = user 的 id)→ 响应带 `created_by_user.username`。
#[tokio::test]
async fn enrichment_fills_created_by_user() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    let user = login(&state, "user").await.access_token;
    let body = body_of(&app, "GET", "/api/v1/frontend/widgets", Some(&user)).await;
    assert!(
        body.contains("\"username\":\"user\""),
        "富化应把 created_by 解析成用户 brief(username): {body}"
    );
}

// ── 其余授权形态:public / 仅登录 / superadmin-only(打真实新增的 /api/v1/frontend/widgets 端点)──

/// public:`/widgets/stats` 无 token 也 200,且统计到 mock seed 的 3 个 widget。
#[tokio::test]
async fn public_stats_needs_no_auth() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    assert_eq!(
        status(&app, "GET", "/api/v1/public/widgets/stats", None).await,
        StatusCode::OK
    );
    let body = body_of(&app, "GET", "/api/v1/public/widgets/stats", None).await;
    assert!(
        body.contains("\"total\":3"),
        "应统计 mock 的 3 个 widget: {body}"
    );
}

/// 仅登录:`/widgets/my-count` 无 token → 401;登录后 200,且只数自己的(user 拥 user-w1 → 1)。
#[tokio::test]
async fn my_count_needs_login_no_perm() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    let user = login(&state, "user").await.access_token;
    assert_eq!(
        status(&app, "GET", "/api/v1/frontend/widgets/my-count", None).await,
        StatusCode::UNAUTHORIZED
    );
    let body = body_of(
        &app,
        "GET",
        "/api/v1/frontend/widgets/my-count",
        Some(&user),
    )
    .await;
    assert!(
        body.contains("\"total\":1"),
        "user 自己有 1 个 user-w1: {body}"
    );
}

/// superadmin-only:`/api/v1/admin/widgets` gate `users:admin`。
/// **关键**:admin 虽有 read:all,但无 users:admin → 403;只有 superadmin → 200。
#[tokio::test]
async fn admin_list_is_superadmin_only() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    let user = login(&state, "user").await.access_token;
    let admin = login(&state, "admin").await.access_token;
    let superadmin = login(&state, "superadmin").await.access_token;

    assert_eq!(
        status(&app, "GET", "/api/v1/admin/widgets", Some(&user)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&app, "GET", "/api/v1/admin/widgets", Some(&admin)).await,
        StatusCode::FORBIDDEN,
        "admin 有 read:all 但无 users:admin → 仍 403"
    );
    assert_eq!(
        status(&app, "GET", "/api/v1/admin/widgets", Some(&superadmin)).await,
        StatusCode::OK
    );
}

/// 三轴扣点:scope 不含 `read:all` → 即便 admin 的 role 有,有效权限被 ∩ 掉 → ownership 跌回 Own。
#[tokio::test]
async fn scope_without_read_all_narrows_admin_to_own() {
    let (state, _) = setup().await;
    let app = real_app(&state);
    let admin = login(&state, "admin").await;

    // admin 满权令牌(role 含 read:all)→ 见全部(含 user-w1)
    let full = body_of(
        &app,
        "GET",
        "/api/v1/frontend/widgets",
        Some(&admin.access_token),
    )
    .await;
    assert!(full.contains("user-w1"), "满权应见全部: {full}");

    // admin 降权令牌:scope=[widgets:read],**不含 read:all** → 跌回 Own → 只见自己的
    let scoped = state
        .tokens
        .mint_scoped(
            admin.user.id,
            &admin.user.username,
            admin.user.roles.clone(),
            vec![Perm::WidgetRead],
            900,
        )
        .unwrap();
    let narrowed = body_of(&app, "GET", "/api/v1/frontend/widgets", Some(&scoped)).await;
    assert!(narrowed.contains("admin-w1"), "降权仍见自己的: {narrowed}");
    assert!(
        !narrowed.contains("user-w1"),
        "降权(无 read:all)应只见自己的: {narrowed}"
    );
}

/// `GET /permissions/me`:有效权限 = role 展开(含 implies)∩ scope,wire 串排序;
/// 降权令牌拿到收窄集;零权限令牌可达(仅登录)且集合为空。打真实 build_router 路由。
#[tokio::test]
async fn my_permissions_reflect_role_and_scope() {
    let config = Config::default();
    let state = AppState::new(&config, Mount::Both).await.unwrap();
    let app = build_router(state.clone(), &config, Mount::Both);
    let admin = state
        .auth
        .login(LoginInput {
            identifier: "admin".to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap();
    let mint = |roles: Vec<String>, scope: Vec<Perm>| {
        state
            .tokens
            .mint_scoped(admin.user.id, "probe", roles, scope, 900)
            .unwrap()
    };
    let fetch = |token: String| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::get("/api/v1/frontend/permissions/me")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        }
    };

    // 满权令牌:admin 全部 10 权(无 users:admin),含 implies 展开;排序稳定
    let v = fetch(admin.access_token.clone()).await;
    assert_eq!(v["roles"], serde_json::json!(["admin"]));
    let perms: Vec<&str> = v["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(perms.len(), 10, "admin 应 10 权,got {perms:?}");
    assert!(perms.contains(&"widgets:read:all"));
    assert!(!perms.contains(&"users:admin"));
    let mut sorted = perms.clone();
    sorted.sort_unstable();
    assert_eq!(perms, sorted, "应已排序");

    // 降权令牌 scope=[widgets:read:all]:implies 展开 → 恰好 read + read:all
    let v = fetch(mint(vec!["admin".to_owned()], vec![Perm::WidgetReadAll])).await;
    assert_eq!(
        v["permissions"],
        serde_json::json!(["widgets:read", "widgets:read:all"]),
        "scope 收窄集应精确"
    );

    // 零权限令牌(roles+scope 皆空):可达(仅登录),集合为空
    let v = fetch(mint(vec![], vec![])).await;
    assert_eq!(v["permissions"], serde_json::json!([]));
}

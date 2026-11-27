//! widget API 集成测试 —— lib.rs 拆分解锁的能力:
//! tests/ 直接 import 库、用内存仓储 oneshot 打**真实端点**(过完整中间件栈),无需数据库。
//! 加业务模块后,照此对其端点写黑盒测试。

use axum::body;
use baserust::app::{AppAuthService, AppContentService, Mount};
use baserust::features::auth::ScopedTenant;
use baserust::features::profile::{InMemoryProfileRepo, ProfileService, StaticAvatarProbe};
use baserust::features::tenants::{StaticMemberProfiles, TenantAdminService};
use baserust::features::users::{StaticProfileDirectory, UserAdminService};
use baserust::features::widget::{EventBus, MemoryEventBus, StaticUserDirectory};
use baserust::infra::config::Config;
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use idm::{InMemoryMemberRepo, InMemoryTenantRepo};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use uuid::Uuid;

use baserust::app::{build_router, AppState};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::widget::{InMemoryWidgetRepo, WidgetService};
use baserust::kernel::authorization::{Permission, Policy};
use idm::{FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

/// 内存仓储的测试 app(无 DB)+ **admin 令牌**(widget 端点现需登录 + RBAC + ownership)。
/// admin 有 read:all → 看全部,故沿用原有"建后即见"断言;struct 直建不跑 mock seed,repo 空、不受干扰。
fn test_app() -> (Router, String) {
    let signer = Arc::new(AppTokenSigner::new_with_development_key());
    let verifier = Arc::new(AppTokenVerifier::new_with_development_key());
    // admin 满权令牌(roles=[admin],scope 空):mint 即可,不必走真实登录。
    let admin = signer
        .mint_scoped(
            Uuid::nil(),
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
    let bus: Arc<dyn EventBus> = Arc::new(MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::new()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: ProfileService::new(
            Arc::new(InMemoryProfileRepo::new()),
            Arc::new(StaticAvatarProbe::new()),
        ),
        contents: test_contents(),
        auth: test_auth(signer.clone(), verifier.clone()),
        user_admin: UserAdminService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(StaticProfileDirectory::new()),
            None,
        ),
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
        policy: Arc::new(test_policy()),
        token_signer: Some(signer),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(state, &Config::default(), Mount::Both);
    (app, admin)
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

/// 测试授权策略:admin 角色拿全部 widget 权限(含 read:all / write:all → 跨用户读写)。
///
/// `user` = **"用户管理自己的 widget"** 这种最自然的配法:read + write + delete,**一个 `:all` 都不给**
/// → `Access::Own`(读写都只及自己创建的)。ownership 断言(读侧/写侧/SSE)都靠它。
/// 线上 seed 里 user 没有 write/delete,但 role→perm 运行期可改,这正是闸必须成立的那种配置。
fn test_policy() -> Policy {
    Policy::new([
        (
            "admin".to_owned(),
            vec![
                Permission::WidgetRead,
                Permission::WidgetReadAll,
                Permission::WidgetWrite,
                Permission::WidgetWriteAll,
                Permission::WidgetDelete,
            ],
        ),
        (
            "user".to_owned(),
            vec![
                Permission::WidgetRead,
                Permission::WidgetWrite,
                Permission::WidgetDelete,
            ],
        ),
    ])
}

/// 普通 user 的令牌(与 `test_app` 的 admin 不同主体;`dev()` 是固定内嵌密钥对,故独立签的
/// 令牌 app 侧照验)。返回 (token, user_id)。
fn user_token() -> (String, Uuid) {
    let user_id = Uuid::now_v7();
    let token = AppTokenSigner::new_with_development_key()
        .mint_scoped(
            user_id,
            "user",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["user".to_owned()],
            }),
            vec![],
            900,
        )
        .unwrap();
    (token, user_id)
}

/// 测试用 AuthService:FakeHasher + 内存 repo + **生产同款非对称签验**(claim 带 roles,中间件才认)。
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
    .access_ttl(::time::Duration::seconds(900))
    .refresh_ttl(::time::Duration::seconds(604_800))
    .build();
    Arc::new(auth)
}

async fn body_string(response: Response) -> String {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
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

/// 建后从 201 响应体取 id(响应是 `Widget` JSON)。
async fn created_id(response: Response) -> String {
    let body: Value = serde_json::from_str(&body_string(response).await).unwrap();
    body["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn health_ok() {
    let (app, token) = test_app();
    let response = app.oneshot(get("/health", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// widget 端点**必须登录**:无 token → 401。
#[tokio::test]
async fn widgets_require_auth_401() {
    let (app, _token) = test_app();
    let response = app
        .oneshot(
            Request::get("/api/v1/frontend/widgets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_then_list_offset() {
    let (app, token) = test_app();
    let response = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"alpha"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(get("/api/v1/frontend/widgets", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(body.contains("alpha"));
    // 默认 offset 模式,PageInfo 内部标签 mode=offset
    assert!(body.contains("\"mode\":\"offset\""));
}

#[tokio::test]
async fn cursor_first_page_ok() {
    let (app, token) = test_app();
    app.clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"a"}"#,
            &token,
        ))
        .await
        .unwrap();
    // 空 cursor = cursor 模式首页
    let response = app
        .oneshot(get("/api/v1/frontend/widgets?cursor=&size=2", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_string(response).await.contains("\"mode\":\"cursor\""));
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let (app, token) = test_app();
    let response = app
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":""}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let (app, token) = test_app();
    let response = app
        .oneshot(get("/api/v1/frontend/widgets?cursor=!!!bad", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let (app, token) = test_app();
    let response = app
        .oneshot(get("/api/v1/frontend/widgets?page=1&cursor=xxx", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn missing_widget_is_404() {
    let (app, token) = test_app();
    let response = app
        .oneshot(get(
            "/api/v1/frontend/widgets/00000000-0000-0000-0000-000000000000",
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 重名 → **409**:name 存活行内全局唯一,重复 create → Conflict(DB 约束违例下钻,非 500)。
#[tokio::test]
async fn duplicate_name_is_409() {
    let (app, token) = test_app();
    let first = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"dup"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let dup = app
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"dup"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

/// PUT **全量替换**:建后 PUT 改名 → 200,且改名生效(写动词状态码端到端契约)。
#[tokio::test]
async fn put_full_replace_renames_returns_200() {
    let (app, token) = test_app();
    let created = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"before"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let id = created_id(created).await;

    let put = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/widgets/{id}"),
            r#"{"name":"after"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    assert!(body_string(put).await.contains("after"));

    let got = app
        .oneshot(get(&format!("/api/v1/frontend/widgets/{id}"), &token))
        .await
        .unwrap();
    assert!(body_string(got).await.contains("after"), "改名应持久");
}

/// DELETE **软删** → 204,且删后 GET → 404(204 契约 + 软删后不可见)。
#[tokio::test]
async fn delete_soft_deletes_returns_204_then_404() {
    let (app, token) = test_app();
    let created = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/widgets",
            r#"{"name":"doomed"}"#,
            &token,
        ))
        .await
        .unwrap();
    let id = created_id(created).await;

    let deleted = app
        .clone()
        .oneshot(delete_req(
            &format!("/api/v1/frontend/widgets/{id}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let got = app
        .oneshot(get(&format!("/api/v1/frontend/widgets/{id}"), &token))
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::NOT_FOUND, "软删后应 404");
}

/// **写侧 ownership**:无 `widgets:write:all` 的 user 改不动/删不掉**别人的** widget(404,同 GET)。
/// 读侧一直有闸,写侧原本没有 → "读自己的、写所有人的":GET 别人的行 404,PUT/DELETE 却放行。
/// widget 是 adding-a-feature 指定照抄的样板,抄出去的每个 CRUD 模块都会继承这个洞。
#[tokio::test]
async fn write_ownership_others_widget_is_404() {
    let (app, admin) = test_app();
    let (user, _user_id) = user_token();

    // admin 建一个**别人的** widget
    let id = created_id(
        app.clone()
            .oneshot(post_json(
                "/api/v1/frontend/widgets",
                r#"{"name":"admins-widget"}"#,
                &admin,
            ))
            .await
            .unwrap(),
    )
    .await;

    // 对照:user 读它已经是 404(读侧闸,既有行为)
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/frontend/widgets/{id}"), &user))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "读别人的 → 404");

    // 写:必须同样 404(不是 200)—— 读不到却改得动 = 越权写
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/widgets/{id}"),
            r#"{"name":"pwned"}"#,
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "改别人的 widget 必须 404(读得到才改得动)"
    );

    // 删:同上
    let response = app
        .clone()
        .oneshot(delete_req(&format!("/api/v1/frontend/widgets/{id}"), &user))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "删别人的 widget 必须 404"
    );

    // 别把闸收成"谁都写不了":user 改自己的照常 200
    let mine = created_id(
        app.clone()
            .oneshot(post_json(
                "/api/v1/frontend/widgets",
                r#"{"name":"users-widget"}"#,
                &user,
            ))
            .await
            .unwrap(),
    )
    .await;
    let response = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/widgets/{mine}"),
            r#"{"name":"renamed-by-owner"}"#,
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "改自己的 widget 应放行");

    // admin 有 read:all + write:all → 跨用户照常改得动
    let response = app
        .oneshot(put_json(
            &format!("/api/v1/frontend/widgets/{mine}"),
            r#"{"name":"renamed-by-admin"}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin 持 write:all,跨用户可改"
    );
}

/// **SSE 行级 ownership**:流必须与 list 同口径 —— 无 `read:all` 的 user 收不到别人的 widget,
/// 但照收自己的。总线是广播(admin 那条也进了同一频道),过滤在 handler 逐帧做。
///
/// 回归意义:漏了这层,任何登录 user 都能从流里实时读到**全站** widget(含名字),而
/// `GET /widgets` / `GET /widgets/{id}` 对他一律过滤/404 —— 流成了 ownership 的绕行道。
#[tokio::test]
async fn sse_stream_filters_other_users_widgets() {
    use futures_util::StreamExt;
    let (app, admin) = test_app();
    let (user, _user_id) = user_token();

    // user 开流(有 widgets:read → 200)
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .header("authorization", format!("Bearer {user}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "user 有 widgets:read,应能开流"
    );
    let mut body = response.into_body().into_data_stream();

    // admin 先建一个**别人的** widget → 必须被 user 的流跳过
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/v1/frontend/widgets")
                .header("authorization", format!("Bearer {admin}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"admins-secret-widget"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    // user 再建**自己的** → 应该收到这条
    let mine = app
        .clone()
        .oneshot(
            Request::post("/api/v1/frontend/widgets")
                .header("authorization", format!("Bearer {user}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"users-own-widget"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mine.status(), StatusCode::CREATED);

    // 两条按序发布,第一条被过滤 → 流上第一帧必是自己那条。
    let frame = time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("5s 内应收到自己的那帧")
        .expect("流不应结束")
        .unwrap();
    let text = String::from_utf8(frame.to_vec()).unwrap();
    assert!(
        !text.contains("admins-secret-widget"),
        "越权:别人的 widget 泄漏进了 user 的流: {text}"
    );
    assert!(
        text.contains("users-own-widget"),
        "自己的 widget 必须照收(别把流过滤成全丢): {text}"
    );
}

/// SSE:开流 → create → 第一帧就是 created 事件(keep-alive 15s 远大于测试窗口,不会先到)。
#[tokio::test]
async fn sse_stream_receives_created_event() {
    use futures_util::StreamExt;
    let (app, admin) = test_app();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.into_body().into_data_stream();

    // handler 返回时订阅已建立 → 此刻 create 必被本流看到
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/v1/frontend/widgets")
                .header("authorization", format!("Bearer {admin}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"sse-demo"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let frame = time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("5s 内应收到 SSE 帧")
        .expect("流不应结束")
        .unwrap();
    let text = String::from_utf8(frame.to_vec()).unwrap();
    assert!(text.contains("event: created"), "应是 created 帧: {text}");
    assert!(
        text.contains(r#""name":"sse-demo""#),
        "应含 widget JSON: {text}"
    );
}

/// 未认证 → 401(EventSource 只能靠 cookie/无 header,这里用无凭据模拟)。
#[tokio::test]
async fn sse_requires_auth() {
    let (app, _admin) = test_app();
    let response = app
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 降权令牌(scope 只有 write,无 read)→ 403:scope 只收窄不放大。
#[tokio::test]
async fn sse_requires_read_scope() {
    let (app, _admin) = test_app();
    let signer = AppTokenSigner::new_with_development_key(); // 与 test_app 同 dev 密钥,验签才过
    let scoped = signer
        .mint_scoped(
            Uuid::nil(),
            "admin",
            vec![],
            Some(ScopedTenant {
                id: DEFAULT_TENANT_ID.as_uuid(),
                roles: vec!["admin".to_owned()],
            }),
            vec![Permission::WidgetWrite],
            900,
        )
        .unwrap();
    let response = app
        .oneshot(
            Request::get("/api/v1/frontend/widgets/events")
                .header("authorization", format!("Bearer {scoped}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 多权限样板行为:AND 缺一 403、全有 200;OR 任一支 200、两支皆无 403。
/// (users:admin 支与 AND 逐成员钉力由 openapi_authz 探针覆盖,这里钉用户可感行为。)
#[tokio::test]
async fn multi_perm_and_or_endpoints() {
    let (app, admin) = test_app();
    let signer = AppTokenSigner::new_with_development_key(); // 与 fixture 同 dev 密钥,可自铸降权令牌
    let narrowed = |scope: Vec<Permission>| {
        signer
            .mint_scoped(
                Uuid::nil(),
                "admin",
                vec![],
                Some(ScopedTenant {
                    id: DEFAULT_TENANT_ID.as_uuid(),
                    roles: vec!["admin".to_owned()],
                }),
                scope,
                900,
            )
            .unwrap()
    };

    // AND:admin 满权(read+delete)→ 200
    let response = app
        .clone()
        .oneshot(get("/api/v1/frontend/widgets/purge-preview", &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // AND:scope 收窄掉 delete → 403
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/frontend/widgets/purge-preview",
            &narrowed(vec![Permission::WidgetRead]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // OR:只有 read 支 → 200
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/frontend/widgets/overview",
            &narrowed(vec![Permission::WidgetRead]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // OR:两支皆无(scope=[widgets:write])→ 403
    let response = app
        .oneshot(get(
            "/api/v1/frontend/widgets/overview",
            &narrowed(vec![Permission::WidgetWrite]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// list 排序(offset):`sort_by=name&order=asc` → 首个 "a";`order=desc` → 首个 "b"。
/// cursor + `sort_by=name` → 200,按 `(name, id)` keyset 翻页(创建序是 b<a,name 序是 a<b ——
/// 两个序相反,所以这个用例能区分"真按 name 翻"和"偷偷按 id 翻")。
#[tokio::test]
async fn list_sort_by_name_offset_and_cursor() {
    let (app, token) = test_app();
    // 建 b、再建 a(创建序 b<a);按 name 排序应与创建序解耦。
    for name in ["b", "a"] {
        let response = app
            .clone()
            .oneshot(post_json(
                "/api/v1/frontend/widgets",
                &format!(r#"{{"name":"{name}"}}"#),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let first_name = |body: &str| -> String {
        let page: Value = serde_json::from_str(body).unwrap();
        page["items"][0]["name"].as_str().unwrap().to_owned()
    };

    // name asc → "a" 在前
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/frontend/widgets?sort_by=name&order=asc&page=1",
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(first_name(&body_string(response).await), "a");

    // name desc → "b" 在前
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/frontend/widgets?sort_by=name&order=desc&page=1",
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(first_name(&body_string(response).await), "b");

    // cursor 模式(空 cursor = 首页)+ sort_by=name → 200,首条按 name 序是 "a"(id 序会是 "b")
    let response = app
        .clone()
        .oneshot(get(
            "/api/v1/frontend/widgets?cursor=&sort_by=name&order=asc&size=1",
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert_eq!(first_name(&body), "a");
    let page: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(page["page_info"]["mode"], "cursor");
    let next = page["page_info"]["next_cursor"]
        .as_str()
        .unwrap()
        .to_owned();

    // 拿 next_cursor 翻第二页 → "b";锚点的 name 值由服务端从锚点行读,cursor 仍只是 16 字节 id。
    let response = app
        .oneshot(get(
            &format!("/api/v1/frontend/widgets?cursor={next}&sort_by=name&order=asc&size=1"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(first_name(&body_string(response).await), "b");
}

//! profile API 集成测试 —— 内存 AppState,oneshot 打真实端点。
//! 头像用**真适配器**(ContentAvatarProbe 包同一个内存 ContentService):
//! 校验/富化走的是真跨模块链路,不打桩。
//!
//! 资料全局一份:`profiles:*` 是平台级(测试策略里只给平台角色 superadmin),本人走 `/profiles/me`。
//! 头像只认**个人内容**(`ContentScope::Personal`):各种形状的个人内容(未 confirm / 非栅格 / SVG)直接经
//! content 服务铺,不走 HTTP(HTTP 的头像上传入口在上传前就拒掉了这些)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot
use uuid::Uuid;

use baserust::app::adapters::ContentAvatarProbe;
use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::{AppTokenSigner, AppTokenVerifier};
use baserust::features::profile::{InMemoryProfileRepo, ProfileService};
use baserust::features::widget::{InMemoryWidgetRepo, StaticUserDirectory, WidgetService};
use baserust::kernel::authz::{Perm, Policy};
use content::ContentScope;
use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

const ADMIN_ID: Uuid = Uuid::from_u128(1);
const ALICE_ID: Uuid = Uuid::from_u128(2);
const BOB_ID: Uuid = Uuid::from_u128(3);

/// admin(平台 superadmin:profiles:* + 默认租户 admin)+ alice/bob(默认租户 user)三枚令牌;
/// 返回同一个 ContentService 句柄,供测试直接铺个人 / 租户内容。
fn test_app() -> (Router, content::ContentService, String, String, String) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());
    let mint = |id: Uuid, name: &str, role: &str| {
        let platform = if role == "admin" {
            vec!["superadmin".to_owned()]
        } else {
            vec![]
        };
        signer
            .mint_scoped(
                id,
                name,
                platform,
                Some(baserust::features::auth::ScopedTenant {
                    id: baserust::kernel::tenant::DEFAULT_TENANT_ID.as_uuid(),
                    roles: vec![role.to_owned()],
                }),
                vec![],
                900,
            )
            .unwrap()
    };
    let admin = mint(ADMIN_ID, "admin", "admin");
    let alice = mint(ALICE_ID, "alice", "user");
    let bob = mint(BOB_ID, "bob", "user");

    let store = Arc::new(content::InMemoryObjectStore::new());
    let contents = content::ContentService::new(
        Arc::new(content::InMemoryContentRepo::new()),
        Arc::new(content::InMemoryObjectRepo::new()),
        store.clone(),
        "memory",
    );
    let bus: Arc<dyn baserust::features::widget::EventBus> =
        Arc::new(baserust::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        profiles: ProfileService::new(
            Arc::new(InMemoryProfileRepo::new()),
            Arc::new(ContentAvatarProbe::new(contents.clone())),
        ),
        contents: contents.clone(),
        auth: AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(idm::InMemoryMemberRepo::new()),
        )
        .hasher(Arc::new(FakeHasher))
        // 独立的空角色仓储:注册不授租户角色(配置了目录里没有的角色会响亮失败)
        .signup_roles(Vec::new())
        .signer(signer.clone())
        .verifier(verifier.clone())
        .build(),
        user_admin: baserust::features::users::UserAdminService::new(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(FakeHasher),
            Arc::new(baserust::features::users::StaticProfileDirectory::empty()),
            None,
        ),
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
        policy: Arc::new(Policy::from_roles([
            (
                "superadmin".to_owned(),
                vec![Perm::ProfileRead, Perm::ProfileWrite, Perm::ProfileWriteAll],
            ),
            (
                "admin".to_owned(),
                vec![
                    Perm::ContentRead,
                    Perm::ContentWrite,
                    // 跨用户删他人头像 content(悬空降级用例)→ 需 write 侧越权 mode
                    Perm::ContentWriteAll,
                    Perm::ContentDelete,
                ],
            ),
            (
                "user".to_owned(),
                vec![Perm::ContentRead, Perm::ContentWrite],
            ),
        ])),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
        app_system_pool: None,
        content_system_pool: None,
        search_system_pool: None,
    };
    let app = build_router(
        state,
        &baserust::infra::config::Config::default(),
        Mount::Both,
    );
    (app, contents, admin, alice, bob)
}

fn put_json(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// 直接经 content 服务铺一条内容(owner = `owner`),返回 id。`confirm=false` 停在 prepare(未销账态)。
async fn seed_content(
    contents: &content::ContentService,
    scope: ContentScope,
    owner: Uuid,
    mime: &str,
    confirm: bool,
) -> String {
    let id = if confirm {
        contents
            .upload_content(
                scope,
                content::UploadContentInput {
                    owner_id: owner,
                    owner_type: None,
                    name: None,
                    description: None,
                    document_type: None,
                    object_key: None,
                    file_name: Some("a.bin".into()),
                    mime_type: Some(mime.to_owned()),
                    tags: vec![],
                    custom_metadata: None,
                    data: bytes::Bytes::from_static(&[137, 80, 78, 71]),
                },
                None,
            )
            .await
            .unwrap()
            .content
            .id
    } else {
        contents
            .prepare_upload(
                scope,
                content::PrepareUploadInput {
                    owner_id: owner,
                    owner_type: None,
                    name: None,
                    description: None,
                    document_type: None,
                    object_key: None,
                    file_name: Some("a.bin".into()),
                    mime_type: Some(mime.to_owned()),
                    tags: vec![],
                    custom_metadata: None,
                },
                None,
            )
            .await
            .unwrap()
            .content
            .id
    };
    id.to_string()
}

/// 本人的个人内容头像(已 confirm 的 png)。
async fn personal_png(contents: &content::ContentService, owner: Uuid) -> String {
    seed_content(contents, ContentScope::Personal, owner, "image/png", true).await
}

const ME: &str = "/api/v1/frontend/profiles/me";

/// PUT /me 建 → 201;再 PUT → 200 且**全量覆盖**;按 id 读别人是平台级:租户成员 403、平台管理员 200。
#[tokio::test]
async fn put_me_upsert_then_platform_admin_can_read() {
    let (app, _contents, admin, alice, bob) = test_app();
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");

    let resp = app
        .clone()
        .oneshot(put_json(
            ME,
            r#"{"display_name":"San","phone":"138"}"#,
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["display_name"], "San");
    assert!(v["avatar_url"].is_null());

    let resp = app
        .clone()
        .oneshot(put_json(ME, r#"{"phone":"999"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["display_name"].is_null(), "全量替换:未给字段清空");
    assert_eq!(v["phone"], "999");

    // 租户成员读别人(含 phone)→ 403;平台管理员 → 200
    let resp = app.clone().oneshot(get(&uri, &bob)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = app.clone().oneshot(get(&uri, &admin)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["phone"], "999");
}

/// 按 id 改别人:租户成员 → 403;平台管理员(write:all)→ 可建可改任何人。
#[tokio::test]
async fn ownership_gate_and_write_all() {
    let (app, _contents, admin, alice, _bob) = test_app();
    let bob_uri = format!("/api/v1/frontend/profiles/{BOB_ID}");

    let resp = app
        .clone()
        .oneshot(put_json(&bob_uri, r#"{"display_name":"X"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "租户成员改别人应 403");

    let resp = app
        .clone()
        .oneshot(put_json(&bob_uri, r#"{"display_name":"ByAdmin"}"#, &admin))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "write:all 应可替任何人建/改"
    );

    // 已存在后再替(区别于"建别人"):write:all 的替换路径 → 200
    let resp = app
        .clone()
        .oneshot(put_json(
            &bob_uri,
            r#"{"display_name":"ByAdminAgain"}"#,
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "write:all 替已存在的别人应 200"
    );
}

/// 头像全链路:个人内容 png → PUT /me 绑定 → avatar_url 富化;头像端点本人 + 跨用户出图;
/// 个人内容经租户作用域的 contents 端点看不到;删 content → 降级 null、头像端点 404。
#[tokio::test]
async fn avatar_bind_enrich_and_dangling_degrade() {
    let (app, contents, _admin, alice, bob) = test_app();
    let cid = personal_png(&contents, ALICE_ID).await;

    let resp = app
        .clone()
        .oneshot(put_json(
            ME,
            &format!(r#"{{"avatar_content_id":"{cid}"}}"#),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let avatar_uri = format!("/api/v1/frontend/profiles/{ALICE_ID}/avatar");
    assert_eq!(v["avatar_url"].as_str().unwrap(), avatar_uri);

    // 头像端点出图:内存 backend 无 presign → 代理 200 图片字节。alice 本人 + 跨用户 bob 都能看。
    for tok in [&alice, &bob] {
        let resp = app.clone().oneshot(get(&avatar_uri, tok)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "头像端点应出图(含跨用户)");
    }
    // 个人内容不在租户作用域里:本人经 contents/{id}/preview 也 404
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{cid}/preview"),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "个人内容不走 contents 端点"
    );

    // 删 content(个人内容没有 HTTP 删除入口,直接经服务)→ 悬空:GET /me 降级 avatar_url=null,不炸
    contents
        .delete_content(ContentScope::Personal, Uuid::parse_str(&cid).unwrap(), None)
        .await
        .unwrap();
    let resp = app.clone().oneshot(get(ME, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["avatar_url"].is_null(), "悬空应降级 null");
    assert_eq!(
        v["avatar_content_id"].as_str().unwrap(),
        cid,
        "原始引用保留"
    );
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "头像 content 已删 → 头像端点 404"
    );
}

/// 头像拒绝:不存在 / 个人内容但未 confirm / 非栅格 / SVG(活动内容,防存储型 XSS)/ 本人的**租户内容** → 422。
#[tokio::test]
async fn avatar_bad_bindings_rejected_422() {
    let (app, contents, _admin, alice, _bob) = test_app();
    let personal = ContentScope::Personal;
    let unconfirmed = seed_content(&contents, personal, ALICE_ID, "image/png", false).await;
    let not_image = seed_content(&contents, personal, ALICE_ID, "text/plain", true).await;
    let svg = seed_content(&contents, personal, ALICE_ID, "image/svg+xml", true).await;
    let tenant_png = seed_content(
        &contents,
        ContentScope::Tenant(content::DEFAULT_TENANT_ID),
        ALICE_ID,
        "image/png",
        true,
    )
    .await;
    for bad in [
        Uuid::now_v7().to_string(),
        unconfirmed,
        not_image,
        svg,
        tenant_png,
    ] {
        let resp = app
            .clone()
            .oneshot(put_json(
                ME,
                &format!(r#"{{"avatar_content_id":"{bad}"}}"#),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad} 应 422"
        );
    }
}

/// 头像 content 必须是**本人**的 —— 绑定别人 owner 的个人内容 → 422(防把别人的图"洗"成头像)。
#[tokio::test]
async fn avatar_bind_foreign_content_rejected_422() {
    let (app, contents, _admin, alice, _bob) = test_app();
    let bob_cid = personal_png(&contents, BOB_ID).await;
    let resp = app
        .clone()
        .oneshot(put_json(
            ME,
            &format!(r#"{{"avatar_content_id":"{bob_cid}"}}"#),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "绑定别人 owner 的 content 应 422"
    );
}

/// 无资料 / 未绑定头像 → 头像端点 404(不泄露、不炸)。
#[tokio::test]
async fn avatar_endpoint_404_when_unset() {
    let (app, _contents, _admin, alice, _bob) = test_app();
    let avatar_uri = format!("/api/v1/frontend/profiles/{ALICE_ID}/avatar");
    // 无资料
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "无资料 → 404");
    // 建资料但不带头像
    app.clone()
        .oneshot(put_json(ME, r#"{"display_name":"San"}"#, &alice))
        .await
        .unwrap();
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "未绑定头像 → 404");
}

/// 401:无 token 读/写皆拒(scope 矩阵归 openapi_authz_test 自动覆盖,这里只钉登录闸)。
#[tokio::test]
async fn unauthenticated_401() {
    let (app, _contents, _a, _b, _c) = test_app();
    for uri in [
        format!("/api/v1/frontend/profiles/{ALICE_ID}"),
        ME.to_owned(),
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

/// `/profiles/me`:未建 → **200 空资料**(不是 404 —— 调用方已认证,账号必在,行没写而已;
/// 404 会锁死前端:建资料只能 PUT,而 PUT 那个页面的 loader 正是拿 me 的 404 抛错打不开)。
/// 建后与按 id 读**逐字节等值**(同一 service 路径,me 只是身份别名)。
#[tokio::test]
async fn my_profile_me_alias() {
    let (app, _contents, admin, alice, _bob) = test_app();
    let resp = app.clone().oneshot(get(ME, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "未建资料应回空资料而非 404");
    let blank = body_json(resp).await;
    assert_eq!(
        blank["user_id"],
        ALICE_ID.to_string(),
        "空资料带本人 id(前端 PUT 要用)"
    );
    assert!(blank["display_name"].is_null() && blank["created_at"].is_null());

    // 按 id 读**别人**未建的资料仍 404:那里存在性是真问题(对比 me 的"自己的行还没写")。
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/profiles/{}", uuid::Uuid::now_v7()),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "读别人未建的资料仍应 404"
    );

    let resp = app
        .clone()
        .oneshot(put_json(ME, r#"{"display_name":"Alice"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let me = body_json(app.clone().oneshot(get(ME, &alice)).await.unwrap()).await;
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");
    let by_id = body_json(app.clone().oneshot(get(&uri, &admin)).await.unwrap()).await;
    assert_eq!(me, by_id, "me 应与按 id 读等值");
    assert_eq!(me["display_name"], "Alice");
}

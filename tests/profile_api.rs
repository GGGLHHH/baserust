//! profile API 集成测试 —— 内存 AppState,oneshot 打真实端点。
//! 头像用**真适配器**(ContentAvatarProbe 包同一个内存 ContentService):
//! 校验/富化走的是真跨模块链路,不打桩。

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
use baserust::infra::authz::{Perm, Policy};
use idm::{AuthService, FakeHasher, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

const ADMIN_ID: Uuid = Uuid::from_u128(1);
const ALICE_ID: Uuid = Uuid::from_u128(2);
const BOB_ID: Uuid = Uuid::from_u128(3);

/// admin(write:all)+ alice/bob(普通 user:read+write 自己)三枚令牌;
/// 返回 store 句柄供两步上传模拟直写字节。
fn test_app() -> (
    Router,
    Arc<content::InMemoryObjectStore>,
    String,
    String,
    String,
) {
    let signer = Arc::new(AppTokenSigner::dev());
    let verifier = Arc::new(AppTokenVerifier::dev());
    // 测试 token 带一个租户:这些用例用**通用 content 端点**(/contents/upload-url)seed 头像
    // 素材,那个端点上了租户轴、要 Tenant extractor。**这不代表 profile 上了轴** ——
    // 真实头像上传走 profile 自己的 set_user_avatar,那里落 NO_TENANT(头像 = 全局身份)。
    // 这里只是让测试的 content-seed 步骤能过 content 的租户门。
    let mint = |id: Uuid, name: &str, role: &str| {
        signer
            .mint_scoped(
                id,
                name,
                vec![role.to_owned()],
                Some(Uuid::from_u128(0x7E57)),
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
        contents,
        auth: AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
        )
        .hasher(Arc::new(FakeHasher))
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
        db_pool: None,
        cookie_secure: false,
        policy: Arc::new(Policy::from_roles([
            (
                "admin".to_owned(),
                vec![
                    Perm::ProfileRead,
                    Perm::ProfileWrite,
                    Perm::ProfileWriteAll,
                    Perm::ContentRead,
                    Perm::ContentWrite,
                    // 跨用户删他人头像 content(悬空降级用例)→ 需 write 侧越权 mode
                    Perm::ContentWriteAll,
                    Perm::ContentDelete,
                ],
            ),
            (
                "user".to_owned(),
                vec![
                    Perm::ProfileRead,
                    Perm::ProfileWrite,
                    Perm::ContentRead,
                    Perm::ContentWrite,
                ],
            ),
        ])),
        token_signer: Some(signer.clone()),
        token_verifier: verifier,
        tenants: None,
        idm_outbox: None,
        auth_audit: None,
        auth_events_bus: None,
    };
    let app = build_router(
        state,
        &baserust::infra::config::Config::default(),
        Mount::Both,
    );
    (app, store, admin, alice, bob)
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

fn post_json(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
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

/// 两步上传一个 content(prepare → 直写 store 模拟客户端 PUT → confirm),返回 content id。
/// 镜像 tests/content_api.rs 的 two_step 模拟;`confirm=false` 时停在 prepare(未销账态)。
async fn seed_content(
    app: &Router,
    store: &Arc<content::InMemoryObjectStore>,
    token: &str,
    mime: &str,
    confirm: bool,
) -> String {
    use content::ObjectStore as _;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/api/v1/frontend/contents/upload-url",
            &format!(r#"{{"name":"avatar-src","file_name":"a.bin","mime_type":"{mime}"}}"#),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let id = v["content"]["id"].as_str().unwrap().to_owned();
    let key = v["object"]["object_key"].as_str().unwrap().to_owned();
    if confirm {
        store
            .upload(
                content::UploadParams {
                    object_key: key,
                    mime_type: Some(mime.to_owned()),
                    file_name: None,
                },
                bytes::Bytes::from_static(&[137, 80, 78, 71]),
            )
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/frontend/contents/{id}/confirm-upload"),
                "{}",
                token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    id
}

/// GET 未建 → 404;PUT 建 → 201;再 PUT → 200 且**全量覆盖**;任意登录可读他人。
#[tokio::test]
async fn put_upsert_then_anyone_can_read() {
    let (app, _store, _admin, alice, bob) = test_app();
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");

    let resp = app.clone().oneshot(get(&uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(put_json(
            &uri,
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
        .oneshot(put_json(&uri, r#"{"phone":"999"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["display_name"].is_null(), "全量替换:未给字段清空");
    assert_eq!(v["phone"], "999");

    // bob(无 write:all)读 alice → 200(任意登录可读)
    let resp = app.clone().oneshot(get(&uri, &bob)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 改别人:无 write:all → 403;admin(write:all)→ 可建可改任何人。
#[tokio::test]
async fn ownership_gate_and_write_all() {
    let (app, _store, admin, alice, _bob) = test_app();
    let bob_uri = format!("/api/v1/frontend/profiles/{BOB_ID}");

    let resp = app
        .clone()
        .oneshot(put_json(&bob_uri, r#"{"display_name":"X"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "无 write:all 改别人应 403"
    );

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

/// 头像全链路:两步上传 image/png → 绑定 → avatar_url 富化;删 content → GET 降级 null。
#[tokio::test]
async fn avatar_bind_enrich_and_dangling_degrade() {
    let (app, store, admin, alice, bob) = test_app();
    let cid = seed_content(&app, &store, &alice, "image/png", true).await;
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");

    let resp = app
        .clone()
        .oneshot(put_json(
            &uri,
            &format!(r#"{{"avatar_content_id":"{cid}"}}"#),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let avatar_uri = format!("/api/v1/frontend/profiles/{ALICE_ID}/avatar");
    assert_eq!(v["avatar_url"].as_str().unwrap(), avatar_uri);

    // 头像端点出图:内存 backend 无 presign → 代理 200 图片字节。alice 本人 + 跨用户 bob 都能看
    // (头像是刻意暴露的公开展示图)。
    for tok in [&alice, &bob] {
        let resp = app.clone().oneshot(get(&avatar_uri, tok)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "头像端点应出图(含跨用户)");
    }
    // 而 content 本体经 contents/{id}/preview 严格按 owner 隔离:非 owner bob 直读 → 404
    // (即"腿 2":头像展示不再让任意 image 被越权直读)。
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/contents/{cid}/preview"),
            &bob,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "非 owner 直读 content preview 应 404"
    );

    // 删 content(admin 有 contents:delete)→ 悬空:GET 降级 avatar_url=null,不炸
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/frontend/contents/{cid}"))
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app.clone().oneshot(get(&uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["avatar_url"].is_null(), "悬空应降级 null");
    assert_eq!(
        v["avatar_content_id"].as_str().unwrap(),
        cid,
        "原始引用保留"
    );
    // 头像端点在悬空(content 已删)时 → 404(不再出图)。
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "头像 content 已删 → 头像端点 404"
    );
}

/// 头像四拒:不存在 / prepare 未 confirm / mime 非栅格 / SVG(活动内容,防存储型 XSS)→ 422。
#[tokio::test]
async fn avatar_bad_bindings_rejected_422() {
    let (app, store, _admin, alice, _bob) = test_app();
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");
    let unconfirmed = seed_content(&app, &store, &alice, "image/png", false).await;
    let not_image = seed_content(&app, &store, &alice, "text/plain", true).await;
    let svg = seed_content(&app, &store, &alice, "image/svg+xml", true).await;
    for bad in [Uuid::now_v7().to_string(), unconfirmed, not_image, svg] {
        let resp = app
            .clone()
            .oneshot(put_json(
                &uri,
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

/// 腿 1:头像 content 必须是**本人**的 —— 绑定别人 owner 的 content → 422(防把私图"洗"成头像)。
#[tokio::test]
async fn avatar_bind_foreign_content_rejected_422() {
    let (app, store, _admin, alice, bob) = test_app();
    // bob 上传自己的 image content(owner = BOB)
    let bob_cid = seed_content(&app, &store, &bob, "image/png", true).await;
    // alice 想把 bob 的 content 设成自己的头像 → 422(非本人)
    let resp = app
        .clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/profiles/{ALICE_ID}"),
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
    let (app, _store, _admin, alice, _bob) = test_app();
    let avatar_uri = format!("/api/v1/frontend/profiles/{ALICE_ID}/avatar");
    // 无资料
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "无资料 → 404");
    // 建资料但不带头像
    app.clone()
        .oneshot(put_json(
            &format!("/api/v1/frontend/profiles/{ALICE_ID}"),
            r#"{"display_name":"San"}"#,
            &alice,
        ))
        .await
        .unwrap();
    let resp = app.clone().oneshot(get(&avatar_uri, &alice)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "未绑定头像 → 404");
}

/// 401:无 token 读/写皆拒(scope 矩阵归 openapi_authz_test 自动覆盖,这里只钉登录闸)。
#[tokio::test]
async fn unauthenticated_401() {
    let (app, _store, _a, _b, _c) = test_app();
    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `/profiles/me`:未建 → **200 空资料**(不是 404 —— 调用方已认证,账号必在,行没写而已;
/// 404 会锁死前端:建资料只能 PUT,而 PUT 那个页面的 loader 正是拿 me 的 404 抛错打不开)。
/// 建后与按 id 读**逐字节等值**(同一 service 路径,me 只是身份别名)。
#[tokio::test]
async fn my_profile_me_alias() {
    let (app, _store, _admin, alice, _bob) = test_app();
    let resp = app
        .clone()
        .oneshot(get("/api/v1/frontend/profiles/me", &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "未建资料应回空资料而非 404");
    let blank = body_json(resp).await;
    assert_eq!(
        blank["user_id"],
        ALICE_ID.to_string(),
        "空资料带本人 id(前端 PUT 要用)"
    );
    assert!(blank["display_name"].is_null() && blank["created_at"].is_null());

    // 读**别人**的资料仍 404:那里存在性是真问题(对比 me 的"自己的行还没写")。
    let resp = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/frontend/profiles/{}", uuid::Uuid::now_v7()),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "读别人未建的资料仍应 404"
    );

    let uri = format!("/api/v1/frontend/profiles/{ALICE_ID}");
    let resp = app
        .clone()
        .oneshot(put_json(&uri, r#"{"display_name":"Alice"}"#, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let me = body_json(
        app.clone()
            .oneshot(get("/api/v1/frontend/profiles/me", &alice))
            .await
            .unwrap(),
    )
    .await;
    let by_id = body_json(app.clone().oneshot(get(&uri, &alice)).await.unwrap()).await;
    assert_eq!(me, by_id, "me 应与按 id 读等值");
    assert_eq!(me["display_name"], "Alice");
}

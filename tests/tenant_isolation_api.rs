//! **跨租户隔离验收**(P5)—— 用户最初的需求:「A 公司永远不能看到 B 公司的数据」。
//!
//! 这是**黑盒端到端**:真实 `AppState::new`(内存,进程内 seed 出租户 + mock widget)、
//! 真实 `authenticate` 中间件、真实 widget 端点、真实 `PUT /auth/active-tenant` 切租户。
//! 不碰 repo,只打 HTTP —— 测的是「整条链合起来是否真的隔离」,而不是某一层。
//!
//! # 为什么它必须存在(冒烟抓过、单测漏过的东西)
//!
//! `widget_repo_conformance` 的 isolation 契约测的是 **repo 层**(`repo.get(tenant, id)`)。
//! 但真正的漏洞面在**整条链**:token 的 tenant claim 从哪来、`Tenant` extractor 有没有装、
//! handler 传给 repo 的到底是不是 claim 里那个租户。这些只有黑盒打得穿。
//!
//! seed 数据(`seed.toml` + `mock.toml`):`user` 同时是 Acme 的 admin 与 Globex 的 member;
//! Acme 有 admin-w1/w2 + user-w1,Globex 有一个同名的 user-w1(不同 id —— 复合唯一约束)。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::AppTokenSigner;
use baserust::infra::authz::Perm;
use baserust::infra::config::Config;

/// 真实 app(内存 + 进程内 seed:两家公司 + 各自的 mock widget)。
async fn app() -> (Router, AppState) {
    let (state, _bg) = AppState::new(&Config::default(), Mount::Both)
        .await
        .expect("内存模式 AppState 应可建(含进程内 seed 租户与 mock)");
    let router = build_router(state.clone(), &Config::default(), Mount::Both);
    (router, state)
}

// ── HTTP 小工具:cookie / claim / 状态码 ──

fn set_cookie(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            s.strip_prefix(&format!("{name}="))
                .map(|r| r.split(';').next().unwrap().to_owned())
        })
}

fn tenant_of(access: &str) -> Option<Uuid> {
    let mid = access.split('.').nth(1)?;
    let json: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mid)
            .ok()?,
    )
    .ok()?;
    json.get("tenant")?.as_str()?.parse().ok()
}

/// 用 cookie 打一个 GET,返回状态码。
async fn get_status(app: &Router, uri: &str, access: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get(uri)
                .header("cookie", format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// 切租户,返回新的 access cookie(端点会整条轮换 token)。
async fn switch(app: &Router, access: &str, refresh: &str, tenant: Uuid) -> Option<String> {
    let res = app
        .clone()
        .oneshot(
            Request::put("/api/v1/frontend/auth/active-tenant")
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!("access_token={access}; refresh_token={refresh}"),
                )
                .body(Body::from(format!(r#"{{"tenant_id":"{tenant}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status() == StatusCode::OK).then(|| set_cookie(&res, "access_token").unwrap())
}

/// 库里某租户某名字的 widget id(测试要按 id 跨租户打)。经 state 的 repo 直查,
/// 绕开 HTTP —— 这是「拿到攻击目标的真实 id」,不是被测路径。
async fn widget_id(state: &AppState, tenant: Uuid, name: &str) -> Uuid {
    use baserust::infra::authz::TenantId;
    let page = state
        .widgets
        .list(
            TenantId::from_claim(tenant),
            baserust::infra::pagination::PageQuery {
                page: Some(1),
                size: Some(100),
                cursor: None,
                with_total: None,
            },
            None, // owner=None → 本租户内全部
        )
        .await
        .unwrap();
    page.items
        .into_iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("租户 {tenant} 里应有 widget `{name}`"))
        .id
}

fn tid(state: &AppState, slug: &str) -> Uuid {
    // 与 seed 同源:租户 id 由 slug 确定性派生(uuid v5)。
    let _ = state;
    baserust::app::seed::tenant_id_for(slug)
}

/// **核心验收**:同一个人,身处哪家公司决定他能读到哪家的数据 —— 按**真实 id** 直读。
///
/// 这是用户最初那句话的直接实证:「A 公司永远不能看到 B 公司的数据」。
#[tokio::test]
async fn same_user_sees_only_the_tenant_they_are_in() {
    let (app, state) = app().await;
    let acme = tid(&state, "acme");
    let globex = tid(&state, "globex");

    // 两个同名 user-w1,不同 id(复合唯一约束的活证明)。
    let acme_w = widget_id(&state, acme, "user-w1").await;
    let globex_w = widget_id(&state, globex, "user-w1").await;
    assert_ne!(acme_w, globex_w, "同名不同租户 → 两个不同的 widget");

    // 登录(落 Acme)+ 拿 refresh 以便切换。
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"identifier":"user","password":"pwd"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let mut access = set_cookie(&res, "access_token").unwrap();
    let refresh = set_cookie(&res, "refresh_token").unwrap();
    assert_eq!(
        tenant_of(&access),
        Some(acme),
        "登录应回退到最早加入的 Acme"
    );

    // 身处 Acme:读得到 Acme 的、读不到 Globex 的(用真实 id,不是靠列表过滤)。
    assert_eq!(
        get_status(&app, &format!("/api/v1/frontend/widgets/{acme_w}"), &access).await,
        StatusCode::OK,
        "本租户自己的 widget 应可读"
    );
    assert_eq!(
        get_status(
            &app,
            &format!("/api/v1/frontend/widgets/{globex_w}"),
            &access
        )
        .await,
        StatusCode::NOT_FOUND,
        "**别租户的 widget,用真实 id 也必须 404**(不泄露存在)"
    );

    // 切到 Globex：完全反过来。
    access = switch(&app, &access, &refresh, globex)
        .await
        .expect("user 是 Globex 成员,切换应成功");
    assert_eq!(tenant_of(&access), Some(globex));
    assert_eq!(
        get_status(&app, &format!("/api/v1/frontend/widgets/{acme_w}"), &access).await,
        StatusCode::NOT_FOUND,
        "**切过来后,原公司的 widget 就读不到了**"
    );
    assert_eq!(
        get_status(
            &app,
            &format!("/api/v1/frontend/widgets/{globex_w}"),
            &access
        )
        .await,
        StatusCode::OK,
        "现公司自己的应可读"
    );
}

/// **`:all` 是 mode 不是闸,压不过租户**：持全平台 write:all/delete,跨租户写也 404。
///
/// 这是设计的中心断言,也是那个提权 bug 的反面:当初 tn:admin 能跨租户看全平台,
/// 现在连拿着真·全平台权限的令牌都被关在租户闸里。
#[tokio::test]
async fn write_all_cannot_cross_the_tenant_wall() {
    let (app, state) = app().await;
    let acme = tid(&state, "acme");
    let globex = tid(&state, "globex");
    let globex_w = widget_id(&state, globex, "user-w1").await;

    // 手铸一个**全权 + 落在 Acme** 的令牌(模拟 PAT/降权令牌的第二条铸币路径)。
    // roles 给 superadmin(Perm::ALL 含 write:all/delete),tenant 给 Acme。
    let su_id = Uuid::from_u128(0x5001);
    let token = AppTokenSigner::dev()
        .mint_scoped(
            su_id,
            "su",
            vec!["superadmin".to_owned()],
            Some(acme),
            vec![], // 空 scope = 不降权,吃满 role 的权限
            900,
        )
        .unwrap();

    // 权限完全足够(write:all + delete),但目标在 Globex → 404,与「不存在」无法区分。
    let put = app
        .clone()
        .oneshot(
            Request::put(format!("/api/v1/frontend/widgets/{globex_w}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"name":"hijacked"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        put.status(),
        StatusCode::NOT_FOUND,
        "有 write:all 但跨租户 → 404(权限够,只是跨墙)"
    );

    let del = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/frontend/widgets/{globex_w}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NOT_FOUND, "delete 同理 → 404");

    // 目标 widget 完好无损:换一个真正在 Globex 的令牌读它,还在、名字没变。
    let globex_token = AppTokenSigner::dev()
        .mint_scoped(
            su_id,
            "su",
            vec!["superadmin".to_owned()],
            Some(globex),
            vec![],
            900,
        )
        .unwrap();
    let check = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/frontend/widgets/{globex_w}"))
                .header("authorization", format!("Bearer {globex_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(check.status(), StatusCode::OK, "跨租户写必须没有任何效果");
    let body: Value = {
        let b = axum::body::to_bytes(check.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    };
    assert_eq!(body["name"], "user-w1", "widget 未被跨租户写改动");
    let _ = Perm::WidgetWriteAll; // 文档锚:被绕过的正是这个 mode
}

/// 列表也隔离:身处不同租户,`GET /widgets` 返回不同的集合。
#[tokio::test]
async fn list_is_scoped_to_active_tenant() {
    let (app, state) = app().await;
    let globex = tid(&state, "globex");

    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"identifier":"user","password":"pwd"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let access = set_cookie(&res, "access_token").unwrap();
    let refresh = set_cookie(&res, "refresh_token").unwrap();

    async fn list_ids(app: &Router, access: &str) -> Vec<String> {
        let r = app
            .clone()
            .oneshot(
                Request::get("/api/v1/frontend/widgets")
                    .header("cookie", format!("access_token={access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["id"].as_str().unwrap().to_owned())
            .collect()
    }

    // user 平台角色无 read:all → 只见自己创建的。Acme 里他有 user-w1,Globex 里也有一个。
    let in_acme = list_ids(&app, &access).await;
    let globex_access = switch(&app, &access, &refresh, globex).await.unwrap();
    let in_globex = list_ids(&app, &globex_access).await;

    assert_eq!(in_acme.len(), 1, "Acme 里 user 有 1 个自己的 widget");
    assert_eq!(in_globex.len(), 1, "Globex 里也有 1 个");
    assert_ne!(
        in_acme, in_globex,
        "两家的列表必须是不同的 widget —— 切换真的换了数据"
    );
}

/// **0 租户用户打租户端点 → 401**:证明 `Tenant` extractor 真的在守门。
///
/// 这道断言看似平凡,却是整条隔离链的地基:如果哪天有人给某个 widget 端点漏了 `Tenant`
/// extractor(或给它 nil 兜底),0 租户用户就能无租户地访问 —— 而 repo 的 `TenantId` 非
/// Option 首参会逼他编译期就传个租户。两者合起来:无租户的请求**到不了** repo。
///
/// 用 register 造一个真·0 租户用户(spec §1.1:0 租户是常规状态,register 的常规出口)。
#[tokio::test]
async fn zero_tenant_user_cannot_reach_widget_endpoints() {
    let (app, _state) = app().await;
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/public/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"loner","password":"pwd12345"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let access = set_cookie(&res, "access_token").unwrap();
    // token 确实没有 tenant claim(0 租户)。
    assert_eq!(
        tenant_of(&access),
        None,
        "0 租户用户的 token 不该有 tenant claim"
    );

    // 打任何租户轴上的端点 → 401(Tenant extractor 缺席即拒),而不是「看到空数据」。
    for uri in ["/api/v1/frontend/widgets", "/api/v1/frontend/widgets/stats"] {
        assert_eq!(
            get_status(&app, uri, &access).await,
            StatusCode::UNAUTHORIZED,
            "{uri}:0 租户用户必须 401(Tenant extractor 守门),不能无租户访问"
        );
    }
}

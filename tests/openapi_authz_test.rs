//! 零漂移的 **by-test 边**:**spec 广告的 security ⟷ handler 实际 `require_scoped`** 一致(行为钉死)。
//! Rust 无法静态读 handler 体内 `require_scoped` 的实参,只能行为观测。
//!
//! **纯 spec 驱动**:method+path 与广告的 scope 都从 `api_spec()` 取(utoipa 从 `#[utoipa::path]` + nest 派生,
//! 是路由的唯一真相)—— **不从 OP_PERMS 取 method/path**,故不引第二个路由来源/漂移。
//! 用 superadmin(持全 Perm,隔离 role 因素让"只有 scope 把门")签**降权令牌**打真实路由:
//! - 广告 scope 非空:`scope=[广告的]` → 穿过授权闸(非 401/403);`scope=[不蕴含它的 perm]` → 403。
//! - 广告 scope 空(仅登录):**零权限**令牌 → 非 403(无暗藏 `require_scoped`)。
//!
//! **AND/OR 结构化探测**:security 的每个 requirement 视作一支(单支多 scope = AND;多支各一 scope = OR)。
//! AND 支额外钉逐成员去一必 403;OR 支额外钉每支单独必过 —— 不再只测并集,连接组合语义都行为钉死。
//!
//! handler 改了 enforce 的 Perm 但 spec 广告没跟上(或反之)→ 这里红。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use tower::ServiceExt; // oneshot
use uuid::Uuid;

use baserust::app::router::api_spec;
use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::AppTokenSigner;
use baserust::infra::authz::Perm;
use baserust::infra::config::Config;
use idm::LoginInput;

/// spec 里的 scope 串 → `Perm`(经 serde rename;非法即 panic,本就该是合法 Perm)。
fn str_to_perm(s: &str) -> Perm {
    serde_json::from_value(Value::String(s.to_owned())).expect("spec scope 应是合法 Perm")
}

/// 用 spec 给的 method+path(替换 {id})打一次,带 Bearer token,返回状态码。
async fn hit(app: &Router, method: &str, uri: &str, op_id: &str, token: &str) -> StatusCode {
    let mut b = Request::builder()
        .method(method.to_uppercase().as_str())
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    // 写端点 gate 在 body 提取**之后**跑 → 反向用例须发可提取的 body,否则提取器的 400/422 遮 403(假绿)。
    let body = match op_id {
        "create_widget" | "update_widget" | "create_content" | "update_content"
        | "prepare_upload" | "put_profile" | "set_user_profile" => {
            b = b.header("content-type", "application/json");
            Body::from(r#"{"name":"probe"}"#)
        }
        "set_content_metadata" => {
            b = b.header("content-type", "application/json");
            Body::from(r#"{"tags":[]}"#)
        }
        // 租户写端点:含各 DTO 必填字段(name/display_name/status/identifier/role,serde 忽略多余键)。
        "create_tenant" | "update_tenant" | "add_member" => {
            b = b.header("content-type", "application/json");
            Body::from(
                r#"{"name":"probe-tenant","display_name":"Probe","status":"active","identifier":"probe","role":"member"}"#,
            )
        }
        // users 写端点:一份含各 DTO 必填字段的 body(serde 忽略多余键)→ 四端点共用,触达 gate。
        "create_user" | "update_user" | "set_user_roles" | "reset_user_password" => {
            b = b.header("content-type", "application/json");
            Body::from(
                r#"{"username":"probe","password":"probe123","roles":[],"new_password":"probe123"}"#,
            )
        }
        // multipart 端点:require_scoped 在 Multipart 提取后、读字段前跑 → 只需 content-type 合法即可触达 gate。
        "upload_content" | "set_user_avatar" => {
            b = b.header("content-type", "multipart/form-data; boundary=X");
            Body::from("--X--\r\n")
        }
        _ => Body::empty(),
    };
    app.clone()
        .oneshot(b.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn spec_security_matches_real_enforcement() {
    let config = Config::default();
    let (state, _bg) = AppState::new(&config, Mount::Both).await.unwrap();
    let app = build_router(state.clone(), &config, Mount::Both);
    let su = state
        .auth
        .login(LoginInput {
            identifier: "superadmin".to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap();
    // state 的 verifier 用内嵌默认 dev 公钥,故本地 dev 私钥签的令牌它也认。
    let signer = AppTokenSigner::dev();
    // ⚠️ **探针 token 必须带租户**:上租户轴后,widget/content 端点都有 Tenant extractor,
    // 它在授权判定**之前**就会对无租户的 token 401 —— 那会把本测试要验的「授权闸」正向断言
    // 全部污染成 401。给探针一个存在的租户(superadmin 在 seed 里是 Acme 成员),
    // 让租户闸放行、authz 闸成为唯一变量。
    let probe_tenant = Some(baserust::app::seed::tenant_id_for("acme"));
    let mint = |scope: Vec<Perm>| {
        signer
            .mint_scoped(
                su.user.id,
                &su.user.username,
                su.user.roles.clone(),
                probe_tenant,
                scope,
                900,
            )
            .unwrap()
    };

    let spec = serde_json::to_value(api_spec()).unwrap();
    let mut checked = 0;
    for (path, item) in spec["paths"].as_object().expect("paths").iter() {
        for (method, op) in item.as_object().expect("path item").iter() {
            // 只看带 security 的 operation(无 security = public,跳过)
            let Some(sec) = op.get("security").and_then(|s| s.as_array()) else {
                continue;
            };
            let op_id = op.get("operationId").and_then(|x| x.as_str()).unwrap_or("");
            // {user_id}(ownership 端点)代入**令牌主体自己的 id**:探针打"自己的"资源,
            // 授权闸才是唯一变量(打别人的会被 ownership 403 污染正向断言)。
            let uri = path
                .replace("{id}", &Uuid::nil().to_string())
                .replace("{user_id}", &su.user.id.to_string());
            // 结构化读取:每个 requirement 一支(单支多 scope = AND;多支 = OR)
            let branches: Vec<Vec<Perm>> = sec
                .iter()
                .filter_map(|r| r.get("oauth2"))
                .filter_map(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|s| str_to_perm(s.as_str().unwrap()))
                        .collect()
                })
                .collect();
            checked += 1;

            // **运行期数据授权的仅登录端点**:授权不来自 op_perms 的 perm,而来自一次数据事实
            // 检查(成员管理:actor 是否是当前租户的 tn:admin)。对非管理员它**合法地 403** ——
            // 与 ownership 端点合法地 404 同类,探针的「LoginOnly ⇒ 不 403」对它不成立。
            // (这不是漏洞:403 说的是「你不是本租户管理员」,而你本就知道这个租户存在,无泄露。)
            const RUNTIME_TENANT_ADMIN_GATED: &[&str] =
                &["list_members", "add_member", "remove_member"];

            let union: Vec<Perm> = branches.iter().flatten().copied().collect();
            if union.is_empty() {
                if RUNTIME_TENANT_ADMIN_GATED.contains(&op_id) {
                    continue; // 授权是运行期租户 admin 事实,不在 perm 层 —— 探针跳过,由 tenants_api 黑盒钉
                }
                // 仅登录:零权限令牌(roles + scope 皆空)→ 非 403(无暗藏 require_scoped)
                let zero = signer
                    .mint_scoped(su.user.id, "probe", vec![], probe_tenant, vec![], 900)
                    .unwrap();
                let s = hit(&app, method, &uri, op_id, &zero).await;
                assert!(
                    s != StatusCode::FORBIDDEN,
                    "{op_id} 仅登录端点不应 403,got {s}"
                );
            } else {
                // 反向(AND/OR 通用):并集外且不蕴含任一的 perm → 403
                let neg = Perm::ALL
                    .into_iter()
                    .find(|&q| {
                        !union.contains(&q) && !union.iter().any(|t| q.implies().contains(t))
                    })
                    .expect("应有一个不蕴含目标的负权限");
                let s = hit(&app, method, &uri, op_id, &mint(vec![neg])).await;
                assert_eq!(
                    s,
                    StatusCode::FORBIDDEN,
                    "{op_id} 反向 scope=[{neg:?}] 应 403,got {s}"
                );
                if branches.len() == 1 {
                    let set = &branches[0];
                    // 正向:全集 → 穿过授权闸(下游 200/201/404/422 都算非 401/403)
                    let s = hit(&app, method, &uri, op_id, &mint(set.clone())).await;
                    assert!(
                        s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                        "{op_id} 正向 scope={set:?} 不应被拒,got {s}"
                    );
                    // AND 钉力:去掉任一成员 → 403(剩余集合经 implies 蕴含被去者则跳过,防假红)
                    if set.len() > 1 {
                        for (i, &dropped) in set.iter().enumerate() {
                            let rest: Vec<Perm> = set
                                .iter()
                                .copied()
                                .enumerate()
                                .filter(|&(j, _)| j != i)
                                .map(|(_, p)| p)
                                .collect();
                            if rest.iter().any(|r| r.implies().contains(&dropped)) {
                                continue;
                            }
                            let s = hit(&app, method, &uri, op_id, &mint(rest)).await;
                            assert_eq!(
                                s,
                                StatusCode::FORBIDDEN,
                                "{op_id} AND 缺 {dropped:?} 应 403,got {s}"
                            );
                        }
                    }
                } else {
                    // OR:每支单独 mint → 都能穿过(文档广告的每条来路都真实可走)
                    for b in &branches {
                        let s = hit(&app, method, &uri, op_id, &mint(b.clone())).await;
                        assert!(
                            s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                            "{op_id} OR 支 {b:?} 应可过,got {s}"
                        );
                    }
                }
            }
        }
    }
    assert!(
        checked >= 10,
        "应覆盖到全部受保护端点,实际只查了 {checked} 个"
    );
}

/// **`api_spec()` 必须与 `build_router` 实际装配的 spec 一致**。
///
/// 两者是**手抄的两份**同一棵 merge/nest 树(router.rs 自称"同源",却把每个 `.merge(xxx::router())`
/// 又列了一遍),而 `op_perms.rs` 的招牌承诺"加端点漏了 → 覆盖测试 fail-closed 报红"完全押在
/// `every_operation_classified` 上,那条测试读的是 `api_spec()`。于是:**新模块只 merge 进
/// build_router**(router.rs 头注恰恰就是这么教的:"加业务模块:在 build_router 对应组里
/// `.merge(xxx::router())` 一行"),api_spec 里没有它 → 覆盖测试遍历不到 → 全绿放行,
/// 而端点已带着**空 security** 上线。加端点到既有模块没事(该模块的 router 两边都 merge 了),
/// 加**模块**才是洞 —— 偏偏那是本脚手架的主要扩展点。
///
/// 这里不重构装配(把树抽成一个 fn 会破掉 per-group 组闸:gate 必须在 nest **之前**逐组上,
/// nest 完就没法只给 frontend 子树加 require_login 了),只钉住两份的**操作集合**相等。
#[tokio::test]
async fn api_spec_matches_the_router_that_actually_ships() {
    let config = Config::default(); // Dev → expose_docs() → 真路由挂 /api-docs/openapi.json
    let (state, _bg) = AppState::new(&config, Mount::Both).await.unwrap();
    let app = build_router(state, &config, Mount::Both);

    let resp = app
        .oneshot(
            Request::get("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "dev 应挂 /api-docs");
    let served: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    /// method+path 集合(spec 的操作全集)。
    fn ops(spec: &Value) -> std::collections::BTreeSet<String> {
        spec["paths"]
            .as_object()
            .expect("paths")
            .iter()
            .flat_map(|(path, item)| {
                item.as_object()
                    .expect("path item")
                    .keys()
                    .map(move |m| format!("{} {path}", m.to_uppercase()))
            })
            .collect()
    }

    let from_spec_fn = ops(&serde_json::to_value(api_spec()).unwrap());
    let from_router = ops(&served);
    assert_eq!(
        from_spec_fn, from_router,
        "api_spec() 与 build_router 实际挂的路由必须一致 —— 不一致则 every_operation_classified \
         遍历不到差集里的端点,op_perms 的 fail-closed 承诺对它们失效(会带着空 security 上线)"
    );
    assert!(!from_router.is_empty(), "别把两边都比成空集");
}

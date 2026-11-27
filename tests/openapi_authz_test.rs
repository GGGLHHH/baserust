//! 零漂移的 **by-test 边**:**spec 广告的 security ⟷ handler 实际 `require_scoped`** 一致(行为钉死)。
//! Rust 无法静态读 handler 体内 `require_scoped` 的实参,只能行为观测。
//!
//! **纯 spec 驱动**:method+path 与广告的 scope 都从 `api_spec()` 取(utoipa 从 `#[utoipa::path]` + nest 派生,
//! 是路由的唯一真相)—— **不从 OPERATION_PERMISSIONS 取 method/path**,故不引第二个路由来源/漂移。
//! 用 superadmin(平台角色 superadmin 给全部平台级权限 + 默认租户 admin 给全部租户级权限 = 持全 Permission,
//! 隔离 role 因素让"只有 scope 把门")签**降权令牌**打真实路由:
//! - 广告 scope 非空:`scope=[广告的]` → 穿过授权闸(非 401/403);`scope=[不蕴含它的 perm]` → 403。
//! - 广告 scope 空(仅登录):**零权限**令牌 → 非 403(无暗藏 `require_scoped`)。
//!
//! **AND/OR 结构化探测**:security 的每个 requirement 视作一支(单支多 scope = AND;多支各一 scope = OR)。
//! AND 支额外钉逐成员去一必 403;OR 支额外钉每支单独必过 —— 不再只测并集,连接组合语义都行为钉死。
//!
//! handler 改了 enforce 的 Permission 但 spec 广告没跟上(或反之)→ 这里红。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{body, Router};
use baserust::features::auth::ScopedTenant;
use baserust::kernel::tenant_id::DEFAULT_TENANT_ID;
use serde_json::Value;
use std::collections::BTreeSet;
use tower::ServiceExt; // oneshot
use uuid::Uuid;

use baserust::app::router::api_spec;
use baserust::app::{build_router, AppState, Mount};
use baserust::features::auth::AppTokenSigner;
use baserust::infra::config::Config;
use baserust::kernel::authorization::Permission;
use idm::LoginInput;

/// spec 里的 scope 串 → `Permission`(经 serde rename;非法即 panic,本就该是合法 Permission)。
fn str_to_perm(scope: &str) -> Permission {
    serde_json::from_value(Value::String(scope.to_owned())).expect("spec scope 应是合法 Permission")
}

/// 用 spec 给的 method+path(替换 {id})打一次,带 Bearer token,返回状态码。
async fn hit(app: &Router, method: &str, uri: &str, operation_id: &str, token: &str) -> StatusCode {
    let mut request_builder = Request::builder()
        .method(method.to_uppercase().as_str())
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    // 写端点 gate 在 body 提取**之后**跑 → 反向用例须发可提取的 body,否则提取器的 400/422 遮 403(假绿)。
    let body = match operation_id {
        "create_widget" | "update_widget" | "create_content" | "update_content"
        | "prepare_upload" | "put_profile" | "set_user_profile" => {
            request_builder = request_builder.header("content-type", "application/json");
            Body::from(r#"{"name":"probe"}"#)
        }
        "set_content_metadata" => {
            request_builder = request_builder.header("content-type", "application/json");
            Body::from(r#"{"tags":[]}"#)
        }
        // users 写端点:一份含各 DTO 必填字段的 body(serde 忽略多余键)→ 四端点共用,触达 gate。
        "create_user" | "update_user" | "set_user_roles" | "reset_user_password" => {
            request_builder = request_builder.header("content-type", "application/json");
            Body::from(
                r#"{"username":"probe","password":"probe123","roles":[],"new_password":"probe123"}"#,
            )
        }
        // 租户 / 成员写端点:一份含各 DTO 必填字段的 body(serde 忽略多余键),触达 gate。
        "create_tenant" | "update_tenant" | "put_tenant_member" | "add_member"
        | "set_member_roles" => {
            request_builder = request_builder.header("content-type", "application/json");
            Body::from(
                r#"{"slug":"probe","name":"probe","status":"active","username":"probe","roles":[]}"#,
            )
        }
        // multipart 端点:require_scoped 在 Multipart 提取后、读字段前跑 → 只需 content-type 合法即可触达 gate。
        "upload_content" | "set_user_avatar" => {
            request_builder =
                request_builder.header("content-type", "multipart/form-data; boundary=X");
            Body::from("--X--\r\n")
        }
        _ => Body::empty(),
    };
    app.clone()
        .oneshot(request_builder.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn spec_security_matches_real_enforcement() {
    let config = Config::default();
    let state = AppState::try_new(&config, Mount::Both).await.unwrap().state;
    let app = build_router(state.clone(), &config, Mount::Both);
    let superadmin = state
        .auth
        .login(LoginInput {
            identifier: "superadmin".to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap();
    // state 的 verifier 用内嵌默认 dev 公钥,故本地 dev 私钥签的令牌它也认。
    let signer = AppTokenSigner::new_with_development_key();
    let mint = |scope: Vec<Permission>| {
        signer
            .mint_scoped(
                superadmin.user.id,
                &superadmin.user.username,
                superadmin.user.roles.clone(),
                Some(ScopedTenant {
                    id: superadmin.tenant_id.expect("superadmin 登录应进默认租户"),
                    roles: superadmin.tenant_roles.clone(),
                }),
                scope,
                900,
            )
            .unwrap()
    };

    let spec = serde_json::to_value(api_spec()).unwrap();
    let mut checked = 0;
    for (path, item) in spec["paths"].as_object().expect("paths").iter() {
        for (method, operation) in item.as_object().expect("path item").iter() {
            // 只看带 security 的 operation(无 security = public,跳过)
            let Some(security) = operation.get("security").and_then(|s| s.as_array()) else {
                continue;
            };
            let operation_id = operation
                .get("operationId")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            // {user_id}(ownership 端点)代入**令牌主体自己的 id**:探针打"自己的"资源,
            // 授权闸才是唯一变量(打别人的会被 ownership 403 污染正向断言)。
            let uri = path
                .replace("{id}", &Uuid::nil().to_string())
                .replace("{user_id}", &superadmin.user.id.to_string());
            // 结构化读取:每个 requirement 一支(单支多 scope = AND;多支 = OR)
            let branches: Vec<Vec<Permission>> = security
                .iter()
                .filter_map(|r| r.get("oauth2"))
                .filter_map(|v| v.as_array())
                .map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| str_to_perm(s.as_str().unwrap()))
                        .collect()
                })
                .collect();
            checked += 1;

            let union: Vec<Permission> = branches.iter().flatten().copied().collect();
            if union.is_empty() {
                // 仅登录:零权限令牌(在默认租户、但平台 / 租户角色与 scope 皆空)→ 非 403(无暗藏 require_scoped)
                let zero = signer
                    .mint_scoped(
                        superadmin.user.id,
                        "probe",
                        vec![],
                        Some(ScopedTenant {
                            id: DEFAULT_TENANT_ID.as_uuid(),
                            roles: vec![],
                        }),
                        vec![],
                        900,
                    )
                    .unwrap();
                let status = hit(&app, method, &uri, operation_id, &zero).await;
                assert!(
                    status != StatusCode::FORBIDDEN,
                    "{operation_id} 仅登录端点不应 403,got {status}"
                );
            } else {
                // 反向(AND/OR 通用):并集外且不蕴含任一的 perm → 403
                let negative = Permission::ALL
                    .into_iter()
                    .find(|&candidate| {
                        !union.contains(&candidate)
                            && !union.iter().any(|t| candidate.implies().contains(t))
                    })
                    .expect("应有一个不蕴含目标的负权限");
                let status = hit(&app, method, &uri, operation_id, &mint(vec![negative])).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{operation_id} 反向 scope=[{negative:?}] 应 403,got {status}"
                );
                if branches.len() == 1 {
                    let set = &branches[0];
                    // 正向:全集 → 穿过授权闸(下游 200/201/404/422 都算非 401/403)
                    let status = hit(&app, method, &uri, operation_id, &mint(set.clone())).await;
                    assert!(
                        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                        "{operation_id} 正向 scope={set:?} 不应被拒,got {status}"
                    );
                    // AND 钉力:去掉任一成员 → 403(剩余集合经 implies 蕴含被去者则跳过,防假红)
                    if set.len() > 1 {
                        for (i, &dropped) in set.iter().enumerate() {
                            let rest: Vec<Permission> = set
                                .iter()
                                .copied()
                                .enumerate()
                                .filter(|&(j, _)| j != i)
                                .map(|(_, p)| p)
                                .collect();
                            if rest.iter().any(|r| r.implies().contains(&dropped)) {
                                continue;
                            }
                            let status = hit(&app, method, &uri, operation_id, &mint(rest)).await;
                            assert_eq!(
                                status,
                                StatusCode::FORBIDDEN,
                                "{operation_id} AND 缺 {dropped:?} 应 403,got {status}"
                            );
                        }
                    }
                } else {
                    // OR:每支单独 mint → 都能穿过(文档广告的每条来路都真实可走)
                    for branch in &branches {
                        let status =
                            hit(&app, method, &uri, operation_id, &mint(branch.clone())).await;
                        assert!(
                            status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                            "{operation_id} OR 支 {branch:?} 应可过,got {status}"
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

/// **条件权限**(`operation_permissions::CONDITIONAL_PERMISSIONS` → spec 的 `x-conditional-scopes` 扩展):OpenAPI 的 security 是逐
/// operation 静态的,表达不了「改别人才要」这种看请求数据的闸(如 `put_profile` 改别人另要 `profiles:write:all` +
/// `platform:roles`)。这类闸写进扩展,这里行为钉死文档 ⟷ handler:
/// - 条件成立(路径 `{user_id}` 是**别人**):security 广告的 + 条件 scope 全给 → 穿过;逐个去掉条件 scope → 403。
/// - 条件不成立(打自己):只给 security 广告的就能过(条件闸没有被无条件化)。
/// - 403 的响应描述写明了每个条件 scope(读文档的人在 403 那里就能看到为什么)。
#[tokio::test]
async fn conditional_scopes_documented_and_enforced() {
    let config = Config::default();
    let state = AppState::try_new(&config, Mount::Both).await.unwrap().state;
    let app = build_router(state.clone(), &config, Mount::Both);
    let superadmin = state
        .auth
        .login(LoginInput {
            identifier: "superadmin".to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap();
    let signer = AppTokenSigner::new_with_development_key();
    let mint = |scope: Vec<Permission>| {
        signer
            .mint_scoped(
                superadmin.user.id,
                &superadmin.user.username,
                superadmin.user.roles.clone(),
                Some(ScopedTenant {
                    id: superadmin.tenant_id.expect("superadmin 登录应进默认租户"),
                    roles: superadmin.tenant_roles.clone(),
                }),
                scope,
                900,
            )
            .unwrap()
    };

    let spec = serde_json::to_value(api_spec()).unwrap();
    let mut checked: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("paths").iter() {
        for (method, operation) in item.as_object().expect("path item").iter() {
            let Some(conditions) = operation
                .get("x-conditional-scopes")
                .and_then(|c| c.as_array())
            else {
                continue;
            };
            let operation_id = operation["operationId"].as_str().unwrap_or("");
            // 条件闸之外的基本要求:取 security 的第一支(单支 = AND)
            let base: Vec<Permission> = operation["security"][0]["oauth2"]
                .as_array()
                .unwrap_or_else(|| panic!("{operation_id} 有条件 scope 却没有 security"))
                .iter()
                .map(|s| str_to_perm(s.as_str().unwrap()))
                .collect();
            let forbidden_doc = operation["responses"]["403"]["description"]
                .as_str()
                .unwrap_or_else(|| panic!("{operation_id} 有条件 scope,应文档化 403"));
            for condition in conditions {
                assert_eq!(
                    condition["when"], "other_user",
                    "{operation_id}:本测试只会探测 other_user 条件,新条件要在这里补探测"
                );
                let extra: Vec<Permission> = condition["scopes"]
                    .as_array()
                    .expect("scopes")
                    .iter()
                    .map(|s| str_to_perm(s.as_str().unwrap()))
                    .collect();
                assert!(!extra.is_empty(), "{operation_id} 条件 scope 不应为空");
                for permission in &extra {
                    assert!(
                        forbidden_doc.contains(&permission.wire()),
                        "{operation_id} 的 403 描述应写明条件 scope {}:{forbidden_doc}",
                        permission.wire()
                    );
                }
                let other = path.replace("{user_id}", &Uuid::now_v7().to_string());
                let mine = path.replace("{user_id}", &superadmin.user.id.to_string());
                let full: Vec<Permission> = base.iter().chain(extra.iter()).copied().collect();
                let status = hit(&app, method, &other, operation_id, &mint(full.clone())).await;
                assert!(
                    status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                    "{operation_id} 改别人、scope={full:?} 不应被拒,got {status}"
                );
                for dropped in &extra {
                    let rest: Vec<Permission> =
                        full.iter().copied().filter(|p| p != dropped).collect();
                    if rest.iter().any(|r| r.implies().contains(dropped)) {
                        continue;
                    }
                    let status = hit(&app, method, &other, operation_id, &mint(rest)).await;
                    assert_eq!(
                        status,
                        StatusCode::FORBIDDEN,
                        "{operation_id} 改别人缺条件 scope {dropped:?} 应 403,got {status}"
                    );
                }
                let status = hit(&app, method, &mine, operation_id, &mint(base.clone())).await;
                assert!(
                    status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                    "{operation_id} 改自己只要 security 广告的 {base:?},got {status}"
                );
            }
            checked.push(operation_id.to_owned());
        }
    }
    assert!(
        checked.iter().any(|o| o == "put_profile"),
        "put_profile 改别人要 platform:roles,应在 x-conditional-scopes 里文档化,实际查到:{checked:?}"
    );
}

/// **`api_spec()` 必须与 `build_router` 实际装配的 spec 一致**。
///
/// 两者是**手抄的两份**同一棵 merge/nest 树(router.rs 自称"同源",却把每个 `.merge(xxx::router())`
/// 又列了一遍),而 `operation_permissions.rs` 的招牌承诺"加端点漏了 → 覆盖测试 fail-closed 报红"完全押在
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
    let state = AppState::try_new(&config, Mount::Both).await.unwrap().state;
    let app = build_router(state, &config, Mount::Both);

    let response = app
        .oneshot(
            Request::get("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "dev 应挂 /api-docs");
    let served: Value = serde_json::from_slice(
        &body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    /// method+path 集合(spec 的操作全集)。
    fn ops(spec: &Value) -> BTreeSet<String> {
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
         遍历不到差集里的端点,operation_permissions 的 fail-closed 承诺对它们失效(会带着空 security 上线)"
    );
    assert!(!from_router.is_empty(), "别把两边都比成空集");
}

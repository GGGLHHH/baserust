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
    let mint = |scope: Vec<Perm>| {
        signer
            .mint_scoped(
                su.user.id,
                &su.user.username,
                su.user.roles.clone(),
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

            let union: Vec<Perm> = branches.iter().flatten().copied().collect();
            if union.is_empty() {
                // 仅登录:零权限令牌(roles + scope 皆空)→ 非 403(无暗藏 require_scoped)
                let zero = signer
                    .mint_scoped(su.user.id, "probe", vec![], vec![], 900)
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

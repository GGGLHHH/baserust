//! 零漂移的 **by-test 边**:**spec 广告的 security ⟷ handler 实际 `require_scoped`** 一致(行为钉死)。
//! Rust 无法静态读 handler 体内 `require_scoped` 的实参,只能行为观测。
//!
//! **纯 spec 驱动**:method+path 与广告的 scope 都从 `api_spec()` 取(utoipa 从 `#[utoipa::path]` + nest 派生,
//! 是路由的唯一真相)—— **不从 OP_PERMS 取 method/path**,故不引第二个路由来源/漂移。
//! 用 superadmin(持全 Perm,隔离 role 因素让"只有 scope 把门")签**降权令牌**打真实路由:
//! - 广告 scope 非空:`scope=[广告的]` → 穿过授权闸(非 401/403);`scope=[不蕴含它的 perm]` → 403。
//! - 广告 scope 空(仅登录):**零权限**令牌 → 非 403(无暗藏 `require_scoped`)。
//!
//! handler 改了 enforce 的 Perm 但 spec 广告没跟上(或反之)→ 这里红。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use tower::ServiceExt; // oneshot
use uuid::Uuid;

use idm::LoginInput;
use xchangeai::app::router::api_spec;
use xchangeai::app::{build_router, AppState, Mount};
use xchangeai::infra::authz::Perm;
use xchangeai::infra::config::Config;

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
        | "prepare_upload" => {
            b = b.header("content-type", "application/json");
            Body::from(r#"{"name":"probe"}"#)
        }
        "set_content_metadata" => {
            b = b.header("content-type", "application/json");
            Body::from(r#"{"tags":[]}"#)
        }
        // multipart 端点:require_scoped 在 Multipart 提取后、读字段前跑 → 只需 content-type 合法即可触达 gate。
        "upload_content" => {
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
    let state = AppState::new(&config, Mount::Both).await.unwrap();
    let app = build_router(state.clone(), &config, Mount::Both);
    let su = state
        .auth
        .login(LoginInput {
            identifier: "superadmin".to_owned(),
            password: "pwd".to_owned(),
        })
        .await
        .unwrap();
    let mint = |scope: Vec<Perm>| {
        state
            .tokens
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
            let uri = path.replace("{id}", &Uuid::nil().to_string());
            // spec 广告的 oauth2 scopes
            let scopes: Vec<Perm> = sec
                .iter()
                .filter_map(|r| r.get("oauth2"))
                .filter_map(|v| v.as_array())
                .flatten()
                .map(|s| str_to_perm(s.as_str().unwrap()))
                .collect();
            checked += 1;

            if scopes.is_empty() {
                // 仅登录:零权限令牌(roles + scope 皆空)→ 非 403(无暗藏 require_scoped)
                let zero = state
                    .tokens
                    .mint_scoped(su.user.id, "probe", vec![], vec![], 900)
                    .unwrap();
                let s = hit(&app, method, &uri, op_id, &zero).await;
                assert!(
                    s != StatusCode::FORBIDDEN,
                    "{op_id} 仅登录端点不应 403,got {s}"
                );
            } else {
                // 正向:广告的 scope → 穿过授权闸(下游 200/201/404/422 都算非 401/403)
                let s = hit(&app, method, &uri, op_id, &mint(scopes.clone())).await;
                assert!(
                    s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                    "{op_id} 正向 scope={scopes:?} 不应被拒,got {s}"
                );
                // 反向:不在广告集、且不蕴含其中任一的 perm → 403(证明 handler enforce 的就是广告的)
                let neg = Perm::ALL
                    .into_iter()
                    .find(|&q| {
                        !scopes.contains(&q) && !scopes.iter().any(|t| q.implies().contains(t))
                    })
                    .expect("应有一个不蕴含目标的负权限");
                let s = hit(&app, method, &uri, op_id, &mint(vec![neg])).await;
                assert_eq!(
                    s,
                    StatusCode::FORBIDDEN,
                    "{op_id} 反向 scope=[{neg:?}] 应 403,got {s}"
                );
            }
        }
    }
    assert!(
        checked >= 10,
        "应覆盖到全部受保护端点,实际只查了 {checked} 个"
    );
}

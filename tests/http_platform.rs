//! 平台层的**黑盒 HTTP 验收测试**:健康探针、当前权限、以及**全局中间件**的对外契约
//! (未知路径 / 不支持的方法也给统一错误体、安全响应头、CORS、request-id)。
//! 换 web 底座时最容易漏的就是这一层 —— 业务 handler 全过了,全局行为却悄悄变了。
//!
//! covers: GET /health
//! covers: GET /livez
//! covers: GET /readyz
//! covers: GET /api/v1/frontend/permissions/me

mod http_support;

use http_support::{expect, expect_error, expect_json, TestServer, ADMIN, PASSWORD, USER};
use reqwest::{Method, StatusCode};

#[tokio::test]
async fn health_probes() {
    let s = TestServer::start().await;
    let c = s.anon();
    for path in ["/health", "/livez"] {
        assert_eq!(
            expect(c.get(path).await, StatusCode::OK).await,
            "ok",
            "{path}"
        );
    }
    // 内存模式无外部依赖 → 恒就绪,逐项检查结果为空
    let v = expect_json(c.get("/readyz").await, StatusCode::OK).await;
    assert_eq!(v["status"], "ok", "{v}");
    assert_eq!(v["checks"], serde_json::json!({}), "{v}");
}

/// 当前令牌的有效权限:role 展开 ∩ scope;未登录 401。
#[tokio::test]
async fn permissions_me() {
    let s = TestServer::start().await;
    let path = "/api/v1/frontend/permissions/me";
    expect(s.anon().get(path).await, StatusCode::UNAUTHORIZED).await;

    let user = s.login(USER, PASSWORD).await;
    let v = expect_json(user.get(path).await, StatusCode::OK).await;
    // user 没有平台角色;它的 user 角色是默认租户里的租户角色
    assert_eq!(v["roles"], serde_json::json!([]));
    assert_eq!(v["tenant_roles"], serde_json::json!(["user"]));
    let perms: Vec<&str> = v["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(perms.contains(&"widgets:read"), "{v}");
    assert!(
        !perms.contains(&"users:admin"),
        "user 不应有 users:admin: {v}"
    );
    let mut sorted = perms.clone();
    sorted.sort();
    assert_eq!(perms, sorted, "权限按 wire 串排序输出");

    let admin = s.login(ADMIN, PASSWORD).await;
    let v = expect_json(admin.get(path).await, StatusCode::OK).await;
    assert!(
        v["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "admin:login"),
        "{v}"
    );
}

/// 未知路径 → 404 **JSON 统一错误体**(不是框架默认的空 body / 纯文本)。
#[tokio::test]
async fn unknown_path_is_json_404() {
    let s = TestServer::start().await;
    expect_error(
        s.anon().get("/api/v1/frontend/no-such-thing").await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        s.anon().get("/nope").await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 路径存在但方法不支持 → 405 + 统一错误体(机器码归 bad_request)+ `allow` 头。
#[tokio::test]
async fn wrong_method_is_json_405() {
    let s = TestServer::start().await;
    let resp = s
        .login(USER, PASSWORD)
        .await
        .req(Method::PATCH, "/api/v1/frontend/widgets")
        .send()
        .await
        .unwrap();
    assert!(resp.headers().get("allow").is_some(), "405 应带 allow 头");
    expect_error(resp, StatusCode::METHOD_NOT_ALLOWED, "bad_request").await;
}

/// 每个响应(含错误响应)都带安全头 + request-id。
#[tokio::test]
async fn security_headers_and_request_id_on_every_response() {
    let s = TestServer::start().await;
    let c = s.anon();
    for path in ["/health", "/api/v1/frontend/widgets", "/nope"] {
        let resp = c.get(path).await;
        let h = resp.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        assert!(h.get("x-request-id").is_some(), "{path} 缺 x-request-id");
    }
}

/// 客户端给的 request-id 原样回传(便于前后端日志关联)。
#[tokio::test]
async fn request_id_is_propagated() {
    let s = TestServer::start().await;
    let resp = s
        .anon()
        .req(Method::GET, "/health")
        .header("x-request-id", "trace-me-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-request-id"], "trace-me-123");
}

/// dev 配置下 CORS 放行任意源(预检 + 实际请求都带 CORS 头,错误响应也带)。
#[tokio::test]
async fn cors_dev_permissive() {
    let s = TestServer::start().await;
    let c = s.anon();
    let pre = c
        .req(Method::OPTIONS, "/api/v1/frontend/widgets")
        .header("origin", "http://example.test")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert!(pre.status().is_success(), "预检应成功: {}", pre.status());
    assert!(pre.headers().get("access-control-allow-origin").is_some());

    let resp = c
        .req(Method::GET, "/api/v1/frontend/widgets")
        .header("origin", "http://example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().get("access-control-allow-origin").is_some(),
        "错误响应也要带 CORS 头,否则浏览器读不到错误体"
    );
}

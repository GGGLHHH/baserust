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
    let server = TestServer::start().await;
    let client = server.anonymous();
    for path in ["/health", "/livez"] {
        assert_eq!(
            expect(client.get(path).await, StatusCode::OK).await,
            "ok",
            "{path}"
        );
    }
    // 内存模式无外部依赖 → 恒就绪,逐项检查结果为空
    let readiness = expect_json(client.get("/readyz").await, StatusCode::OK).await;
    assert_eq!(readiness["status"], "ok", "{readiness}");
    assert_eq!(readiness["checks"], serde_json::json!({}), "{readiness}");
}

/// 当前令牌的有效权限:role 展开 ∩ scope;未登录 401。
#[tokio::test]
async fn permissions_me() {
    let server = TestServer::start().await;
    let path = "/api/v1/frontend/permissions/me";
    expect(server.anonymous().get(path).await, StatusCode::UNAUTHORIZED).await;

    let user = server.login(USER, PASSWORD).await;
    let me = expect_json(user.get(path).await, StatusCode::OK).await;
    // user 没有平台角色;它的 user 角色是默认租户里的租户角色
    assert_eq!(me["roles"], serde_json::json!([]));
    assert_eq!(me["tenant_roles"], serde_json::json!(["user"]));
    let permissions: Vec<&str> = me["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(permissions.contains(&"widgets:read"), "{me}");
    assert!(
        !permissions.contains(&"users:admin"),
        "user 不应有 users:admin: {me}"
    );
    let mut sorted = permissions.clone();
    sorted.sort();
    assert_eq!(permissions, sorted, "权限按 wire 串排序输出");

    let admin = server.login(ADMIN, PASSWORD).await;
    let me = expect_json(admin.get(path).await, StatusCode::OK).await;
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "admin:login"),
        "{me}"
    );
}

/// 未知路径 → 404 **JSON 统一错误体**(不是框架默认的空 body / 纯文本)。
#[tokio::test]
async fn unknown_path_is_json_404() {
    let server = TestServer::start().await;
    expect_error(
        server
            .anonymous()
            .get("/api/v1/frontend/no-such-thing")
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    expect_error(
        server.anonymous().get("/nope").await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

/// 路径存在但方法不支持 → 405 + 统一错误体(机器码归 bad_request)+ `allow` 头。
#[tokio::test]
async fn wrong_method_is_json_405() {
    let server = TestServer::start().await;
    let response = server
        .login(USER, PASSWORD)
        .await
        .request(Method::PATCH, "/api/v1/frontend/widgets")
        .send()
        .await
        .unwrap();
    assert!(
        response.headers().get("allow").is_some(),
        "405 应带 allow 头"
    );
    expect_error(response, StatusCode::METHOD_NOT_ALLOWED, "bad_request").await;
}

/// 每个响应(含错误响应)都带安全头 + request-id。
#[tokio::test]
async fn security_headers_and_request_id_on_every_response() {
    let server = TestServer::start().await;
    let client = server.anonymous();
    for path in ["/health", "/api/v1/frontend/widgets", "/nope"] {
        let response = client.get(path).await;
        let headers = response.headers();
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["x-frame-options"], "DENY", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
        assert!(
            headers.get("x-request-id").is_some(),
            "{path} 缺 x-request-id"
        );
    }
}

/// 客户端给的 request-id 原样回传(便于前后端日志关联)。
#[tokio::test]
async fn request_id_is_propagated() {
    let server = TestServer::start().await;
    let response = server
        .anonymous()
        .request(Method::GET, "/health")
        .header("x-request-id", "trace-me-123")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-request-id"], "trace-me-123");
}

/// dev 配置下 CORS 放行任意源(预检 + 实际请求都带 CORS 头,错误响应也带)。
#[tokio::test]
async fn cors_dev_permissive() {
    let server = TestServer::start().await;
    let client = server.anonymous();
    let preflight = client
        .request(Method::OPTIONS, "/api/v1/frontend/widgets")
        .header("origin", "http://example.test")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert!(
        preflight.status().is_success(),
        "预检应成功: {}",
        preflight.status()
    );
    assert!(preflight
        .headers()
        .get("access-control-allow-origin")
        .is_some());

    let response = client
        .request(Method::GET, "/api/v1/frontend/widgets")
        .header("origin", "http://example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_some(),
        "错误响应也要带 CORS 头,否则浏览器读不到错误体"
    );
}

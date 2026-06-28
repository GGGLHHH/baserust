//! widget API 集成测试 —— lib.rs 拆分解锁的能力:
//! tests/ 直接 import 库、用内存仓储 oneshot 打**真实端点**(过完整中间件栈),无需数据库。
//! 加业务模块后,照此对其端点写黑盒测试。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt; // oneshot

use xchangeai::app::{build_router, AppState};
use xchangeai::features::widget::{InMemoryWidgetRepo, WidgetService};

/// 内存仓储的测试 app(无 DB);AppState 字段 pub,直接装配。
fn test_app() -> Router {
    let state = AppState {
        widgets: WidgetService::new(Arc::new(InMemoryWidgetRepo::new())),
        db_pool: None, // 内存模式:readyz 恒就绪
    };
    build_router(state, &xchangeai::infra::config::Config::default())
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn post_json(uri: &str, json: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn health_ok() {
    let resp = test_app().oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_then_list_offset() {
    let app = test_app();
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/widgets", r#"{"name":"alpha"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app.oneshot(get("/api/v1/widgets")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("alpha"));
    // 默认 offset 模式,PageInfo 内部标签 mode=offset
    assert!(body.contains("\"mode\":\"offset\""));
}

#[tokio::test]
async fn cursor_first_page_ok() {
    let app = test_app();
    app.clone()
        .oneshot(post_json("/api/v1/widgets", r#"{"name":"a"}"#))
        .await
        .unwrap();
    // 空 cursor = cursor 模式首页
    let resp = app
        .oneshot(get("/api/v1/widgets?cursor=&size=2"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("\"mode\":\"cursor\""));
}

#[tokio::test]
async fn create_empty_name_is_422() {
    let resp = test_app()
        .oneshot(post_json("/api/v1/widgets", r#"{"name":""}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn bad_cursor_is_400() {
    let resp = test_app()
        .oneshot(get("/api/v1/widgets?cursor=!!!bad"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn page_and_cursor_conflict_is_422() {
    let resp = test_app()
        .oneshot(get("/api/v1/widgets?page=1&cursor=xxx"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn missing_widget_is_404() {
    let resp = test_app()
        .oneshot(get("/api/v1/widgets/00000000-0000-0000-0000-000000000000"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use utoipa::OpenApi;

use crate::error::AppError;
use crate::state::AppState;

/// OpenAPI 文档根。范式:
/// - 顶层 info/tags 在此声明;path 与 schema 由各模块的 `#[utoipa::path]` + `routes!()` 贡献。
/// - `split_for_parts()` 把所有模块的规范合并成一份。
#[derive(OpenApi)]
#[openapi(
    info(title = "xchangeai API", version = "0.1.0", description = "Rust 脚手架"),
    tags(
        (name = "health", description = "健康检查"),
        (name = "widgets", description = "示例资源")
    )
)]
pub struct ApiDoc;

/// 暴露 `/api-docs/openapi.json` 与 `/api-docs/openapi.yaml`。
/// yaml 用 utoipa 自带的 `to_yaml()`(yaml feature),整条绕开 2026 混乱的 serde_yaml 生态。
pub fn doc_routes(api: utoipa::openapi::OpenApi) -> Router<AppState> {
    let json_api = api.clone();
    let yaml_api = api;
    Router::new()
        .route(
            "/api-docs/openapi.json",
            get(move || {
                let api = json_api.clone();
                async move { axum::Json(api) }
            }),
        )
        .route(
            "/api-docs/openapi.yaml",
            get(move || {
                let api = yaml_api.clone();
                async move { yaml_response(&api) }
            }),
        )
}

fn yaml_response(api: &utoipa::openapi::OpenApi) -> Response {
    match api.to_yaml() {
        Ok(body) => ([(header::CONTENT_TYPE, "application/yaml")], body).into_response(),
        Err(e) => {
            AppError::Internal(anyhow::anyhow!("生成 OpenAPI YAML 失败: {e}")).into_response()
        }
    }
}

use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{CreateWidget, Widget};
use crate::error::{AppError, ErrorBody};
use crate::extract::{Json, Path};
use crate::state::AppState;

/// 列出所有 widget。范式:handler 薄 —— 只取 state、调 service、返回。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",
    responses((status = 200, description = "widget 列表", body = [Widget]))
)]
pub async fn list_widgets(State(state): State<AppState>) -> Result<Json<Vec<Widget>>, AppError> {
    let widgets = state.widgets.list().await?;
    Ok(Json(widgets))
}

/// 创建一个 widget。
#[utoipa::path(
    post,
    path = "/widgets",
    tag = "widgets",
    request_body = CreateWidget,
    responses(
        (status = 201, description = "已创建", body = Widget),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn create_widget(
    State(state): State<AppState>,
    Json(input): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), AppError> {
    let widget = state.widgets.create(input).await?;
    Ok((StatusCode::CREATED, Json(widget)))
}

/// 按 id 取一个 widget;不存在 → 404(展示 Path 提取 + NotFound 范式)。
#[utoipa::path(
    get,
    path = "/widgets/{id}",
    tag = "widgets",
    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 200, description = "找到", body = Widget),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn get_widget(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Widget>, AppError> {
    let widget = state.widgets.get(id).await?;
    Ok(Json(widget))
}

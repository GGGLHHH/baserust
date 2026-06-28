use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{CreateWidget, UpdateWidget, Widget};
use crate::audit::AuditContext;
use crate::error::{AppError, ErrorBody};
use crate::extract::{Json, Path, Query};
use crate::pagination::{Page, PageQuery};
use crate::state::AppState;

/// 分页列出 widget。默认 offset 第 1 页;带 `cursor` 切 keyset 高性能模式。
/// handler 薄 —— 取 state、调 service、返回。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",
    params(PageQuery),
    responses((status = 200, description = "widget 分页列表", body = Page<Widget>))
)]
pub async fn list_widgets(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<Widget>>, AppError> {
    Ok(Json(state.widgets.list(query).await?))
}

/// 创建一个 widget。审计主体(created_by)来自 `AuditContext`。
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
    ctx: AuditContext,
    Json(input): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), AppError> {
    let widget = state.widgets.create(input, &ctx).await?;
    Ok((StatusCode::CREATED, Json(widget)))
}

/// 按 id 取一个存活 widget;不存在/已软删 → 404。
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
    Ok(Json(state.widgets.get(id).await?))
}

/// 更新 widget(改名);updated_by 来自 `AuditContext`,updated_at 由触发器自动盖。
#[utoipa::path(
    put,
    path = "/widgets/{id}",
    tag = "widgets",
    params(("id" = Uuid, Path, description = "widget id")),
    request_body = UpdateWidget,
    responses(
        (status = 200, description = "已更新", body = Widget),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_widget(
    State(state): State<AppState>,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateWidget>,
) -> Result<Json<Widget>, AppError> {
    Ok(Json(state.widgets.update(id, input, &ctx).await?))
}

/// 软删除 widget(盖 deleted_at,非物理删除)。
#[utoipa::path(
    delete,
    path = "/widgets/{id}",
    tag = "widgets",
    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 204, description = "已软删除"),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn delete_widget(
    State(state): State<AppState>,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state.widgets.delete(id, &ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

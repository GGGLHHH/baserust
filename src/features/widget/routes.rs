use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{CreateWidget, UpdateWidget, Widget};
use super::view::{WidgetStats, WidgetView};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path, Query};
use crate::infra::pagination::{Page, PageQuery};

// 三轴授权(详见 `authorization` skill):**必须登录**(`CurrentUser` → 401);RBAC(`require_scoped` → 403);
// 数据所有权(`data_access` → `owner_filter`/`allows_created_by`:`user` 只看/取自己创建的,有 `read:all` 的看全部)。

/// 分页列出 widget。**user 只列自己创建的**(read:all → 全部)。默认 offset;带 `cursor` 切 keyset。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",    params(PageQuery),
    responses(
        (status = 200, description = "widget 分页列表(按所有权过滤,created_by 富化为用户)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限", body = ErrorBody)
    )
)]
pub async fn list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<WidgetView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    // ownership:无 read:all → 只列自己创建的(过滤落查询层,分页正确)。
    let owner = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll)
        .owner_filter();
    Ok(Json(state.widgets.list_enriched(query, owner).await?))
}

/// 创建一个 widget(需 `widgets:write`)。审计主体(created_by)= 当前登录用户,来自 `AuditContext`。
#[utoipa::path(
    post,
    path = "/widgets",
    tag = "widgets",    request_body = CreateWidget,
    responses(
        (status = 201, description = "已创建", body = Widget),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:write 权限", body = ErrorBody),
        (status = 409, description = "name 已存在(存活行内唯一)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn create_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Json(input): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetWrite)?;
    let widget = state.widgets.create(input, &ctx).await?;
    Ok((StatusCode::CREATED, Json(widget)))
}

/// 按 id 取一个存活 widget。**user 只能取自己创建的**:不是自己的 / 不存在 / 已软删 → 404。
#[utoipa::path(
    get,
    path = "/widgets/{id}",
    tag = "widgets",    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 200, description = "找到", body = Widget),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 非本人(不区分,防泄露存在)", body = ErrorBody)
    )
)]
pub async fn get_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Widget>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll);
    let widget = state.widgets.get(id).await?;
    if access.allows_created_by(widget.created_by.as_deref()) {
        Ok(Json(widget))
    } else {
        Err(AppError::NotFound) // 不是你的 → 404(不泄露存在,区别于 403)
    }
}

/// 更新 widget(改名,需 `widgets:write`);updated_by 来自 `AuditContext`,updated_at 由触发器自动盖。
#[utoipa::path(
    put,
    path = "/widgets/{id}",
    tag = "widgets",    params(("id" = Uuid, Path, description = "widget id")),
    request_body = UpdateWidget,
    responses(
        (status = 200, description = "已更新", body = Widget),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:write 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 409, description = "name 撞已有(存活行内唯一)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateWidget>,
) -> Result<Json<Widget>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetWrite)?;
    Ok(Json(state.widgets.update(id, input, &ctx).await?))
}

/// 软删除 widget(盖 deleted_at,需 `widgets:delete`)。
#[utoipa::path(
    delete,
    path = "/widgets/{id}",
    tag = "widgets",    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 204, description = "已软删除"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:delete 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn delete_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetDelete)?;
    state.widgets.delete(id, &ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── 授权形态样板:除上面"登录 + perm(+ownership)"外,补齐 public / 仅登录 / superadmin-only ──

/// **public**:全站 widget 计数。无 `CurrentUser`/`require_scoped` → 任何人可调
/// (不进 `OP_PERMS` → 文档不挂 security)。演示"无需登录"形态。
#[utoipa::path(
    get,
    path = "/widgets/stats",
    tag = "widgets",
    responses((status = 200, description = "全站 widget 计数(公开)", body = WidgetStats))
)]
pub async fn widget_stats(State(state): State<AppState>) -> Result<Json<WidgetStats>, AppError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(None).await?,
    }))
}

/// **仅登录**(authenticated):当前用户创建的 widget 数。要 `CurrentUser`、**无特定 perm**
/// (`OP_PERMS` 标 `None` → 文档 `security:[{"oauth2":[]}]`)。演示"只需登录"形态。
#[utoipa::path(
    get,
    path = "/widgets/my-count",
    tag = "widgets",
    responses(
        (status = 200, description = "当前用户创建的 widget 数", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody)
    )
)]
pub async fn my_widget_count(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<WidgetStats>, AppError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(Some(user.0.id)).await?,
    }))
}

/// **superadmin-only**:跨所有人列出全部 widget。gate 在 `users:admin`(seed 里只 superadmin 持有)。
/// 演示"role 限制 = gate 一个该 role 专属的 perm";注意 admin 虽有 `read:all`,无 `users:admin` 仍 403。
#[utoipa::path(
    get,
    path = "/widgets/admin/all",
    tag = "widgets",
    params(PageQuery),
    responses(
        (status = 200, description = "全部 widget(跨所有人,富化)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限(仅 superadmin)", body = ErrorBody)
    )
)]
pub async fn admin_list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<WidgetView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(state.widgets.list_enriched(query, None).await?))
}

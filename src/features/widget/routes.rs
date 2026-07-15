use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use uuid::Uuid;

use super::events::WidgetEvent;
use super::types::{CreateWidget, UpdateWidget, Widget, WidgetSortField};
use super::view::{WidgetStats, WidgetView};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path, Query};
use crate::infra::pagination::{Page, PageParams, PageQuery};
use crate::infra::sort::SortOrder;

/// 列表排序 query(**第二个 `Query` 提取器**,避免把 sort 塞进共享 `PageQuery`)。
/// `#[serde(default)]`:两参都缺时回落默认(否则 serde_urlencoded 对必填字段缺失即 400)。
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct WidgetSort {
    pub sort_by: WidgetSortField,
    pub order: SortOrder,
}

/// cursor keyset 恒按 id;非默认 sort 只能配 offset。cursor + 非默认 sort → 422(而非静默忽略)。
fn ensure_sort_pagination(params: &PageParams, sort: &WidgetSort) -> Result<(), AppError> {
    let is_default_sort =
        matches!(sort.sort_by, WidgetSortField::CreatedAt) && matches!(sort.order, SortOrder::Desc);
    if matches!(params, PageParams::Cursor { .. }) && !is_default_sort {
        return Err(AppError::Validation(
            "sort_by requires offset/page pagination".into(),
        ));
    }
    Ok(())
}

// 三轴授权(详见 `authorization` skill):**必须登录**(`CurrentUser` → 401);RBAC(`require_scoped` → 403);
// 数据所有权(`data_access` → `owner_filter`/`allows_created_by`:`user` 只看/取自己创建的,有 `read:all` 的看全部)。

/// 分页列出 widget。**user 只列自己创建的**(read:all → 全部)。默认 offset;带 `cursor` 切 keyset。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",    params(PageQuery, WidgetSort),
    responses(
        (status = 200, description = "widget 分页列表(按所有权过滤,created_by 富化为用户)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by(仅 offset 支持排序)", body = ErrorBody)
    )
)]
pub async fn list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
    Query(sort): Query<WidgetSort>,
) -> Result<Json<Page<WidgetView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    // ownership:无 read:all → 只列自己创建的(过滤落查询层,分页正确)。
    let owner = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll)
        .owner_filter();
    let params = query.resolve()?;
    ensure_sort_pagination(&params, &sort)?;
    Ok(Json(
        state
            .widgets
            .list_enriched(params, owner, sort.sort_by, sort.order)
            .await?,
    ))
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

/// **多权限 AND 样板**:删除预检 —— 读得见**且**删得动才允许看"可删多少"。
/// `require_all` 缺任一 perm 即 403;文档 = 单 requirement 多 scope(`OP_PERMS` 的 `PermReq::All`)。
#[utoipa::path(
    get,
    path = "/widgets/purge-preview",
    tag = "widgets",
    responses(
        (status = 200, description = "本人可见域内可删 widget 计数", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "缺 widgets:read 或 widgets:delete 任一", body = ErrorBody)
    )
)]
pub async fn purge_preview(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Json<WidgetStats>, AppError> {
    state
        .policy
        .require_all(&user.0, &scope.0, &[Perm::WidgetRead, Perm::WidgetDelete])?;
    Ok(Json(WidgetStats {
        total: state.widgets.count(Some(user.0.id)).await?,
    }))
}

/// **多权限 OR 样板**:概览 —— 普通读权**或**管理员任一即可。
/// `require_any` 全败才 403;文档 = 多 requirement 各一 scope(`PermReq::Any`)。
#[utoipa::path(
    get,
    path = "/widgets/overview",
    tag = "widgets",
    responses(
        (status = 200, description = "全站 widget 计数(读权或管理员)", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "widgets:read 与 users:admin 皆无", body = ErrorBody)
    )
)]
pub async fn widget_overview(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Json<WidgetStats>, AppError> {
    state
        .policy
        .require_any(&user.0, &scope.0, &[Perm::WidgetRead, Perm::UsersAdmin])?;
    Ok(Json(WidgetStats {
        total: state.widgets.count(None).await?,
    }))
}

/// **superadmin-only**:跨所有人列出全部 widget。gate 在 `users:admin`(seed 里只 superadmin 持有)。
/// 演示"role 限制 = gate 一个该 role 专属的 perm";注意 admin 虽有 `read:all`,无 `users:admin` 仍 403。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",
    params(PageQuery, WidgetSort),
    responses(
        (status = 200, description = "全部 widget(跨所有人,富化)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限(仅 superadmin)", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by(仅 offset 支持排序)", body = ErrorBody)
    )
)]
pub async fn admin_list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
    Query(sort): Query<WidgetSort>,
) -> Result<Json<Page<WidgetView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let params = query.resolve()?;
    ensure_sort_pagination(&params, &sort)?;
    Ok(Json(
        state
            .widgets
            .list_enriched(params, None, sort.sort_by, sort.order)
            .await?,
    ))
}

/// 订阅 widget 变更事件流(SSE)。需登录 + `widgets:read` —— 与列表同权:能看列表就能看变更。
/// EventSource 不能自定义 header,凭据靠 httponly cookie(Bearer 兜底给 curl/测试)。
/// best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
///
/// **行级 ownership 与 list 同口径**:总线是广播(不分频道),过滤落在本 handler —— 逐帧
/// `allows_created_by`,不过就跳帧(`continue`),**不**结束流。没这层,无 `read:all` 的 `user`
/// 能从流里读到 `list_widgets`/`get_widget` 都不给他看的**别人的 widget**(名字等全量 `Widget`)。
/// `Access` 在开流时刻算定并随流存活 —— 同下面的鉴权时刻取舍。
///
/// 鉴权只在开流时刻评估:流存活期间 token 过期/吊销不会断流(SSE 惯例取舍;低敏数据可接受)。
/// 要收紧:按 claim 的 exp 到点结束流,EventSource 重连即重新鉴权。
#[utoipa::path(
    get,
    path = "/widgets/events",
    tag = "widgets",
    responses(
        (status = 200, description = "SSE 事件流;每帧 event = type(created/updated/deleted),data = WidgetEvent JSON", content_type = "text/event-stream", body = WidgetEvent),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限", body = ErrorBody)
    )
)]
pub async fn widget_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    // ownership:无 read:all → 只收自己创建的那些 widget 的事件(与 list_widgets 同一判定)。
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll);
    let sub = state.widget_events.subscribe().await?;
    // recv() → SSE 帧;None(总线关)→ 流结束。json_data 对我们的类型不会失败,失败即结束流(ok()?)。
    // 不在可见域内的帧:continue 跳过(丢帧 ≠ 断流 —— 广播里本就混着别人的事件)。
    let stream = futures_util::stream::unfold((sub, access), |(mut sub, access)| async move {
        loop {
            let event = sub.recv().await?;
            if !access.allows_created_by(event.owner()) {
                continue;
            }
            let frame = Event::default()
                .event(event.name())
                .json_data(&event)
                .ok()?;
            return Some((Ok::<_, Infallible>(frame), (sub, access)));
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

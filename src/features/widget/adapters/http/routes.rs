//! widget 的 **HTTP 适配器**(驱动侧):axum handler。职责只有三件 —— 鉴权三轴、线格式 ↔ 领域
//! 互转(`dto`)、调用例(`WidgetService`)。业务规则不写在这里。

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{stream, Stream};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use super::dto::{
    CreateWidget, UpdateWidget, Widget, WidgetEvent, WidgetSortField, WidgetStats, WidgetView,
};
use crate::app::app_state::AppState;
use crate::features::widget::model;
use crate::infra::authorization::TokenScope;
use crate::infra::http::audit::{Audit, CurrentTenant, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Path, Query};
use crate::infra::http::pagination::{Page, PageQuery};
use crate::infra::http::sort_order::SortOrder;
use crate::infra::telemetry::SseConnectionGuard;
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::{Permission, PermissionCheck};
use crate::kernel::pagination::PageParams;
use crate::kernel::tenant_id::TenantId;

/// 列表排序 query(**第二个 `Query` 提取器**,避免把 sort 塞进共享 `PageQuery`)。
/// `#[serde(default)]`:两参都缺时回落默认(否则 serde_urlencoded 对必填字段缺失即 400)。
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct WidgetSort {
    pub sort_by: WidgetSortField,
    pub order: SortOrder,
}

/// cursor keyset 只支持 [`model::WidgetSortField::keyset_capable`] 的键(准入条件见那里);
/// 不支持的键 + cursor → 422,**而非静默按别的键排**。两个方向(`order`)都支持。
fn ensure_sort_pagination(page_params: &PageParams, sort: &WidgetSort) -> Result<(), AppError> {
    if matches!(page_params, PageParams::Cursor { .. })
        && !model::WidgetSortField::from(sort.sort_by).keyset_capable()
    {
        return Err(AppError::Validation(
            "sort_by requires offset/page pagination".into(),
        ));
    }
    Ok(())
}

// 三轴授权(详见 `authorization` skill):**必须登录**(`CurrentUser` → 401);RBAC(`require_scoped` → 403);
// 数据所有权(`data_access` → `owner_filter`/`allows_created_by`:`user` 只看/取自己创建的,有 `read:all` 的看全部)。
// **租户**(多租户,spec §4.3 / §4.4):租户级接口一律经 `CurrentTenant` 取当前租户(只来自 token;缺 → 403
// `tenant_required`),原样交给 service / repo。别的租户的 id 在仓储里就查不到 → 404(不泄露存在)。
// `read:all` / `write:all` 的「全部」都只是**本租户内**的全部。

/// 分页列出 widget。**user 只列自己创建的**(read:all → 全部)。默认 offset;带 `cursor` 切 keyset。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",    params(PageQuery, WidgetSort),
    responses(
        (status = 200, description = "widget 分页列表(按所有权过滤,created_by 富化为用户)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by(仅 offset 支持排序)", body = ErrorBody)
    )
)]
pub async fn list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
    Query(sort): Query<WidgetSort>,
) -> Result<Json<Page<WidgetView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetRead)?;
    // ownership:无 read:all → 只列自己创建的(过滤落查询层,分页正确)。
    let owner = state
        .policy
        .data_access(&user.0, &scope.0, Permission::WidgetReadAll)
        .owner_filter();
    let page_params = query.resolve()?;
    ensure_sort_pagination(&page_params, &sort)?;
    let page = state
        .widgets
        .list_enriched(
            tenant,
            page_params,
            owner,
            sort.sort_by.into(),
            sort.order.into(),
        )
        .await?;
    Ok(Json(Page::from(page)))
}

/// 创建一个 widget(需 `widgets:write`)。审计主体(created_by)= 当前登录用户,来自 `AuditContext`。
#[utoipa::path(
    post,
    path = "/widgets",
    tag = "widgets",    request_body = CreateWidget,
    responses(
        (status = 201, description = "已创建", body = Widget),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 409, description = "name 已存在(本租户存活行内唯一)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn create_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Json(input): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetWrite)?;
    let widget = state.widgets.create(tenant, input.into(), &ctx).await?;
    Ok((StatusCode::CREATED, Json(widget.into())))
}

/// 按 id 取一个存活 widget。**user 只能取自己创建的**:不是自己的 / 不存在 / 已软删 → 404。
#[utoipa::path(
    get,
    path = "/widgets/{id}",
    tag = "widgets",    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 200, description = "找到", body = Widget),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 非本人 / 别的租户的(不区分,防泄露存在)", body = ErrorBody)
    )
)]
pub async fn get_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Widget>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetRead)?;
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Permission::WidgetReadAll);
    let widget = state.widgets.get(tenant, id).await?;
    if access.allows_created_by(widget.created_by.as_deref()) {
        Ok(Json(widget.into()))
    } else {
        Err(AppError::NotFound.into()) // 不是你的 → 404(不泄露存在,区别于 403)
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
        (status = 403, description = "无 widgets:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 非本人 / 别的租户的", body = ErrorBody),
        (status = 409, description = "name 撞已有(本租户存活行内唯一)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateWidget>,
) -> Result<Json<Widget>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetWrite)?;
    ensure_may_write(&state, &user, &scope, tenant, id).await?;
    Ok(Json(
        state
            .widgets
            .update(tenant, id, input.into(), &ctx)
            .await?
            .into(),
    ))
}

/// 写侧 ownership 闸(update/delete 共用):无 `widgets:write:all` → 只能动**自己创建的**行,
/// 否则 404(同 `get_widget`,不泄露存在)。
///
/// 读侧一直有闸(`get_widget` + SSE 逐帧),写侧原本没有 —— 于是"读自己的、写所有人的":
/// 一个既有 `widgets:read` 又有 `widgets:write` 的角色(即"用户管理自己的 widget"这种最自然的配法)
/// GET 别人的行 404,PUT/DELETE 却能改能删。线上 seed 恰好没这么配所以打不出来,但 role→perm
/// 是运行期可改的(`role_permissions` 表),且 widget 是 adding-a-feature 指定照抄的样板模块 ——
/// 抄出去的每个 CRUD 模块都继承这个洞。content/profile 早有 `*:write:all` 并逐个 gate,
/// 范式是 widget(read) → profile(write) → content(write) 传下去的,唯独没回填 widget 自己的写侧。
async fn ensure_may_write(
    state: &AppState,
    user: &CurrentUser,
    scope: &TokenScope,
    tenant: TenantId,
    id: Uuid,
) -> Result<(), AppError> {
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Permission::WidgetWriteAll);
    let widget = state.widgets.get(tenant, id).await?; // 不存在 / 别的租户 → 404(先于 ownership,口径同 get_widget)
    if access.allows_created_by(widget.created_by.as_deref()) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// 软删除 widget(盖 deleted_at,需 `widgets:delete`)。
#[utoipa::path(
    delete,
    path = "/widgets/{id}",
    tag = "widgets",    params(("id" = Uuid, Path, description = "widget id")),
    responses(
        (status = 204, description = "已软删除"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:delete 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 非本人 / 别的租户的", body = ErrorBody)
    )
)]
pub async fn delete_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetDelete)?;
    ensure_may_write(&state, &user, &scope, tenant, id).await?;
    state.widgets.delete(tenant, id, &ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── 授权形态样板:除上面"登录 + perm(+ownership)"外,补齐 仅登录 / 多权限 AND·OR / 后台组内的租户级接口 ──
// (平台级接口的样板见 users / monitoring:gate 平台级 `users:admin` / `ops:read`。)

/// **仅登录**:当前租户的 widget 计数。要登录(frontend 组闸)+ 当前租户(`CurrentTenant`,缺 → 403
/// `tenant_required`),**无特定 perm**(`OPERATION_PERMISSIONS` 标 `LoginOnly`)。按租户计数走普通运行时池 + 租户事务。
///
/// 曾是免登录的「全站计数」:多租户下匿名请求没有租户,跨租户汇总要绕过 RLS,违背「租户互相看不见」,
/// 所以移到 frontend 组、只数当前租户。业务里要做公开数字,先想清楚它属于哪个租户。
#[utoipa::path(
    get,
    path = "/widgets/stats",
    tag = "widgets",
    responses(
        (status = 200, description = "当前租户的 widget 计数(仅登录)", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn widget_stats(
    State(state): State<AppState>,
    CurrentTenant(tenant): CurrentTenant,
) -> Result<Json<WidgetStats>, ApiError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant, None).await?,
    }))
}

/// **仅登录**(authenticated):当前用户在**当前租户**里创建的 widget 数。要 `CurrentUser`、**无特定 perm**
/// (`OPERATION_PERMISSIONS` 标 `LoginOnly` → 文档 `security:[{"oauth2":[]}]`)。演示"只需登录"形态。
/// 数的是租户数据,所以仍要当前租户(平台上下文 → 403 `tenant_required`)。
#[utoipa::path(
    get,
    path = "/widgets/my-count",
    tag = "widgets",
    responses(
        (status = 200, description = "当前用户在当前租户里创建的 widget 数", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn my_widget_count(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
) -> Result<Json<WidgetStats>, ApiError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant, Some(user.0.id)).await?,
    }))
}

/// **多权限 AND 样板**:删除预检 —— 读得见**且**删得动才允许看"可删多少"。
/// `require_all` 缺任一 perm 即 403;文档 = 单 requirement 多 scope(`OPERATION_PERMISSIONS` 的 `PermissionRequirement::All`)。
#[utoipa::path(
    get,
    path = "/widgets/purge-preview",
    tag = "widgets",
    responses(
        (status = 200, description = "本人可见域内可删 widget 计数", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "缺 widgets:read 或 widgets:delete 任一 / 没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn purge_preview(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
) -> Result<Json<WidgetStats>, ApiError> {
    state.policy.require_all(
        &user.0,
        PermissionCheck {
            scope: &scope.0,
            required: &[Permission::WidgetRead, Permission::WidgetDelete],
        },
    )?;
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant, Some(user.0.id)).await?,
    }))
}

/// **多权限 OR 样板**:概览 —— 普通读权**或**本组织成员管理员(`members:admin`)任一即可。
/// 两支都是租户级权限:租户数据的接口不拿平台级权限(如 `users:admin`)当闸(spec §4.3)。
/// `require_any` 全败才 403;文档 = 多 requirement 各一 scope(`PermissionRequirement::Any`)。
#[utoipa::path(
    get,
    path = "/widgets/overview",
    tag = "widgets",
    responses(
        (status = 200, description = "当前租户的 widget 计数(读权或本组织成员管理员)", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "widgets:read 与 members:admin 皆无 / 没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn widget_overview(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
) -> Result<Json<WidgetStats>, ApiError> {
    state.policy.require_any(
        &user.0,
        PermissionCheck {
            scope: &scope.0,
            required: &[Permission::WidgetRead, Permission::MembersAdmin],
        },
    )?;
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant, None).await?,
    }))
}

/// **后台 widget 列表**:列出**当前租户**的 widget(富化创建人)。
///
/// 准入 = admin 组闸(后台准入)+ 租户级 `widgets:read` —— 租户管理员(租户角色 admin)就能看,不要平台级权限(租户数据的后台接口不拿平台权限当闸,spec §4.3)。
/// 可见域照旧:有当前租户角色给的 `widgets:read:all` → 本租户全部,否则只列自己建的
/// (平台管理员在某租户里只是普通成员时也一样)。数据限当前租户(缺 → 403 `tenant_required`)。
#[utoipa::path(
    get,
    path = "/widgets",
    tag = "widgets",
    params(PageQuery, WidgetSort),
    responses(
        (status = 200, description = "当前租户内;无租户级 read:all 时只含本人创建的(富化)", body = Page<WidgetView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无后台准入(admin 组闸)/ 无 widgets:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by(仅 offset 支持排序)", body = ErrorBody)
    )
)]
pub async fn admin_list_widgets(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Query(query): Query<PageQuery>,
    Query(sort): Query<WidgetSort>,
) -> Result<Json<Page<WidgetView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetRead)?;
    let owner = state
        .policy
        .data_access(&user.0, &scope.0, Permission::WidgetReadAll)
        .owner_filter();
    let page_params = query.resolve()?;
    ensure_sort_pagination(&page_params, &sort)?;
    let page = state
        .widgets
        .list_enriched(
            tenant,
            page_params,
            owner,
            sort.sort_by.into(),
            sort.order.into(),
        )
        .await?;
    Ok(Json(Page::from(page)))
}

/// 订阅 widget 变更事件流(SSE)。需登录 + `widgets:read` —— 与列表同权:能看列表就能看变更。
/// EventSource 不能自定义 header,凭据靠 httponly cookie(Bearer 兜底给 curl/测试)。
/// best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
///
/// **先比租户、再比 owner**:总线是全实例广播(不分租户、不分频道),过滤落在本 handler —— 逐帧先看
/// `event.tenant_id() == 当前租户`,再 `allows_created_by`,不过就跳帧(`continue`),**不**结束流。
/// 租户这一道在前:`read:all` 的 admin 也只是「本租户全部」,别的租户的帧一律看不见。没这层,无 `read:all` 的 `user`
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
        (status = 403, description = "无 widgets:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn widget_events(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::WidgetRead)?;
    // ownership:无 read:all → 只收自己创建的那些 widget 的事件(与 list_widgets 同一判定)。
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Permission::WidgetReadAll);
    let subscription = state.widget_events.subscribe().await?;
    // recv() → SSE 帧;None(总线关)→ 流结束。json_data 对我们的类型不会失败,失败即结束流(ok()?)。
    // 不在可见域内的帧:continue 跳过(丢帧 ≠ 断流 —— 广播里本就混着别人的事件)。
    // 在线连接数指标:守卫随流存活,客户端断开(流被丢弃)时自动 -1。
    let guard = SseConnectionGuard::new("widgets");
    let frames = stream::unfold(
        (subscription, access, guard),
        move |(mut subscription, access, guard)| async move {
            loop {
                let event = subscription.recv().await?;
                // 第一道:租户。别的租户的帧连 owner 都不必看。
                if event.tenant_id() != tenant || !access.allows_created_by(event.owner()) {
                    continue;
                }
                let frame = Event::default()
                    .event(event.name())
                    .json_data(WidgetEvent::from(event))
                    .ok()?;
                let item: Result<Event, Infallible> = Ok(frame);
                return Some((item, (subscription, access, guard)));
            }
        },
    );
    Ok(Sse::new(frames).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

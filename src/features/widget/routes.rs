use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{Stream, StreamExt};
use uuid::Uuid;

use super::events::WidgetEvent;
use super::types::{CreateWidget, UpdateWidget, Widget, WidgetSortField};
use super::view::{WidgetStats, WidgetView};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, Tenant, TokenExp, TokenScope};
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
    tenant: Tenant,
    Query(query): Query<PageQuery>,
    Query(sort): Query<WidgetSort>,
) -> Result<Json<Page<WidgetView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    // ownership:无 read:all → 只列自己创建的(过滤落查询层,分页正确)。
    let owner = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll, tenant.0)
        .owner_filter();
    let params = query.resolve()?;
    ensure_sort_pagination(&params, &sort)?;
    Ok(Json(
        state
            .widgets
            .list_enriched(tenant.0, params, owner, sort.sort_by, sort.order)
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
    tenant: Tenant,
    ctx: AuditContext,
    Json(input): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetWrite)?;
    // 租户来自 claim,不是请求体 —— 建出来的行落在你**当前**所在的公司。
    let widget = state.widgets.create(tenant.0, input, &ctx).await?;
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
    tenant: Tenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Widget>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll, tenant.0);
    // 复合键 get:别租户的 id 在这一步就 NotFound —— 下面那道闸是**纵深**,不是唯一防线。
    let widget = state.widgets.get(tenant.0, id).await?;
    if access.allows_created_by(widget.tenant_id, widget.created_by.as_deref()) {
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
    tenant: Tenant,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateWidget>,
) -> Result<Json<Widget>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetWrite)?;
    ensure_may_write(&state, &user, &scope, tenant, id).await?;
    Ok(Json(state.widgets.update(tenant.0, id, input, &ctx).await?))
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
    tenant: Tenant,
    id: Uuid,
) -> Result<(), AppError> {
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetWriteAll, tenant.0);
    // 不存在 / **别租户** → 404(先于 ownership,口径同 get_widget)。
    // **租户判定收在这一处** —— update 与 delete 共用它,两个 handler 不用各写一遍、也就漏不掉。
    let w = state.widgets.get(tenant.0, id).await?;
    if access.allows_created_by(w.tenant_id, w.created_by.as_deref()) {
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
        (status = 403, description = "无 widgets:delete 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn delete_widget(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    tenant: Tenant,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetDelete)?;
    ensure_may_write(&state, &user, &scope, tenant, id).await?;
    state.widgets.delete(tenant.0, id, &ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── 授权形态样板:除上面"登录 + perm(+ownership)"外,补齐 仅登录 / superadmin-only ──

/// **仅登录**:本租户的 widget 计数。
///
/// # 它曾经是 public,上租户轴后**必须挪进来**(spec §6.1)
///
/// 原来它无 `CurrentUser`、任何人可调,演示"无需登录"形态。但 public 端点**没有 token,
/// 就造不出 `TenantId`** —— 而"全站计数"在多租户下的意思是「把所有客户公司的数据加总告诉
/// 匿名访问者」。那不是一个能加闸的端点,是一个不该存在的端点。
///
/// **代价**:widget 不再演示 "public 端点" 形态。**这是正确的** —— 多租户下「public + 租户
/// 数据」本身就是反模式,留着它当样板是在教人写洞。真要 public 样板,另找一个**真无租户语义**
/// 的端点去演示(如 /healthz 之类)。
#[utoipa::path(
    get,
    path = "/widgets/stats",
    tag = "widgets",
    responses(
        (status = 200, description = "本租户 widget 计数", body = WidgetStats),
        (status = 401, description = "未认证", body = ErrorBody)
    )
)]
pub async fn widget_stats(
    State(state): State<AppState>,
    _user: CurrentUser,
    tenant: Tenant,
) -> Result<Json<WidgetStats>, AppError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant.0, None).await?,
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
    tenant: Tenant,
) -> Result<Json<WidgetStats>, AppError> {
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant.0, Some(user.0.id)).await?,
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
    tenant: Tenant,
) -> Result<Json<WidgetStats>, AppError> {
    state
        .policy
        .require_all(&user.0, &scope.0, &[Perm::WidgetRead, Perm::WidgetDelete])?;
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant.0, Some(user.0.id)).await?,
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
    tenant: Tenant,
) -> Result<Json<WidgetStats>, AppError> {
    state
        .policy
        .require_any(&user.0, &scope.0, &[Perm::WidgetRead, Perm::UsersAdmin])?;
    // `count(tenant, None)` = **本租户内**全部(owner 不过滤)。
    // 「全站」这个词在多租户下已经没有意义 —— 连 superadmin 也关在租户闸里(spec §7.1)。
    Ok(Json(WidgetStats {
        total: state.widgets.count(tenant.0, None).await?,
    }))
}

/// **superadmin-only**:跨所有人列出 widget。gate 在 `users:admin`(seed 里只 superadmin 持有)。
/// 演示"role 限制 = gate 一个该 role 专属的 perm";注意 admin 虽有 `read:all`,无 `users:admin` 仍 403。
///
/// ⚠️ **语义已降级为「本租户内、跨所有人」**(spec §6.3):它原本是「跨所有人、跨所有租户」——
/// 那是一条泄露行。superadmin 也被关在租户闸里:这只影响它读**业务数据**,不影响它管租户
/// (那是 `idm.tenants` 的 CRUD,另一件事,见 spec §7.1)。
/// 真要「客服跨租户看客户数据」,那是 `Rows::AllTenants` + 一个 `platform:*:all` perm,
/// 触发条件写在 spec §7 —— 别顺手把这个端点改回去。
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
    tenant: Tenant,
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
            // owner=None = 跨所有人;tenant = **本租户内**(见本 handler 的 doc)。
            .list_enriched(tenant.0, params, None, sort.sort_by, sort.order)
            .await?,
    ))
}

/// 订阅 widget 变更事件流(SSE)。需登录 + `widgets:read` —— 与列表同权:能看列表就能看变更。
/// EventSource 不能自定义 header,凭据靠 httponly cookie(Bearer 兜底给 curl/测试)。
/// best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
///
/// **租户闸 + 行级 ownership 与 list 同口径**:总线是**全局广播**(NATS subject / PG NOTIFY
/// 都不分租户),过滤落在本 handler —— 逐帧 `allows_created_by(event.tenant(), event.owner())`,
/// 不过就跳帧(`continue`),**不**结束流。
///
/// 没这层,无 `read:all` 的 `user` 能从流里读到 `list_widgets`/`get_widget` 都不给他看的
/// 别人的 widget;**没有租户那一维,他能读到别的公司的**。
///
/// # 流必须随 token 过期而断(spec §6.4a)
///
/// `Access` 在开流时刻算定、被 move 进流状态,之后每帧只读不重算 —— 而 `keep_alive` 还主动
/// 每 15s 续命。合起来就是:**一条流能活过它的 token**。用户切了租户、被踢出公司、租户被停用,
/// 那条流照推旧租户的事件不误,直到浏览器自己断开。
///
/// 所以按 claim 的 `exp` 截流(`take_until`)。EventSource 会自动重连 → 拿新 token 重新鉴权
/// → 新的 `Access`。这也是「切租户后旧流还在推旧租户」的收口:最长一个 access TTL。
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
    tenant: Tenant,
    exp: TokenExp,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    // 租户闸 + ownership:与 list_widgets 同一判定。
    let access = state
        .policy
        .data_access(&user.0, &scope.0, Perm::WidgetReadAll, tenant.0);
    let sub = state.widget_events.subscribe().await?;
    // recv() → SSE 帧;None(总线关)→ 流结束。json_data 对我们的类型不会失败,失败即结束流(ok()?)。
    // 不在可见域内的帧:continue 跳过(丢帧 ≠ 断流 —— 广播里本就混着别的租户/别人的事件)。
    let stream = futures_util::stream::unfold((sub, access), |(mut sub, access)| async move {
        loop {
            let event = sub.recv().await?;
            if !access.allows_created_by(event.tenant(), event.owner()) {
                continue;
            }
            let frame = Event::default()
                .event(event.name())
                .json_data(&event)
                .ok()?;
            return Some((Ok::<_, Infallible>(frame), (sub, access)));
        }
    });
    // **随 token 过期截流**(见本 handler 的 doc)。exp 已过 → 立即结束(饱和减,不 panic)。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(exp.0.saturating_sub(now).max(0) as u64);
    let stream = stream.take_until(tokio::time::sleep_until(deadline));
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

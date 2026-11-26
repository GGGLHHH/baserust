//! 认证审计的 **HTTP 适配器**(admin 组,归 idm 进程)。线格式 ↔ 领域互转见 `dto`。镜像 `features::users` 的 `list_users` handler
//! 的守卫 + 分页范式:`require_scoped(AuditRead)` + `PageQuery` + 过滤 DTO。
//! `AppState.auth_audit` 为 `None`(非 needs_idm 进程 / 无 search pool)时 → 404。

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use super::dto::{AuthEventFilter, AuthEventRow, AuthStats, StatsQuery};
use crate::app::state::AppState;
use crate::infra::authz::TokenScope;
use crate::infra::http::audit::CurrentUser;
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Path, Query};
use crate::infra::http::pagination::{Page, PageQuery};
use crate::kernel::authz::Perm;
use crate::kernel::error::AppError;

/// 某用户的认证事件历史(后台用户详情页 / 排障用)。
#[utoipa::path(
    get,
    path = "/users/{id}/auth-events",
    tag = "users",
    params(("id" = Uuid, Path), PageQuery, AuthEventFilter),
    responses(
        (status = 200, body = Page<AuthEventRow>),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 audit:read 权限(superadmin 独占)", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
        (status = 422, description = "page 与 cursor 互斥", body = ErrorBody),
    )
)]
pub async fn list_user_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
    Query(filter): Query<AuthEventFilter>,
) -> Result<Json<Page<AuthEventRow>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::AuditRead)?;
    let svc = state.auth_audit.as_ref().ok_or(AppError::NotFound)?;
    let page = svc
        .list_for_user(id, filter.into(), page.resolve()?)
        .await?;
    Ok(Json(Page::from_core(page, AuthEventRow::from)))
}

/// 全局认证审计流(后台安全排障用)。
#[utoipa::path(
    get,
    path = "/auth-events",
    tag = "users",
    params(PageQuery, AuthEventFilter),
    responses(
        (status = 200, body = Page<AuthEventRow>),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 audit:read 权限(superadmin 独占)", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
        (status = 422, description = "page 与 cursor 互斥", body = ErrorBody),
    )
)]
pub async fn list_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(page): Query<PageQuery>,
    Query(filter): Query<AuthEventFilter>,
) -> Result<Json<Page<AuthEventRow>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::AuditRead)?;
    let svc = state.auth_audit.as_ref().ok_or(AppError::NotFound)?;
    let page = svc.list(filter.into(), page.resolve()?).await?;
    Ok(Json(Page::from_core(page, AuthEventRow::from)))
}

/// 认证审计仪表盘(时间序列 + 各维度 group-by 计数 + KPI)。默认区间最近 24h。
#[utoipa::path(
    get,
    path = "/auth-events/stats",
    tag = "users",
    params(StatsQuery),
    responses(
        (status = 200, body = AuthStats),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 audit:read 权限(superadmin 独占)", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
    )
)]
pub async fn stats_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(q): Query<StatsQuery>,
) -> Result<Json<AuthStats>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::AuditRead)?;
    let svc = state.auth_audit.as_ref().ok_or(AppError::NotFound)?;
    Ok(Json(svc.stats(q.from, q.to).await?.into()))
}

/// 认证事件实时推送(SSE)。projector 落库成功后立即推送;镜像 `widget` 的 `widget_events` handler
/// 的鉴权/心跳范式。best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
/// ponytail:总线是单 idm 实例内广播,见 `AuthEventBus` 头注(多实例扇出需换 JetStream 直连)。
#[utoipa::path(
    get,
    path = "/auth-events/stream",
    tag = "users",
    responses(
        (status = 200, description = "SSE 事件流;event = auth_event,data = AuthEventRow JSON", content_type = "text/event-stream", body = AuthEventRow),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 audit:read 权限(superadmin 独占)", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
    )
)]
pub async fn stream_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::AuditRead)?;
    let bus = state.auth_events_bus.as_ref().ok_or(AppError::NotFound)?;
    let rx = bus.subscribe();
    let guard = crate::infra::telemetry::SseConnectionGuard::new("auth_events");
    let stream = futures_util::stream::unfold((rx, guard), |(mut rx, guard)| async move {
        loop {
            match rx.recv().await {
                Ok(row) => {
                    let frame = Event::default()
                        .event("auth_event")
                        .json_data(AuthEventRow::from(row))
                        .ok()?;
                    return Some((Ok::<_, Infallible>(frame), (rx, guard)));
                }
                // 慢消费者掉队:跳过丢失的继续收,不断流(同 widget 事件总线契约)。
                Err(RecvError::Lagged(_)) => continue,
                // 总线关(进程关闭中):流结束,浏览器 EventSource 自动重连。
                Err(RecvError::Closed) => return None,
            }
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

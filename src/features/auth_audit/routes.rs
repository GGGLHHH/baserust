//! 认证审计查询端点(admin 组,归 idm 进程)。镜像 `features::users::routes::list_users`
//! 的守卫 + 分页范式:`require_scoped(UsersAdmin)` + `PageQuery` + 过滤 DTO。
//! `AppState.auth_events` 为 `None`(非 needs_idm 进程 / 无 search pool)时 → 404。

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use time::OffsetDateTime;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::app::state::AppState;
use crate::features::auth_audit::{
    AuthEventQuery, AuthEventRow, AuthEventType, AuthOutcome, AuthStats,
};
use crate::infra::audit::CurrentUser;
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path, Query};
use crate::infra::pagination::{Page, PageQuery};

/// 列表过滤(admin)。空 = 不限。
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct AuthEventFilter {
    /// 事件类型(闭集;未知值 → 422 而非静默空结果)。
    pub event_type: Option<AuthEventType>,
    pub outcome: Option<AuthOutcome>,
    pub ip: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

/// 某用户的认证事件历史(后台用户详情页 / 排障用)。
#[utoipa::path(
    get,
    path = "/users/{id}/auth-events",
    tag = "users",
    params(("id" = Uuid, Path), PageQuery, AuthEventFilter),
    responses(
        (status = 200, body = Page<AuthEventRow>),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
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
) -> Result<Json<Page<AuthEventRow>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let repo = state.auth_events.as_ref().ok_or(AppError::NotFound)?;
    let q = AuthEventQuery {
        user_id: Some(id),
        event_type: filter.event_type,
        outcome: filter.outcome,
        ip: filter.ip,
        from: filter.from,
        to: filter.to,
    };
    Ok(Json(repo.list(&q, page.resolve()?).await?))
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
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
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
) -> Result<Json<Page<AuthEventRow>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let repo = state.auth_events.as_ref().ok_or(AppError::NotFound)?;
    let q = AuthEventQuery {
        user_id: None,
        event_type: filter.event_type,
        outcome: filter.outcome,
        ip: filter.ip,
        from: filter.from,
        to: filter.to,
    };
    Ok(Json(repo.list(&q, page.resolve()?).await?))
}

/// 统计区间。空 = 默认最近 24h(`to`=now,`from`=now-24h)。
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
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
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
    )
)]
pub async fn stats_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(q): Query<StatsQuery>,
) -> Result<Json<AuthStats>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let repo = state.auth_events.as_ref().ok_or(AppError::NotFound)?;
    let now = OffsetDateTime::now_utc();
    let to = q.to.unwrap_or(now);
    let from = q.from.unwrap_or(now - time::Duration::hours(24));
    // 夹住区间:防止 generate_series 被拉成跨年的巨量小时桶(见 review #3)。
    // 92d ≥ 90d 留存期,不会截断真实数据;from >= to 时退化成 1h 窗口而非报错。
    let from = from.max(to - time::Duration::days(92));
    let from = if from < to {
        from
    } else {
        to - time::Duration::hours(1)
    };
    Ok(Json(repo.stats(from, to).await?))
}

/// 认证事件实时推送(SSE)。projector 落库成功后立即推送;镜像 `widget::routes::widget_events`
/// 的鉴权/心跳范式。best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
/// ponytail:总线是单 idm 实例内广播,见 `AuthEventBus` 头注(多实例扇出需换 JetStream 直连)。
#[utoipa::path(
    get,
    path = "/auth-events/stream",
    tag = "users",
    responses(
        (status = 200, description = "SSE 事件流;event = auth_event,data = AuthEventRow JSON", content_type = "text/event-stream", body = AuthEventRow),
        (status = 401, body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "审计后端未接线(无 search 投影库)", body = ErrorBody),
    )
)]
pub async fn stream_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let bus = state.auth_events_bus.as_ref().ok_or(AppError::NotFound)?;
    let rx = bus.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(row) => {
                    let frame = Event::default().event("auth_event").json_data(&row).ok()?;
                    return Some((Ok::<_, Infallible>(frame), rx));
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

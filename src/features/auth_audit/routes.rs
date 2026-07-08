//! 认证审计查询端点(admin 组,归 idm 进程)。镜像 `features::users::routes::list_users`
//! 的守卫 + 分页范式:`require_scoped(UsersAdmin)` + `PageQuery` + 过滤 DTO。
//! `AppState.auth_events` 为 `None`(非 needs_idm 进程 / 无 search pool)时 → 404。

use axum::extract::State;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::state::AppState;
use crate::features::auth_audit::{AuthEventQuery, AuthEventRow};
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
    pub event_type: Option<String>,
    pub outcome: Option<String>,
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

//! 后台用户管理端点(admin 组,归 idm 进程)。每 handler 首行 `require_scoped(UsersAdmin)`
//! (组闸 admin:login 之上再 gate superadmin 专属的 users:admin)。写操作 `by = ctx.audit_id()`。
//! `#[utoipa::path]` **不手写 security** —— op_perms 经 `inject_operation_security` 注入。
//! path 相对 admin 组(nest 加 `/api/v1/admin`)→ 实际 `/api/v1/admin/users*`。

use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, SetRolesRequest,
    UpdateUserRequest, UserSortField,
};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path, Query};
use crate::infra::pagination::{Page, PageParams, PageQuery};
use crate::infra::sort::SortOrder;

/// 分页列出用户(过滤 + 排序 + 富化)。默认 offset;带 `cursor` 切 keyset。
/// cursor + 非默认 sort_by → 422(keyset 恒按 id 序,非默认排序只能配 offset)。
#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    params(PageQuery, ListUsersFilter),
    responses(
        (status = 200, description = "用户分页列表(display_name/avatar 富化,缺则 null)", body = Page<AdminUserView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限(仅 superadmin)", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by(仅 offset 支持排序)", body = ErrorBody)
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(page): Query<PageQuery>,
    Query(filter): Query<ListUsersFilter>,
) -> Result<Json<Page<AdminUserView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let params = page.resolve()?;
    let is_default_sort = matches!(filter.sort_by, UserSortField::CreatedAt)
        && matches!(filter.order, SortOrder::Desc);
    if matches!(params, PageParams::Cursor { .. }) && !is_default_sort {
        return Err(AppError::Validation(
            "sort_by requires offset/page pagination".into(),
        ));
    }
    Ok(Json(state.user_admin.list(&filter, params).await?))
}

/// 建号(原子含角色)。`by` = 当前 superadmin。
#[utoipa::path(
    post,
    path = "/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "已创建(新号 display_name=null)", body = AdminUserView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 409, description = "username/email 已占用", body = ErrorBody),
        (status = 422, description = "校验失败 / 未知角色名", body = ErrorBody)
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<AdminUserView>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let view = state.user_admin.create(req, ctx.audit_id()).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

/// 详情。不存在/软删 → 404(superadmin 看全部,不 404-隐藏 ownership)。
#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    responses(
        (status = 200, description = "找到", body = AdminUserView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 已软删", body = ErrorBody)
    )
)]
pub async fn get_user(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminUserView>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(state.user_admin.get(id).await?))
}

/// 改身份(PUT 全量)。`email=None` 即清空(替换 email 重置 email_verified)。
#[utoipa::path(
    put,
    path = "/users/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "已更新", body = AdminUserView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 409, description = "username/email 已占用", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<AdminUserView>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(
        state.user_admin.update(id, req, ctx.audit_id()).await?,
    ))
}

/// 软删(注销)。幂等(已删/不存在 → 404)+ best-effort 撤会话。
#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    responses(
        (status = 204, description = "已软删"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 已软删", body = ErrorBody)
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    state.user_admin.delete(id, ctx.audit_id()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// 全量设角色(原子替换)。未知角色名 → 422。
#[utoipa::path(
    put,
    path = "/users/{id}/roles",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    request_body = SetRolesRequest,
    responses(
        (status = 200, description = "已设角色", body = AdminUserView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "用户不存在", body = ErrorBody),
        (status = 422, description = "未知角色名", body = ErrorBody)
    )
)]
pub async fn set_user_roles(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(req): Json<SetRolesRequest>,
) -> Result<Json<AdminUserView>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(
        state.user_admin.set_roles(id, req, ctx.audit_id()).await?,
    ))
}

/// 管理员重置密码(无需旧密码)+ best-effort 撤会话(强制重新登录)。
#[utoipa::path(
    post,
    path = "/users/{id}/password",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    request_body = ResetPasswordRequest,
    responses(
        (status = 204, description = "已重置密码,撤销既有会话"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "用户不存在", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn reset_user_password(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    state.user_admin.reset_password(id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

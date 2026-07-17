//! 租户管理端点(P6)。**全部落 `/auth/` 前缀** —— nginx 只把 `/{public,frontend,admin}/auth/`
//! 分流进 idm 进程,而租户/成员/用户数据都在 idm schema(spec §2.3)。
//!
//! 两个面:
//! - **平台开通**(admin 组 → `/admin/auth/tenants`):gate `Perm::TenantsAdmin`(superadmin 专属)。
//! - **租户内成员管理**(frontend 组 → `/frontend/auth/tenants/members`):gate 仅登录 + **活的
//!   tn:admin 检查**。授权靠 `tenant_members.role` 这个数据事实(每次查库),不靠 claim 里的角色、
//!   也不靠 `Policy` 的 perm —— 与切换端点同款,提权口保持关闭(见 `TenantAdminService::member_role`)。

use axum::extract::State;
use axum::http::StatusCode;
use garde::Validate;
use uuid::Uuid;

use super::service::TenantAdminService;
use super::types::{
    AddMemberRequest, CreateTenantRequest, Tenant, TenantMember, TenantRole, UpdateTenantRequest,
};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, Tenant as TenantCtx, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path};

/// 取本进程的租户管理服务。这些端点只挂 needs_idm 组,走到这就是 wiring bug → 500。
fn tenant_admin(state: &AppState) -> Result<&TenantAdminService, AppError> {
    state.tenant_admin.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "租户管理端点挂到了没有 idm_pool 的进程上 —— 必须只挂 needs_idm 组"
        ))
    })
}

// ─────────────────────────── 平台开通(admin/auth/tenants)───────────────────────────

pub fn admin_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::router::OpenApiRouter;
    use utoipa_axum::routes;
    OpenApiRouter::new()
        .routes(routes!(create_tenant, list_tenants))
        .routes(routes!(update_tenant))
}

#[utoipa::path(
    post, path = "/tenants", tag = "tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "已开通", body = Tenant),
        (status = 404, description = "初始 admin 不存在", body = ErrorBody),
        (status = 409, description = "name(slug)已占用", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn create_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<Tenant>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    req.validate()?;
    let tenant = tenant_admin(&state)?
        .create(
            &req.name,
            &req.display_name,
            req.admin_identifier.as_deref(),
            ctx.audit_id(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(tenant)))
}

#[utoipa::path(
    get, path = "/tenants", tag = "tenants",
    responses(
        (status = 200, description = "全部存活租户(最近建的在前)", body = Vec<Tenant>),
        (status = 403, description = "无 tenants:admin", body = ErrorBody),
    )
)]
pub async fn list_tenants(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Json<Vec<Tenant>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    Ok(Json(tenant_admin(&state)?.list().await?))
}

#[utoipa::path(
    put, path = "/tenants/{id}", tag = "tenants",
    params(("id" = Uuid, Path, description = "tenant id")),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "已更新(status=suspended 即停用)", body = Tenant),
        (status = 403, description = "无 tenants:admin", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn update_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<Tenant>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    req.validate()?;
    let tenant = tenant_admin(&state)?
        .update(id, &req.display_name, req.status, ctx.audit_id())
        .await?;
    Ok(Json(tenant))
}

// ──────────────────── 租户内成员管理(frontend/auth/tenants/members)────────────────────

pub fn frontend_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    use utoipa_axum::router::OpenApiRouter;
    use utoipa_axum::routes;
    OpenApiRouter::new()
        .routes(routes!(list_members, add_member))
        .routes(routes!(remove_member))
}

/// **自助端点的授权支点**:actor 必须是自己**当前激活租户**的 `tn:admin`。
///
/// 用 `member_role`(活的 `tenant_members.role`,过滤停用租户)—— 不是 claim 里的角色。
/// 非 admin(成员/已被移除/租户已停用)→ 403(access 拒绝:你没这个能力)。
async fn require_active_tenant_admin(
    svc: &TenantAdminService,
    user_id: Uuid,
    tenant_id: Uuid,
) -> Result<(), AppError> {
    match svc.member_role(user_id, tenant_id).await? {
        Some(TenantRole::Admin) => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

#[utoipa::path(
    get, path = "/auth/tenants/members", tag = "me",
    responses(
        (status = 200, description = "我当前租户的成员", body = Vec<TenantMember>),
        (status = 403, description = "你不是当前租户的管理员", body = ErrorBody),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    user: CurrentUser,
    tenant: TenantCtx,
) -> Result<Json<Vec<TenantMember>>, AppError> {
    let svc = tenant_admin(&state)?;
    require_active_tenant_admin(svc, user.0.id, tenant.0.get()).await?;
    Ok(Json(svc.members(tenant.0.get()).await?))
}

#[utoipa::path(
    post, path = "/auth/tenants/members", tag = "me",
    request_body = AddMemberRequest,
    responses(
        (status = 201, description = "已邀请(对已是成员的人 = 改角色)"),
        (status = 403, description = "你不是当前租户的管理员", body = ErrorBody),
        (status = 404, description = "被邀请者不存在(须先有账号)", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
pub async fn add_member(
    State(state): State<AppState>,
    user: CurrentUser,
    tenant: TenantCtx,
    ctx: AuditContext,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, AppError> {
    let svc = tenant_admin(&state)?;
    require_active_tenant_admin(svc, user.0.id, tenant.0.get()).await?;
    req.validate()?;
    svc.add_member(tenant.0.get(), &req.identifier, req.role, ctx.audit_id())
        .await?;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete, path = "/auth/tenants/members/{user_id}", tag = "me",
    params(("user_id" = Uuid, Path, description = "被移除成员的 user id")),
    responses(
        (status = 204, description = "已移除"),
        (status = 403, description = "你不是当前租户的管理员", body = ErrorBody),
        (status = 404, description = "此人不是本租户成员", body = ErrorBody),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    user: CurrentUser,
    tenant: TenantCtx,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let svc = tenant_admin(&state)?;
    require_active_tenant_admin(svc, user.0.id, tenant.0.get()).await?;
    svc.remove_member(tenant.0.get(), user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

//! 后台用户管理端点(admin 组,归 idm 进程)。每 handler 首行 `require_scoped(UsersAdmin)`
//! (组闸 admin:login 之上再 gate superadmin 专属的 users:admin)。写操作 `by = ctx.audit_id()`。
//! `#[utoipa::path]` **不手写 security** —— op_perms 经 `inject_operation_security` 注入。
//! path 相对 admin 组(nest 加 `/api/v1/admin/auth`)→ 实际 `/api/v1/admin/auth/users*`。

use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use idm::AuthUser;
use uuid::Uuid;

use super::types::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, RoleView,
    SetRolesRequest, UpdateUserRequest, UserSortField,
};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, Policy, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path, Query};
use crate::infra::pagination::{Page, PageParams, PageQuery};
use crate::infra::sort::SortOrder;

// ── 授权守卫(自锁 / 提权):放 handler(授权边界),judgment 抽纯函数便于单测 ──

/// 自锁:destructive 操作不能作用于**自己**(删自己号 / 后续复用)。
fn assert_not_self(actor: Uuid, target: Uuid) -> Result<(), AppError> {
    if actor == target {
        Err(AppError::Conflict(
            "cannot perform this action on your own account".into(),
        ))
    } else {
        Ok(())
    }
}

/// 提权闸:被授的每个角色的权限,授予者(role∩scope)自己都必须持有 —— 不能授出自己没有的权。
/// superadmin 持全 Perm,恒过;仅当出现"有 users:admin 但非满权"的中间管理员才真正拦。
fn assert_no_escalation(
    policy: &Policy,
    granter: &AuthUser,
    scope: &[Perm],
    granted_role_names: &[String],
) -> Result<(), AppError> {
    for name in granted_role_names {
        for perm in policy.perms_for(std::slice::from_ref(name)) {
            policy.require_scoped(granter, scope, perm)?; // 缺该权 → Forbidden(403)
        }
    }
    Ok(())
}

/// 自锁:改**自己**的角色不能把 `users:admin` 弄没(否则自我降权、锁死后台)。
fn assert_self_keeps_admin(
    policy: &Policy,
    actor: Uuid,
    target: Uuid,
    new_role_names: &[String],
) -> Result<(), AppError> {
    if actor == target && !policy.perms_for(new_role_names).contains(&Perm::UsersAdmin) {
        return Err(AppError::Conflict(
            "cannot remove your own admin access".into(),
        ));
    }
    Ok(())
}

/// 把角色 id 解析成名字(经 list_roles 目录)。未知 id 跳过(交 service 走 422)。
/// 提权/自锁判定要角色名(→ 经 policy 展成权限);故先解析。
async fn role_names_of(state: &AppState, role_ids: &[Uuid]) -> Result<Vec<String>, AppError> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }
    let catalog = state.user_admin.list_roles().await?;
    let by_id: HashMap<Uuid, String> = catalog
        .items
        .into_iter()
        .map(|r| (r.id, r.name.as_str().to_owned()))
        .collect();
    Ok(role_ids
        .iter()
        .filter_map(|id| by_id.get(id).cloned())
        .collect())
}

/// 分页列出用户(过滤 + 排序 + 富化)。默认 offset;带 `cursor` 切 keyset。
/// cursor + 非默认 sort_by → 422(keyset 恒按 id 序,非默认排序只能配 offset)。
/// `q`(用户名 + 显示名模糊)与 `sort_by=display_name` 仅在接了 search 投影后端时可用;
/// 未接后端时二者 → 422(回退路只能 idm 直查,不具备搜索能力)。
#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    params(PageQuery, ListUsersFilter),
    responses(
        (status = 200, description = "用户分页列表(display_name/avatar 富化,缺则 null)", body = Page<AdminUserView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限(仅 superadmin)", body = ErrorBody),
        (status = 422, description = "cursor 分页 + 非默认 sort_by;或 q/sort_by=display_name 但无 search 投影后端", body = ErrorBody)
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
    // 提权闸:不能建带"超出自己权限"角色的号。
    let role_names = role_names_of(&state, &req.roles).await?;
    assert_no_escalation(&state.policy, &user.0, &scope.0, &role_names)?;
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
        (status = 404, description = "不存在 / 已软删", body = ErrorBody),
        (status = 409, description = "不能删除自己的账号", body = ErrorBody)
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
    // 自锁:不能删自己的账号。
    assert_not_self(user.0.id, id)?;
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
        (status = 409, description = "不能移除自己的 admin 权限", body = ErrorBody),
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
    // 提权闸 + 自锁:不能授超出自己的权;改自己的角色不能丢 users:admin。
    let role_names = role_names_of(&state, &req.roles).await?;
    assert_no_escalation(&state.policy, &user.0, &scope.0, &role_names)?;
    assert_self_keeps_admin(&state.policy, user.0.id, id, &role_names)?;
    Ok(Json(
        state.user_admin.set_roles(id, req, ctx.audit_id()).await?,
    ))
}

/// 角色目录(admin 分配角色的候选集)。全量存活角色,单页游标包络(has_more=false)。
/// 供前端 role-select 拉候选;`name`=机器码,`display_name`=展示名。
#[utoipa::path(
    get,
    path = "/roles",
    tag = "users",
    params(PageQuery),
    responses(
        (status = 200, description = "角色目录(单页,全量存活角色)", body = Page<RoleView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody)
    )
)]
pub async fn list_roles(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(_page): Query<PageQuery>,
) -> Result<Json<Page<RoleView>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(state.user_admin.list_roles().await?))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(roles: &[&str]) -> AuthUser {
        AuthUser {
            id: Uuid::now_v7(),
            username: "u".into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn self_action_blocked() {
        let id = Uuid::now_v7();
        assert!(matches!(
            assert_not_self(id, id),
            Err(AppError::Conflict(_))
        ));
        assert!(assert_not_self(id, Uuid::now_v7()).is_ok());
    }

    #[test]
    fn escalation_blocks_granting_perms_you_lack() {
        // 中间管理员:有 users:admin,但没有 contents:delete。
        let policy = Policy::from_roles([
            ("mgr".to_owned(), vec![Perm::UsersAdmin]),
            ("purger".to_owned(), vec![Perm::ContentDelete]),
        ]);
        let granter = auth(&["mgr"]);
        // 授 purger(含 contents:delete,granter 没有) → 403
        assert!(matches!(
            assert_no_escalation(&policy, &granter, &[], &["purger".to_owned()]),
            Err(AppError::Forbidden)
        ));
        // 授自己也有的 mgr → OK;空 → OK
        assert!(assert_no_escalation(&policy, &granter, &[], &["mgr".to_owned()]).is_ok());
        assert!(assert_no_escalation(&policy, &granter, &[], &[]).is_ok());
    }

    #[test]
    fn superadmin_can_grant_anything() {
        let policy = Policy::from_roles([
            ("super".to_owned(), Perm::ALL.to_vec()),
            ("purger".to_owned(), vec![Perm::ContentDelete]),
        ]);
        let god = auth(&["super"]);
        assert!(assert_no_escalation(&policy, &god, &[], &["purger".to_owned()]).is_ok());
    }

    #[test]
    fn self_role_change_must_keep_admin() {
        let policy = Policy::from_roles([
            ("mgr".to_owned(), vec![Perm::UsersAdmin]),
            ("plain".to_owned(), vec![Perm::WidgetRead]),
        ]);
        let me = Uuid::now_v7();
        // 改自己 + 仍含 users:admin → OK
        assert!(assert_self_keeps_admin(&policy, me, me, &["mgr".to_owned()]).is_ok());
        // 改自己 + 丢了 users:admin(或清空) → Conflict
        assert!(matches!(
            assert_self_keeps_admin(&policy, me, me, &["plain".to_owned()]),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            assert_self_keeps_admin(&policy, me, me, &[]),
            Err(AppError::Conflict(_))
        ));
        // 改别人 → 不受自锁约束
        assert!(
            assert_self_keeps_admin(&policy, me, Uuid::now_v7(), &["plain".to_owned()]).is_ok()
        );
    }
}

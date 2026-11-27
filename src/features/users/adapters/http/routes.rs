//! 后台用户管理的 **HTTP 适配器**(admin 组,归 idm 进程)。线格式 ↔ 领域互转见 `dto`。每 handler 首行 `require_scoped(UsersAdmin)`
//! (组闸之上再 gate 平台级 users:admin:平台管理员 + superadmin)。写操作 `by = ctx.audit_id().as_deref()`。
//! `#[utoipa::path]` **不手写 security** —— operation_permissions 经 `inject_operation_security` 注入。
//! path 相对 admin 组(nest 加 `/api/v1/admin/auth`)→ 实际 `/api/v1/admin/auth/users*`。
//!
//! 2026-11-26 角色补充的两道闸(都在 handler,判断抽纯函数 / `Policy` 方法):
//! - **superadmin 不经任何接口授予 / 撤销**(`assert_superadmin_untouched`):建号带它、改角色加上 / 去掉它 → 403;
//! - **防接管**(`Policy::require_platform_role_authority`):授出平台角色、或目标账号**现有**平台角色(未过滤原始名)
//!   → 操作者要 `platform:roles`(只有 superadmin)。平台管理员因此碰不到 superadmin 和别的平台管理员。

use std::slice;

use axum::extract::State;
use axum::http::StatusCode;
use idm::AuthUser;
use uuid::Uuid;

use super::dto::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, RoleView,
    SetRolesRequest, UpdateUserRequest,
};
use crate::app::app_state::AppState;
use crate::features::users::model;
use crate::infra::authorization::TokenScope;
use crate::infra::http::audit::{Audit, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Path, Query};
use crate::infra::http::pagination::{Page, PageQuery};
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::{Permission, Policy, RoleName, RoleNames};
use crate::kernel::pagination::{Page as CorePage, PageParams};

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
/// 这里授的是**平台角色**(落 `user_roles`),故只算该角色给的平台级权限(租户角色写进来不生效,也不给权)。
/// superadmin 持全部平台级权限,恒过;仅当出现"有 users:admin 但非满权"的中间管理员才真正拦。
fn assert_no_escalation(
    policy: &Policy,
    granter: &AuthUser,
    scope: &[Permission],
    granted_role_names: &[String],
) -> Result<(), AppError> {
    for name in granted_role_names {
        for permission in policy.permissions_for(RoleNames {
            platform: slice::from_ref(name),
            tenant: &[],
        }) {
            policy.require_scoped(granter, scope, permission)?; // 缺该权 → Forbidden(403)
        }
    }
    Ok(())
}

/// superadmin 只由 seed 声明(只有一个):任何接口都**不能授出、也不能撤掉**它 —— `current`(目标现有的原始角色名,
/// 建号时为空)与 `new`(要写入的)里有没有 superadmin 必须一致,否则 403。保留它的改动(如再加个平台管理员)放行。
/// 持 `platform:roles` 也不行:那条权限管的是平台管理员,不是 superadmin。
fn assert_superadmin_untouched(current: &[String], new: &[String]) -> Result<(), AppError> {
    let superadmin = RoleName::Superadmin.as_str();
    let had = current.iter().any(|r| r == superadmin);
    let has = new.iter().any(|r| r == superadmin);
    if had == has {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// 目录里留不留这个(平台)角色:superadmin 永不;其余平台角色只给持 `platform:roles` 的调用者。
fn grantable_in_catalog(role: RoleName, can_grant_platform: bool) -> bool {
    role != RoleName::Superadmin && can_grant_platform
}

/// 自锁:改**自己**的角色不能把 `users:admin` 弄没(否则自我降权、锁死后台)。
fn assert_self_keeps_admin(
    policy: &Policy,
    actor: Uuid,
    target: Uuid,
    new_role_names: &[String],
) -> Result<(), AppError> {
    if actor == target
        && !policy
            .permissions_for(RoleNames {
                platform: new_role_names,
                tenant: &[],
            })
            .contains(&Permission::UsersAdmin)
    {
        return Err(AppError::Conflict(
            "cannot remove your own admin access".into(),
        ));
    }
    Ok(())
}

/// 分页列出用户(过滤 + 排序 + 富化)。默认 offset;带 `cursor` 切 keyset。
/// **平台账号列表**:不论当前租户,列全部账号(不属于任何租户的也在),角色列 / `roles_any` / `roles_none` 都是平台角色。
/// 接了 search 投影读全局账号目录,没接读 idm。租户成员列表是另外的接口。
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
) -> Result<Json<Page<AdminUserView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    let page_params = page.resolve()?;
    let filter = model::ListUsers::from(filter);
    if matches!(page_params, PageParams::Cursor { .. }) && !filter.is_default_sort() {
        return Err(AppError::Validation("sort_by requires offset/page pagination".into()).into());
    }
    let page = state.user_admin.list(&filter, page_params).await?;
    Ok(Json(Page::from(page)))
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
    Audit(ctx): Audit,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<AdminUserView>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    // 提权闸:不能建带"超出自己权限"角色的号。名字经 service 的未过滤目录解析
    // (与落库校验同一实现,未知 id 此处即 422)—— 守卫失明/落库分裂从结构上不可能。
    let role_names = state.user_admin.role_names_by_ids(&request.roles).await?;
    // superadmin 授不出;授任何平台角色(任命平台管理员)要 platform:roles
    assert_superadmin_untouched(&[], &role_names)?;
    state
        .policy
        .require_platform_role_authority(&user.0, &scope.0, &role_names)?;
    assert_no_escalation(&state.policy, &user.0, &scope.0, &role_names)?;
    let view = state
        .user_admin
        .create(request.into(), ctx.audit_id().as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(view.into())))
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
) -> Result<Json<AdminUserView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    Ok(Json(state.user_admin.get(id).await?.into()))
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
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<AdminUserView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    // 目标现有角色闸(同 delete / reset_password / set_roles):改身份字段也是对目标动手 ——
    // 改掉 superadmin 的 username 就等于把它锁在门外(登录靠 username/email)。
    // 本模块四个写端点口径统一:够得着目标的全部权,才动得了它;目标持平台角色还要 platform:roles(防接管)。
    guard_target(
        &state,
        &user.0,
        &scope.0,
        &target_role_names(&state, id).await?,
    )?;
    Ok(Json(
        state
            .user_admin
            .update(id, request.into(), ctx.audit_id().as_deref())
            .await?
            .into(),
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
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    // 自锁:不能删自己的账号。
    assert_not_self(user.0.id, id)?;
    // 提权闸(同 reset_password,闸目标现有角色):中间管理员不该能删掉比自己权大的账号。
    // 这条是破坏而非接管,但同属"对更高权目标动手",与本模块的闸口径一致;目标持平台角色还要 platform:roles。
    guard_target(
        &state,
        &user.0,
        &scope.0,
        &target_role_names(&state, id).await?,
    )?;
    state
        .user_admin
        .delete(id, ctx.audit_id().as_deref())
        .await?;
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
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(request): Json<SetRolesRequest>,
) -> Result<Json<AdminUserView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    // 提权闸 + 自锁:不能授超出自己的权;改自己的角色不能丢 users:admin。
    // 名字经未过滤目录解析(未知 id 此处即 422,先于自锁 409,错误码不串台)。
    let role_names = state.user_admin.role_names_by_ids(&request.roles).await?;
    let current = target_role_names(&state, id).await?;
    // superadmin 授不出、撤不掉(含 superadmin 去掉自己的);授出平台角色要 platform:roles。
    assert_superadmin_untouched(&current, &role_names)?;
    state
        .policy
        .require_platform_role_authority(&user.0, &scope.0, &role_names)?;
    assert_no_escalation(&state.policy, &user.0, &scope.0, &role_names)?;
    // 目标现有角色闸(同 delete_user / reset_user_password 口径):全量替换角色是对目标的破坏性
    // 操作 —— 少了这道闸,中间管理员传一组"自己也有的角色"就能把 superadmin 整个降权/清空
    // (被授角色闸放行、自锁闸只护 actor 自己),唯一的 superadmin 被剥权后系统再无人能改回。
    // 本模块三个 destructive 端点里,这条曾是唯一没上闸的。目标持平台角色(撤销平台管理员)还要 platform:roles。
    guard_target(&state, &user.0, &scope.0, &current)?;
    assert_self_keeps_admin(&state.policy, user.0.id, id, &role_names)?;
    Ok(Json(
        state
            .user_admin
            .set_roles(id, request.into(), ctx.audit_id().as_deref())
            .await?
            .into(),
    ))
}

/// 角色目录(分配角色的候选集 = **调用者能授出的平台角色**),单页游标包络(has_more=false)。
/// 供前端 role-select 拉候选;`name`=机器码,`display_name`=展示名。
/// superadmin 永不出现(不经接口授予);授平台角色要 `platform:roles`,没有它的调用者(平台管理员)拿到空目录。
#[utoipa::path(
    get,
    path = "/roles",
    tag = "users",
    params(PageQuery),
    responses(
        (status = 200, description = "角色目录(单页;调用者能授出的平台角色:不含 superadmin,无 platform:roles 时为空)", body = Page<RoleView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody)
    )
)]
pub async fn list_roles(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(_page): Query<PageQuery>,
) -> Result<Json<Page<RoleView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    let can_grant_platform = state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::PlatformRoles)
        .is_ok();
    let items: Vec<model::Role> = state
        .user_admin
        .list_roles()
        .await?
        .items
        .into_iter()
        .filter(|r| grantable_in_catalog(r.name, can_grant_platform))
        .collect();
    // 单页包络:limit 跟过滤后的条数走(同 service 的口径)
    let limit = items.len().max(1) as u64;
    Ok(Json(Page::from_core(
        CorePage::new_with_cursor(items, limit, None),
        RoleView::from,
    )))
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
    Json(request): Json<ResetPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::UsersAdmin)?;
    // 提权闸,闸的是**目标现有的角色**(不是被授的角色):改谁的密码 = 能以谁的身份登录,
    // 所以必须"自己已持有目标的全部权"才准改。少了这道闸,"有 users:admin 但非满权"的中间
    // 管理员(role→权限运行期可改,见 `kernel::authorization`)虽被 set_roles 挡着授不出 superadmin,却能直接
    // 把 superadmin 的密码改成自己知道的再登进去 —— 本模块辛苦建的提权闸从这个端点整个绕过。
    // 平台管理员与 superadmin 的差只在 superadmin 独占权限上,所以目标持平台角色还要 platform:roles(防接管)。
    guard_target(
        &state,
        &user.0,
        &scope.0,
        &target_role_names(&state, id).await?,
    )?;
    state.user_admin.reset_password(id, request.into()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// 目标用户**现有**角色名(供提权闸)。不存在 → 404(与端点契约一致)。
/// 走 service 的**未过滤**取名(不是 `get()` 的闭集读模型)—— 详见 `raw_role_names`:
/// lossy 会丢掉闭集外角色,而那些角色在 `Policy` 里确实持有真权限,闸会因此失明。
async fn target_role_names(state: &AppState, id: Uuid) -> Result<Vec<String>, AppError> {
    state.user_admin.raw_role_names(id).await
}

/// 对**目标账号**动手的两道闸(写端点共用):防接管(目标持平台角色 → 要 `platform:roles`)+ 提权闸(够得着目标的全部权)。
fn guard_target(
    state: &AppState,
    actor: &AuthUser,
    scope: &[Permission],
    target_roles: &[String],
) -> Result<(), AppError> {
    state
        .policy
        .require_platform_role_authority(actor, scope, target_roles)?;
    assert_no_escalation(&state.policy, actor, scope, target_roles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(roles: &[&str]) -> AuthUser {
        AuthUser::new(
            Uuid::now_v7(),
            "u".into(),
            roles.iter().map(|s| s.to_string()).collect(),
        )
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
        // 中间管理员:有 users:admin,但没有 tenants:admin(账号管理授的是平台角色,只比平台级权限)。
        let policy = Policy::new([
            ("mgr".to_owned(), vec![Permission::UsersAdmin]),
            ("tenancy".to_owned(), vec![Permission::TenantsAdmin]),
            // 租户级权限经平台角色授出不生效,也就不算提权
            ("purger".to_owned(), vec![Permission::ContentDelete]),
        ]);
        let granter = auth(&["mgr"]);
        assert!(assert_no_escalation(&policy, &granter, &[], &["purger".to_owned()]).is_ok());
        // 授 tenancy(含 tenants:admin,granter 没有) → 403
        assert!(matches!(
            assert_no_escalation(&policy, &granter, &[], &["tenancy".to_owned()]),
            Err(AppError::Forbidden)
        ));
        // 授自己也有的 mgr → OK;空 → OK
        assert!(assert_no_escalation(&policy, &granter, &[], &["mgr".to_owned()]).is_ok());
        assert!(assert_no_escalation(&policy, &granter, &[], &[]).is_ok());
    }

    #[test]
    fn superadmin_can_grant_anything() {
        let policy = Policy::new([
            ("super".to_owned(), Permission::ALL.to_vec()),
            ("tenancy".to_owned(), vec![Permission::TenantsAdmin]),
        ]);
        let god = auth(&["super"]);
        assert!(assert_no_escalation(&policy, &god, &[], &["tenancy".to_owned()]).is_ok());
    }

    /// superadmin 不经接口授出 / 撤掉:建号带它、加上、去掉都 403;保留它的改动、与它无关的改动放行。
    #[test]
    fn superadmin_is_never_granted_or_revoked() {
        let to_strings =
            |values: &[&str]| -> Vec<String> { values.iter().map(|x| x.to_string()).collect() };
        let forbidden = |current: &[&str], new: &[&str]| {
            matches!(
                assert_superadmin_untouched(&to_strings(current), &to_strings(new)),
                Err(AppError::Forbidden)
            )
        };
        assert!(forbidden(&[], &["superadmin"]), "授出");
        assert!(forbidden(&["superadmin"], &[]), "撤掉");
        assert!(forbidden(&["superadmin"], &["platform_admin"]), "换掉");
        assert!(assert_superadmin_untouched(
            &to_strings(&["superadmin"]),
            &to_strings(&["superadmin", "platform_admin"])
        )
        .is_ok());
        assert!(
            assert_superadmin_untouched(&to_strings(&[]), &to_strings(&["platform_admin"])).is_ok()
        );
        assert!(
            assert_superadmin_untouched(&to_strings(&["platform_admin"]), &to_strings(&[])).is_ok()
        );
    }

    #[test]
    fn catalog_hides_superadmin_and_needs_platform_roles() {
        assert!(!grantable_in_catalog(
            RoleName::Superadmin,
            /* can_grant_platform= */ true
        ));
        assert!(grantable_in_catalog(
            RoleName::PlatformAdmin,
            /* can_grant_platform= */ true
        ));
        assert!(!grantable_in_catalog(
            RoleName::PlatformAdmin,
            /* can_grant_platform= */ false
        ));
    }

    #[test]
    fn self_role_change_must_keep_admin() {
        let policy = Policy::new([
            ("mgr".to_owned(), vec![Permission::UsersAdmin]),
            ("plain".to_owned(), vec![Permission::WidgetRead]),
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

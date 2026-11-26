//! 租户 / 成员管理的 **HTTP 适配器**(admin 组,归 idm 进程)。每个 handler 首行 `require_scoped`:
//! 平台接口 gate `tenants:admin`(平台级),成员接口 gate `members:read` / `members:admin`(租户级)。
//! 写操作 `by = ctx.audit_id()`。`#[utoipa::path]` **不手写 security** —— op_perms 经 `inject_operation_security` 注入。
//!
//! 租户从哪来:租户级接口**只**用 token 的当前租户(`CurrentTenant`,不收 query / body 里的 tenant_id),别的租户的
//! 成员 id → 404;平台接口用路径里的租户 id(先确认租户存在,不存在 → 404)。
//!
//! 防接管(2026-11-26):改角色 / 移出一个**持平台角色**的成员(superadmin / 平台管理员)要 `platform:roles`
//! (只有 superadmin)—— 组织角色比较拦不住(superadmin 在默认组织里也只是 admin)。经 `AppState::guard_platform_account`
//! 看目标的原始平台角色名;组织内接口先确认是本租户成员再判(别的租户的人仍 404,不借 403 泄露他是谁)。

use axum::extract::State;
use axum::http::StatusCode;
use idm::AuthUser;
use uuid::Uuid;

use super::dto::{
    AddMemberRequest, CreateTenantRequest, ListMembersFilter, MemberRolesRequest, MemberView,
    TenantView, UpdateTenantRequest,
};
use crate::app::state::AppState;
use crate::features::tenants::model;
use crate::infra::authz::TokenScope;
use crate::infra::http::audit::{Audit, CurrentTenant, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Path, Query};
use crate::infra::http::pagination::{Page, PageQuery};
use crate::kernel::authz::{Perm, Policy, RoleName};
use crate::kernel::error::AppError;

// ── 授权守卫(自锁 / 提权):放 handler(授权边界),判断抽纯函数便于单测 ──

/// 提权闸:授出的每个租户角色给的**租户级**权限,授予者(当前租户的角色 ∩ token scope)自己都得有 ——
/// 租户管理员不能授出自己没有的权(role→权限运行期可改,出现"有 members:admin 但非满权"的成员时才真拦)。
/// 也用来闸**目标现有**的角色:改 / 移出一个权限比自己大的成员,同样拒绝。
fn assert_can_grant(
    policy: &Policy,
    granter: &AuthUser,
    scope: &[Perm],
    role_names: &[String],
) -> Result<(), AppError> {
    for name in role_names {
        for perm in policy.perms_for(&[], std::slice::from_ref(name)) {
            policy.require_scoped(granter, scope, perm)?; // 缺该权 → 403
        }
    }
    Ok(())
}

/// 自锁:改**自己**的租户角色不能把 `members:admin` 弄没(否则自己把自己锁出成员管理)。
fn assert_self_keeps_members_admin(
    policy: &Policy,
    actor: Uuid,
    target: Uuid,
    new_role_names: &[String],
) -> Result<(), AppError> {
    if actor == target
        && !policy
            .perms_for(&[], new_role_names)
            .contains(&Perm::MembersAdmin)
    {
        return Err(AppError::Conflict(
            "cannot remove your own member management access".into(),
        ));
    }
    Ok(())
}

/// 自锁:不能把**自己**移出当前租户(要离开找另一位管理员或平台管理员)。
fn assert_not_self(actor: Uuid, target: Uuid) -> Result<(), AppError> {
    if actor == target {
        Err(AppError::Conflict(
            "cannot remove yourself from the current tenant".into(),
        ))
    } else {
        Ok(())
    }
}

fn role_names(roles: &[RoleName]) -> Vec<String> {
    roles.iter().map(|r| r.as_str().to_owned()).collect()
}

// ───────────────────────────── 平台:租户 ─────────────────────────────

/// 租户列表(存活租户,按创建序)。默认 offset;带 `cursor` 切 keyset。
#[utoipa::path(
    get,
    path = "/tenants",
    tag = "tenants",
    params(PageQuery),
    responses(
        (status = 200, description = "租户分页列表", body = Page<TenantView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限(平台级)", body = ErrorBody)
    )
)]
pub async fn list_tenants(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(page): Query<PageQuery>,
) -> Result<Json<Page<TenantView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    let page = state.tenant_admin.list_tenants(page.resolve()?).await?;
    Ok(Json(Page::from_core(page, TenantView::from)))
}

/// 建租户(status = active,还没有成员;用 PUT 成员接口指定第一个管理员)。
#[utoipa::path(
    post,
    path = "/tenants",
    tag = "tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "已创建", body = TenantView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限", body = ErrorBody),
        (status = 409, description = "slug 已被占用(含已删除的租户,slug 不复用)", body = ErrorBody),
        (status = 422, description = "校验失败(slug / name 不合规)", body = ErrorBody)
    )
)]
pub async fn create_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<TenantView>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    let t = state
        .tenant_admin
        .create_tenant(req.into(), ctx.audit_id())
        .await?;
    Ok((StatusCode::CREATED, Json(t.into())))
}

/// 租户详情。不存在 / 已删除 → 404。
#[utoipa::path(
    get,
    path = "/tenants/{id}",
    tag = "tenants",
    params(("id" = Uuid, Path, description = "tenant id")),
    responses(
        (status = 200, description = "找到", body = TenantView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 已删除", body = ErrorBody)
    )
)]
pub async fn get_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<TenantView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    Ok(Json(state.tenant_admin.get_tenant(id).await?.into()))
}

/// 改租户(PUT 全量:名称 + 状态)。停用(`suspended`)立即吊销该租户里所有人的会话:refresh 立刻 401,
/// 已发出的 access token 到期前仍有效(最长 = access token 有效期)。恢复(`active`)后成员重新登录即可。
#[utoipa::path(
    put,
    path = "/tenants/{id}",
    tag = "tenants",
    params(("id" = Uuid, Path, description = "tenant id")),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "已更新", body = TenantView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 已删除", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<TenantView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    Ok(Json(
        state
            .tenant_admin
            .update_tenant(id, req.into(), ctx.audit_id())
            .await?
            .into(),
    ))
}

// ───────────────────────────── 平台:任意租户的成员 ─────────────────────────────

/// 某租户的成员列表(平台管理员看任意租户)。租户不存在 → 404。过滤 / 分页同 `GET /admin/auth/members`。
#[utoipa::path(
    get,
    path = "/tenants/{id}/members",
    tag = "tenants",
    params(("id" = Uuid, Path, description = "tenant id"), PageQuery, ListMembersFilter),
    responses(
        (status = 200, description = "成员分页列表", body = Page<MemberView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限", body = ErrorBody),
        (status = 404, description = "租户不存在", body = ErrorBody),
        (status = 422, description = "q 但无 search 投影后端", body = ErrorBody)
    )
)]
pub async fn list_tenant_members(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
    Query(filter): Query<ListMembersFilter>,
) -> Result<Json<Page<MemberView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    let tenant = state.tenant_admin.tenant_scope(id).await?;
    let page = state
        .tenant_admin
        .list_members(tenant, &model::ListMembers::from(filter), page.resolve()?)
        .await?;
    Ok(Json(Page::from_core(page, MemberView::from)))
}

/// 设某租户的成员(PUT:不是成员则加入,是成员则全量替换租户角色)。用于给新租户指定第一个管理员。
/// 只能授租户角色(平台角色 → 422)。租户 / 账号不存在 → 404。
#[utoipa::path(
    put,
    path = "/tenants/{id}/members/{user_id}",
    tag = "tenants",
    params(
        ("id" = Uuid, Path, description = "tenant id"),
        ("user_id" = Uuid, Path, description = "user id")
    ),
    request_body = MemberRolesRequest,
    responses(
        (status = 200, description = "已加入 / 已更新", body = MemberView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限 / 改持平台角色的成员而无 platform:roles", body = ErrorBody),
        (status = 404, description = "租户或账号不存在", body = ErrorBody),
        (status = 422, description = "校验失败 / 平台角色", body = ErrorBody)
    )
)]
pub async fn put_tenant_member(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<MemberRolesRequest>,
) -> Result<Json<MemberView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    let tenant = state.tenant_admin.tenant_scope(id).await?;
    // 防接管:已是成员时这是「改角色」,目标持平台角色要 platform:roles(把他加进新组织不算动他,放行)
    match state.tenant_admin.member_role_names(tenant, user_id).await {
        Ok(_) => {
            state
                .guard_platform_account(&user.0, &scope.0, user_id)
                .await?
        }
        Err(AppError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(Json(
        state
            .tenant_admin
            .put_member(tenant, user_id, &req.roles, ctx.audit_id())
            .await?
            .into(),
    ))
}

/// 把某人移出某租户,并立即吊销他在该租户的会话。租户不存在 / 不是成员 → 404。
#[utoipa::path(
    delete,
    path = "/tenants/{id}/members/{user_id}",
    tag = "tenants",
    params(
        ("id" = Uuid, Path, description = "tenant id"),
        ("user_id" = Uuid, Path, description = "user id")
    ),
    responses(
        (status = 204, description = "已移出,该租户里的会话已吊销"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 tenants:admin 权限 / 移出持平台角色的账号而无 platform:roles", body = ErrorBody),
        (status = 404, description = "租户不存在 / 不是该租户的成员", body = ErrorBody)
    )
)]
pub async fn remove_tenant_member(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::TenantsAdmin)?;
    let tenant = state.tenant_admin.tenant_scope(id).await?;
    // 防接管:移出持平台角色的账号要 platform:roles
    state
        .guard_platform_account(&user.0, &scope.0, user_id)
        .await?;
    state
        .tenant_admin
        .remove_member(tenant, user_id, ctx.audit_id())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ───────────────────────────── 租户管理员:本租户的成员 ─────────────────────────────

/// 本租户的成员列表(替代旧的后台「用户」页;数据来自租户成员索引,没接 search 时读 idm)。
/// 默认 offset;带 `cursor` 切 keyset。`q`(用户名 + 显示名模糊)仅接了 search 投影后端时可用,未接 → 422。
#[utoipa::path(
    get,
    path = "/members",
    tag = "members",
    params(PageQuery, ListMembersFilter),
    responses(
        (status = 200, description = "成员分页列表(display_name / avatar 富化,缺则 null)", body = Page<MemberView>),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 members:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "q 但无 search 投影后端", body = ErrorBody)
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    CurrentTenant(tenant): CurrentTenant,
    Query(page): Query<PageQuery>,
    Query(filter): Query<ListMembersFilter>,
) -> Result<Json<Page<MemberView>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::MembersRead)?;
    let page = state
        .tenant_admin
        .list_members(tenant, &model::ListMembers::from(filter), page.resolve()?)
        .await?;
    Ok(Json(Page::from_core(page, MemberView::from)))
}

/// 按**完整用户名**把已有账号加进本租户(spec §4.5)。精确匹配(邮箱、大小写不同都不算),查不到 → 404
/// `account_not_found`(不建账号:账号由平台管理员建)。只能授租户角色,且不能授出自己没有的权限。
/// 对方持平台角色(superadmin / 平台管理员)→ 要 `platform:roles`(与「移出」同一口径:组织管理员加进来就移不走)。
#[utoipa::path(
    post,
    path = "/members",
    tag = "members",
    request_body = AddMemberRequest,
    responses(
        (status = 201, description = "已加入本租户", body = MemberView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 members:admin 权限 / 授出的角色超出自己的权限 / 对方持平台角色(要 platform:roles)/ 没有当前租户", body = ErrorBody),
        (status = 404, description = "account_not_found:没有这个用户名的账号", body = ErrorBody),
        (status = 409, description = "已是本租户成员", body = ErrorBody),
        (status = 422, description = "校验失败 / 平台角色", body = ErrorBody)
    )
)]
pub async fn add_member(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    CurrentTenant(tenant): CurrentTenant,
    Audit(ctx): Audit,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<MemberView>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::MembersAdmin)?;
    assert_can_grant(&state.policy, &user.0, &scope.0, &role_names(&req.roles))?;
    let req: model::AddMember = req.into();
    // 防接管:先找到目标账号(422 / 404 口径不变),对方持平台角色 → 要 platform:roles
    let (target, _) = state.tenant_admin.resolve_add_member(&req).await?;
    state
        .guard_platform_account(&user.0, &scope.0, target)
        .await?;
    let m = state
        .tenant_admin
        .add_member(tenant, req, ctx.audit_id())
        .await?;
    Ok((StatusCode::CREATED, Json(m.into())))
}

/// 全量设本租户某成员的租户角色(原子替换)。别的租户的成员 / 不是成员 → 404。
/// 不能授出自己没有的权限、不能改权限比自己大的成员(403);改自己时不能丢掉 `members:admin`(409)。
#[utoipa::path(
    put,
    path = "/members/{user_id}/roles",
    tag = "members",
    params(("user_id" = Uuid, Path, description = "user id")),
    request_body = MemberRolesRequest,
    responses(
        (status = 200, description = "已更新", body = MemberView),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 members:admin 权限 / 越权 / 目标持平台角色(要 platform:roles)/ 没有当前租户", body = ErrorBody),
        (status = 404, description = "不是本租户的成员", body = ErrorBody),
        (status = 409, description = "改自己的角色会丢掉成员管理权", body = ErrorBody),
        (status = 422, description = "校验失败 / 平台角色", body = ErrorBody)
    )
)]
pub async fn set_member_roles(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    CurrentTenant(tenant): CurrentTenant,
    Audit(ctx): Audit,
    Path(user_id): Path<Uuid>,
    Json(req): Json<MemberRolesRequest>,
) -> Result<Json<MemberView>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::MembersAdmin)?;
    let granted = role_names(&req.roles);
    assert_self_keeps_members_admin(&state.policy, user.0.id, user_id, &granted)?;
    assert_can_grant(&state.policy, &user.0, &scope.0, &granted)?;
    // 目标现有角色闸(不是本租户成员 → 404):不能把权限比自己大的成员降权 / 清空。
    let current = state
        .tenant_admin
        .member_role_names(tenant, user_id)
        .await?;
    assert_can_grant(&state.policy, &user.0, &scope.0, &current)?;
    // 防接管:本租户成员里持平台角色的(superadmin / 平台管理员)只有 platform:roles 能改
    state
        .guard_platform_account(&user.0, &scope.0, user_id)
        .await?;
    Ok(Json(
        state
            .tenant_admin
            .set_member_roles(tenant, user_id, &req.roles, ctx.audit_id())
            .await?
            .into(),
    ))
}

/// 把某成员移出本租户,并立即吊销他在本租户的会话(他在别的租户的成员关系 / 会话不动;账号本身不删)。
/// 别的租户的成员 / 不是成员 → 404;不能移出自己(409);不能移出权限比自己大的成员(403)。
#[utoipa::path(
    delete,
    path = "/members/{user_id}",
    tag = "members",
    params(("user_id" = Uuid, Path, description = "user id")),
    responses(
        (status = 204, description = "已移出,本租户里的会话已吊销"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 members:admin 权限 / 越权 / 目标持平台角色(要 platform:roles)/ 没有当前租户", body = ErrorBody),
        (status = 404, description = "不是本租户的成员", body = ErrorBody),
        (status = 409, description = "不能移出自己", body = ErrorBody)
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    CurrentTenant(tenant): CurrentTenant,
    Audit(ctx): Audit,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::MembersAdmin)?;
    assert_not_self(user.0.id, user_id)?;
    // 目标现有角色闸。已不是本租户成员(含别的租户的人)→ 没有可比的角色,交给 service:它照样补吊销
    // 该人在本租户的会话(上次移出成功、吊销失败的重试靠这个补上)再回 404。
    match state.tenant_admin.member_role_names(tenant, user_id).await {
        Ok(current) => {
            assert_can_grant(&state.policy, &user.0, &scope.0, &current)?;
            // 防接管:是本租户成员才判(别的租户的人照旧走 404)
            state
                .guard_platform_account(&user.0, &scope.0, user_id)
                .await?;
        }
        Err(AppError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    state
        .tenant_admin
        .remove_member(tenant, user_id, ctx.audit_id())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::tenant::DEFAULT_TENANT_ID;

    fn member(roles: &[&str]) -> AuthUser {
        AuthUser {
            id: Uuid::now_v7(),
            username: "m".into(),
            roles: vec![],
            tenant_id: Some(DEFAULT_TENANT_ID.as_uuid()),
            tenant_roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 「有 members:admin 但非满权」的租户成员:授不出自己没有的权,平台级权限不参与(租户角色给不了)。
    #[test]
    fn grant_is_limited_to_own_tenant_perms() {
        let policy = Policy::from_roles([
            ("mgr".to_owned(), vec![Perm::MembersAdmin, Perm::WidgetRead]),
            ("purger".to_owned(), vec![Perm::WidgetDelete]),
            // 平台级权限经租户角色不生效,也就不算提权
            ("weird".to_owned(), vec![Perm::UsersAdmin]),
        ]);
        let mgr = member(&["mgr"]);
        assert!(assert_can_grant(&policy, &mgr, &[], &["mgr".to_owned()]).is_ok());
        assert!(assert_can_grant(&policy, &mgr, &[], &["weird".to_owned()]).is_ok());
        assert!(assert_can_grant(&policy, &mgr, &[], &[]).is_ok());
        assert!(matches!(
            assert_can_grant(&policy, &mgr, &[], &["purger".to_owned()]),
            Err(AppError::Forbidden)
        ));
        // token scope 收窄后,自己的角色也授不出
        assert!(matches!(
            assert_can_grant(&policy, &mgr, &[Perm::MembersAdmin], &["mgr".to_owned()]),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn self_locks() {
        let policy = Policy::from_roles([
            ("mgr".to_owned(), vec![Perm::MembersAdmin]),
            ("plain".to_owned(), vec![Perm::WidgetRead]),
        ]);
        let me = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(assert_self_keeps_members_admin(&policy, me, me, &["mgr".to_owned()]).is_ok());
        assert!(matches!(
            assert_self_keeps_members_admin(&policy, me, me, &["plain".to_owned()]),
            Err(AppError::Conflict(_))
        ));
        assert!(assert_self_keeps_members_admin(&policy, me, other, &[]).is_ok());
        assert!(matches!(
            assert_not_self(me, me),
            Err(AppError::Conflict(_))
        ));
        assert!(assert_not_self(me, other).is_ok());
    }
}

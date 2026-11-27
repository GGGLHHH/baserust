//! auth 端点(app 拥有的 HTTP 边界)。认证用 **httponly cookie**:login/register 把 access/refresh
//! 写进 `Set-Cookie`,body 只返 `UserResponse`(token 不进响应体);鉴权由 `authenticate` 中间件读
//! cookie(Bearer 兜底)。业务逻辑全在 idm 库的 `AuthService` —— 这里只做校验 + cookie + DTO 翻译。
//!
//! 端点分三组挂载(public:register/login/refresh/logout;frontend:me*/logout-all;
//! admin:admin_login/admin_get_me),nginx 按 `/api/v1/{public,frontend,admin}/auth/` 三组前缀 + `/api/v1/admin/platform/`(平台租户管理)分流到 idm。

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use garde::Validate;
use uuid::Uuid;

use super::dto::{
    ChangePasswordRequest, DeleteMeRequest, LoginRequest, MyTenantView, RegisterRequest,
    SwitchTenantRequest, UpdateMeRequest, UserResponse,
};
use crate::app::state::AppState;
use crate::features::auth::adapters::emit::{emit_auth_event, failure_data, success_data};
use crate::features::auth_audit::{AuthChannel, AuthEventType, FailureReason};
use crate::infra::client_context::ClientContext;
use crate::infra::http::audit::{Audit, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::Json;
use crate::kernel::authz::RoleName;
use crate::kernel::error::AppError;

const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";

/// 构造 httponly 认证 cookie:HttpOnly + SameSite=Lax + Secure(prod)+ Path=/ + Max-Age。
fn auth_cookie(
    name: &'static str,
    value: String,
    max_age_secs: i64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

/// 把 access/refresh 写进 cookie(发会话)。
fn set_auth_cookies(jar: CookieJar, outcome: &idm::AuthOutcome, secure: bool) -> CookieJar {
    jar.add(auth_cookie(
        ACCESS_COOKIE,
        outcome.access_token.clone(),
        outcome.access_max_age_secs,
        secure,
    ))
    .add(auth_cookie(
        REFRESH_COOKIE,
        outcome.refresh_token.clone(),
        outcome.refresh_max_age_secs,
        secure,
    ))
}

/// 清 access/refresh cookie(登出):显式发 `Max-Age=0` 的同名空 cookie 强制浏览器回收。
/// (不用 `CookieJar::remove` —— 它只在请求**带了**原 cookie 时才发 removal,登出请求未必带。)
fn clear_auth_cookies(jar: CookieJar) -> CookieJar {
    jar.add(expired_cookie(ACCESS_COOKIE))
        .add(expired_cookie(REFRESH_COOKIE))
}

fn expired_cookie(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, ""))
        .http_only(true)
        .path("/")
        .max_age(time::Duration::ZERO)
        .build()
}

#[utoipa::path(
    post, path = "/auth/register", tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "注册成功,token 写入 httponly cookie", body = UserResponse),
        (status = 409, description = "用户名或邮箱已占用", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    ctx: ClientContext,
    Audit(audit): Audit,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, CookieJar, Json<UserResponse>), ApiError> {
    req.validate()?;
    let outcome = state.auth.register(req.into(), audit.audit_id()).await?;
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::Registered,
        outcome.user.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            outcome.user.id,
            Some(outcome.session_id),
            Some(&outcome.user.username),
            outcome.tenant_id,
        ),
    )
    .await;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((StatusCode::CREATED, jar, Json(outcome.user.into())))
}

#[utoipa::path(
    post, path = "/auth/login", tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登录成功,token 写入 httponly cookie", body = UserResponse),
        (status = 401, description = "用户名/邮箱或密码错误(同码同文案,防枚举)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), ApiError> {
    req.validate()?;
    let identifier = req.identifier.clone();
    match state.auth.login(req.into()).await {
        Ok(outcome) => {
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::LoginSucceeded,
                outcome.user.id,
                success_data(
                    &ctx,
                    AuthChannel::Public,
                    outcome.user.id,
                    Some(outcome.session_id),
                    Some(&outcome.user.username),
                    outcome.tenant_id,
                ),
            )
            .await;
            let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
            Ok((jar, Json(outcome.user.into())))
        }
        // 失败原因(仅供审计)必须在 `idm::IdmError` → `AppError` 的 `From` 转换**之前**读出
        // (转换后统一收口 401,原因丢失);HTTP 仍统一 401,防枚举不变。
        Err(idm_err) => {
            let reason = match &idm_err {
                idm::IdmError::InvalidCredentials(f) => FailureReason::from(f),
                _ => return Err(idm_err.into()),
            };
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::LoginFailed,
                Uuid::nil(),
                failure_data(
                    &ctx,
                    AuthChannel::Public,
                    None,
                    Some(&identifier),
                    reason,
                    None,
                ),
            )
            .await;
            Err(idm_err.into())
        }
    }
}

#[utoipa::path(
    post, path = "/auth/refresh", tag = "auth",
    responses(
        (status = 200, description = "刷新成功,新 token 写入 cookie", body = UserResponse),
        (status = 401, description = "refresh cookie 无效/过期/已撤销", body = ErrorBody),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
) -> Result<(CookieJar, Json<UserResponse>), ApiError> {
    let refresh = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or(AppError::Unauthorized)?;
    let outcome = state.auth.refresh(&refresh).await?;
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::Refreshed,
        outcome.user.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            outcome.user.id,
            Some(outcome.session_id),
            Some(&outcome.user.username),
            outcome.tenant_id,
        ),
    )
    .await;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user.into())))
}

#[utoipa::path(
    post, path = "/auth/logout", tag = "auth",
    responses((status = 204, description = "已登出,清除 cookie(幂等)"))
)]
pub async fn logout(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), ApiError> {
    // 撤销服务端 session(若 cookie 带了 refresh)+ 清 cookie。幂等 —— 没找到活跃会话不发事件。
    if let Some(c) = jar.get(REFRESH_COOKIE) {
        if let Some(session) = state.auth.logout(c.value()).await? {
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::LoggedOut,
                session.user_id,
                success_data(
                    &ctx,
                    AuthChannel::Public,
                    session.user_id,
                    Some(session.id),
                    None,
                    session.tenant_id,
                ),
            )
            .await;
        }
    }
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    post, path = "/auth/logout-all", tag = "auth",    responses((status = 204, description = "已撤销所有会话"), (status = 401, body = ErrorBody))
)]
pub async fn logout_all(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    user: CurrentUser,
) -> Result<(StatusCode, CookieJar), ApiError> {
    state.auth.logout_all(user.0.id).await?;
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::LogoutAll,
        user.0.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            user.0.id,
            None,
            Some(&user.0.username),
            user.0.tenant_id,
        ),
    )
    .await;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    get, path = "/auth/me", tag = "me",    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody))
)]
pub async fn get_me(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<UserResponse>, ApiError> {
    let view = state.auth.me(user.0.id).await?;
    Ok(Json(view.into()))
}

#[utoipa::path(
    put, path = "/auth/me", tag = "me",    request_body = UpdateMeRequest,
    responses(
        (status = 200, body = UserResponse),
        (status = 409, description = "新用户名/邮箱已占用", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn update_me(
    State(state): State<AppState>,
    Audit(ctx): Audit,
    user: CurrentUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    req.validate()?;
    let view = state
        .auth
        .update_me(user.0.id, req.into(), ctx.audit_id())
        .await?;
    Ok(Json(view.into()))
}

#[utoipa::path(
    delete, path = "/auth/me", tag = "me",    request_body = DeleteMeRequest,
    responses(
        (status = 204, description = "已注销"),
        (status = 401, description = "密码错", body = ErrorBody),
        (status = 403, description = "superadmin 不能注销自己(superadmin 不经任何接口撤销)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn delete_me(
    State(state): State<AppState>,
    ctx: ClientContext,
    Audit(audit): Audit,
    user: CurrentUser,
    jar: CookieJar,
    Json(req): Json<DeleteMeRequest>,
) -> Result<(StatusCode, CookieJar), ApiError> {
    req.validate()?;
    // superadmin 只有一个、只由 seed 声明,任何接口都撤不掉 —— 注销自己也不行(删了之后同名注册 / 下次 seed 都会出事)。
    // 看库里的原始平台角色(不信 token 里的 roles:降权令牌 / 闭集过滤都不该让它溜过去)。账号已不在 → 交给 delete_me 照旧回 401。
    match state.user_admin.raw_role_names(user.0.id).await {
        Ok(roles) if roles.iter().any(|r| r == RoleName::Superadmin.as_str()) => {
            return Err(AppError::Forbidden.into());
        }
        Ok(_) | Err(AppError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    state
        .auth
        .delete_me(user.0.id, req.password, audit.audit_id())
        .await?;
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::AccountDeleted,
        user.0.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            user.0.id,
            None,
            Some(&user.0.username),
            user.0.tenant_id,
        ),
    )
    .await;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    post, path = "/auth/me/password", tag = "me",    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "已改密,撤销所有会话(需重新登录)"),
        (status = 401, description = "旧密码错", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    ctx: ClientContext,
    user: CurrentUser,
    jar: CookieJar,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<(StatusCode, CookieJar), ApiError> {
    req.validate()?;
    state.auth.change_password(user.0.id, req.into()).await?;
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::PasswordChanged,
        user.0.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            user.0.id,
            None,
            Some(&user.0.username),
            user.0.tenant_id,
        ),
    )
    .await;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

// ── 租户:我的租户列表 / 切换当前租户(frontend 组,需登录)。 ──

#[utoipa::path(
    get, path = "/auth/tenants", tag = "me",
    responses(
        (status = 200, description = "当前账号有效的成员关系(租户 active + 成员 active),最近用过的在前;`current` 标出当前 token 所在租户", body = Vec<MyTenantView>),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_my_tenants(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<MyTenantView>>, ApiError> {
    let current = user.0.tenant_id;
    let items = state
        .auth
        .my_tenants(user.0.id)
        .await?
        .into_iter()
        .map(|m| MyTenantView::from_membership(m, current))
        .collect();
    Ok(Json(items))
}

#[utoipa::path(
    post, path = "/auth/switch-tenant", tag = "me",
    request_body = SwitchTenantRequest,
    responses(
        (status = 200, description = "已切换:旧会话吊销,带新租户的 token 写入 httponly cookie", body = UserResponse),
        (status = 401, description = "未登录 / refresh cookie 无效 / refresh 会话不属于当前身份(原会话不动)", body = ErrorBody),
        (status = 403, description = "不是该租户的有效成员(含平台管理员切进自己不是成员的租户),原会话不动", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn switch_tenant(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    user: CurrentUser, // frontend 组已闸登录;切哪个会话由 refresh cookie 定,但会话必须属于当前身份
    Json(req): Json<SwitchTenantRequest>,
) -> Result<(CookieJar, Json<UserResponse>), ApiError> {
    req.validate()?;
    // 换租户 = 换会话:凭 refresh cookie(会话身份)切,不能只凭 access token。
    let refresh = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or(AppError::Unauthorized)?;
    // refresh 会话不属于当前身份(拿别人的 cookie 借道)→ 401,原会话不动(idm 校验)。
    let outcome = state
        .auth
        .switch_tenant(&refresh, user.0.id, req.tenant_id)
        .await?;
    // 认证审计:记切换后的租户与新会话(失败 —— 不是成员 / refresh 无效 —— 不发事件,原会话不动)。
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::TenantSwitched,
        outcome.user.id,
        success_data(
            &ctx,
            AuthChannel::Public,
            outcome.user.id,
            Some(outcome.session_id),
            Some(&outcome.user.username),
            outcome.tenant_id,
        ),
    )
    .await;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user.into())))
}

// ── admin 组(后台)。login 在组闸外(public 语义,验密后自查);me 在闸内。 ──

#[utoipa::path(
    post, path = "/auth/login", tag = "admin",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "后台登录成功,token 写入 httponly cookie。进入的上下文:有效成员关系里按最近使用挑第一个有 admin:login 的租户;都没有而有平台级权限 → 平台上下文(无当前租户)", body = UserResponse),
        (status = 401, description = "用户名/邮箱或密码错误(同码同文案,防枚举)", body = ErrorBody),
        (status = 403, description = "凭据正确但无后台准入,不发 token 不设 cookie:一个有效成员关系都没有、也没有平台级权限 → `tenant_required`;有成员关系但哪个租户里都没有 admin:login(也没有平台级权限)→ `forbidden`", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn admin_login(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), ApiError> {
    req.validate()?;
    let identifier = req.identifier.clone();
    // 验密后**挑进哪里**(`Policy::admin_login_entry`):有效成员关系按 last_used_at 倒序,第一个当前租户角色给了
    // admin:login 的租户;都没有 → 有平台级权限进平台上下文;否则拒绝(没有成员关系 → tenant_required,
    // 有 → forbidden)。拒绝时 idm **不建会话、不记 last_used_at**,不发 token 不设 cookie。
    // 前台登录不走这里,仍进最近用过的租户。
    let mut candidate: Option<Uuid> = None;
    let mut denial: Option<AppError> = None;
    let result = state
        .auth
        .login_with(req.into(), |c| {
            candidate = Some(c.user_id);
            let tenants = c
                .memberships
                .iter()
                .map(|m| (m.tenant.id, m.roles.as_slice()));
            match state.policy.admin_login_entry(c.platform_roles, tenants) {
                Ok(Some(tenant)) => Some(idm::LoginEntry::Tenant(tenant)),
                Ok(None) => Some(idm::LoginEntry::Platform),
                Err(e) => {
                    denial = Some(e);
                    None
                }
            }
        })
        .await;
    let outcome = match result {
        Ok(outcome) => outcome,
        // 凭据本身错(同 public login 的原因匹配);HTTP 仍统一 401,防枚举不变。
        Err(idm::IdmError::InvalidCredentials(f)) => {
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::LoginFailed,
                Uuid::nil(),
                failure_data(
                    &ctx,
                    AuthChannel::Admin,
                    None,
                    Some(&identifier),
                    FailureReason::from(&f),
                    None,
                ),
            )
            .await;
            return Err(idm::IdmError::InvalidCredentials(f).into());
        }
        // 验过密但没有后台准入(或挑中的租户刚好被并发移出)。
        Err(idm::IdmError::Forbidden) if candidate.is_some() => {
            let user_id = candidate.unwrap_or_default();
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::AdminAccessDenied,
                user_id,
                failure_data(
                    &ctx,
                    AuthChannel::Admin,
                    Some(user_id),
                    Some(&identifier),
                    FailureReason::NoAdminPerm,
                    None,
                ),
            )
            .await;
            return Err(denial.unwrap_or(AppError::Forbidden).into());
        }
        Err(e) => return Err(e.into()),
    };
    // 不变量护栏:挑选与 /admin 组闸(`Policy::require_admin_entry`)是同一准入口径,进来的 token 必然过组闸。
    // 万一两边漂移:撤掉刚建的会话,403,不发 token(不然后台每接口 403)。
    let entered = idm::AuthUser {
        id: outcome.user.id,
        username: outcome.user.username.clone(),
        roles: outcome.user.roles.clone(),
        tenant_id: outcome.tenant_id,
        tenant_roles: outcome.tenant_roles.clone(),
    };
    if let Err(e) = state.policy.require_admin_entry(&entered, &[]) {
        tracing::error!(user_id = %outcome.user.id, "后台登录挑出的上下文过不了后台组闸(准入口径漂移)");
        state.auth.logout(&outcome.refresh_token).await?;
        return Err(e.into());
    }
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::LoginSucceeded,
        outcome.user.id,
        success_data(
            &ctx,
            AuthChannel::Admin,
            outcome.user.id,
            Some(outcome.session_id),
            Some(&outcome.user.username),
            outcome.tenant_id,
        ),
    )
    .await;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user.into())))
}

#[utoipa::path(
    get, path = "/auth/me", tag = "admin",
    responses(
        (status = 200, body = UserResponse),
        (status = 401, body = ErrorBody),
        (status = 403, description = "组闸:无 admin:login(后台准入)", body = ErrorBody),
    )
)]
pub async fn admin_get_me(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<UserResponse>, ApiError> {
    let view = state.auth.me(user.0.id).await?;
    Ok(Json(view.into()))
}

//! auth 端点(app 拥有的 HTTP 边界)。认证用 **httponly cookie**:login/register 把 access/refresh
//! 写进 `Set-Cookie`,body 只返 `UserResponse`(token 不进响应体);鉴权由 `authenticate` 中间件读
//! cookie(Bearer 兜底)。业务逻辑全在 idm 库的 `AuthService` —— 这里只做校验 + cookie + DTO 翻译。
//!
//! 端点分三组挂载(public:register/login/refresh/logout;frontend:me*/logout-all;
//! admin:admin_login/admin_get_me),nginx 按 `/api/v1/{public,frontend,admin}/auth/` 三前缀分流。

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use garde::Validate;
use uuid::Uuid;

use super::emit::{emit_auth_event, failure_data, success_data};
use super::port::TenantDirectory;
use super::types::{
    ChangePasswordRequest, DeleteMeRequest, LoginRequest, MyTenantResponse, RegisterRequest,
    SetActiveTenantRequest, UpdateMeRequest, UserResponse,
};
use crate::app::state::AppState;
use crate::features::auth_audit::{AuthChannel, AuthEventType, FailureReason};
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, Tenant};
use crate::infra::client_context::ClientContext;
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::Json;

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
    audit: AuditContext,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, CookieJar, Json<UserResponse>), AppError> {
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
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
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
                failure_data(&ctx, AuthChannel::Public, None, Some(&identifier), reason),
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
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
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
) -> Result<(StatusCode, CookieJar), AppError> {
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
) -> Result<(StatusCode, CookieJar), AppError> {
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
) -> Result<Json<UserResponse>, AppError> {
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
    ctx: AuditContext,
    user: CurrentUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<UserResponse>, AppError> {
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
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn delete_me(
    State(state): State<AppState>,
    ctx: ClientContext,
    audit: AuditContext,
    user: CurrentUser,
    jar: CookieJar,
    Json(req): Json<DeleteMeRequest>,
) -> Result<(StatusCode, CookieJar), AppError> {
    req.validate()?;
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
) -> Result<(StatusCode, CookieJar), AppError> {
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
        ),
    )
    .await;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

// ── admin 组(后台)。login 在组闸外(public 语义,验密后自查);me 在闸内。 ──

#[utoipa::path(
    post, path = "/auth/login", tag = "admin",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "后台登录成功,token 写入 httponly cookie", body = UserResponse),
        (status = 401, description = "用户名/邮箱或密码错误(同码同文案,防枚举)", body = ErrorBody),
        (status = 403, description = "凭据正确但无后台准入(admin:login),不发 token 不设 cookie", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
pub async fn admin_login(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    req.validate()?;
    let identifier = req.identifier.clone();
    let outcome = match state.auth.login(req.into()).await {
        Ok(outcome) => outcome,
        // 凭据本身错(同 public login 的原因匹配);HTTP 仍统一 401,防枚举不变。
        Err(idm_err) => {
            let reason = match &idm_err {
                idm::IdmError::InvalidCredentials(f) => FailureReason::from(f),
                _ => return Err(idm_err.into()),
            };
            emit_auth_event(
                &state.idm_outbox,
                AuthEventType::LoginFailed,
                Uuid::nil(),
                failure_data(&ctx, AuthChannel::Admin, None, Some(&identifier), reason),
            )
            .await;
            return Err(idm_err.into());
        }
    };
    // 验密后闸:无 admin:login(后台准入)→ 403,**不发 token 不设 cookie**(不然后台每接口 403,体验差)。
    // login 已铸的 refresh 会话立即撤销,不留"验过密但没资格"的孤儿会话。
    if !state
        .policy
        .perms_for(&outcome.user.roles)
        .contains(&Perm::AdminLogin)
    {
        state.auth.logout(&outcome.refresh_token).await?;
        emit_auth_event(
            &state.idm_outbox,
            AuthEventType::AdminAccessDenied,
            outcome.user.id,
            failure_data(
                &ctx,
                AuthChannel::Admin,
                Some(outcome.user.id),
                Some(&identifier),
                FailureReason::NoAdminPerm,
            ),
        )
        .await;
        return Err(AppError::Forbidden);
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
) -> Result<Json<UserResponse>, AppError> {
    let view = state.auth.me(user.0.id).await?;
    Ok(Json(view.into()))
}

// ── 租户切换(spec §4.9)──
//
// ⚠️ **这两个端点必须挂 `/auth/` 前缀**,不是直觉上的 `/frontend/tenants`。
// `deploy/nginx.conf` 的 `^/api/v1/(public|frontend|admin)/auth/` 是唯一把请求分流进 idm
// 进程的规则 —— 只有那里读得到 `tenant_members`、也只有那里握着签名私钥。路由到 app 进程
// 则一签名就 panic(`NoopSigner`)。它们写在本文件而非新模块,是因为 `set_auth_cookies`
// 是模块私有 fn;而且切租户本就是认证域的动作(它改的是铸币的输入)。

/// 取本进程的租户目录。`Mount::App` 恒 `None`(见 `AppState::tenants` 的 doc)——
/// 但这两个端点只挂 needs_idm 组,走到这就是 wiring bug,故 500 而非静默空列表。
fn tenants_of(state: &AppState) -> Result<&std::sync::Arc<dyn TenantDirectory>, AppError> {
    state.tenants.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "租户端点挂到了没有 idm_pool 的进程上 —— 它们必须只挂 needs_idm 组(spec §2.3)"
        ))
    })
}

#[utoipa::path(
    get, path = "/auth/tenants", tag = "me",
    responses(
        (status = 200, description = "我的租户列表(按加入顺序)", body = Vec<MyTenantResponse>),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_my_tenants(
    State(state): State<AppState>,
    user: CurrentUser,
    // `Option<Tenant>` 而非裸 `Tenant`:**0 租户该返回空数组,不是 401**
    // (register 的常规出口,spec §1.1 —— 前端据此渲染「你还没有租户」)。
    tenant: Option<Tenant>,
) -> Result<Json<Vec<MyTenantResponse>>, AppError> {
    // 端口契约:已过滤停用/软删租户、按加入顺序。
    let items = tenants_of(&state)?.memberships_of(user.0.id).await?;

    // `is_active` **以 claim 为准** —— 只有它知道本会话实际落在哪个租户
    // (可能来自「没显式选过 → 取第一个」的回退)。见 `MyTenantResponse::with_active`。
    let active = tenant.map(|t| t.0.get());
    Ok(Json(
        items
            .into_iter()
            .map(|t| MyTenantResponse::with_active(t, active))
            .collect(),
    ))
}

#[utoipa::path(
    put, path = "/auth/active-tenant", tag = "me",
    request_body = SetActiveTenantRequest,
    responses(
        (status = 200, description = "切换成功,**新 token 已写入 cookie**", body = UserResponse),
        (status = 401, description = "未登录 / refresh cookie 无效", body = ErrorBody),
        (status = 404, description = "非本人成员(**不是 403** —— 不泄露该租户是否存在)", body = ErrorBody),
    )
)]
pub async fn put_active_tenant(
    State(state): State<AppState>,
    ctx: ClientContext,
    user: CurrentUser,
    // 审计的 `from_tenant` 用它。`Option`:0 租户的用户也能切(被邀请后的第一次),此时确实没有「从」。
    from: Option<Tenant>,
    jar: CookieJar,
    Json(req): Json<SetActiveTenantRequest>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    req.validate()?;
    let tenants = tenants_of(&state)?;

    // ── 1. **副作用前置检查**:refresh cookie 必须在 set_active **之前**取。 ──
    // 反了的话会出现「active 已改、token 没换」的不一致:用户下次刷新才切过去,
    // 而本次响应还是旧租户 —— 一个没人能解释的中间态。
    let refresh = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or(AppError::Unauthorized)?;

    // ── 2. **两枚凭证必须是同一个人**。 ──
    // 本 handler 是全仓唯一同时吃 access token(`CurrentUser`)与 refresh cookie 的地方,
    // 而这两者**不保证同源**:`authenticate` 接受 cookie **或** `Authorization: Bearer`
    // (middleware.rs),而 `refresh()` 只按 refresh 的哈希认人 —— 它根本看不到 `user.0.id`。
    // 不核对的话,`Bearer <A 的 access>` + `Cookie: refresh_token=<B 的>` 会:按 A 校验成员
    // 资格、**改 A 的 active_tenant**、按 B 铸新会话、把这笔账记在 B 头上而 from_tenant 取自
    // A 的 claim。四件事,四个主体错位。
    //
    // 必须用 `session_owner`(只读)而不是「先 refresh 再比对」—— 后者要先把 A 的
    // active_tenant 改掉才发现不对,检查来得太晚。
    if state.auth.session_owner(&refresh).await? != Some(user.0.id) {
        return Err(AppError::Unauthorized);
    }

    // ── 3. 安全支点:成员资格校验。 ──
    // **客户端说的 tenant 只是一个「请求」,不是断言** —— 它只到达签发方(本进程)且必须
    // 过这一关;资源 API 永远只读已签名的 claim,绝不从 header/query/body 读 active tenant。
    // 非成员 → 404(不是 403):403 等于承认「这个租户存在,只是你不在里面」。
    // `memberships_of` 同样过滤停用/软删租户,所以「租户被停用」与「你不是成员」对外同为 404。
    if !tenants
        .memberships_of(user.0.id)
        .await?
        .iter()
        .any(|t| t.id == req.tenant_id)
    {
        return Err(AppError::NotFound);
    }

    // ── 4. 改状态。 ──
    // 租户选择必须状态化:idm 的 `roles_for_user` 只收 user_id,收不到「哪个租户」,
    // per-request 的选择不可能在 idm 内部发生(spec §4.1)。
    tenants.set_active(user.0.id, req.tenant_id).await?;

    // ── 5. 重新铸币 —— 这是 idm 唯一公开的「重新发 token」API(issue_session 是私有的)。 ──
    // refresh() 会:撤旧 session → 建新 session(**新 jti**)→ 重问一遍 TenantClaimsExtender
    // (此时读到的 active 已是新租户)→ 重签 access(带新 tenant claim)+ 新 refresh。
    // 失败(refresh 过期)→ 401 → 前端重新登录;但 active 已改,重登即落新租户(状态化的意外好处)。
    let outcome = state.auth.refresh(&refresh).await?;

    // ⚠️ **必须用 `success_data` 组 payload,别手搓 json!** —— 投影器的 `AuthEventData`
    // 要求 `occurred_at` / `channel` / `outcome` 等字段,缺一个就整条被当**毒消息 ack 丢弃**
    // (`projector 跳过不可投的毒消息`),事件进得了 outbox 却永远进不了 `auth_events` 读模型
    // ⇒ 后台审计界面看不到它,而且**没有任何测试会红**。这是本仓所有 auth 事件的统一口径。
    // channel 用 Public:与同在 `/frontend/auth/` 下的 `logout_all` 一致(闭集只有 Public/Admin)。
    let mut data = success_data(
        &ctx,
        AuthChannel::Public,
        outcome.user.id,
        Some(outcome.session_id),
        Some(&outcome.user.username),
    );
    // 租户专属字段合并进 payload。
    //
    // ⚠️ **`from_tenant` 取 claim(`Option<Tenant>`),不查 `Membership::is_active`** —— 同
    // `list_my_tenants` 的口径,理由也同:`user_active_tenant` 里显式设过的那个 ≠ 本会话实际
    // 生效的那个(后者可能来自 `.or(ms.first())` 回退)。从没切过的用户 —— **每个人的初始
    // 状态** —— 查库会得到 null,于是审计记成「从 null 切到 Globex」,而真相是「从 Acme 切到
    // Globex」。这条事件的全部价值就是 from→to,记错等于没记。顺带省掉一次库往返。
    // 真 null 只剩一种:0 租户的用户被邀请后第一次切进来 —— 那时确实没有「从」。
    //
    // ponytail: **这两个字段目前只到 outbox,进不了 `auth_event` 读模型** —— 后者是固定 schema
    // (无 raw/JSON 列),投影器只映射它认识的列,额外字段静默丢弃。⇒ 后台审计现在只看得到
    // 「某人在某时切了租户」,看不到「从哪切到哪」,而那正是这个事件的价值所在。
    // 补法有先例:`identifier_attempted`/`failure_reason` 就是事件类型专属列(对其他事件恒 NULL)——
    // 照它加 `from_tenant`/`to_tenant` 两列,要动 8 个文件(migration + projector + 两个 repo +
    // types + API DTO + 测试)。见 spec §4.9 的收尾项。
    if let Some(obj) = data.as_object_mut() {
        obj.insert(
            "from_tenant".into(),
            serde_json::json!(from.map(|t| t.0.get())),
        );
        obj.insert("to_tenant".into(), serde_json::json!(req.tenant_id));
    }
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::TenantSwitched,
        outcome.user.id,
        data,
    )
    .await;

    // ── 6. **refresh cookie 必须整条轮换** ——旧 refresh 一次性、已被 idm 撤销,
    //    前端留着下次必 401。 ──
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user.into())))
}

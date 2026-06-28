//! idm 端点。认证用 **httponly cookie**:login/register 把 access/refresh 写进 `Set-Cookie`,
//! body 只返 `UserResponse`(token 不进响应体);鉴权由中间件读 cookie(Bearer 兜底)。
//!
//! 端点都在 `/auth` 前缀下:register/login/refresh/logout/logout-all + me GET/PATCH/DELETE/改密。
//! nest /api/v1 后即 /api/v1/auth/*,nginx 按此前缀分流到独立的 idm 进程。

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::audit::{AuditContext, CurrentUser};
use crate::error::{ErrorBody, IdmError};
use crate::extract::Json;
use crate::state::IdmState;

use super::types::{
    ChangePasswordRequest, DeleteMeRequest, LoginRequest, RegisterRequest, UpdateMeRequest,
    UserResponse,
};
use super::AuthOutcome;

const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";

/// idm 的端点 + OpenAPI(`OpenApiRouter<S>`)。端点 path 已是 /api/v1/auth/*。
/// 泛型 over 宿主 state `S`:idm 独立跑 / 测试用 `IdmState`,app 集成用 `AppState` —— 只需
/// `IdmState: FromRef<S>`(app 从自己的 state 派生 IdmState、**共享同一个 AuthService 实例**)。
/// app `build_router` 直接 `.merge(idm::router::<AppState>())`,idm bin/测试用 `::<IdmState>()`。
pub fn router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IdmState: axum::extract::FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(register))
        .routes(routes!(login))
        .routes(routes!(refresh))
        .routes(routes!(logout))
        .routes(routes!(logout_all))
        .routes(routes!(get_me))
        .routes(routes!(update_me))
        .routes(routes!(delete_me))
        .routes(routes!(change_password))
}

/// idm 独立服务的完整 axum `Router`(端点 + best-effort 鉴权中间件 + 注入 state)。
/// 给 idm 分进程部署 与 oneshot 契约测试用;app 集成时**不用**这个(用泛型 `router::<AppState>()` merge)。
pub fn app(state: IdmState) -> axum::Router {
    let (router, _api) = OpenApiRouter::<IdmState>::new()
        .routes(routes!(register))
        .routes(routes!(login))
        .routes(routes!(refresh))
        .routes(routes!(logout))
        .routes(routes!(logout_all))
        .routes(routes!(get_me))
        .routes(routes!(update_me))
        .routes(routes!(delete_me))
        .routes(routes!(change_password))
        .split_for_parts();
    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::authenticate::<IdmState>,
        ))
        .with_state(state)
}

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
fn set_auth_cookies(jar: CookieJar, outcome: &AuthOutcome, secure: bool) -> CookieJar {
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
    post, path = "/api/v1/auth/register", tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "注册成功,token 写入 httponly cookie", body = UserResponse),
        (status = 409, description = "用户名或邮箱已占用", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
async fn register(
    State(state): State<IdmState>,
    jar: CookieJar,
    ctx: AuditContext,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, CookieJar, Json<UserResponse>), IdmError> {
    let outcome = state.auth.register(req, &ctx).await?;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((StatusCode::CREATED, jar, Json(outcome.user)))
}

#[utoipa::path(
    post, path = "/api/v1/auth/login", tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登录成功,token 写入 httponly cookie", body = UserResponse),
        (status = 401, description = "用户名/邮箱或密码错误(同码同文案,防枚举)", body = ErrorBody),
    )
)]
async fn login(
    State(state): State<IdmState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), IdmError> {
    let outcome = state.auth.login(req).await?;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user)))
}

#[utoipa::path(
    post, path = "/api/v1/auth/refresh", tag = "auth",
    responses(
        (status = 200, description = "刷新成功,新 token 写入 cookie", body = UserResponse),
        (status = 401, description = "refresh cookie 无效/过期/已撤销", body = ErrorBody),
    )
)]
async fn refresh(
    State(state): State<IdmState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<UserResponse>), IdmError> {
    let refresh = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or(IdmError::Unauthorized)?;
    let outcome = state.auth.refresh(&refresh).await?;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user)))
}

#[utoipa::path(
    post, path = "/api/v1/auth/logout", tag = "auth",
    responses((status = 204, description = "已登出,清除 cookie(幂等)"))
)]
async fn logout(
    State(state): State<IdmState>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), IdmError> {
    // 撤销服务端 session(若 cookie 带了 refresh)+ 清 cookie。幂等。
    if let Some(c) = jar.get(REFRESH_COOKIE) {
        state.auth.logout(c.value()).await?;
    }
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    post, path = "/api/v1/auth/logout-all", tag = "auth",
    responses((status = 204, description = "已撤销所有会话"), (status = 401, body = ErrorBody))
)]
async fn logout_all(
    State(state): State<IdmState>,
    jar: CookieJar,
    user: CurrentUser,
) -> Result<(StatusCode, CookieJar), IdmError> {
    state.auth.logout_all(user.0.id).await?;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    get, path = "/api/v1/auth/me", tag = "me",
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody))
)]
async fn get_me(
    State(state): State<IdmState>,
    user: CurrentUser,
) -> Result<Json<UserResponse>, IdmError> {
    let resp = state.auth.me(user.0.id).await?;
    Ok(Json(resp))
}

#[utoipa::path(
    put, path = "/api/v1/auth/me", tag = "me",
    request_body = UpdateMeRequest,
    responses(
        (status = 200, body = UserResponse),
        (status = 409, description = "新用户名/邮箱已占用", body = ErrorBody),
        (status = 401, body = ErrorBody),
    )
)]
async fn update_me(
    State(state): State<IdmState>,
    ctx: AuditContext,
    user: CurrentUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<UserResponse>, IdmError> {
    let resp = state.auth.update_me(user.0.id, req, &ctx).await?;
    Ok(Json(resp))
}

#[utoipa::path(
    delete, path = "/api/v1/auth/me", tag = "me",
    request_body = DeleteMeRequest,
    responses(
        (status = 204, description = "已注销"),
        (status = 401, description = "密码错", body = ErrorBody),
    )
)]
async fn delete_me(
    State(state): State<IdmState>,
    ctx: AuditContext,
    user: CurrentUser,
    jar: CookieJar,
    Json(req): Json<DeleteMeRequest>,
) -> Result<(StatusCode, CookieJar), IdmError> {
    state.auth.delete_me(user.0.id, req, ctx.audit_id()).await?;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

#[utoipa::path(
    post, path = "/api/v1/auth/me/password", tag = "me",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "已改密,撤销其它会话"),
        (status = 401, description = "旧密码错", body = ErrorBody),
    )
)]
async fn change_password(
    State(state): State<IdmState>,
    user: CurrentUser,
    jar: CookieJar,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<(StatusCode, CookieJar), IdmError> {
    state.auth.change_password(user.0.id, req).await?;
    Ok((StatusCode::NO_CONTENT, clear_auth_cookies(jar)))
}

//! idm 端点。认证用 **httponly cookie**:login/register 把 access/refresh 写进 `Set-Cookie`,
//! body 只返 `UserResponse`(token 不进响应体);鉴权由中间件读 cookie(Bearer 兜底)。
//!
//! 已实现:register/login(发 cookie)、logout(清 cookie)、me(取当前用户)。
//! 仍 stub(逻辑待后续块):refresh、logout-all、update/delete me、改密。

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::Json;

use super::types::{
    ChangePasswordRequest, DeleteMeRequest, LoginRequest, RegisterRequest, UpdateMeRequest,
    UserResponse,
};
use super::AuthOutcome;

const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";

pub fn router() -> OpenApiRouter<AppState> {
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

/// 待实现占位:契约已定,逻辑留待后续块填充。
fn not_impl(what: &str) -> AppError {
    AppError::Internal(anyhow::anyhow!("idm {what} 未实现"))
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
    post, path = "/auth/register", tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "注册成功,token 写入 httponly cookie", body = UserResponse),
        (status = 409, description = "用户名或邮箱已占用", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody),
    )
)]
async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    ctx: AuditContext,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, CookieJar, Json<UserResponse>), AppError> {
    let outcome = state.auth.register(req, &ctx).await?;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((StatusCode::CREATED, jar, Json(outcome.user)))
}

#[utoipa::path(
    post, path = "/auth/login", tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登录成功,token 写入 httponly cookie", body = UserResponse),
        (status = 401, description = "用户名/邮箱或密码错误(同码同文案,防枚举)", body = ErrorBody),
    )
)]
async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    let outcome = state.auth.login(req).await?;
    let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
    Ok((jar, Json(outcome.user)))
}

#[utoipa::path(
    post, path = "/auth/refresh", tag = "auth",
    responses(
        (status = 200, description = "刷新成功,新 token 写入 cookie"),
        (status = 401, description = "refresh cookie 无效/过期/已撤销", body = ErrorBody),
    )
)]
async fn refresh(_jar: CookieJar) -> Result<StatusCode, AppError> {
    Err(not_impl("refresh"))
}

#[utoipa::path(
    post, path = "/auth/logout", tag = "auth",
    responses((status = 204, description = "已登出,清除 cookie(幂等)"))
)]
async fn logout(jar: CookieJar) -> (StatusCode, CookieJar) {
    // 清 cookie(前端登出)。撤销服务端 session 留待 refresh/logout 逻辑块。
    (StatusCode::NO_CONTENT, clear_auth_cookies(jar))
}

#[utoipa::path(
    post, path = "/auth/logout-all", tag = "auth",
    responses((status = 204), (status = 401, body = ErrorBody))
)]
async fn logout_all() -> Result<StatusCode, AppError> {
    Err(not_impl("logout-all"))
}

#[utoipa::path(
    get, path = "/me", tag = "me",
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorBody))
)]
async fn get_me(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<UserResponse>, AppError> {
    let resp = state.auth.me(user.0.id).await?;
    Ok(Json(resp))
}

#[utoipa::path(
    patch, path = "/me", tag = "me",
    request_body = UpdateMeRequest,
    responses(
        (status = 200, body = UserResponse),
        (status = 409, description = "新用户名/邮箱已占用", body = ErrorBody),
        (status = 401, body = ErrorBody),
    )
)]
async fn update_me(Json(req): Json<UpdateMeRequest>) -> Result<Json<UserResponse>, AppError> {
    let _ = req;
    Err(not_impl("update_me"))
}

#[utoipa::path(
    delete, path = "/me", tag = "me",
    request_body = DeleteMeRequest,
    responses(
        (status = 204, description = "已注销"),
        (status = 401, description = "密码错", body = ErrorBody),
    )
)]
async fn delete_me(Json(req): Json<DeleteMeRequest>) -> Result<StatusCode, AppError> {
    let _ = req;
    Err(not_impl("delete_me"))
}

#[utoipa::path(
    post, path = "/me/password", tag = "me",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "已改密,撤销其它会话"),
        (status = 401, description = "旧密码错", body = ErrorBody),
    )
)]
async fn change_password(Json(req): Json<ChangePasswordRequest>) -> Result<StatusCode, AppError> {
    let _ = req;
    Err(not_impl("change_password"))
}

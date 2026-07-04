//! profile HTTP 边界(薄)。三轴:CurrentUser(401)→ require_scoped(403)→ ownership。
//! GET 无 ownership(任意登录可读);PUT 的 ownership 用 `data_access(ProfileWriteAll)`:
//! 越权失败给 **403 而非 404** —— profile 本就任意可读,存在性不敏感,藏 404 无意义
//! (对比 widget GET 的 404:那里 ownership 是可见性,这里只是写权)。

use axum::extract::State;
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{ProfileResponse, PutProfileRequest};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path};

/// 读任意用户的资料(需 `profiles:read`;所有登录角色都有)。
/// 注意:响应含 phone 等 PII,"任意登录可读"是脚手架的刻意选择——收紧时给 GET 加 ownership 或拆敏感字段视图。
#[utoipa::path(
    get,
    path = "/profiles/{user_id}",
    tag = "profiles",
    params(("user_id" = Uuid, Path, description = "idm user id(1:1)")),
    responses(
        (status = 200, description = "资料(avatar_url 为相对 preview 路径;悬空/未就绪 → null)", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 profiles:read 权限", body = ErrorBody),
        (status = 404, description = "该用户尚未建资料", body = ErrorBody)
    )
)]
pub async fn get_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ProfileResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ProfileRead)?;
    Ok(Json(state.profiles.get(user_id).await?))
}

/// 全量替换 upsert 自己的资料(`profiles:write`);带 `profiles:write:all` 可替任何人。
/// 未建 → 201,已有 → 200(PUT 即建即替,RFC 7231 本义;profile 无独立 POST)。
#[utoipa::path(
    put,
    path = "/profiles/{user_id}",
    tag = "profiles",
    params(("user_id" = Uuid, Path, description = "idm user id(1:1)")),
    request_body = PutProfileRequest,
    responses(
        (status = 200, description = "已替换", body = ProfileResponse),
        (status = 201, description = "首次建立", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 profiles:write / 改别人无 write:all", body = ErrorBody),
        (status = 422, description = "校验失败(超长 / 头像不存在 / 未 confirm / 非 image)", body = ErrorBody)
    )
)]
pub async fn put_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(user_id): Path<Uuid>,
    Json(input): Json<PutProfileRequest>,
) -> Result<(StatusCode, Json<ProfileResponse>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ProfileWrite)?;
    // ownership:path 即资源 owner(user_id 主键),无需查行 —— 越权直接 403。
    if !state
        .policy
        .data_access(&user.0, &scope.0, Perm::ProfileWriteAll)
        .allows(user_id)
    {
        return Err(AppError::Forbidden);
    }
    let (created, resp) = state.profiles.put(user_id, input, &ctx).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(resp)))
}

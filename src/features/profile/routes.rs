//! profile HTTP 边界(薄)。三轴:CurrentUser(401)→ require_scoped(403)→ ownership。
//! GET 无 ownership(任意登录可读);PUT 的 ownership 用 `data_access(ProfileWriteAll)`:
//! 越权失败给 **403 而非 404** —— profile 本就任意可读,存在性不敏感,藏 404 无意义
//! (对比 widget GET 的 404:那里 ownership 是可见性,这里只是写权)。

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use uuid::Uuid;

use super::types::{AvatarForm, ProfileResponse, PutProfileRequest};
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

/// 读**请求者自己**的资料(仅登录,零 perm —— "自己"是身份事实不是授权决策,
/// 对齐 `get_me`/`my_widget_count` 的自我操作范式;`profiles:read` 留给"读任意人")。
/// 静态段 `/profiles/me` 与参数段 `/profiles/{user_id}` 共存,axum 静态优先。
#[utoipa::path(
    get,
    path = "/profiles/me",
    tag = "profiles",
    responses(
        (status = 200, description = "自己的资料(avatar_url 为相对 preview 路径)", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 404, description = "尚未建资料(前端以此引导建资料)", body = ErrorBody)
    )
)]
pub async fn get_my_profile(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<ProfileResponse>, AppError> {
    Ok(Json(state.profiles.get(user.0.id).await?))
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

// ── 后台资料管理(admin 组,路径仍在 /users/{id} 下、归 users:admin 授权面;
//    handler 归 profile 模块:只编排 state.profiles/state.contents,与 users 模块零耦合)──

use content::UploadContentInput;

/// 后台读某用户资料(display_name/phone/avatar)。归 `users:admin`。资料未建 → 404。
#[utoipa::path(
    get,
    path = "/users/{id}/profile",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    responses(
        (status = 200, description = "用户资料", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 404, description = "资料未建", body = ErrorBody)
    )
)]
pub async fn get_user_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ProfileResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(state.profiles.get(id).await?))
}

/// 后台改某用户资料(PUT 全量:display_name/phone/avatar_content_id)。归 `users:admin`。
#[utoipa::path(
    put,
    path = "/users/{id}/profile",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    request_body = PutProfileRequest,
    responses(
        (status = 200, description = "已更新", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 422, description = "校验失败 / 头像非法", body = ErrorBody)
    )
)]
pub async fn set_user_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(input): Json<PutProfileRequest>,
) -> Result<Json<ProfileResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let (_created, resp) = state.profiles.put(id, input, &ctx).await?;
    Ok(Json(resp))
}

/// 后台传某用户头像(multipart 表单,`file` 部分为图片)。上传即绑定(auto-bind):
/// content owner = 目标用户,保留现有 display_name/phone,返回更新后的资料。归 `users:admin`。
#[utoipa::path(
    post,
    path = "/users/{id}/avatar",
    tag = "users",
    params(("id" = Uuid, Path, description = "user id")),
    request_body(content = inline(AvatarForm), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "头像已更新并绑定", body = ProfileResponse),
        (status = 400, description = "multipart 解析失败", body = ErrorBody),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 users:admin 权限", body = ErrorBody),
        (status = 422, description = "缺 file 部分 / 非 image", body = ErrorBody)
    )
)]
pub async fn set_user_avatar(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<ProfileResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;

    let mut data = None;
    let mut file_name = None;
    let mut mime_type = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().map(str::to_owned);
            mime_type = field.content_type().map(str::to_owned);
            data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(e.to_string()))?,
            );
        } else {
            let _ = field.bytes().await;
        }
    }
    let data = data.ok_or_else(|| AppError::Validation("missing `file` part".into()))?;

    // content 归目标用户(是他的头像);单租户 tenant=nil。
    let input = UploadContentInput {
        tenant_id: Uuid::nil(),
        owner_id: id,
        owner_type: None,
        name: None,
        description: None,
        document_type: None,
        object_key: None,
        file_name,
        mime_type,
        tags: Vec::new(),
        custom_metadata: None,
        data,
    };
    let outcome = state.contents.upload_content(input, ctx.audit_id()).await?;
    let content_id = outcome.content.id;

    // auto-bind:保留现有 display_name/phone(无资料行 → None),换上新头像。
    let (display_name, phone) = match state.profiles.get(id).await {
        Ok(p) => (p.display_name, p.phone),
        Err(AppError::NotFound) => (None, None),
        Err(e) => return Err(e),
    };
    let (_created, resp) = state
        .profiles
        .put(
            id,
            PutProfileRequest {
                avatar_content_id: Some(content_id),
                display_name,
                phone,
            },
            &ctx,
        )
        .await?;
    Ok(Json(resp))
}

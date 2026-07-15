//! profile HTTP 边界(薄)。三轴:CurrentUser(401)→ require_scoped(403)→ ownership。
//! GET 无 ownership(任意登录可读);PUT 的 ownership 用 `data_access(ProfileWriteAll)`:
//! 越权失败给 **403 而非 404** —— profile 本就任意可读,存在性不敏感,藏 404 无意义
//! (对比 widget GET 的 404:那里 ownership 是可见性,这里只是写权)。

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use uuid::Uuid;

use super::types::{AvatarForm, ProfileResponse, PutProfileRequest};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Multipart, Path};

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
        (status = 422, description = "校验失败(超长 / 头像不存在或非本人 / 未 confirm / 非 image)", body = ErrorBody)
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

/// 用户头像展示端点(**跨用户可见**:任意登录用户都能看别人的头像 —— 头像是 profile 刻意暴露
/// 的单张公开图,与"content 本体严格按 owner 隔离"分开)。读该用户的 avatar_content_id → 出字节。
/// 无资料 / 未绑定头像 / 头像 content 已删或未就绪 → 404。
/// **只服务被指定为头像的那个 content**(且 put 已校验 owner==本人、image/*),故不重开
/// `contents/{id}/preview` 那种"任意 image 越权读"的面。仅需登录(头像非敏感展示数据,不额外要 contents:read)。
#[utoipa::path(
    get,
    path = "/profiles/{user_id}/avatar",
    tag = "profiles",
    params(("user_id" = Uuid, Path, description = "idm user id(1:1)")),
    responses(
        (status = 307, description = "跳转到短时效签名 URL(presign 后端)"),
        (status = 200, description = "inline 图片字节(代理回退)", content_type = "application/octet-stream"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 404, description = "无资料 / 未绑定头像 / 头像不可用", body = ErrorBody)
    )
)]
pub async fn get_user_avatar(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let cid = state
        .profiles
        .avatar_content_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // **出字节前再验栅格**(纵深,不只信绑定时那次):presign 分支 307 直连存储,浏览器拿到的
    // Content-Type 是对象上传时存进 S3 的那个、且 app 加不了 CSP —— 非栅格从这里出去 = 存储型 XSS,
    // 且本端点任何登录用户跨用户可达。mime 现已不可改(见 SetContentMetadataRequest),故它与 S3
    // 那份恒一致;这层兜住"绑定早于该约束的历史数据"。不可用 → 404(同本端点其余不可用分支)。
    if !state
        .contents
        .get_content_metadata(cid)
        .await
        .ok()
        .and_then(|m| m.mime_type)
        .as_deref()
        .is_some_and(super::service::is_allowed_avatar_mime)
    {
        return Err(AppError::NotFound);
    }
    // 出字节:presign 后端 → 307 到签名 URL;内存 backend → 代理 inline。刻意重复
    // content::preview_content 的服务段(去掉 owner 闸 —— 本端点契约就是"这个用户的公开头像"),
    // 而非跨 feature 复用其 handler(维持业务模块彼此零 import,胶水只在组合根)。
    if let Some(url) = state.contents.preview_url(cid).await? {
        // 307 默认不可缓存(RFC 9110);no-store 防错配 CDN/代理缓存 5min 签名 URL。
        let mut resp = Redirect::temporary(&url).into_response();
        resp.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(resp);
    }
    let p = state.contents.preview_content(cid).await?;
    let mime = p
        .metadata
        .as_ref()
        .and_then(|m| m.mime_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_DISPOSITION, "inline")
        // CSP sandbox 全禁脚本/表单/同源访问,栅格图照常渲染。纵深防御:上传已限栅格白名单
        // (service::is_allowed_avatar_mime 排除 SVG),此 header 再兜一层(代理分支专有;presign
        // 分支直连存储、加不了 CSP —— 故防线必须在上传白名单,不能靠出字节时补)。
        .header("content-security-policy", "sandbox")
        .body(Body::from(p.data))
        .map_err(|e| AppError::Internal(e.into()))
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
    Multipart(mut multipart): Multipart,
) -> Result<Json<ProfileResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;

    let file = crate::infra::extract::file_part(&mut multipart)
        .await?
        .ok_or_else(|| AppError::Validation("missing `file` part".into()))?;
    // 先校验后写(transactions skill):非白名单 mime 就不该产生任何持久化副作用 ——
    // 否则 put 的三查 422 时,已落库的 content(owner=目标用户)成孤儿且无清理路径。
    // 栅格白名单(排除 SVG 活动内容),口径收口在 service::is_allowed_avatar_mime。
    if !file
        .mime_type
        .as_deref()
        .is_some_and(super::service::is_allowed_avatar_mime)
    {
        return Err(AppError::Validation(
            "avatar must be a raster image (png/jpeg/gif/webp)".into(),
        ));
    }

    // content 归目标用户(是他的头像);单租户 tenant=nil。
    let input = UploadContentInput {
        tenant_id: Uuid::nil(),
        owner_id: id,
        owner_type: None,
        name: None,
        description: None,
        document_type: None,
        object_key: None,
        file_name: file.file_name,
        mime_type: file.mime_type,
        tags: Vec::new(),
        custom_metadata: None,
        data: file.data,
    };
    let outcome = state.contents.upload_content(input, ctx.audit_id()).await?;
    let content_id = outcome.content.id;

    // auto-bind:保留现有 display_name/phone(无资料行 → None),换上新头像。
    // content(app.contents)与 profile(app.profiles)跨表写,不共享一个事务:绑定任一步
    // 失败(get/put 报错)则 best-effort 软删刚上传的 content(owner=目标用户、尚无引用),
    // 避免留下无法回收的孤儿行/对象字节。清理失败只 warn,不掩盖原始错误。
    let bind: Result<(bool, ProfileResponse), AppError> = async {
        let (display_name, phone) = match state.profiles.get(id).await {
            Ok(p) => (p.display_name, p.phone),
            Err(AppError::NotFound) => (None, None),
            Err(e) => return Err(e),
        };
        state
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
            .await
    }
    .await;
    let (_created, resp) = match bind {
        Ok(r) => r,
        Err(e) => {
            if let Err(cleanup) = state
                .contents
                .delete_content(content_id, ctx.audit_id())
                .await
            {
                tracing::warn!(error = %cleanup, %content_id, "头像绑定失败后清理孤儿 content 失败(软删)");
            }
            return Err(e);
        }
    };
    Ok(Json(resp))
}

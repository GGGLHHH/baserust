//! profile 的 **HTTP 适配器**(薄)。线格式 ↔ 领域互转见 `dto`。三轴:CurrentUser(401)→ require_scoped(403)→ ownership。
//!
//! **资料全局一份**(spec §6.2,不分租户):
//! - 本人读 / 改自己的资料、传自己的头像走 `/profiles/me`、`/profiles/me/avatar` —— **仅登录**(零 perm,
//!   "自己"是身份事实不是授权决策;也不要当前租户)。
//! - 按 id 读 / 改任意人的资料用 `profiles:*`,它们是**平台级**权限(只有平台管理员有):租户管理员不能改
//!   所有人的全局资料,租户成员也读不到别的租户的人的资料(含 phone)。PUT 的 ownership 用
//!   `data_access(ProfileWriteAll)`,越权给 **403 而非 404**(持 `profiles:read` 的人本就可读,存在性不敏感)。
//!   **按 id 改别人**另要 `platform:roles`(只有 superadmin):这个端点在 app 进程,app 里的 idm 仓储是内存占位,
//!   查不到目标的平台角色,没法像后台那样按目标判防接管闸 —— 只好一律收紧。平台管理员改普通账号的资料走后台
//!   `PUT /admin/auth/users/{id}/profile`(idm 进程,有 `guard_platform_account`)。
//!
//! **头像是个人内容**(`ContentScope::Personal`,spec §4.4):不属于任何租户,只有本人(或后台 `users:admin`)
//! 能上传 / 替换;头像端点对所有已登录用户可读、跨租户可见。租户作用域的内容不能当头像(绑定 422)。

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use uuid::Uuid;

use super::dto::{AvatarForm, ProfileResponse, PutProfileRequest};
use crate::app::state::AppState;
use crate::features::profile::model::{self, is_allowed_avatar_mime};
use crate::infra::authz::TokenScope;
use crate::infra::http::audit::{Audit, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Multipart, Path};
use crate::kernel::authz::Perm;
use crate::kernel::error::AppError;

/// 按 id 读任意用户的资料(需 `profiles:read`,**平台级**:只有平台管理员有)。
/// 响应含 phone 等 PII,且资料跨租户全局一份 —— 所以不给租户成员;本人读自己走 `/profiles/me`。
#[utoipa::path(
    get,
    path = "/profiles/{user_id}",
    tag = "profiles",
    params(("user_id" = Uuid, Path, description = "idm user id(1:1)")),
    responses(
        (status = 200, description = "资料(avatar_url 为相对 preview 路径;悬空/未就绪 → null)", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 profiles:read 权限(平台级)", body = ErrorBody),
        (status = 404, description = "该用户尚未建资料", body = ErrorBody)
    )
)]
pub async fn get_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ProfileResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ProfileRead)?;
    Ok(Json(state.profiles.get(user_id).await?.into()))
}

/// 读**请求者自己**的资料(仅登录,零 perm —— "自己"是身份事实不是授权决策,
/// 对齐 `get_me`/`my_widget_count` 的自我操作范式;`profiles:read` 留给"读任意人")。
/// 静态段 `/profiles/me` 与参数段 `/profiles/{user_id}` 共存,axum 静态优先。
///
/// **不 404**:未建资料 → 200 + 空资料(时间戳 null),前端照常渲染空表单、保存即 PUT 建行。
/// 与按 id 读(`get_profile`)刻意不同,理由见 `ProfileService::get_or_empty`。
#[utoipa::path(
    get,
    path = "/profiles/me",
    tag = "profiles",
    responses(
        (status = 200, description = "自己的资料;尚未建则各段为 null(user_id 仍是本人,前端据此 PUT 建资料)", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody)
    )
)]
pub async fn get_my_profile(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<ProfileResponse>, ApiError> {
    Ok(Json(state.profiles.get_or_empty(user.0.id).await?.into()))
}

/// 按 id 全量替换 upsert 资料(`profiles:write`,**平台级**);改别人还要 `profiles:write:all` **和** `platform:roles`
/// (只有 superadmin —— 防平台管理员改 superadmin 的资料;平台管理员改普通账号走后台 `PUT /admin/auth/users/{id}/profile`)。
/// 未建 → 201,已有 → 200(PUT 即建即替,RFC 7231 本义;profile 无独立 POST)。本人改自己走 `PUT /profiles/me`。
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
        (status = 403, description = "无 profiles:write / 改别人缺 profiles:write:all 或 platform:roles(平台级;平台管理员改别人走后台资料接口)", body = ErrorBody),
        (status = 422, description = "校验失败(超长 / 头像不是目标本人的个人内容 / 未 confirm / 非栅格图)", body = ErrorBody)
    )
)]
pub async fn put_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(user_id): Path<Uuid>,
    Json(input): Json<PutProfileRequest>,
) -> Result<(StatusCode, Json<ProfileResponse>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ProfileWrite)?;
    // ownership:path 即资源 owner(user_id 主键),无需查行 —— 越权直接 403。
    if !state
        .policy
        .data_access(&user.0, &scope.0, Perm::ProfileWriteAll)
        .allows(user_id)
    {
        return Err(AppError::Forbidden.into());
    }
    // 防接管:改别人的资料另要 platform:roles(只有 superadmin)。不按目标的平台角色判(后台那套
    // guard_platform_account):本端点归 app 进程,app 里的 idm 仓储是内存占位,查不到目标 → 闸会放行。
    if user_id != user.0.id {
        state
            .policy
            .require_scoped(&user.0, &scope.0, Perm::PlatformRoles)?;
    }
    let (created, view) = state.profiles.put(user_id, input.into(), &ctx).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(view.into())))
}

/// 全量替换 upsert **自己**的资料(仅登录,零 perm;不要当前租户 —— 资料全局一份)。
/// 未建 → 201,已有 → 200。头像只能绑本人的个人内容(`POST /profiles/me/avatar` 传的那种)。
#[utoipa::path(
    put,
    path = "/profiles/me",
    tag = "profiles",
    request_body = PutProfileRequest,
    responses(
        (status = 200, description = "已替换", body = ProfileResponse),
        (status = 201, description = "首次建立", body = ProfileResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 422, description = "校验失败(超长 / 头像不是本人的个人内容 / 未 confirm / 非栅格图)", body = ErrorBody)
    )
)]
pub async fn put_my_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    Audit(ctx): Audit,
    Json(input): Json<PutProfileRequest>,
) -> Result<(StatusCode, Json<ProfileResponse>), ApiError> {
    let (created, view) = state.profiles.put(user.0.id, input.into(), &ctx).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(view.into())))
}

/// 传**自己**的头像(multipart 表单,`file` 部分为栅格图)。仅登录,零 perm,不要当前租户。
/// 存成个人内容(`ContentScope::Personal`,owner = 本人,不属于任何租户)并立即绑定(保留 display_name / phone),
/// 返回更新后的资料。换下来的旧头像(本人的个人内容)会被 best-effort 软删(见 `upload_and_bind_avatar`)。
#[utoipa::path(
    post,
    path = "/profiles/me/avatar",
    tag = "profiles",
    request_body(content = inline(AvatarForm), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "头像已上传并绑定", body = ProfileResponse),
        (status = 400, description = "multipart 解析失败", body = ErrorBody),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 422, description = "缺 file 部分 / 非栅格图", body = ErrorBody)
    )
)]
pub async fn upload_my_avatar(
    State(state): State<AppState>,
    user: CurrentUser,
    Audit(ctx): Audit,
    Multipart(mut multipart): Multipart,
) -> Result<Json<ProfileResponse>, ApiError> {
    let view = upload_and_bind_avatar(&state, user.0.id, &mut multipart, &ctx).await?;
    Ok(Json(view.into()))
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
) -> Result<Response, ApiError> {
    let cid = state
        .profiles
        .avatar_content_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // 头像一律是个人内容(只认 Personal;绑定时 AvatarProbe 也只认 Personal)。
    let scope = ContentScope::Personal;
    // **出字节前再验栅格**(纵深,不只信绑定时那次):presign 分支 307 直连存储,浏览器拿到的
    // Content-Type 是对象上传时存进 S3 的那个、且 app 加不了 CSP —— 非栅格从这里出去 = 存储型 XSS,
    // 且本端点任何登录用户跨用户可达。mime 现已不可改(见 SetContentMetadataRequest),故它与 S3
    // 那份恒一致;这层兜住"绑定早于该约束的历史数据"。不可用 → 404(同本端点其余不可用分支)。
    if !state
        .contents
        .get_content_metadata(scope, cid)
        .await
        .ok()
        .and_then(|m| m.mime_type)
        .as_deref()
        .is_some_and(is_allowed_avatar_mime)
    {
        return Err(AppError::NotFound.into());
    }
    // 出字节:presign 后端 → 307 到签名 URL;内存 backend → 代理 inline。刻意重复
    // content::preview_content 的服务段(去掉 owner 闸 —— 本端点契约就是"这个用户的公开头像"),
    // 而非跨 feature 复用其 handler(维持业务模块彼此零 import,胶水只在组合根)。
    if let Some(url) = state.contents.preview_url(scope, cid).await? {
        // 307 默认不可缓存(RFC 9110);no-store 防错配 CDN/代理缓存 5min 签名 URL。
        let mut resp = Redirect::temporary(&url).into_response();
        resp.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(resp);
    }
    let p = state.contents.preview_content(scope, cid).await?;
    let mime = p
        .metadata
        .as_ref()
        .and_then(|m| m.mime_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_DISPOSITION, "inline")
        // CSP sandbox 全禁脚本/表单/同源访问,栅格图照常渲染。纵深防御:上传已限栅格白名单
        // (model::is_allowed_avatar_mime 排除 SVG),此 header 再兜一层(代理分支专有;presign
        // 分支直连存储、加不了 CSP —— 故防线必须在上传白名单,不能靠出字节时补)。
        .header("content-security-policy", "sandbox")
        .body(Body::from(p.data))
        .map_err(|e| AppError::Internal(e.into()).into())
}

// ── 后台资料管理(admin 组,路径仍在 /users/{id} 下、归 users:admin 授权面;
//    handler 归 profile 模块:只编排 state.profiles/state.contents,与 users 模块零耦合;
//    写操作对持平台角色的账号另要 platform:roles —— 防接管闸经组合根 `AppState::guard_platform_account`)──

use content::{ContentScope, UploadContentInput};

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
) -> Result<Json<ProfileResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    Ok(Json(state.profiles.get(id).await?.into()))
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
        (status = 403, description = "无 users:admin 权限 / 目标持平台角色而无 platform:roles", body = ErrorBody),
        (status = 422, description = "校验失败 / 头像非法", body = ErrorBody)
    )
)]
pub async fn set_user_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(input): Json<PutProfileRequest>,
) -> Result<Json<ProfileResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    // 防接管:改 superadmin / 平台管理员的资料要 platform:roles(superadmin 改自己的照常)
    state.guard_platform_account(&user.0, &scope.0, id).await?;
    let (_created, view) = state.profiles.put(id, input.into(), &ctx).await?;
    Ok(Json(view.into()))
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
        (status = 403, description = "无 users:admin 权限 / 目标持平台角色而无 platform:roles", body = ErrorBody),
        (status = 422, description = "缺 file 部分 / 非 image", body = ErrorBody)
    )
)]
pub async fn set_user_avatar(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Multipart(mut multipart): Multipart,
) -> Result<Json<ProfileResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    state.guard_platform_account(&user.0, &scope.0, id).await?;

    let view = upload_and_bind_avatar(&state, id, &mut multipart, &ctx).await?;
    Ok(Json(view.into()))
}

/// 传头像并绑定到 `target` 的资料(本人自助 / 后台代传共用):先校验栅格白名单(不合格不产生任何持久化副作用)→
/// 以 `ContentScope::Personal` 上传(owner = `target`,对象 key `personal/{owner}/…`)→ 保留现有 display_name / phone
/// 换上新头像;绑定失败 best-effort 软删刚上传的 content。
///
/// **换下来的旧头像回收**:上传入口零权限(本人即可),旧头像不回收就是一条存储耗尽面 —— 绑定成功后 best-effort
/// 软删上一张已绑定的头像,仅当它是 Personal、owner 是同一用户、且不是这次新传的 content;软删失败只记日志,
/// 不影响本次请求。显式「按已有 content id 重新绑定」(PUT 资料)不走这里,不删任何东西。
async fn upload_and_bind_avatar(
    state: &AppState,
    target: Uuid,
    multipart: &mut axum::extract::Multipart,
    ctx: &crate::kernel::audit::AuditContext,
) -> Result<model::ProfileView, ApiError> {
    let file = crate::infra::http::extract::file_part(multipart)
        .await?
        .ok_or_else(|| AppError::Validation("missing `file` part".into()))?;
    // 先校验后写(transactions skill):非白名单 mime 就不该产生任何持久化副作用 ——
    // 否则 put 的三查 422 时,已落库的 content(owner=目标用户)成孤儿且无清理路径。
    // 栅格白名单(排除 SVG 活动内容),口径收口在 model::is_allowed_avatar_mime。
    if !file
        .mime_type
        .as_deref()
        .is_some_and(is_allowed_avatar_mime)
    {
        return Err(AppError::Validation(
            "avatar must be a raster image (png/jpeg/gif/webp)".into(),
        )
        .into());
    }

    // content 归目标用户(是他的头像)。头像是个人内容(资料全局一份,不属于任何租户)→ Personal 作用域。
    let input = UploadContentInput {
        owner_id: target,
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
    let outcome = state
        .contents
        .upload_content(ContentScope::Personal, input, ctx.audit_id())
        .await?;
    let content_id = outcome.content.id;

    // auto-bind:保留现有 display_name/phone(无资料行 → None),换上新头像。
    // content(app.contents)与 profile(app.profiles)跨表写,不共享一个事务:绑定任一步
    // 失败(get/put 报错)则 best-effort 软删刚上传的 content(owner=目标用户、尚无引用),
    // 避免留下无法回收的孤儿行/对象字节。清理失败只 warn,不掩盖原始错误。
    let bind: Result<(Option<Uuid>, model::ProfileView), AppError> = async {
        let (display_name, phone, previous) = match state.profiles.get(target).await {
            Ok(p) => (p.display_name, p.phone, p.avatar_content_id),
            Err(AppError::NotFound) => (None, None, None),
            Err(e) => return Err(e),
        };
        let (_created, view) = state
            .profiles
            .put(
                target,
                model::PutProfile {
                    avatar_content_id: Some(content_id),
                    display_name,
                    phone,
                },
                ctx,
            )
            .await?;
        Ok((previous, view))
    }
    .await;
    let (previous, view) = match bind {
        Ok(r) => r,
        Err(e) => {
            if let Err(cleanup) = state
                .contents
                .delete_content(ContentScope::Personal, content_id, ctx.audit_id())
                .await
            {
                tracing::warn!(error = %cleanup, %content_id, "头像绑定失败后清理孤儿 content 失败(软删)");
            }
            return Err(e.into());
        }
    };
    if let Some(old) = previous.filter(|old| *old != content_id) {
        retire_replaced_avatar(state, target, old, ctx).await;
    }
    Ok(view)
}

/// best-effort 软删换下来的旧头像:只删 Personal 作用域里、owner 是 `owner` 的那一条(查不到 = 已删 / 不是个人内容 /
/// 不是本人的 → 什么都不做)。任何失败只 warn —— 新头像已经绑好,不能因回收失败让请求报错。
async fn retire_replaced_avatar(
    state: &AppState,
    owner: Uuid,
    old: Uuid,
    ctx: &crate::kernel::audit::AuditContext,
) {
    match state
        .contents
        .get_content(ContentScope::Personal, old)
        .await
    {
        Ok(c) if c.owner_id == owner => {
            if let Err(e) = state
                .contents
                .delete_content(ContentScope::Personal, old, ctx.audit_id())
                .await
            {
                tracing::warn!(error = %e, content_id = %old, "回收换下来的旧头像失败(软删)");
            }
        }
        Ok(_) | Err(content::ContentError::NotFound) => {}
        Err(e) => {
            tracing::warn!(error = %e, content_id = %old, "回收旧头像前读取失败,跳过");
        }
    }
}

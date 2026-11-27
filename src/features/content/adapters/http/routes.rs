//! content 端点 —— 薄 handler:authz gate → 构建库 input → 调 service → `?` 经 `From<ContentError>` 出错。
//! 镜像 widget 的三轴:**必须登录**(`CurrentUser` → 401)+ RBAC(`require_scoped` → 403)+ 行级 ownership(404)。
//!
//! **owner / 租户映射**:
//! - `owner_id` = 认证主体的 UUID(`CurrentUser.0.id`)。未认证由 `CurrentUser` 先 401,故到此恒有主体。
//! - 租户 = **当前租户**(`CurrentTenant`,只来自 token;没有 → 403 `tenant_required`),所有调用都用
//!   `ContentScope::Tenant(当前租户)`。请求里不再有 `tenant_id` 字段(客户端自报的租户不可信)。
//!   别的租户的 id 在库里就查不到 → 404(不泄露存在);`:all` 的「全部」只是本租户内的全部。
//! - 头像等个人内容(`ContentScope::Personal`)只归 profile 模块,这里看不到、也碰不到。

use axum::body::Body;
use axum::extract::multipart::Field;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use bytes::Bytes;
use content::{Content, ContentError, ContentScope, CreateContentInput, UploadContentInput};
use garde::Validate;
use idm::AuthUser;
use uuid::Uuid;

use super::dto::{
    ContentMetadataResponse, ContentResponse, CreateContentRequest, ObjectResponse,
    PrepareUploadRequest, PrepareUploadResponse, SetContentMetadataRequest, UpdateContentRequest,
    UploadResponse,
};
use crate::app::app_state::AppState;
use crate::infra::authorization::TokenScope;
use crate::infra::http::audit::{Audit, CurrentTenant, CurrentUser};
use crate::infra::http::error::{ApiError, ErrorBody};
use crate::infra::http::extract::{Json, Multipart, Path};
use crate::infra::percent;
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::Permission;
use crate::kernel::tenant_id::TenantId;

/// 本模块所有 content 调用的作用域 = 当前租户(`CurrentTenant` 已保证非 nil)。
fn tenant_scope(tenant: TenantId) -> ContentScope {
    ContentScope::Tenant(tenant.as_uuid())
}

/// 行级 ownership(镜像 widget 的 get 范式):owner 本人或持越权 perm(`contents:read:all` /
/// `contents:write:all`,经 `data_access` 判 mode)→ 放行并返回该行;否则 **404**。
/// 读写同码 404:本模块读侧 owner-scoped(list 只回自己的),存在性敏感,403 会泄露"这 id 存在"。
/// ponytail: 每个单条端点多一次 PK 查询(下游 ContentService 方法内部会再 get 同一行);
/// content 库零 authz 是刻意分层,守卫只能落 app。真在意时把 Access 下推进库的 service 方法签名。
async fn fetch_content_owned(
    state: &AppState,
    tenant: TenantId,
    user: &AuthUser,
    scope: &[Permission],
    all_permission: Permission,
    id: Uuid,
) -> Result<Content, AppError> {
    let found = state.contents.get_content(tenant_scope(tenant), id).await?;
    let owned = state
        .policy
        .data_access(user, scope, all_permission)
        .allows(found.owner_id);
    if owned {
        Ok(found)
    } else {
        Err(AppError::NotFound)
    }
}

/// 307 跳到短时效签名 URL,带 `Cache-Control: no-store`。
///
/// 307 默认不可缓存(RFC 9110),no-store 是对错配置 CDN/代理缓存 300s 签名 URL 的防御。
fn no_store_redirect(url: &str) -> Response {
    let mut response = Redirect::temporary(url).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// 可安全 inline 渲染的 MIME 白名单(浏览器不执行脚本):栅格图 / 视频 / 音频 / PDF / 纯文本。
/// **排除活动内容**(image/svg+xml、text/html、application/xml…):它们 inline + 同源 + 无 CSP =
/// 存储型 XSS。presign 分支 app 加不了 CSP,且 relative-presign 拓扑(见 compose/nginx)下 presign
/// 与 app **同源** —— 故不能靠"presign 天然异源"兜底。不在白名单 → 强制 attachment(浏览器下载不渲染)。
///
/// **形状必须是"白名单 + 精确匹配",不能是"前缀放行 + 逐个排除活动类型"**:后者对新的/带参数的活动
/// 类型恒 fail-open(`image/svg+xml; charset=utf-8` 曾绕过 `== "image/svg+xml"` 再被 `starts_with("image/")`
/// 放行)。mime 是**用户上传时自报**的原样串(axum 保留参数),故先归一:切掉 `;` 参数、trim、小写。
fn is_safe_inline_mime(mime: &str) -> bool {
    let base = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/bmp"
            | "image/x-icon"
            | "image/avif"
            | "application/pdf"
            | "text/plain"
    ) || base.starts_with("video/")
        || base.starts_with("audio/")
}

/// 建内容(仅 content 行,status=created)。需 `contents:write`。owner_id = 当前用户。
#[utoipa::path(
    post,
    path = "/contents",
    tag = "contents",
    request_body = CreateContentRequest,
    responses(
        (status = 201, description = "已创建", body = ContentResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn create_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Json(input): Json<CreateContentRequest>,
) -> Result<(StatusCode, Json<ContentResponse>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;
    input.validate()?;
    let mut domain = CreateContentInput::new(user.0.id);
    domain.owner_type = input.owner_type;
    domain.name = input.name;
    domain.description = input.description;
    domain.document_type = input.document_type;
    domain.derivation_type = input.derivation_type;
    let content = state
        .contents
        .create_content(tenant_scope(tenant), domain, ctx.audit_id().as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(content.try_into()?)))
}

/// 一次性上传(multipart/form-data):建 content + object 行、推字节、同步元数据、翻状态。需 `contents:write`。
/// 表单字段:`file`(必填,带 filename + content-type)、`name`、`tags`(逗号分隔)、`document_type`。
/// 内容落当前租户(令牌里的租户)。
#[utoipa::path(
    post,
    path = "/contents/upload",
    tag = "contents",
    request_body(content = inline(super::dto::UploadForm), content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "已上传(content + object 皆 uploaded)", body = UploadResponse),
        (status = 400, description = "multipart 解析失败", body = ErrorBody),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "缺 file 部分", body = ErrorBody)
    )
)]
pub async fn upload_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Multipart(mut multipart): Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;

    let mut data: Option<Bytes> = None;
    let mut file_name: Option<String> = None;
    let mut mime_type: Option<String> = None;
    let mut name: Option<String> = None;
    let mut document_type: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        // field.name() 借用 field,先取成 owned 再读 body(bytes()/text() 会消费 field)。
        let field_name = field.name().map(str::to_owned);
        match field_name.as_deref() {
            Some("file") => {
                file_name = field.file_name().map(str::to_owned);
                mime_type = field.content_type().map(str::to_owned);
                data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(e.to_string()))?,
                );
            }
            Some("name") => name = Some(read_text(field).await?),
            Some("document_type") => document_type = Some(read_text(field).await?),
            Some("tags") => {
                tags = read_text(field)
                    .await?
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            // 未知部分(含旧客户端还在送的 `tenant_id`:租户只来自令牌):读掉以推进 multipart 流。
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let data = data.ok_or_else(|| AppError::Validation("missing `file` part".to_owned()))?;
    // multipart 是手解的,没有 `Json<T>` 那层 derive 校验 —— 本端点原本是**唯一**不 validate 的写
    // handler,同样的领域字段在 JSON 两步上传(`PrepareUploadRequest`)上全都有上限,这条路一个没有。
    let fields = UploadFields {
        name,
        document_type,
        file_name,
        mime_type,
        tags,
    };
    fields.validate()?;
    let UploadFields {
        name,
        document_type,
        file_name,
        mime_type,
        tags,
    } = fields;
    let mut input = UploadContentInput::new(user.0.id, data);
    input.name = name;
    input.document_type = document_type;
    input.file_name = file_name;
    input.mime_type = mime_type;
    input.tags = tags;
    let outcome = state
        .contents
        .upload_content(tenant_scope(tenant), input, ctx.audit_id().as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(outcome.try_into()?)))
}

/// 列当前用户在**当前租户**里的内容。需 `contents:read`。
/// 所有权固有:service 按 (当前租户, owner_id) 列,只回自己创建的。
/// ponytail: `contents:read:all` 在此**不生效**(content 库 list 签名强制 owner,无"列全部"入口);
/// 单条端点已按 mode 放行。要让越权读贯通列表,需 content 库 list 的 owner 参数改 Option。
#[utoipa::path(
    get,
    path = "/contents",
    tag = "contents",
    responses(
        (status = 200, description = "当前用户的内容列表", body = [ContentResponse]),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody)
    )
)]
pub async fn list_contents(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
) -> Result<Json<Vec<ContentResponse>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    let items = state
        .contents
        .list_content(tenant_scope(tenant), user.0.id)
        .await?;
    let responses: Vec<ContentResponse> = items
        .into_iter()
        .map(ContentResponse::try_from)
        .collect::<Result<_, AppError>>()?;
    Ok(Json(responses))
}

/// 按 id 取内容。需 `contents:read`。不存在 / 已软删 → 404。
#[utoipa::path(
    get,
    path = "/contents/{id}",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 200, description = "找到", body = ContentResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人(不区分,防泄露存在;contents:read:all 可看全部)", body = ErrorBody)
    )
)]
pub async fn get_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    let found = fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentReadAll,
        id,
    )
    .await?;
    Ok(Json(found.try_into()?))
}

/// 全量更新内容可编辑字段(PUT)。需 `contents:write`。不存在 → 404。
#[utoipa::path(
    put,
    path = "/contents/{id}",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    request_body = UpdateContentRequest,
    responses(
        (status = 200, description = "已更新", body = ContentResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:write:all(不区分,防泄露存在)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateContentRequest>,
) -> Result<Json<ContentResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;
    input.validate()?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentWriteAll,
        id,
    )
    .await?;
    let updated = state
        .contents
        .update_content(
            tenant_scope(tenant),
            id,
            input.into(),
            ctx.audit_id().as_deref(),
        )
        .await?;
    Ok(Json(updated.try_into()?))
}

/// 软删内容。需 `contents:delete`。不存在 → 404。
#[utoipa::path(
    delete,
    path = "/contents/{id}",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 204, description = "已软删除"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:delete 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:write:all(不区分,防泄露存在)", body = ErrorBody)
    )
)]
pub async fn delete_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentDelete)?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentWriteAll,
        id,
    )
    .await?;
    state
        .contents
        .delete_content(tenant_scope(tenant), id, ctx.audit_id().as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// 下载内容主对象字节。需 `contents:read`。Content-Type / Content-Disposition 取自元数据。
/// 内容不存在 → 404;状态不允许下载(未上传完)→ 409。
#[utoipa::path(
    get,
    path = "/contents/{id}/download",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 307, description = "跳转到短时效签名 URL(presign 后端)"),
        (status = 200, description = "字节流(Content-Type/Disposition 取自元数据)", content_type = "application/octet-stream"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:read:all / 无可下载对象(不区分,防泄露存在)", body = ErrorBody),
        (status = 409, description = "内容未就绪(状态不允许下载)", body = ErrorBody)
    )
)]
pub async fn download_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentReadAll,
        id,
    )
    .await?;
    // presign 可用 → 307(字节直达存储);不可用 → 走下面的代理现状。
    if let Some(url) = state
        .contents
        .download_url(tenant_scope(tenant), id)
        .await?
    {
        return Ok(no_store_redirect(&url));
    }
    let bytes = state
        .contents
        .download_content(tenant_scope(tenant), id)
        .await?;
    // 元数据用于命名/类型;缺失(未同步)→ 通用兜底,不致命。
    let metadata = state
        .contents
        .get_content_metadata(tenant_scope(tenant), id)
        .await
        .ok();
    let (mime_type, file_name) = match metadata {
        Some(metadata) => (metadata.mime_type, metadata.file_name),
        None => (None, None),
    };
    let mime = mime_type.unwrap_or_else(|| "application/octet-stream".to_owned());
    let file_name = file_name.unwrap_or_else(|| id.to_string());
    // RFC 6266 文件名(ascii 兜底 + filename*),与 presign 下载路径同口径(见 percent 模块)。
    let disposition = percent::content_disposition_attachment(&file_name);
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_DISPOSITION, disposition)
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(e.into()).into())
}

/// 预览内容(inline 展示,`<img src>` 即用)。需 `contents:read`。
/// presign 可用(minio/S3)→ **307** 跳短时效签名 URL(字节直达存储,Range/大文件白送);
/// 不可用(内存 backend)→ 代理字节。稳定 URL 是本端点 —— 每次跳转都重新过鉴权,签名 URL 只活 5 分钟。
#[utoipa::path(
    get,
    path = "/contents/{id}/preview",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 307, description = "跳转到短时效签名 URL(presign 后端)"),
        (status = 200, description = "inline 字节(代理回退,Content-Type 取自元数据)", content_type = "application/octet-stream"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:read:all(不区分,防泄露存在)", body = ErrorBody),
        (status = 409, description = "内容未就绪", body = ErrorBody)
    )
)]
pub async fn preview_content(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    // 严格 owner 隔离(同 get/download):非 owner 且无 contents:read:all → 404。
    // 头像跨用户展示不再从这里"放行任意 image"(那会让 owner 隔离被整体绕过)——
    // 改由 `profiles/{user_id}/avatar` 专用端点服务:只出被指定为头像、且属主本人的那一张图。
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentReadAll,
        id,
    )
    .await?;
    // inline 是否安全:活动内容(html/svg/xml…)绝不 inline。presign 分支 app 加不了 CSP,relative-presign
    // 拓扑下又与 app 同源 —— 不安全类型强制 attachment(浏览器下载不执行),安全类型才 inline 预览。
    let safe_inline = state
        .contents
        .get_content_metadata(tenant_scope(tenant), id)
        .await
        .ok()
        .and_then(|m| m.mime_type)
        .as_deref()
        .is_some_and(is_safe_inline_mime);

    // presign 分支(prod 默认):安全 → inline 预览凭证;不安全 → attachment 下载凭证(不渲染活动内容)。
    let presigned = if safe_inline {
        state.contents.preview_url(tenant_scope(tenant), id).await?
    } else {
        state
            .contents
            .download_url(tenant_scope(tenant), id)
            .await?
    };
    if let Some(url) = presigned {
        return Ok(no_store_redirect(&url));
    }
    // 代理回退(memory 后端):Preview 自带元数据说明书(不像 download 代理路径要二次查询)。
    let preview = state
        .contents
        .preview_content(tenant_scope(tenant), id)
        .await?;
    let mime = preview
        .metadata
        .and_then(|metadata| metadata.mime_type)
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    // 安全类型 inline 渲染;活动类型已降级 attachment(不渲染即不执行)。CSP sandbox 再兜一层:
    // 禁脚本/表单/同源访问,即便 inline 的用户可控 mime 也拿不到 app origin 的任何东西。
    let disposition = if safe_inline { "inline" } else { "attachment" };
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_DISPOSITION, disposition)
        .header("content-security-policy", "sandbox")
        .body(Body::from(preview.data))
        .map_err(|e| AppError::Internal(e.into()).into())
}

/// 列某内容的对象。需 `contents:read`。
#[utoipa::path(
    get,
    path = "/contents/{id}/objects",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 200, description = "对象列表", body = [ObjectResponse]),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人(不区分,防泄露存在)", body = ErrorBody)
    )
)]
pub async fn list_content_objects(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ObjectResponse>>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentReadAll,
        id,
    )
    .await?;
    let objects = state.contents.get_objects(tenant_scope(tenant), id).await?;
    let responses: Vec<ObjectResponse> = objects
        .into_iter()
        .map(ObjectResponse::try_from)
        .collect::<Result<_, AppError>>()?;
    Ok(Json(responses))
}

/// 取内容元数据。需 `contents:read`。不存在 → 404。
#[utoipa::path(
    get,
    path = "/contents/{id}/metadata",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 200, description = "内容元数据", body = ContentMetadataResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:read:all / 无元数据(不区分,防泄露存在)", body = ErrorBody)
    )
)]
pub async fn get_content_metadata(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentMetadataResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentRead)?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentReadAll,
        id,
    )
    .await?;
    Ok(Json(
        state
            .contents
            .get_content_metadata(tenant_scope(tenant), id)
            .await?
            .into(),
    ))
}

/// 全量替换内容元数据(PUT,upsert)。需 `contents:write`。内容不存在 → 404。
#[utoipa::path(
    put,
    path = "/contents/{id}/metadata",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    request_body = SetContentMetadataRequest,
    responses(
        (status = 204, description = "已设置"),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:write:all(不区分,防泄露存在)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn set_content_metadata(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Json(input): Json<SetContentMetadataRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;
    input.validate()?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentWriteAll,
        id,
    )
    .await?;
    // mime 服务端所有:原样回填现有值(库端全量替换,不带 = 清空)。**不能让客户端改** ——
    // 改了就能与 S3 里那份 Content-Type 分叉,骗过 inline 闸门(见 SetContentMetadataRequest)。
    //
    // **只有 NotFound 能降级成 None**(upsert 建首行,如 create_content 未上传字节 → 本就没 mime);
    // 其余错误(连接抖动/池超时)必须上抛:`.ok()` 会把它们一起吞成 None,于是这次全量替换把好端端
    // 的 mime 写成 NULL 还回 204 —— 而 mime 是服务端所有物,客户端再也没法把它写回来,只能重传整个
    // content(preview 从此恒 attachment;若是头像,`get_user_avatar` 的栅格闸会让它永久 404)。
    // 口径照抄库里同一调用的两处(content 库 `content_service.rs` 的 `preview_content` / `download_url`)。
    let mime_type = match state
        .contents
        .get_content_metadata(tenant_scope(tenant), id)
        .await
    {
        Ok(metadata) => metadata.mime_type,
        Err(ContentError::NotFound) => None,
        Err(error) => return Err(error.into()),
    };
    state
        .contents
        .set_content_metadata(tenant_scope(tenant), input.into_input(id, mime_type))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// 一次性上传(multipart)手解出来的字段 —— 上闸用,上限**与 `PrepareUploadRequest` 逐条对齐**:
/// 同样的领域字段走 JSON(两步上传)还是 multipart(一步上传),不该有两套契约。
///
/// `file_name` 尤其不能不封顶:它会被原样编进 `Content-Disposition` 当作 S3 PUT 的**请求头**
/// (见 infra::s3_object_store::upload),几十 KB 的文件名足以让后端拒绝 —— 而 2MB 的 body 上限
/// 随手就塞得下。(`UploadForm` 是纯文档 schema、不参与反序列化,且不含 file_name/mime_type
/// 这两个来自 part 头的字段,故另立此结构而非给它加 derive。)
#[derive(Validate)]
struct UploadFields {
    #[garde(inner(length(max = 255)))]
    name: Option<String>,
    #[garde(inner(length(max = 64)))]
    document_type: Option<String>,
    #[garde(inner(length(max = 255)))]
    file_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    mime_type: Option<String>,
    #[garde(length(max = 64))]
    tags: Vec<String>,
}

/// multipart 标量字段读成 String(失败 → 400)。
async fn read_text(field: Field<'_>) -> Result<String, AppError> {
    field
        .text()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))
}

/// 两步上传①:建账 + 占格 + 签直传凭证(字节不过 app)。需 `contents:write`。
/// `upload_url = null` → 后端不支持,回退 multipart 一步上传。传完调 confirm-upload 销账。
#[utoipa::path(
    post,
    path = "/contents/upload-url",
    tag = "contents",
    request_body = PrepareUploadRequest,
    responses(
        (status = 201, description = "账已建(created);upload_url=null 时回退一步上传", body = PrepareUploadResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn prepare_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Json(input): Json<PrepareUploadRequest>,
) -> Result<(StatusCode, Json<PrepareUploadResponse>), ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;
    input.validate()?;
    let prepared = state
        .contents
        .prepare_upload(
            tenant_scope(tenant),
            input.into_input(user.0.id),
            ctx.audit_id().as_deref(),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PrepareUploadResponse {
            content: prepared.content.try_into()?,
            object: prepared.object.try_into()?,
            upload_url: prepared.upload_url,
        }),
    ))
}

/// 两步上传③:核对字节已落桶 → 销账(翻 uploaded + 补 size)。需 `contents:write`。
/// 幂等(重试安全);没传就来 → 409;账不存在 → 404。
#[utoipa::path(
    post,
    path = "/contents/{id}/confirm-upload",
    tag = "contents",
    params(("id" = Uuid, Path, description = "content id")),
    responses(
        (status = 200, description = "已销账(uploaded)", body = ContentResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限 / 没有当前租户(tenant_required)", body = ErrorBody),
        (status = 404, description = "不存在 / 别的租户 / 非本人且无 contents:write:all(不区分,防泄露存在)", body = ErrorBody),
        (status = 409, description = "字节未落桶(先传再销账)", body = ErrorBody)
    )
)]
pub async fn confirm_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    CurrentTenant(tenant): CurrentTenant,
    scope: TokenScope,
    Audit(ctx): Audit,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentResponse>, ApiError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Permission::ContentWrite)?;
    fetch_content_owned(
        &state,
        tenant,
        &user.0,
        &scope.0,
        Permission::ContentWriteAll,
        id,
    )
    .await?;
    let confirmed = state
        .contents
        .confirm_upload(tenant_scope(tenant), id, ctx.audit_id().as_deref())
        .await?;
    Ok(Json(confirmed.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::is_safe_inline_mime;

    /// 闸门必须 **fail-closed**:活动内容(可执行脚本)一律不 inline —— 带 MIME 参数、
    /// 大小写变形、前后空白都不能把它绕过去(mime 是上传方自报的原样串)。
    #[test]
    fn active_content_never_inlines_despite_parameters_or_case() {
        for bad in [
            "image/svg+xml",
            "image/svg+xml; charset=utf-8", // 参数曾绕过 `== "image/svg+xml"` 再被前缀放行
            "IMAGE/SVG+XML",
            "  image/svg+xml  ",
            "text/html",
            "text/html; charset=utf-8",
            "application/xml",
            "application/xhtml+xml",
            "image/svg+xml;foo=bar",
        ] {
            assert!(!is_safe_inline_mime(bad), "{bad} 绝不能 inline");
        }
    }

    /// 惰性类型照常 inline(别把闸门收成全拒),含带参数/大小写变形的正常写法。
    #[test]
    fn inert_types_still_inline() {
        for ok in [
            "image/png",
            "image/jpeg",
            "IMAGE/PNG",
            "image/jpeg; charset=binary",
            "application/pdf",
            "text/plain; charset=utf-8",
            "video/mp4",
            "audio/mpeg",
        ] {
            assert!(is_safe_inline_mime(ok), "{ok} 应可 inline");
        }
    }
}

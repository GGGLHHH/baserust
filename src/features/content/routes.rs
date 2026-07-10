//! content 端点 —— 薄 handler:authz gate → 构建库 input → 调 service → `?` 经 `From<ContentError>` 出错。
//! 镜像 widget 的三轴:**必须登录**(`CurrentUser` → 401)+ RBAC(`require_scoped` → 403)。
//!
//! **owner/tenant 映射(刻意的脚手架简化)**:
//! - `owner_id` = 认证主体的 UUID(`CurrentUser.0.id`)。未认证由 `CurrentUser` 先 401,故到此恒有主体。
//! - `tenant_id` = 可选请求字段,默认 `Uuid::nil()`。本脚手架单租户;多租户隔离是 app authz 的职责
//!   (按 spec,库不强制 tenant)。
//!
//! ponytail: 单租户先用 nil 兜底;真要多租户时把 tenant 从 token/claim 取,别现在加抽象。

use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use bytes::Bytes;
use uuid::Uuid;

use super::types::{
    ContentMetadataResponse, ContentResponse, CreateContentRequest, ObjectResponse,
    PrepareUploadRequest, PrepareUploadResponse, SetContentMetadataRequest, UpdateContentRequest,
    UploadResponse,
};
use crate::app::state::AppState;
use crate::infra::audit::{AuditContext, CurrentUser};
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::{AppError, ErrorBody};
use crate::infra::extract::{Json, Path};
use content::{CreateContentInput, UploadContentInput};
use garde::Validate;

/// 建内容(仅 content 行,status=created)。需 `contents:write`。owner_id = 当前用户。
#[utoipa::path(
    post,
    path = "/contents",
    tag = "contents",
    request_body = CreateContentRequest,
    responses(
        (status = 201, description = "已创建", body = ContentResponse),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn create_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Json(input): Json<CreateContentRequest>,
) -> Result<(StatusCode, Json<ContentResponse>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;
    input.validate()?;
    let domain = CreateContentInput {
        tenant_id: input.tenant_id.unwrap_or(Uuid::nil()),
        owner_id: user.0.id,
        owner_type: input.owner_type,
        name: input.name,
        description: input.description,
        document_type: input.document_type,
        derivation_type: input.derivation_type,
    };
    let content = state
        .contents
        .create_content(domain, ctx.audit_id())
        .await?;
    Ok((StatusCode::CREATED, Json(content.into())))
}

/// 一次性上传(multipart/form-data):建 content + object 行、推字节、同步元数据、翻状态。需 `contents:write`。
/// 表单字段:`file`(必填,带 filename + content-type)、`name`、`tags`(逗号分隔)、`document_type`、`tenant_id`(可选)。
#[utoipa::path(
    post,
    path = "/contents/upload",
    tag = "contents",
    request_body(content = inline(super::types::UploadForm), content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "已上传(content + object 皆 uploaded)", body = UploadResponse),
        (status = 400, description = "multipart 解析失败", body = ErrorBody),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 422, description = "缺 file 部分", body = ErrorBody)
    )
)]
pub async fn upload_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;

    let mut data: Option<Bytes> = None;
    let mut file_name: Option<String> = None;
    let mut mime_type: Option<String> = None;
    let mut name: Option<String> = None;
    let mut document_type: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut tenant_id = Uuid::nil();

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
            Some("tenant_id") => {
                let raw = read_text(field).await?;
                if !raw.trim().is_empty() {
                    tenant_id = Uuid::parse_str(raw.trim())
                        .map_err(|e| AppError::BadRequest(e.to_string()))?;
                }
            }
            // 未知部分:读掉以推进 multipart 流。
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let data = data.ok_or_else(|| AppError::Validation("missing `file` part".to_owned()))?;
    let input = UploadContentInput {
        tenant_id,
        owner_id: user.0.id,
        owner_type: None,
        name,
        description: None,
        document_type,
        object_key: None,
        file_name,
        mime_type,
        tags,
        custom_metadata: None,
        data,
    };
    let outcome = state.contents.upload_content(input, ctx.audit_id()).await?;
    Ok((StatusCode::CREATED, Json(outcome.into())))
}

/// 列当前用户的内容(单租户:tenant=nil)。需 `contents:read`。
/// 所有权固有:service 按 (owner_id, tenant_id) 列,只回自己创建的。
#[utoipa::path(
    get,
    path = "/contents",
    tag = "contents",
    responses(
        (status = 200, description = "当前用户的内容列表", body = [ContentResponse]),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 contents:read 权限", body = ErrorBody)
    )
)]
pub async fn list_contents(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Json<Vec<ContentResponse>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    let items = state.contents.list_content(user.0.id, Uuid::nil()).await?;
    Ok(Json(items.into_iter().map(ContentResponse::from).collect()))
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
        (status = 403, description = "无 contents:read 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn get_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    Ok(Json(state.contents.get_content(id).await?.into()))
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
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn update_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateContentRequest>,
) -> Result<Json<ContentResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;
    input.validate()?;
    let updated = state
        .contents
        .update_content(id, input.into_input(), ctx.audit_id())
        .await?;
    Ok(Json(updated.into()))
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
        (status = 403, description = "无 contents:delete 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody)
    )
)]
pub async fn delete_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentDelete)?;
    state.contents.delete_content(id, ctx.audit_id()).await?;
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
        (status = 403, description = "无 contents:read 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 无可下载对象", body = ErrorBody),
        (status = 409, description = "内容未就绪(状态不允许下载)", body = ErrorBody)
    )
)]
pub async fn download_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    // presign 可用 → 307(字节直达存储);不可用 → 走下面的代理现状。
    if let Some(url) = state.contents.download_url(id).await? {
        // 307 默认不可缓存(RFC 9110),no-store 是对错配置 CDN/代理缓存 300s 签名 URL 的防御。
        let mut resp = Redirect::temporary(&url).into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        return Ok(resp);
    }
    let bytes = state.contents.download_content(id).await?;
    // 元数据用于命名/类型;缺失(未同步)→ 通用兜底,不致命。
    let meta = state.contents.get_content_metadata(id).await.ok();
    let mime = meta
        .as_ref()
        .and_then(|m| m.mime_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let file_name = meta
        .as_ref()
        .and_then(|m| m.file_name.clone())
        .unwrap_or_else(|| id.to_string());
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file_name.replace('"', "")),
        )
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(e.into()))
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
        (status = 403, description = "无 contents:read 权限", body = ErrorBody),
        (status = 404, description = "不存在 / 无可预览对象", body = ErrorBody),
        (status = 409, description = "内容未就绪", body = ErrorBody)
    )
)]
pub async fn preview_content(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    if let Some(url) = state.contents.preview_url(id).await? {
        // 307 默认不可缓存(RFC 9110),no-store 是对错配置 CDN/代理缓存 300s 签名 URL 的防御。
        let mut resp = Redirect::temporary(&url).into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        return Ok(resp);
    }
    // 代理回退:Preview 自带元数据说明书(不像 download 代理路径要二次查询)。
    let p = state.contents.preview_content(id).await?;
    let mime = p
        .metadata
        .as_ref()
        .and_then(|m| m.mime_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_DISPOSITION, "inline")
        // inline + 用户可控 mime(上传/元数据均可声明 text/html、svg)= 同源执行面。
        // CSP sandbox:本响应里脚本/表单/同源访问全禁 —— 图片/视频照常渲染;
        // 恶意 html/svg 拿不到 app origin 的任何东西。注意 sandbox 管不到浏览器 PDF
        // 阅读器自带的 JS action 模型(要彻底 → mime 白名单外回退 attachment)。
        // presign 路径天然异源,无此问题。
        .header("content-security-policy", "sandbox")
        .body(Body::from(p.data))
        .map_err(|e| AppError::Internal(e.into()))
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
        (status = 403, description = "无 contents:read 权限", body = ErrorBody)
    )
)]
pub async fn list_content_objects(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ObjectResponse>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    let objects = state.contents.get_objects(id).await?;
    Ok(Json(
        objects.into_iter().map(ObjectResponse::from).collect(),
    ))
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
        (status = 403, description = "无 contents:read 权限", body = ErrorBody),
        (status = 404, description = "无元数据", body = ErrorBody)
    )
)]
pub async fn get_content_metadata(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentMetadataResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentRead)?;
    Ok(Json(state.contents.get_content_metadata(id).await?.into()))
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
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 404, description = "内容不存在", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn set_content_metadata(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Json(input): Json<SetContentMetadataRequest>,
) -> Result<StatusCode, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;
    input.validate()?;
    state
        .contents
        .set_content_metadata(input.into_input(id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// multipart 标量字段读成 String(失败 → 400)。
async fn read_text(field: axum::extract::multipart::Field<'_>) -> Result<String, AppError> {
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
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 422, description = "校验失败", body = ErrorBody)
    )
)]
pub async fn prepare_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Json(input): Json<PrepareUploadRequest>,
) -> Result<(StatusCode, Json<PrepareUploadResponse>), AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;
    input.validate()?;
    let out = state
        .contents
        .prepare_upload(input.into_input(user.0.id), ctx.audit_id())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PrepareUploadResponse {
            content: out.content.into(),
            object: out.object.into(),
            upload_url: out.upload_url,
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
        (status = 403, description = "无 contents:write 权限", body = ErrorBody),
        (status = 404, description = "不存在", body = ErrorBody),
        (status = 409, description = "字节未落桶(先传再销账)", body = ErrorBody)
    )
)]
pub async fn confirm_upload(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentResponse>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::ContentWrite)?;
    let c = state.contents.confirm_upload(id, ctx.audit_id()).await?;
    Ok(Json(c.into()))
}

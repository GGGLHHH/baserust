//! content 模块的 HTTP DTO —— **app 拥有的对外形状**(投影自 content 库的领域类型)。
//! 出参 DTO:`Serialize` + `ToSchema`,`status` 投影成闭集视图枚举(镜像库里的 typed 枚举);
//! 入参 DTO:`Deserialize` + garde `Validate`,handler 校验后转成库的领域 input(无额外参数的走 `From`,
//! 要补服务端字段的走 `into_input(..)`)。
//!
//! owner/tenant 约定见 routes.rs:owner_id = 认证主体的 UUID(不入参);租户 = 当前租户(只来自令牌,请求里没有 tenant_id)。

use garde::Validate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::kernel::app_error::AppError;
use content::{
    Content, ContentMetadata, ContentStatus, Object, ObjectStatus, PrepareUploadInput,
    SetContentMetadataInput, UpdateContentInput, UploadOutcome,
};

/// 内容生命周期状态闭集(镜像 `content::ContentStatus` 的 wire 串;库零 HTTP 不 derive
/// ToSchema,视图枚举归消费方 —— 见 closed-enums skill)。库的枚举是 `#[non_exhaustive]`,转换用 `TryFrom`:
/// 已知变体逐个列出,库以后新加的变体 → 500(细节只进日志)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ContentStatusView {
    Created,
    Uploading,
    Uploaded,
    Processing,
    Processed,
    Failed,
    Archived,
}

// 不静默折成某个已知状态:通配分支报错而不是映射到某个已知视图。
impl TryFrom<ContentStatus> for ContentStatusView {
    type Error = AppError;

    fn try_from(status: ContentStatus) -> Result<Self, Self::Error> {
        match status {
            ContentStatus::Created => Ok(Self::Created),
            ContentStatus::Uploading => Ok(Self::Uploading),
            ContentStatus::Uploaded => Ok(Self::Uploaded),
            ContentStatus::Processing => Ok(Self::Processing),
            ContentStatus::Processed => Ok(Self::Processed),
            ContentStatus::Failed => Ok(Self::Failed),
            ContentStatus::Archived => Ok(Self::Archived),
            // 指南「Don't omit patterns on non_exhaustive enums when matching」:通配只兜库以后新加的变体。
            other => Err(AppError::Internal(anyhow::anyhow!(
                "content status {other} has no API view"
            ))),
        }
    }
}

/// 对象状态闭集(镜像 `content::ObjectStatus`;无 `Archived`,归档是内容级语义)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ObjectStatusView {
    Created,
    Uploading,
    Uploaded,
    Processing,
    Processed,
    Failed,
}

impl TryFrom<ObjectStatus> for ObjectStatusView {
    type Error = AppError;

    fn try_from(status: ObjectStatus) -> Result<Self, Self::Error> {
        match status {
            ObjectStatus::Created => Ok(Self::Created),
            ObjectStatus::Uploading => Ok(Self::Uploading),
            ObjectStatus::Uploaded => Ok(Self::Uploaded),
            ObjectStatus::Processing => Ok(Self::Processing),
            ObjectStatus::Processed => Ok(Self::Processed),
            ObjectStatus::Failed => Ok(Self::Failed),
            // 同 ContentStatusView:通配只兜库以后新加的变体。
            other => Err(AppError::Internal(anyhow::anyhow!(
                "object status {other} has no API view"
            ))),
        }
    }
}

/// 内容主体的对外响应(投影 `content::Content`;`status` 投影成闭集视图)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentResponse {
    pub id: Uuid,
    /// 所属租户;`null` = 个人内容(不属于任何租户,如头像 —— 本模块的端点看不到个人内容,
    /// 但形状上如实反映库的 `Option`)。
    pub tenant_id: Option<Uuid>,
    pub owner_id: Uuid,
    pub owner_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub document_type: Option<String>,
    /// 生命周期状态(闭集,生成前端 union)。
    pub status: ContentStatusView,
    pub derivation_type: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl TryFrom<Content> for ContentResponse {
    type Error = AppError;

    fn try_from(content: Content) -> Result<Self, Self::Error> {
        Ok(Self {
            id: content.id,
            tenant_id: content.tenant_id,
            owner_id: content.owner_id,
            owner_type: content.owner_type,
            name: content.name,
            description: content.description,
            document_type: content.document_type,
            status: content.status.try_into()?,
            derivation_type: content.derivation_type,
            created_at: content.created_at,
            updated_at: content.updated_at,
        })
    }
}

/// 存储对象的对外响应(投影 `content::Object`)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ObjectResponse {
    pub id: Uuid,
    pub content_id: Uuid,
    pub storage_backend_name: String,
    pub storage_class: Option<String>,
    pub object_key: String,
    pub file_name: Option<String>,
    pub version: i32,
    pub object_type: Option<String>,
    /// 对象状态(闭集,生成前端 union)。
    pub status: ObjectStatusView,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl TryFrom<Object> for ObjectResponse {
    type Error = AppError;

    fn try_from(object: Object) -> Result<Self, Self::Error> {
        Ok(Self {
            id: object.id,
            content_id: object.content_id,
            storage_backend_name: object.storage_backend_name,
            storage_class: object.storage_class,
            object_key: object.object_key,
            file_name: object.file_name,
            version: object.version,
            object_type: object.object_type,
            status: object.status.try_into()?,
            created_at: object.created_at,
            updated_at: object.updated_at,
        })
    }
}

/// 内容元数据的对外响应(投影 `content::ContentMetadata`)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentMetadataResponse {
    pub content_id: Uuid,
    pub tags: Vec<String>,
    pub file_size: Option<i64>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub checksum: Option<String>,
    pub checksum_algorithm: Option<String>,
    /// 自由表单 JSONB。
    pub metadata: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<ContentMetadata> for ContentMetadataResponse {
    fn from(metadata: ContentMetadata) -> Self {
        Self {
            content_id: metadata.content_id,
            tags: metadata.tags,
            file_size: metadata.file_size,
            file_name: metadata.file_name,
            mime_type: metadata.mime_type,
            checksum: metadata.checksum,
            checksum_algorithm: metadata.checksum_algorithm,
            metadata: metadata.metadata,
            created_at: metadata.created_at,
            updated_at: metadata.updated_at,
        }
    }
}

/// 一次性上传的 multipart 表单形状(只为 OpenAPI 文档,handler 逐字段手解)。
#[derive(Debug, ToSchema)]
pub struct UploadForm {
    /// 文件本体(必填,带 filename + content-type)。
    #[schema(value_type = String, format = Binary)]
    pub file: String,
    pub name: Option<String>,
    /// 逗号分隔。
    pub tags: Option<String>,
    pub document_type: Option<String>,
}

/// 一次性上传的对外响应(内容 + 其主对象)。投影 `content::UploadOutcome`。
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub content: ContentResponse,
    pub object: ObjectResponse,
}

impl TryFrom<UploadOutcome> for UploadResponse {
    type Error = AppError;

    fn try_from(outcome: UploadOutcome) -> Result<Self, Self::Error> {
        Ok(Self {
            content: outcome.content.try_into()?,
            object: outcome.object.try_into()?,
        })
    }
}

/// 建内容的入参(仅建 content 行,不碰对象/字节)。owner_id 来自认证主体、租户来自令牌(都不入参)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateContentRequest {
    #[garde(inner(length(max = 64)))]
    pub owner_type: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub name: Option<String>,
    #[garde(inner(length(max = 2000)))]
    pub description: Option<String>,
    #[garde(inner(length(max = 64)))]
    pub document_type: Option<String>,
    #[garde(inner(length(max = 32)))]
    pub derivation_type: Option<String>,
}

/// **全量更新**内容可编辑字段(PUT 语义:都替换;tenant/owner/status/derivation 不动)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateContentRequest {
    #[garde(inner(length(max = 64)))]
    pub owner_type: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub name: Option<String>,
    #[garde(inner(length(max = 2000)))]
    pub description: Option<String>,
    #[garde(inner(length(max = 64)))]
    pub document_type: Option<String>,
}

impl From<UpdateContentRequest> for UpdateContentInput {
    fn from(request: UpdateContentRequest) -> Self {
        Self {
            owner_type: request.owner_type,
            name: request.name,
            description: request.description,
            document_type: request.document_type,
        }
    }
}

/// 设置内容元数据(全量替换,upsert)。
///
/// **无 `mime_type` 字段 —— 它是服务端所有物**(上传时由字节的实际 Content-Type 定,见
/// `into_input`)。理由是安全而非洁癖:presign 出的 URL 只 override disposition,浏览器拿到的
/// Content-Type 恒是**对象上传时存进 S3 的那个**;而 inline 安全闸(`is_safe_inline_mime`)与头像
/// 栅格白名单读的都是**这张表**的 mime。两者若能分叉,攻击者就能 `text/html` 上传、改 mime 成
/// `image/png` 骗过闸门,再经 presign 拿回 `Content-Type: text/html` + inline = 存储型 XSS。
/// 让 mime 不可改,分叉就不存在。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetContentMetadataRequest {
    #[garde(length(max = 64))]
    pub tags: Vec<String>,
    #[garde(skip)]
    pub file_size: Option<i64>,
    #[garde(inner(length(max = 255)))]
    pub file_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub checksum: Option<String>,
    #[garde(inner(length(max = 64)))]
    pub checksum_algorithm: Option<String>,
    /// 自由表单 JSONB(省略 → `{}`)。
    #[garde(skip)]
    #[serde(default)]
    pub metadata: Value,
}

impl SetContentMetadataRequest {
    /// `mime_type` 由调用方从**现有元数据**取来原样回填(库端是全量替换,不带就等于清空)——
    /// 客户端给不了,见类型头。无现有行(upsert 建首行)→ `None`:没有字节就没有 mime,
    /// 且 `None` 在所有闸门下都是 fail-closed(不 inline)。
    #[must_use]
    pub fn into_input(
        self,
        content_id: Uuid,
        mime_type: Option<String>,
    ) -> SetContentMetadataInput {
        let mut input = SetContentMetadataInput::new(content_id);
        input.tags = self.tags;
        input.file_size = self.file_size;
        input.file_name = self.file_name;
        input.mime_type = mime_type;
        input.checksum = self.checksum;
        input.checksum_algorithm = self.checksum_algorithm;
        input.metadata = self.metadata;
        input
    }
}

/// 两步上传①的入参(仅声明,不带字节)。owner_id 来自认证主体、租户来自令牌(同 create)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PrepareUploadRequest {
    #[garde(inner(length(max = 64)))]
    pub owner_type: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub name: Option<String>,
    #[garde(inner(length(max = 2000)))]
    pub description: Option<String>,
    #[garde(inner(length(max = 64)))]
    pub document_type: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub file_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub mime_type: Option<String>,
    #[garde(length(max = 64))]
    #[serde(default)]
    pub tags: Vec<String>,
}

/// 两步上传①的响应:账 + 格 + 凭证。`upload_url = null` = 后端不支持直传,
/// **回退一步上传**(multipart /contents/upload)—— 客户端按此判别。
#[derive(Debug, Serialize, ToSchema)]
pub struct PrepareUploadResponse {
    pub content: ContentResponse,
    pub object: ObjectResponse,
    pub upload_url: Option<String>,
}

impl PrepareUploadRequest {
    /// 转成库的领域 input;`owner_id` 由 handler 从认证主体取(不入参)。对象 key 与自定义元数据
    /// 不开放给客户端,恒为 `None`。
    #[must_use]
    pub fn into_input(self, owner_id: Uuid) -> PrepareUploadInput {
        let mut input = PrepareUploadInput::new(owner_id);
        input.owner_type = self.owner_type;
        input.name = self.name;
        input.description = self.description;
        input.document_type = self.document_type;
        input.file_name = self.file_name;
        input.mime_type = self.mime_type;
        input.tags = self.tags;
        input
    }
}

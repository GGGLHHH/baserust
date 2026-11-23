//! content 模块的 HTTP DTO —— **app 拥有的对外形状**(投影自 content 库的领域类型)。
//! 出参 DTO:`Serialize` + `ToSchema`,`status` 投影成闭集视图枚举(镜像库里的 typed 枚举);
//! 入参 DTO:`Deserialize` + garde `Validate`,handler 校验后 `.into_input()` 成库的领域 input。
//!
//! owner/tenant 约定见 routes.rs:owner_id = 认证主体的 UUID(不入参);tenant_id 单租户脚手架默认 nil。

use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use content::{
    Content, ContentMetadata, ContentStatus, Object, ObjectStatus, PrepareUploadInput,
    SetContentMetadataInput, UpdateContentInput, UploadOutcome,
};

/// 内容生命周期状态闭集(镜像 `content::ContentStatus` 的 wire 串;库零 HTTP 不 derive
/// ToSchema,视图枚举归消费方 —— 见 closed-enums skill)。`From` 穷尽匹配:库加变体这里编译错。
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

impl From<ContentStatus> for ContentStatusView {
    fn from(s: ContentStatus) -> Self {
        match s {
            ContentStatus::Created => Self::Created,
            ContentStatus::Uploading => Self::Uploading,
            ContentStatus::Uploaded => Self::Uploaded,
            ContentStatus::Processing => Self::Processing,
            ContentStatus::Processed => Self::Processed,
            ContentStatus::Failed => Self::Failed,
            ContentStatus::Archived => Self::Archived,
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

impl From<ObjectStatus> for ObjectStatusView {
    fn from(s: ObjectStatus) -> Self {
        match s {
            ObjectStatus::Created => Self::Created,
            ObjectStatus::Uploading => Self::Uploading,
            ObjectStatus::Uploaded => Self::Uploaded,
            ObjectStatus::Processing => Self::Processing,
            ObjectStatus::Processed => Self::Processed,
            ObjectStatus::Failed => Self::Failed,
        }
    }
}

/// 内容主体的对外响应(投影 `content::Content`;`status` 投影成闭集视图)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
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

impl From<Content> for ContentResponse {
    fn from(c: Content) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            owner_id: c.owner_id,
            owner_type: c.owner_type,
            name: c.name,
            description: c.description,
            document_type: c.document_type,
            status: c.status.into(),
            derivation_type: c.derivation_type,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
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

impl From<Object> for ObjectResponse {
    fn from(o: Object) -> Self {
        Self {
            id: o.id,
            content_id: o.content_id,
            storage_backend_name: o.storage_backend_name,
            storage_class: o.storage_class,
            object_key: o.object_key,
            file_name: o.file_name,
            version: o.version,
            object_type: o.object_type,
            status: o.status.into(),
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
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
    pub metadata: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<ContentMetadata> for ContentMetadataResponse {
    fn from(m: ContentMetadata) -> Self {
        Self {
            content_id: m.content_id,
            tags: m.tags,
            file_size: m.file_size,
            file_name: m.file_name,
            mime_type: m.mime_type,
            checksum: m.checksum,
            checksum_algorithm: m.checksum_algorithm,
            metadata: m.metadata,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// 一次性上传的 multipart 表单形状(只为 OpenAPI 文档,handler 逐字段手解)。
#[derive(Debug, ToSchema)]
#[allow(dead_code)] // 仅供 utoipa 生成 request_body schema,不实际反序列化
pub struct UploadForm {
    /// 文件本体(必填,带 filename + content-type)。
    #[schema(value_type = String, format = Binary)]
    pub file: String,
    pub name: Option<String>,
    /// 逗号分隔。
    pub tags: Option<String>,
    pub document_type: Option<String>,
    pub tenant_id: Option<Uuid>,
}

/// 一次性上传的对外响应(内容 + 其主对象)。投影 `content::UploadOutcome`。
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub content: ContentResponse,
    pub object: ObjectResponse,
}

impl From<UploadOutcome> for UploadResponse {
    fn from(o: UploadOutcome) -> Self {
        Self {
            content: o.content.into(),
            object: o.object.into(),
        }
    }
}

/// 建内容的入参(仅建 content 行,不碰对象/字节)。owner_id 来自认证主体(不入参)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateContentRequest {
    /// 单租户脚手架:省略 → `Uuid::nil()`(多租户隔离是 app authz 的职责,见 routes.rs)。
    #[garde(skip)]
    pub tenant_id: Option<Uuid>,
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

impl UpdateContentRequest {
    pub fn into_input(self) -> UpdateContentInput {
        UpdateContentInput {
            owner_type: self.owner_type,
            name: self.name,
            description: self.description,
            document_type: self.document_type,
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
    pub metadata: serde_json::Value,
}

impl SetContentMetadataRequest {
    /// `mime_type` 由调用方从**现有元数据**取来原样回填(库端是全量替换,不带就等于清空)——
    /// 客户端给不了,见类型头。无现有行(upsert 建首行)→ `None`:没有字节就没有 mime,
    /// 且 `None` 在所有闸门下都是 fail-closed(不 inline)。
    pub fn into_input(
        self,
        content_id: Uuid,
        mime_type: Option<String>,
    ) -> SetContentMetadataInput {
        SetContentMetadataInput {
            content_id,
            tags: self.tags,
            file_size: self.file_size,
            file_name: self.file_name,
            mime_type,
            checksum: self.checksum,
            checksum_algorithm: self.checksum_algorithm,
            metadata: self.metadata,
        }
    }
}

/// 两步上传①的入参(仅声明,不带字节)。owner_id 来自认证主体;tenant 单租户默认 nil(同 create)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PrepareUploadRequest {
    #[garde(skip)]
    pub tenant_id: Option<Uuid>,
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
    pub fn into_input(self, owner_id: Uuid) -> PrepareUploadInput {
        PrepareUploadInput {
            tenant_id: self.tenant_id.unwrap_or(Uuid::nil()),
            owner_id,
            owner_type: self.owner_type,
            name: self.name,
            description: self.description,
            document_type: self.document_type,
            object_key: None,
            file_name: self.file_name,
            mime_type: self.mime_type,
            tags: self.tags,
            custom_metadata: None,
        }
    }
}

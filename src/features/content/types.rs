//! content 模块的 HTTP DTO —— **app 拥有的对外形状**(投影自 content 库的领域类型)。
//! 出参 DTO:`Serialize` + `ToSchema`,`status` 投影成字符串(库里是 typed 枚举);
//! 入参 DTO:`Deserialize` + garde `Validate`,handler 校验后 `.into_input()` 成库的领域 input。
//!
//! owner/tenant 约定见 routes.rs:owner_id = 认证主体的 UUID(不入参);tenant_id 单租户脚手架默认 nil。

use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use content::{
    Content, ContentMetadata, Object, SetContentMetadataInput, UpdateContentInput, UploadOutcome,
};

/// 内容主体的对外响应(投影 `content::Content`;`status` 投影成字符串)。
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub owner_type: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub document_type: Option<String>,
    /// 生命周期状态(created/uploading/uploaded/processing/processed/failed/archived)。
    pub status: String,
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
            status: c.status.as_str().to_owned(),
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
    pub status: String,
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
            status: o.status.as_str().to_owned(),
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
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetContentMetadataRequest {
    #[garde(length(max = 64))]
    pub tags: Vec<String>,
    #[garde(skip)]
    pub file_size: Option<i64>,
    #[garde(inner(length(max = 255)))]
    pub file_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub mime_type: Option<String>,
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
    pub fn into_input(self, content_id: Uuid) -> SetContentMetadataInput {
        SetContentMetadataInput {
            content_id,
            tags: self.tags,
            file_size: self.file_size,
            file_name: self.file_name,
            mime_type: self.mime_type,
            checksum: self.checksum,
            checksum_algorithm: self.checksum_algorithm,
            metadata: self.metadata,
        }
    }
}

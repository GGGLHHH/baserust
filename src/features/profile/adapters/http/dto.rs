//! profile 的 **HTTP 线格式**:请求/响应 JSON + OpenAPI schema,与领域模型互转。类型名即 schema 名。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::features::profile::model;

/// PUT 入参 —— **全量替换**:字段 null/缺省 = 清空(PUT 语义;不是 PATCH 的"跳过不改")。
/// display_name / phone 最长 255;phone 只做长度不做 E.164。
#[derive(Debug, Deserialize, ToSchema)]
pub struct PutProfileRequest {
    pub display_name: Option<String>,
    pub phone: Option<String>,
    /// 绑定头像:必须指向**已 confirm** 的本人栅格图 content(png/jpeg/gif/webp)。
    pub avatar_content_id: Option<Uuid>,
}

impl From<PutProfileRequest> for model::PutProfile {
    fn from(r: PutProfileRequest) -> Self {
        Self {
            display_name: r.display_name,
            phone: r.phone,
            avatar_content_id: r.avatar_content_id,
        }
    }
}

/// 传头像的 multipart 表单形状(只为 OpenAPI 文档,handler 逐字段手解)。
#[derive(Debug, ToSchema)]
#[allow(dead_code)] // 仅供 utoipa 生成 request_body schema,不实际反序列化
pub struct AvatarForm {
    /// 图片本体(必填,带 filename + content-type,须 image/*)。
    #[schema(value_type = String, format = Binary)]
    pub file: String,
}

/// 出参 = 资料字段 + 富化的 `avatar_url`(相对头像端点路径;悬空/未就绪/探测故障 → null)。
/// 时间戳:`/profiles/me` 在资料未建时回空资料,此时为 null;其余端点恒有值。
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileResponse {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub avatar_content_id: Option<Uuid>,
    /// 相对路径 `/api/v1/frontend/profiles/{user_id}/avatar`(单域名哲学,无 base-url 变量;
    /// 头像专用端点,只出本人的头像图 —— content 本体经 `contents/{id}/preview` 严格按 owner 隔离)。
    pub avatar_url: Option<String>,
    /// 资料未建(仅 `/profiles/me` 的空资料)→ null。
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    /// 资料未建(仅 `/profiles/me` 的空资料)→ null。
    #[serde(with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
}

impl From<model::ProfileView> for ProfileResponse {
    fn from(v: model::ProfileView) -> Self {
        Self {
            user_id: v.user_id,
            display_name: v.display_name,
            phone: v.phone,
            avatar_content_id: v.avatar_content_id,
            avatar_url: v.avatar_url,
            created_at: v.created_at,
            updated_at: v.updated_at,
        }
    }
}

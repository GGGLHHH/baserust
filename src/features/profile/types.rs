use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// profile 行(领域形状 = DB 行)。**无 deleted_at**:profile 无删除语义,与 user 同生死
/// (0003 迁移注释已钉);`user_id` 即主键(1:1,天然防一人多行)。
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct Profile {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    /// content 模块的引用(标识非 FK,跨模块);悬空由读侧富化降级(avatar_url=null)。
    pub avatar_content_id: Option<Uuid>,
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// PUT 入参 —— **全量替换**:字段 null/缺省 = 清空(PUT 语义;不是 PATCH 的"跳过不改")。
/// phone 只做长度不做 E.164(刻意:格式是前端/业务关注,脚手架不猜地区)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PutProfileRequest {
    #[garde(inner(length(max = 255)))]
    pub display_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub phone: Option<String>,
    /// 绑定头像:必须指向**已 confirm** 的 image/* content(service 写前经端口三查)。
    #[garde(skip)]
    pub avatar_content_id: Option<Uuid>,
}

/// 传头像的 multipart 表单形状(只为 OpenAPI 文档,handler 逐字段手解)。
#[derive(Debug, ToSchema)]
#[allow(dead_code)] // 仅供 utoipa 生成 request_body schema,不实际反序列化
pub struct AvatarForm {
    /// 图片本体(必填,带 filename + content-type,须 image/*)。
    #[schema(value_type = String, format = Binary)]
    pub file: String,
}

/// 出参 = 行字段 + 富化的 `avatar_url`(相对头像端点路径;悬空/未就绪/探测故障 → null)。
///
/// 时间戳 `Option`:`/profiles/me` 在资料未建时回**空资料**(见 [`ProfileService::get_or_empty`]),
/// 那一刻行还不存在、没有真时间戳 —— 回 null,而不是编一个 now() 冒充。其余端点回的都是真行,恒 `Some`。
///
/// [`ProfileService::get_or_empty`]: super::service::ProfileService::get_or_empty
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

impl ProfileResponse {
    pub fn from_profile(p: Profile, avatar_url: Option<String>) -> Self {
        Self {
            user_id: p.user_id,
            display_name: p.display_name,
            phone: p.phone,
            avatar_content_id: p.avatar_content_id,
            avatar_url,
            created_at: Some(p.created_at),
            updated_at: Some(p.updated_at),
        }
    }

    /// 资料未建时的空壳(各段 null,`user_id` 是调用者本人 —— 前端据此 PUT 建资料)。
    /// **只给 `/profiles/me`**:读别人仍 404(见 `ProfileService::get`)。
    pub fn empty(user_id: Uuid) -> Self {
        Self {
            user_id,
            display_name: None,
            phone: None,
            avatar_content_id: None,
            avatar_url: None,
            created_at: None,
            updated_at: None,
        }
    }
}

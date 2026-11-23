//! profile(用户资料)的**领域模型**:实体、写入字段、PUT 命令(含校验规则)、读模型(含富化的头像
//! 路径)、头像 MIME 准入规则。纯 Rust;请求/响应 JSON 在 `adapters::http::dto`,数据库行在
//! `adapters::postgres`。

use garde::Validate;
use time::OffsetDateTime;
use uuid::Uuid;

/// profile 实体。**无 deleted_at**:profile 无删除语义,与 user 同生死(0003 迁移注释已钉);
/// `user_id` 即主键(1:1,天然防一人多行)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    /// content 模块的引用(标识非 FK,跨模块);悬空由读侧富化降级(avatar_url=None)。
    pub avatar_content_id: Option<Uuid>,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_by: Option<String>,
    pub updated_at: OffsetDateTime,
}

/// 写入的业务字段(全量替换单元)。审计 `by` 单独传:实现体在"建"时落 created_*、"替"时**保留**。
#[derive(Debug, Clone, Default)]
pub struct ProfileFields {
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub avatar_content_id: Option<Uuid>,
}

/// PUT 命令 —— **全量替换**:字段 None = 清空(PUT 语义;不是 PATCH 的"跳过不改")。
/// phone 只做长度不做 E.164(刻意:格式是前端/业务关注,脚手架不猜地区)。
#[derive(Debug, Clone, Validate)]
pub struct PutProfile {
    #[garde(inner(length(max = 255)))]
    pub display_name: Option<String>,
    #[garde(inner(length(max = 255)))]
    pub phone: Option<String>,
    /// 绑定头像:必须指向**已 confirm** 的本人栅格图 content(service 写前经端口校验)。
    #[garde(skip)]
    pub avatar_content_id: Option<Uuid>,
}

/// 读模型 = 实体字段 + 富化的 `avatar_url`(相对头像端点路径;悬空/未就绪/探测故障 → None)。
///
/// 时间戳 `Option`:`get_or_empty` 在资料未建时回**空资料**,那一刻行还不存在、没有真时间戳 ——
/// 回 None,而不是编一个 now() 冒充。其余用例回的都是真行,恒 `Some`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileView {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub avatar_content_id: Option<Uuid>,
    /// 相对路径 `/api/v1/frontend/profiles/{user_id}/avatar`(头像专用端点,只出本人的头像图)。
    pub avatar_url: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

impl ProfileView {
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

    /// 资料未建时的空壳(各段 None,`user_id` 是调用者本人 —— 前端据此 PUT 建资料)。
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

/// 头像准入 MIME 白名单:只收**栅格图**。刻意**排除 `image/svg+xml`**(及其他非栅格 `image/*`)——
/// SVG 是活动内容(可内联脚本);presign 后端把头像 307 直连存储出字节、**无 CSP sandbox**(只有代理
/// 回退分支才加 sandbox),而头像端点任何登录用户跨用户可达 → 恶意 SVG 头像 = 存储型 XSS。收口在上传
/// 边界(两处),从源头挡住,而非依赖出字节时的 `image/*` 前缀"双保险"(它并不排除 SVG)。
pub fn is_allowed_avatar_mime(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

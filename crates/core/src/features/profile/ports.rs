//! profile 的**端口**(实现由适配器 / 组合根提供):
//! - [`ProfileRepo`] 仓储(实现:`in_memory_profile_repo` / `adapters::pg_profile_repo`)
//! - [`AvatarProbe`] 跨模块:头像绑定校验 + 读侧富化只需"content 存在吗/就绪吗/是图吗/谁的"
//!   (端口归消费方,profile 不 import content;实现在 `app/adapters/`,测试替身在 `static_avatar_probe`)

use async_trait::async_trait;
use uuid::Uuid;

use super::model::{Profile, ProfileFields, UpsertedProfile};
use crate::kernel::app_error::AppError;

/// 仓储端口。无删除(profile 无删除语义)、无列表(YAGNI)。
#[async_trait]
pub trait ProfileRepo: Send + Sync {
    /// 未建 → `None`(路由译 404)。
    async fn get(&self, user_id: Uuid) -> Result<Option<Profile>, AppError>;
    /// 按 user_id **批量**取(跨模块富化的根原语:users 列表补 display_name/avatar)。
    /// 一条 SQL(`WHERE user_id = ANY(...)`)解 N+1;查不到的 id 不在结果里(交调用方降级)。
    async fn find_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>, AppError>;
    /// **全量替换 upsert**;`created` = 新建(路由据此 201/200)。
    /// 替换只盖业务字段 + updated_by(updated_at PG 归触发器 / memory 手动),**created_by/created_at 保留**。
    async fn upsert(
        &self,
        user_id: Uuid,
        fields: ProfileFields,
        by: Option<String>,
    ) -> Result<UpsertedProfile, AppError>;
}

/// 头像探测的瘦快照 —— 只含 profile 要的三个事实(窄接口)。
#[derive(Clone, Debug)]
pub struct AvatarInfo {
    pub mime_type: Option<String>,
    /// 已 confirm 可读(Uploaded/Processed/Archived);false = prepare 了没传完(两步上传中途)。
    pub ready: bool,
    /// content 的属主 —— 头像绑定必须是**本人**的 content(防把别人私图"洗"成自己头像)。
    pub owner_id: Uuid,
}

/// 探测端口。`Ok(None)` = content 不存在/已删(能力性缺席,交调用方定语义)。
#[async_trait]
pub trait AvatarProbe: Send + Sync {
    async fn probe(&self, content_id: Uuid) -> Result<Option<AvatarInfo>, AppError>;
}

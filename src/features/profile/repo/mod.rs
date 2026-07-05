//! profile 仓储:契约 + 两实现装配点。
//! **与 widget 的刻意差异**:本模块查询全为固定语句 → 直接 const SQL(sqlx 静态串),
//! 不引 sea-query/Iden/COLS——那套是给动态查询(可选 filter/分页)的,这里没有。

mod memory;
mod postgres;

use async_trait::async_trait;
use uuid::Uuid;

use super::types::Profile;
use crate::infra::error::AppError;

pub use memory::InMemoryProfileRepo;
pub use postgres::PgProfileRepo;

/// 写入的业务字段(全量替换单元)。审计 `by` 单独传:实现体在"建"时落 created_*、"替"时**保留**。
#[derive(Debug, Clone, Default)]
pub struct ProfileFields {
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub avatar_content_id: Option<Uuid>,
}

/// 仓储端口。无删除(profile 无删除语义)、无列表(YAGNI)。
#[async_trait]
pub trait ProfileRepo: Send + Sync {
    /// 未建 → `None`(路由译 404)。
    async fn get(&self, user_id: Uuid) -> Result<Option<Profile>, AppError>;
    /// 按 user_id **批量**取(跨模块富化的根原语:users 列表补 display_name/avatar)。
    /// 一条 SQL(`WHERE user_id = ANY(...)`)解 N+1;查不到的 id 不在结果里(交调用方降级)。
    async fn find_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>, AppError>;
    /// **全量替换 upsert**;bool = 新建(路由据此 201/200)。
    /// 替换只盖业务字段 + updated_by(updated_at PG 归触发器 / memory 手动),**created_by/created_at 保留**。
    async fn upsert(
        &self,
        user_id: Uuid,
        f: ProfileFields,
        by: Option<String>,
    ) -> Result<(Profile, bool), AppError>;
}

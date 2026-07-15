//! search 仓储:**契约(trait)+ 两实现的装配点**。范式同 widget —— trait 与实现分文件。
//!
//! 守卫 upsert 是全模块的重点:idm 与 profile 是两个独立来源、各自的领域事件到达顺序不保证
//! (乱序 / 重放),**每个来源只准写自己的列** + 各自的水位(`idm_seq`/`profile_seq`),事件
//! `seq` 不大于当前水位就跳过 —— 这样重放/乱序投影天然幂等,不会用旧事件覆盖新状态。

mod memory;
mod postgres;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::types::{AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort};
use crate::infra::error::AppError;
use crate::infra::pagination::PageParams;
use crate::infra::sort::SortOrder;

pub use memory::InMemorySearchIndexRepo;
pub use postgres::PgSearchIndexRepo;

/// 仓储端口。所有 `apply_*` 方法都是**守卫 upsert**:仅当 `seq` 严格大于该行当前的对应水位
/// (未见过该 user_id 时水位视作最小值,即"必应用")才写入;否则整次调用是 no-op。
#[async_trait]
pub trait SearchIndexRepo: Send + Sync {
    /// idm `user.created`:写 username/email/email_verified/roles/created_at + `deleted=false` +
    /// `idm_seq`。守卫:`seq > idm_seq`(或该行 `idm_seq` 为空)才应用。
    #[allow(clippy::too_many_arguments)] // 领域事件字段展开,拆参数对象不值当(仅此一处超阈)
    async fn apply_user_created(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        roles: &[String],
        created_at: OffsetDateTime,
        seq: i64,
    ) -> Result<(), AppError>;

    /// idm `user.updated`:只写 username/email/email_verified + `idm_seq`(**不动** roles/created_at/deleted)。
    async fn apply_user_updated(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        seq: i64,
    ) -> Result<(), AppError>;

    /// idm `roles.set`:只写 roles + `idm_seq`。
    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError>;

    /// idm `user.deleted`:只写 `deleted=true` + `idm_seq`。
    async fn apply_user_deleted(&self, user_id: Uuid, seq: i64) -> Result<(), AppError>;

    /// profile `profile.updated`:只写 display_name + `profile_seq`(与 idm 列不相交,独立水位)。
    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        seq: i64,
    ) -> Result<(), AppError>;

    /// 重建 bin 用:**无守卫**全量覆写一行(idm+profile 列一次填全,水位设为快照 max outbox id)。
    async fn rebuild_upsert(&self, row: AdminUserIndexRow) -> Result<(), AppError>;

    /// 重建 bin 用:把**不在快照里**的行扫成 `deleted=true`(+ `idm_seq = p_idm`),返回扫中行数。
    ///
    /// 没有它,rebuild 只能单向收敛:`rebuild_upsert` 能把"索引说已删、源里还活着"改回来,
    /// 却修不了反向的"源里已删、索引还活着"(`UserRepo::list` 不返已删用户 → 那行根本不被触及,
    /// 重跑多少次都还在搜索结果里)。而丢一条 `user.deleted` 正是 projector 明说要靠 rebuild_search
    /// 补的缺口(毒消息跳过 / 流保留期过期),不扫这一刀,"漂移恢复"对删除就是假的。
    ///
    /// 守卫 `idm_seq <= p_idm`:比快照新的行(rebuild 期间刚投影进来的)不动 —— 同"先读 P、再读
    /// 数据"的保守收敛口径。`alive` 为空 = 源里一个存活用户都没有 → 全扫(合法,别当成"没数据别动")。
    async fn mark_deleted_except(&self, alive: &[Uuid], p_idm: i64) -> Result<usize, AppError>;

    /// 测试/P4 用:按 user_id 读一行;不存在 → `None`。
    async fn get(&self, user_id: Uuid) -> Result<Option<AdminUserIndexRow>, AppError>;

    /// CQRS 读路径:动态 filter + 排序 + 分页。基线过滤(`username IS NOT NULL AND !deleted`)
    /// 恒生效 —— partial row(某源未落地)与软删行永不出现在结果里。
    /// cursor 分页是 `user_id` 上的 keyset,方向跟随 `order`(不跟随 `sort`)——因此只在默认
    /// `created_at` 排序时才与 `order` 语义一致(handler 层对非默认 `sort_by` + cursor 组合 422)。
    async fn query(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError>;
}

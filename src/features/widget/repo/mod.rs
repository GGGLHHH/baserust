//! widget 仓储:**契约(trait)+ 共享 Iden/列定义 + 两实现的装配点**。
//! 范式:trait 端口与实现分文件 —— 业务方照抄时一眼看到契约,内存/PG 实现各自独立、互不淹没。

mod memory;
mod postgres;

use async_trait::async_trait;
use sea_query::Iden;
use uuid::Uuid;

use super::types::Widget;
use crate::infra::authz::TenantId;
use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};

pub use memory::InMemoryWidgetRepo;
pub use postgres::PgWidgetRepo;

/// sea-query 表/列标识符。`#[derive(Iden)]` 按 snake_case 渲染:`Widgets::Table` -> "widgets" 等。
#[derive(Iden)]
pub(crate) enum Widgets {
    Table,
    Id,
    TenantId,
    Name,
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    DeletedAt,
}

/// 读列(**不含 deleted_at**:DTO 不暴露)。列名按 name 映射到 `Widget` 的 FromRow 字段。
/// **加列必同步 `Widget` 结构体**:FromRow 按列名匹配,SELECT 少一列 = 运行期
/// `no column found for name`(编译期查不出 —— sea-query 拼串,非 `sqlx::query!` 宏)。
pub(crate) const COLS: [Widgets; 7] = [
    Widgets::Id,
    Widgets::TenantId,
    Widgets::Name,
    Widgets::CreatedBy,
    Widgets::CreatedAt,
    Widgets::UpdatedBy,
    Widgets::UpdatedAt,
];

/// 子表 `widget_tags` 的 sea-query 标识符(父子双表事务样板用)。
#[derive(Iden)]
pub(crate) enum WidgetTags {
    Table,
    Id,
    WidgetId,
    Label,
}

/// 仓储端口。范式:trait 定义数据访问契约,service 依赖 trait 而非实现(内存 ↔ Postgres 可拔插)。
/// 写操作的 `by` = 审计主体(created_by/updated_by),来自 `AuditContext`;时间由 DB default/触发器管。
///
/// # `tenant: TenantId` 是**每个方法的首参**,且**不是 `Option`**
///
/// 漏传编译不过。这是本仓租户隔离的**主防线** —— 它在内存实现下同样生效,而 CI 默认跑的
/// 就是内存模式(对比 Postgres RLS:内存实现里没有等价物,直接违反 conformance 对拍,
/// 见 spec §5.3)。
///
/// 租户过滤**恒在查询层**,与 owner 同理:内存里事后筛会让分页 / total 出错。
/// owner 仍可 `None`(「本租户内看全部」);**租户不行** —— 「不过滤租户」这个状态不可表达。
///
/// 按 id 的查找一律**复合键 `(tenant, id)`**:别租户的 id → `NotFound`(404,不泄露存在),
/// 而**不是**「先按 id 查出来、再让 handler 判租户」—— 那条路一定会有人忘。
/// 这是 OWASP 的建议,但用 Rust 类型系统而非数据库强制。
#[async_trait]
pub trait WidgetRepo: Send + Sync {
    /// 列表分页(offset 跳页 / cursor keyset 双模式,由 `PageParams` 选)。只返回存活行。
    /// `owner = Some(id)` → 只列 `created_by = id` 的行(数据所有权:user 只看自己的);`None` → 全部。
    /// **ownership 过滤在查询层**(非内存事后筛)—— 分页/total 才正确。
    /// `sort_by`/`order` **只在 offset 分支生效**;cursor 分支恒按 id keyset(换排序键会破翻页正确性)。
    async fn list(
        &self,
        tenant: TenantId,
        page: &PageParams,
        owner: Option<&str>,
        sort_by: crate::features::widget::types::WidgetSortField,
        order: crate::infra::sort::SortOrder,
    ) -> Result<Page<Widget>, AppError>;
    /// 按**复合键 `(tenant, id)`** 取存活行;不存在 / 已软删 / **别租户** → NotFound。
    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError>;
    /// 创建;created_by/updated_by 都填 `by`,created_at/updated_at 由 DB default。
    async fn create(
        &self,
        tenant: TenantId,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError>;
    /// 改名(**全量替换**语义,配 PUT)。updated_by 填 `by`,updated_at 由触发器自动盖。已软删 → NotFound。
    /// **不防丢失更新**:两个并发全量写,后写静默覆盖先写。要并发安全 —— 加 `version` 列 +
    /// `WHERE id=? AND version=?`,命中 0 行即 `Conflict`(409),让客户端带最新版本重试。
    /// 脚手架按 YAGNI 不实现,留此提示:照抄全量 PUT 时别忘了这是它的经典脚枪。
    async fn update(
        &self,
        tenant: TenantId,
        id: Uuid,
        name: String,
        by: Option<String>,
    ) -> Result<Widget, AppError>;
    /// 软删除(盖 deleted_at,非物理 DELETE);幂等(已删再删 → NotFound)。
    async fn soft_delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError>;

    /// **父子双表事务范式**:一个原子单元里建 1 个 widget(父)+ N 个 tag(子)。
    /// **全有或全无** —— 任一 label 撞 `(widget_id, label)` 唯一(批内重复)→ 整笔回滚,widget 也不落库。
    /// 事务边界归实现体:PG 内部 `begin/commit`、memory 在一把锁内"先校验后落盘"。
    /// **`sqlx::Transaction` 绝不出现在此签名**(否则泄漏 sqlx、对象安全破、memory 无 Tx 可给)。
    async fn create_with_tags(
        &self,
        tenant: TenantId,
        name: String,
        labels: Vec<String>,
        by: Option<String>,
    ) -> Result<Widget, AppError>;
    /// 取某 widget 的 tag label(label 升序);供读取/测试用。
    async fn tags_of(&self, tenant: TenantId, widget_id: Uuid) -> Result<Vec<String>, AppError>;
}

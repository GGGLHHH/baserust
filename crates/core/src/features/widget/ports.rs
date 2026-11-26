//! widget 的**端口**:核心对外要用的能力,定义成 trait,由适配器在外层实现、组合根注入。
//! - [`WidgetRepo`] 仓储(实现:`adapters::memory` / `adapters::postgres`),**每个方法都带 `tenant`**
//! - [`UserDirectory`] 跨模块富化要的用户目录(实现在组合根 `app/adapters/`,widget 不 import idm)
//! - [`EventBus`] / [`EventSubscription`] 变更事件总线(实现:`adapters::memory` / `adapters::bus`)
//!
//! 端口归**消费方**:widget 只声明"我要什么",窄接口、typed 到自己的领域类型,不做通用总线。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use super::events::WidgetEvent;
use super::model::{Widget, WidgetSortField};
use crate::kernel::error::AppError;
use crate::kernel::pagination::{Page, PageParams};
use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

/// 仓储端口。范式:trait 定义数据访问契约,service 依赖 trait 而非实现(内存 ↔ Postgres 可拔插)。
/// 写操作的 `by` = 审计主体(created_by/updated_by),来自 `AuditContext`;时间由 DB default/触发器管。
///
/// **多租户(spec §4.4)**:每个方法第一个参数都是 `tenant`(handler 从 `CurrentTenant` 提取器取,只来自 token)。
/// 读写都只落在这个租户里:别的租户的行一律当不存在(按 id 取 / 改 / 删 → `NotFound`,列表 / 计数不含,
/// cursor 锚点 → `BadRequest`),名字唯一也只在租户内。
/// - 内存实现没有 RLS,**这个参数是唯一防线**,每条路径都按它过滤;
/// - PG 实现每个方法自己开 `infra::pg::tenant_tx`(事务级 `app.tenant_id`,RLS 兜底)并在 SQL 里**同时**写
///   `tenant_id = $1`(走 `(tenant_id, …)` 索引)。
#[async_trait]
pub trait WidgetRepo: Send + Sync {
    /// 列表分页(offset 跳页 / cursor keyset 双模式,由 `PageParams` 选)。只返回存活行。
    /// `owner = Some(id)` → 只列 `created_by = id` 的行(数据所有权:user 只看自己的);`None` → 全部。
    /// **ownership 过滤在查询层**(非内存事后筛)—— 分页/total 才正确。
    /// `sort_by`/`order` **两个分支都生效**。cursor 分支的 keyset 键随 `sort_by` 走:
    /// `created_at` 用 v7 id 单列代理,其余用 `(key, id)` 复合(键值从锚点行读,cursor payload 不变)。
    /// 哪些键能配 cursor 由 `WidgetSortField::keyset_capable` 圈定,handler 层挡不合格的组合。
    async fn list(
        &self,
        tenant: TenantId,
        page: &PageParams,
        owner: Option<&str>,
        sort_by: WidgetSortField,
        order: SortOrder,
    ) -> Result<Page<Widget>, AppError>;
    /// 按 id 取存活行;不存在/已软删 → NotFound。
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
    /// **`sqlx::Transaction` 绝不出现在此签名**(否则泄漏 sqlx 进核心、对象安全破、memory 无 Tx 可给)。
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

/// 富化用的用户瘦快照 —— **只含 widget 展示要的字段**,不是 idm.User 全貌(窄接口)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserBrief {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
}

/// widget 富化所需的用户目录端口:**一次**按 id 批量解析,防 N+1。
/// 实现见 app/adapters(InProcess 进程内 / 将来 Http 分进程);测试用 `adapters::memory::StaticUserDirectory`。
#[async_trait]
pub trait UserDirectory: Send + Sync {
    /// 批量解析 id→brief;查不到的 id **不在** map 里(交调用方降级)。
    async fn batch_by_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, UserBrief>, AppError>;
}

/// 事件总线端口。发布方(service)与订阅方(SSE handler)都在 widget 模块 —— 端口归消费方。
///
/// 契约(各实现一致,`event_bus_conformance` 一份契约全实现跑):
/// - **fire-and-forget**:publish 失败只落日志,绝不让写操作失败;
/// - **best-effort、无回放**:订阅只收订阅之后的事件,断线丢事件(要回放 = 事件表 + 游标,另一个范式);
/// - 慢消费者掉队(Lagged)跳过继续,不断流。
#[async_trait]
pub trait EventBus: Send + Sync {
    /// fire-and-forget:失败只落日志(warn),**绝不让写操作失败**。
    async fn publish(&self, event: WidgetEvent);
    /// 新订阅,从订阅时刻起收事件(无回放)。
    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError>;
}

/// 一条订阅。`None` = 总线关闭(SSE 流随之正常结束,浏览器 EventSource 自动重连)。
#[async_trait]
pub trait EventSubscription: Send {
    async fn recv(&mut self) -> Option<WidgetEvent>;
}

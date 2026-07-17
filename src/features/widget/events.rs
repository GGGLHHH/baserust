//! widget 变更事件 + **可拔插事件总线端口**(SSE 范式的发布/订阅侧)。
//!
//! 生态没有标准 EventBus 抽象(只有 channel 原语与各家 broker 客户端),正解即本 repo 范式:
//! **端口归消费方、自定义窄 trait、多实现可拔插**(同 `WidgetRepo`/`UserDirectory`)。
//! 端口 typed 到 `WidgetEvent`(窄接口):别的模块要事件,照抄这套自己定义,不做通用总线。
//!
//! **选择链(IoC,组合根 `AppState::new` 装配)**:`NATS_URL` 设了 → [`NatsEventBus`](多实例默认);
//! 没设但有 app pool → [`PgEventBus`](已有 PG 不加组件的退路);都没有 → [`MemoryEventBus`](单实例兜底)。
//!
//! 契约(各实现一致,`event_bus_conformance` 一份契约全实现跑):
//! - **fire-and-forget**:publish 失败只落日志,绝不让写操作失败;
//! - **best-effort、无回放**:订阅只收订阅之后的事件,断线丢事件(要回放 = 事件表 + 游标,另一个范式);
//! - 慢消费者掉队(Lagged)跳过继续,不断流。

use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use super::types::Widget;
use crate::infra::error::AppError;

/// widget 变更事件。SSE 帧的 event name = serde tag(created/updated/deleted)。
///
/// **每个变体都带得出 tenant 与 owner**([`WidgetEvent::tenant`] / [`WidgetEvent::owner`])——
/// SSE handler 要按 `Access` **逐帧**过滤,缺任一维的帧都无法判定:放行=泄露、丢弃=本人收不到
/// 自己的事件。
///
/// `Deleted` 因此单带 `created_by` **与 `tenant_id`** —— 两者理由**逐字同源**:删除后行已软删,
/// 订阅侧无从回查。
///
/// ⚠️ **总线是全局广播**(NATS subject / PG NOTIFY 不分租户),过滤**纯在消费端**。
/// 所以别租户的帧会进本进程内存 —— 但出不去。要连"进内存"都不许,那是按租户分 subject,
/// 另一个威胁模型(spec §7)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetEvent {
    Created {
        widget: Widget,
    },
    Updated {
        widget: Widget,
    },
    Deleted {
        id: Uuid,
        /// 见本枚举 doc:行已软删,订阅侧回查不到 —— 必须随帧带上。
        tenant_id: Uuid,
        created_by: Option<String>,
    },
}

impl WidgetEvent {
    /// SSE event name。与 serde tag 手动保持一致(仅 3 个变体,不值得运行期序列化再解析)。
    pub fn name(&self) -> &'static str {
        match self {
            WidgetEvent::Created { .. } => "created",
            WidgetEvent::Updated { .. } => "updated",
            WidgetEvent::Deleted { .. } => "deleted",
        }
    }

    /// 该事件所指 widget 的 `created_by`(行级 ownership 判定用)。
    /// 喂 [`Access::allows_created_by`](crate::infra::authz::Access::allows_created_by):
    /// `None` / 非 UUID 脏值在 `Own` 下一律不可见 —— 与 list 的 `owner_filter`(`created_by = me`)同口径。
    pub fn owner(&self) -> Option<&str> {
        match self {
            WidgetEvent::Created { widget } | WidgetEvent::Updated { widget } => {
                widget.created_by.as_deref()
            }
            WidgetEvent::Deleted { created_by, .. } => created_by.as_deref(),
        }
    }

    /// 该事件所指 widget 的租户(**租户闸判定用**)。
    ///
    /// 喂 [`Access::allows_created_by`](crate::infra::authz::Access::allows_created_by) 的首参。
    /// 没有它,SSE 订阅端**没有任何东西可以按租户过滤** —— 总线是全局广播,
    /// 别租户的每一帧都会推给你的浏览器。
    pub fn tenant(&self) -> Uuid {
        match self {
            WidgetEvent::Created { widget } | WidgetEvent::Updated { widget } => widget.tenant_id,
            WidgetEvent::Deleted { tenant_id, .. } => *tenant_id,
        }
    }
}

/// 事件总线端口。发布方(service)与订阅方(SSE handler)都在 widget 模块 —— 端口归消费方。
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

// ── 内存实现:tokio broadcast(零依赖默认,单进程测试/开发用)──

/// ponytail: 单实例 —— 多实例各见各的写;跨实例扇出设 NATS_URL(或 PG 退路),见模块头选择链。
pub struct MemoryEventBus {
    tx: broadcast::Sender<WidgetEvent>,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        // 64:突发缓冲。慢消费者超出即 Lagged(跳过),不是背压 —— SSE 场景丢旧事件可接受。
        Self {
            tx: broadcast::channel(64).0,
        }
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for MemoryEventBus {
    async fn publish(&self, event: WidgetEvent) {
        // 无订阅者时 send 返 Err —— 合法状态(没人在看),刻意忽略。
        let _ = self.tx.send(event);
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        Ok(Box::new(MemorySubscription(self.tx.subscribe())))
    }
}

struct MemorySubscription(broadcast::Receiver<WidgetEvent>);

#[async_trait]
impl EventSubscription for MemorySubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.recv().await {
                Ok(e) => return Some(e),
                // 掉队:跳过丢失的继续收,不断流(契约)。
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "事件订阅者掉队,跳过");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

// ── PG 实现:pg_notify / LISTEN(多实例扇出)──
// 注意:publish 走**自己的 pool 连接、独立 autocommit**,不在任何调用方事务里 ——
// 正确性来自 service 只在写成功后 publish。要"回滚不发幽灵事件"的事务性投递,
// 必须在写操作**同一事务连接**上 NOTIFY,本实现不做(需要时把 publish 挪进 repo 事务)。

/// 信任边界:NOTIFY 频道是**数据库级**(不受 schema/search_path 隔离),同库任何 role 都能
/// NOTIFY 本频道,订阅侧只校验形状(serde)不校验来源 —— 能连本库执行 SQL 即视为可信。
/// 事件仅 UI 提示、不回写状态,伪造后果止于展示;要跨信任域投递,换带鉴权的外部 broker。
const CHANNEL: &str = "widget_events";

pub struct PgEventBus {
    pool: sqlx::PgPool,
}

impl PgEventBus {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EventBus for PgEventBus {
    async fn publish(&self, event: WidgetEvent) {
        // ponytail: NOTIFY payload 上限 8000 字节(widget 事件几百字节,富余);超限升级路径 = 只发 id、订阅方回查。
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "widget 事件序列化失败,丢弃");
                return;
            }
        };
        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(&payload)
            .execute(&self.pool)
            .await
        {
            // fire-and-forget 契约:失败只落日志,绝不上抛影响写操作。
            tracing::warn!(error = %e, "widget 事件发布失败(NOTIFY)");
        }
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        // ponytail: 每条订阅从共享 pool 长期占走 1 连接(LISTEN 期间不归还)——
        // SSE 客户端多时会挤兑业务查询;上量再给事件总线独立小 pool / 单连接多路复用。
        let mut listener = PgListener::connect_with(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        listener
            .listen(CHANNEL)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(Box::new(PgSubscription(listener)))
    }
}

struct PgSubscription(PgListener);

#[async_trait]
impl EventSubscription for PgSubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.recv().await {
                // 坏 payload(未来版本混发/人为 NOTIFY):跳过,不断流。
                Ok(n) => match serde_json::from_str(n.payload()) {
                    Ok(e) => return Some(e),
                    Err(e) => tracing::warn!(error = %e, "widget 事件 payload 非法,跳过"),
                },
                // PgListener 自带断线重连;到这说明不可恢复 → 结束流(客户端 EventSource 自动重连)。
                Err(e) => {
                    tracing::warn!(error = %e, "PgListener 断开,事件流结束");
                    return None;
                }
            }
        }
    }
}

// ── NATS 实现:多实例扇出的**默认后端**(选择链最高优先;生产常态用外部 broker)──
// core NATS(非 JetStream):语义与其余实现同契约 —— best-effort、无回放;
// 要持久化/回放/消费组上 JetStream,是另一个范式(事件表+游标的 broker 版)。

/// NATS subject(点分层级是 NATS 惯例;将来 `widget.*` 通配订阅留给消费方)。
const SUBJECT: &str = "widget.events";

/// ponytail: 脚手架连**无鉴权** NATS(compose 默认,内网/开发);网络可达即可发/订。
/// 跨信任域部署给 NATS 配 token/nkey(`ConnectOptions`)+ TLS。
pub struct NatsEventBus {
    client: async_nats::Client,
}

impl NatsEventBus {
    /// 启动期连接,fail-fast(NATS 挂着进程起不来 —— 同 DB pool 的哲学);之后 Client 自动重连。
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let client = async_nats::connect(url)
            .await
            .with_context(|| format!("连接 NATS 失败: {url}"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl EventBus for NatsEventBus {
    async fn publish(&self, event: WidgetEvent) {
        let payload = match serde_json::to_vec(&event) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "widget 事件序列化失败,丢弃");
                return;
            }
        };
        // fire-and-forget 契约:入客户端发送缓冲即返回(自动 flush);失败只落日志,绝不上抛。
        if let Err(e) = self.client.publish(SUBJECT, payload.into()).await {
            tracing::warn!(error = %e, "widget 事件发布失败(NATS)");
        }
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        let sub = self
            .client
            .subscribe(SUBJECT)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(Box::new(NatsSubscription(sub)))
    }
}

struct NatsSubscription(async_nats::Subscriber);

#[async_trait]
impl EventSubscription for NatsSubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.next().await {
                // 坏 payload(版本混发/人为发布):跳过,不断流(同 PG 实现的契约)。
                Some(msg) => match serde_json::from_slice(&msg.payload) {
                    Ok(e) => return Some(e),
                    Err(e) => tracing::warn!(error = %e, "widget 事件 payload 非法,跳过"),
                },
                // 断线由 Client 自动重连、订阅存续(窗口内丢事件,best-effort);
                // 到 None 说明客户端已关闭 → 结束流(客户端 EventSource 自动重连)。
                None => return None,
            }
        }
    }
}

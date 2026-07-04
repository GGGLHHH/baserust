//! widget 变更事件 + **可拔插事件总线端口**(SSE 范式的发布/订阅侧)。
//!
//! 生态没有标准 EventBus 抽象(只有 channel 原语与各家 broker 客户端),正解即本 repo 范式:
//! **端口归消费方、自定义窄 trait、双实现可拔插**(同 `WidgetRepo`/`UserDirectory`)。
//! 端口 typed 到 `WidgetEvent`(窄接口):别的模块要事件,照抄这套自己定义,不做通用总线。
//!
//! 契约(两实现一致,`event_bus_conformance` 钉住):
//! - **fire-and-forget**:publish 失败只落日志,绝不让写操作失败;
//! - **best-effort、无回放**:订阅只收订阅之后的事件,断线丢事件(要回放 = 事件表 + 游标,另一个范式);
//! - 慢消费者掉队(Lagged)跳过继续,不断流。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use super::types::Widget;
use crate::infra::error::AppError;

/// widget 变更事件。SSE 帧的 event name = serde tag(created/updated/deleted)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetEvent {
    Created { widget: Widget },
    Updated { widget: Widget },
    Deleted { id: Uuid },
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

/// ponytail: 单实例 —— 多实例各见各的写;跨实例扇出用 PgEventBus。
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

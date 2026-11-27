//! widget 事件总线端口的**内存实现**:tokio broadcast(零依赖默认,单进程测试 / 开发用)。纯 Rust。

use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::features::widget::ports::{EventBus, EventSubscription};
use crate::features::widget::widget_event::WidgetEvent;
use crate::kernel::app_error::AppError;

/// ponytail: 单实例 —— 多实例各见各的写;跨实例扇出设 NATS_URL(或 PG 退路),见模块头选择链。
pub struct MemoryEventBus {
    tx: broadcast::Sender<WidgetEvent>,
}

impl MemoryEventBus {
    #[must_use]
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
                Ok(event) => return Some(event),
                // 掉队:跳过丢失的继续收,不断流(契约)。
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "事件订阅者掉队,跳过");
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }
}

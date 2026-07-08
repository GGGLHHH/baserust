//! auth_event 实时推送总线(SSE 端点用)。projector 落库成功后 publish,`stream_auth_events`
//! 订阅广播。
//!
//! ponytail: 进程内 `tokio::broadcast`,只覆盖单 idm 实例 —— 多实例部署下每个实例各见各的
//! 投影结果,SSE 客户端连到哪个实例就只收哪个实例投的事件。要多实例扇出,SSE handler 应直接
//! 订阅 JetStream `events.idm.auth.>`(而非经本进程内总线),或换 widget 那套 NATS/PG 退路。

use tokio::sync::broadcast;

use super::types::AuthEventRow;

#[derive(Clone)]
pub struct AuthEventBus {
    tx: broadcast::Sender<AuthEventRow>,
}

impl AuthEventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self { tx }
    }

    /// fire-and-forget:无订阅者时 send 返 Err,忽略(与 widget MemoryEventBus 同契约)。
    pub fn publish(&self, row: AuthEventRow) {
        let _ = self.tx.send(row);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEventRow> {
        self.tx.subscribe()
    }
}

impl Default for AuthEventBus {
    fn default() -> Self {
        Self::new()
    }
}

//! auth_event 实时推送总线(SSE 端点用)。projector 落库成功后 publish,`stream_auth_events`
//! 订阅广播。进程内实现,纯 Rust(tokio broadcast),载荷是领域读模型。
//!
//! ponytail: 进程内 `tokio::broadcast`,只覆盖单 idm 实例 —— 多实例部署下每个实例各见各的
//! 投影结果,SSE 客户端连到哪个实例就只收哪个实例投的事件。要多实例扇出,SSE handler 应直接
//! 订阅 JetStream `events.idm.auth.>`(而非经本进程内总线),或换 widget 那套 NATS/PG 退路。

use tokio::sync::broadcast;

use super::model::AuthEventRow;

/// 认证事件的进程内广播总线(容量 256;慢订阅者掉队即丢旧事件,SSE 场景可接受)。`Clone` 廉价(共享同一个发送端)。
#[derive(Clone)]
pub struct AuthEventBus {
    tx: broadcast::Sender<AuthEventRow>,
}

impl AuthEventBus {
    #[must_use]
    pub fn new() -> Self {
        let (sender, _receiver) = broadcast::channel(256);
        Self { tx: sender }
    }

    /// fire-and-forget:无订阅者时 send 返 Err,忽略(与 widget MemoryEventBus 同契约)。
    pub fn publish(&self, row: AuthEventRow) {
        let _ = self.tx.send(row);
    }

    /// 新订阅:只收订阅之后发布的事件(无回放)。
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<AuthEventRow> {
        self.tx.subscribe()
    }
}

impl Default for AuthEventBus {
    fn default() -> Self {
        Self::new()
    }
}

//! 通用发件箱源端口(`OutboxSource`)—— relay(P3)消费的**窄端口**,消费方(relay/组合根)拥有,
//! 不 import 任何具体业务/idm 类型。idm 侧 `idm::OutboxRepo`(`OutboxRecord`)、app 侧
//! `PgAppOutbox`/`InMemoryAppOutbox`(`AppOutboxRecord`)各自的具体记录类型经
//! `src/app/adapters/` 里的适配器翻译成本文件的 `OutboxItem` —— 胶水只在组合根,本层零业务耦合。
//!
//! wire 格式(`subject`/`event_id` 命名 + envelope 形状)只在 [`build_outbox_item`] 定一份,
//! 所有适配器共用,避免"两处拼字符串、迟早不一致"。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::infra::error::AppError;

/// relay 从某个发件箱源拉到的一条待发布事件 —— 已是发布就绪的形状
/// (`subject` + `event_id` 作未来 JetStream `Nats-Msg-Id` 去重键 + 序列化好的 payload 字节)。
pub struct OutboxItem {
    /// 源表行 id —— 回传给 `mark_published` 用,不进 wire。
    pub id: i64,
    pub subject: String,
    pub event_id: String,
    pub payload: Vec<u8>,
}

/// relay(P3)消费的发件箱源端口。每个 schema(idm / app)各自的具体 outbox 仓储经
/// `src/app/adapters/` 适配实现本 trait —— relay 只认这个窄端口,不 import 具体类型。
#[async_trait]
pub trait OutboxSource: Send + Sync {
    /// 取最早的未发布记录(按 id 升序),最多 `limit` 条。
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxItem>, AppError>;

    /// 标记已发布(幂等)。
    async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError>;
}

/// 各 schema 适配器共用的 wire-format 组装,唯一定义处。`schema` 是 `"idm"`/`"app"`;
/// `id` 是源表行 id(per-schema 自增,兼作 envelope 里的 `seq` —— 后续 P3 projector 拿它当
/// 该 schema 的水位线,不用解析 subject/event_id 字符串)。
pub(crate) fn build_outbox_item(
    schema: &str,
    id: i64,
    event_type: &str,
    aggregate_id: Uuid,
    payload: &Value,
) -> OutboxItem {
    let event_id = format!("{schema}-{id}");
    let envelope = json!({
        "event_id": event_id,
        "schema": schema,
        "type": event_type,
        "aggregate_id": aggregate_id,
        "seq": id,
        "data": payload,
    });
    OutboxItem {
        id,
        subject: format!("events.{schema}.{event_type}"),
        event_id,
        payload: serde_json::to_vec(&envelope)
            .expect("envelope 只含字符串/数字/已验证过的 Value,序列化不会失败"),
    }
}

/// relay 发布事件依赖的窄端口 —— relay 只认这个 trait,不认具体 `JetStreamPublisher`,
/// 换成 fake 就能脱离 NATS 单测(见下方 tests)。`JetStreamPublisher` 的实现见
/// `src/infra/jetstream.rs`,转调它已有的同名 inherent 方法。
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, subject: &str, event_id: &str, payload: &[u8]) -> anyhow::Result<()>;
}

/// 通用发件箱中继:轮询 [`OutboxSource`] → 按 id 升序逐条发布到 [`EventPublisher`] →
/// 只标记发布成功的前缀。发布失败即停止本批(避免标记未发的、避免乱序),
/// 未标记的记录留到下一轮重试 —— at-least-once,JetStream `Nats-Msg-Id` 去重兜底。
pub struct OutboxRelay {
    source: Arc<dyn OutboxSource>,
    publisher: Arc<dyn EventPublisher>,
    poll_interval: Duration,
    batch: i64,
}

impl OutboxRelay {
    pub fn new(
        source: Arc<dyn OutboxSource>,
        publisher: Arc<dyn EventPublisher>,
        poll_interval: Duration,
        batch: i64,
    ) -> Self {
        Self {
            source,
            publisher,
            poll_interval,
            batch,
        }
    }

    /// 一轮:poll → 逐条 publish(id 升序,首次失败即停)→ 标记已发布前缀。
    /// 拆成独立方法是为了脱离真实 sleep/shutdown 循环单测(见 tests)。
    async fn poll_once(&self) {
        let items = match self.source.poll_unpublished(self.batch).await {
            Ok(items) => items,
            Err(err) => {
                tracing::warn!(error = %err, "outbox poll_unpublished 失败,下轮重试");
                return;
            }
        };

        let mut published_ids = Vec::with_capacity(items.len());
        for item in items {
            match self
                .publisher
                .publish(&item.subject, &item.event_id, &item.payload)
                .await
            {
                Ok(()) => published_ids.push(item.id),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        event_id = %item.event_id,
                        "outbox publish 失败,停止本批以保序,下轮重试"
                    );
                    break;
                }
            }
        }

        if !published_ids.is_empty() {
            if let Err(err) = self.source.mark_published(&published_ids).await {
                tracing::warn!(error = %err, "outbox mark_published 失败,下轮重试(可能重复发布)");
            }
        }
    }

    /// 后台循环:poll_once → 睡 `poll_interval` 或等 shutdown。`shutdown` 置 `true`
    /// 或发送端被丢弃(`changed()` 返回 `Err`)都视为退出信号。
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }

            self.poll_once().await;

            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_subject_event_id_and_envelope() {
        let aggregate_id = Uuid::now_v7();
        let payload = json!({"username": "alice"});
        let item = build_outbox_item("idm", 42, "user.created", aggregate_id, &payload);

        assert_eq!(item.id, 42);
        assert_eq!(item.subject, "events.idm.user.created");
        assert_eq!(item.event_id, "idm-42");

        let envelope: Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(envelope["event_id"], "idm-42");
        assert_eq!(envelope["schema"], "idm");
        assert_eq!(envelope["type"], "user.created");
        assert_eq!(envelope["seq"], 42);
        assert_eq!(envelope["aggregate_id"], aggregate_id.to_string());
        assert_eq!(envelope["data"], payload);
    }

    // ---- OutboxRelay::poll_once —— fake source/publisher,零 NATS/DB 依赖 ----

    fn item(id: i64) -> OutboxItem {
        OutboxItem {
            id,
            subject: format!("events.test.item{id}"),
            event_id: format!("evt-{id}"),
            payload: format!("payload-{id}").into_bytes(),
        }
    }

    /// 内存发件箱源:未发布队列 + 已标记 id 记录。
    struct FakeSource {
        unpublished: std::sync::Mutex<Vec<OutboxItem>>,
        marked: std::sync::Mutex<Vec<i64>>,
    }

    impl FakeSource {
        fn new(items: Vec<OutboxItem>) -> Self {
            Self {
                unpublished: std::sync::Mutex::new(items),
                marked: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OutboxSource for FakeSource {
        async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxItem>, AppError> {
            let guard = self.unpublished.lock().unwrap();
            Ok(guard
                .iter()
                .take(limit.max(0) as usize)
                .map(|it| OutboxItem {
                    id: it.id,
                    subject: it.subject.clone(),
                    event_id: it.event_id.clone(),
                    payload: it.payload.clone(),
                })
                .collect())
        }

        async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
            self.unpublished
                .lock()
                .unwrap()
                .retain(|it| !ids.contains(&it.id));
            self.marked.lock().unwrap().extend_from_slice(ids);
            Ok(())
        }
    }

    /// fake 发布端:记录发布顺序;`fail_event_ids` 中的 event_id 发布时返回 Err
    /// (测试用它模拟"这轮失败、下轮恢复")。
    struct FakePublisher {
        published: std::sync::Mutex<Vec<String>>,
        fail_event_ids: std::sync::Mutex<Vec<String>>,
    }

    impl FakePublisher {
        fn new() -> Self {
            Self {
                published: std::sync::Mutex::new(Vec::new()),
                fail_event_ids: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn fail_on(&self, event_id: &str) {
            self.fail_event_ids
                .lock()
                .unwrap()
                .push(event_id.to_owned());
        }

        fn stop_failing(&self, event_id: &str) {
            self.fail_event_ids
                .lock()
                .unwrap()
                .retain(|id| id != event_id);
        }
    }

    #[async_trait]
    impl EventPublisher for FakePublisher {
        async fn publish(
            &self,
            _subject: &str,
            event_id: &str,
            _payload: &[u8],
        ) -> anyhow::Result<()> {
            if self
                .fail_event_ids
                .lock()
                .unwrap()
                .iter()
                .any(|id| id == event_id)
            {
                anyhow::bail!("fake publish failure for {event_id}");
            }
            self.published.lock().unwrap().push(event_id.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn poll_once_happy_path_publishes_and_marks_in_order() {
        let source = Arc::new(FakeSource::new(vec![item(1), item(2), item(3)]));
        let publisher = Arc::new(FakePublisher::new());
        let relay = OutboxRelay::new(
            source.clone(),
            publisher.clone(),
            Duration::from_secs(60),
            10,
        );

        relay.poll_once().await;

        assert_eq!(
            *publisher.published.lock().unwrap(),
            vec![
                "evt-1".to_string(),
                "evt-2".to_string(),
                "evt-3".to_string()
            ]
        );
        assert_eq!(*source.marked.lock().unwrap(), vec![1, 2, 3]);
        assert!(source.unpublished.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn poll_once_stops_batch_on_first_failure_and_retries_next_round() {
        let source = Arc::new(FakeSource::new(vec![item(1), item(2), item(3)]));
        let publisher = Arc::new(FakePublisher::new());
        publisher.fail_on("evt-2");
        let relay = OutboxRelay::new(
            source.clone(),
            publisher.clone(),
            Duration::from_secs(60),
            10,
        );

        // 第一轮:item1 发布+标记;item2 失败 → 停止,item3 未尝试;2/3 都不标记。
        relay.poll_once().await;
        assert_eq!(
            *publisher.published.lock().unwrap(),
            vec!["evt-1".to_string()]
        );
        assert_eq!(*source.marked.lock().unwrap(), vec![1]);
        let remaining: Vec<i64> = source
            .unpublished
            .lock()
            .unwrap()
            .iter()
            .map(|it| it.id)
            .collect();
        assert_eq!(remaining, vec![2, 3]);

        // 第二轮:publisher 恢复(不再对 evt-2 失败) → 重发 2、3,均标记。
        publisher.stop_failing("evt-2");
        relay.poll_once().await;
        assert_eq!(
            *publisher.published.lock().unwrap(),
            vec![
                "evt-1".to_string(),
                "evt-2".to_string(),
                "evt-3".to_string()
            ]
        );
        assert_eq!(*source.marked.lock().unwrap(), vec![1, 2, 3]);
        assert!(source.unpublished.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn poll_once_empty_poll_does_nothing() {
        let source = Arc::new(FakeSource::new(vec![]));
        let publisher = Arc::new(FakePublisher::new());
        let relay = OutboxRelay::new(
            source.clone(),
            publisher.clone(),
            Duration::from_secs(60),
            10,
        );

        relay.poll_once().await;

        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(source.marked.lock().unwrap().is_empty());
    }
}

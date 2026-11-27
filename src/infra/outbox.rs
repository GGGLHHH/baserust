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
use tokio::sync::watch;
use tokio::time;
use uuid::Uuid;

use crate::infra::telemetry;
use crate::kernel::app_error::AppError;

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

/// 一条源发件箱记录的借用视图([`build_outbox_item`] 的入参)。
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutboxRecordRef<'record> {
    /// `"idm"` / `"app"`。
    pub schema: &'record str,
    /// 源表行 id。
    pub id: i64,
    pub event_type: &'record str,
    pub aggregate_id: Uuid,
    pub payload: &'record Value,
}

/// 各 schema 适配器共用的 wire-format 组装,唯一定义处。`schema` 是 `"idm"`/`"app"`;
/// `id` 是源表行 id(per-schema 自增,兼作 envelope 里的 `seq` —— 后续 P3 projector 拿它当
/// 该 schema 的水位线,不用解析 subject/event_id 字符串)。
///
/// **`tenant_id`**(多租户,spec §4.4):payload 里带合法(非 nil)的 `tenant_id` 就抄到信封上,否则为
/// `null`。租户事件(idm 的 `tenant.*`)、进了租户的认证事件都带;`user.*` / `profile.*`(账号、资料全局)
/// 不带 —— **消费方不得要求它**(按需用 payload 里的那份)。outbox 表本身是全局表,不加列。
pub(crate) fn build_outbox_item(record: OutboxRecordRef<'_>) -> OutboxItem {
    let OutboxRecordRef {
        schema,
        id,
        event_type,
        aggregate_id,
        payload,
    } = record;
    let event_id = format!("{schema}-{id}");
    let envelope = json!({
        "event_id": event_id,
        "schema": schema,
        "type": event_type,
        "aggregate_id": aggregate_id,
        "seq": id,
        "tenant_id": payload_tenant(payload),
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

/// payload 里的 `tenant_id`(合法 UUID 且非 nil)→ 信封上的 `tenant_id`;没有 / 不合法 → None。
fn payload_tenant(payload: &Value) -> Option<Uuid> {
    payload
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|t| !t.is_nil())
}

/// relay 发布事件依赖的窄端口 —— relay 只认这个 trait,不认具体 `JetStreamPublisher`,
/// 换成 fake 就能脱离 NATS 单测(见下方 tests)。`JetStreamPublisher` 的实现见
/// `src/infra/jet_stream_publisher.rs`,转调它已有的同名 inherent 方法。
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// 发布一条事件,**服务端确认持久化后**才返回 `Ok`;`event.event_id` 是去重键。
    async fn publish(&self, event: OutboundEvent<'_>) -> anyhow::Result<()>;
}

/// 要发布的一条事件([`EventPublisher::publish`] 的入参):subject 与去重键都是字符串,按名字区分。
#[derive(Clone, Copy, Debug)]
pub struct OutboundEvent<'event> {
    /// 发到哪个 subject(`events.<source>.<type>`)。
    pub subject: &'event str,
    /// 去重键(JetStream `Nats-Msg-Id`)。
    pub event_id: &'event str,
    /// 序列化好的信封。
    pub payload: &'event [u8],
}

/// 通用发件箱中继:轮询 [`OutboxSource`] → 按 id 升序逐条发布到 [`EventPublisher`] →
/// 只标记发布成功的前缀。发布失败即停止本批(避免标记未发的、避免乱序),
/// 未标记的记录留到下一轮重试 —— at-least-once,JetStream `Nats-Msg-Id` 去重兜底。
pub struct OutboxRelay {
    /// 指标 / 链路里的来源名(`idm` / `app`),见 [`OutboxRelay::named`]。
    name: &'static str,
    source: Arc<dyn OutboxSource>,
    publisher: Arc<dyn EventPublisher>,
    poll_interval: Duration,
    batch_size: i64,
}

impl OutboxRelay {
    /// 每 `poll_interval` 从 `source` 取至多 `batch_size` 条发给 `publisher`;来源名缺省 `outbox`。
    pub fn new(
        source: Arc<dyn OutboxSource>,
        publisher: Arc<dyn EventPublisher>,
        poll_interval: Duration,
        batch_size: i64,
    ) -> Self {
        Self {
            name: "outbox",
            source,
            publisher,
            poll_interval,
            batch_size,
        }
    }

    /// 来源名(指标标签 `source`、链路 span 字段)。
    #[must_use]
    pub fn named(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    /// 一轮:poll → 逐条 publish(id 升序,首次失败即停)→ 标记已发布前缀。
    /// 拆成独立方法是为了脱离真实 sleep/shutdown 循环单测(见 tests)。
    async fn poll_once(&self) {
        use tracing::Instrument;
        let items = match self.source.poll_unpublished(self.batch_size).await {
            Ok(items) => items,
            Err(error) => {
                tracing::warn!(error = %error, "outbox poll_unpublished 失败,下轮重试");
                return;
            }
        };
        let source = self.name;
        telemetry::outbox_polled(source, items.len());
        if items.is_empty() {
            return; // 空轮询不建 span:每秒一轮,记下来全是噪音
        }
        let span = tracing::info_span!("outbox.publish", source, batch = items.len());
        async move {
            let published = self.publish_batch(items).await;
            telemetry::outbox_published(source, published);
        }
        .instrument(span)
        .await;
    }

    /// 逐条发布(id 升序,首次失败即停)→ 标记已发布前缀。返回成功发布的条数。
    async fn publish_batch(&self, items: Vec<OutboxItem>) -> usize {
        let mut published_ids = Vec::with_capacity(items.len());
        for item in items {
            match self
                .publisher
                .publish(OutboundEvent {
                    subject: &item.subject,
                    event_id: &item.event_id,
                    payload: &item.payload,
                })
                .await
            {
                Ok(()) => published_ids.push(item.id),
                Err(error) => {
                    telemetry::outbox_publish_failed(self.name);
                    tracing::warn!(
                        error = %error,
                        event_id = %item.event_id,
                        "outbox publish 失败,停止本批以保序,下轮重试"
                    );
                    break;
                }
            }
        }

        let published = published_ids.len();
        if !published_ids.is_empty() {
            if let Err(error) = self.source.mark_published(&published_ids).await {
                tracing::warn!(error = %error, "outbox mark_published 失败,下轮重试(可能重复发布)");
            }
        }
        published
    }

    /// 后台循环:poll_once → 睡 `poll_interval` 或等 shutdown。`shutdown` 置 `true`
    /// 或发送端被丢弃(`changed()` 返回 `Err`)都视为退出信号。
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        telemetry::outbox_started(self.name);
        loop {
            if *shutdown.borrow() {
                break;
            }

            self.poll_once().await;

            tokio::select! {
                () = time::sleep(self.poll_interval) => {}
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
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn builds_subject_event_id_and_envelope() {
        let aggregate_id = Uuid::now_v7();
        let payload = json!({"username": "alice"});
        let item = build_outbox_item(OutboxRecordRef {
            schema: "idm",
            id: 42,
            event_type: "user.created",
            aggregate_id,
            payload: &payload,
        });

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
        assert!(
            envelope["tenant_id"].is_null(),
            "账号事件没有租户:信封上 tenant_id = null"
        );
    }

    /// 多租户:payload 带 tenant_id → 信封上带同一个;nil / 非 UUID 不当租户。
    #[test]
    fn envelope_carries_tenant_id_from_payload() {
        let tenant = Uuid::now_v7();
        let user = Uuid::now_v7();
        let payload = json!({ "tenant_id": tenant, "user_id": user, "roles": ["admin"] });
        let item = build_outbox_item(OutboxRecordRef {
            schema: "idm",
            id: 7,
            event_type: "tenant.member_added",
            aggregate_id: tenant,
            payload: &payload,
        });
        let envelope: Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(envelope["tenant_id"], tenant.to_string());
        assert_eq!(envelope["data"], payload, "payload 原样不动");

        for bad in [
            json!({ "tenant_id": Uuid::nil() }),
            json!({ "tenant_id": "nope" }),
        ] {
            let item = build_outbox_item(OutboxRecordRef {
                schema: "idm",
                id: 8,
                event_type: "tenant.member_added",
                aggregate_id: tenant,
                payload: &bad,
            });
            let envelope: Value = serde_json::from_slice(&item.payload).unwrap();
            assert!(envelope["tenant_id"].is_null(), "{bad}: 不是合法租户");
        }
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
        unpublished: Mutex<Vec<OutboxItem>>,
        marked: Mutex<Vec<i64>>,
    }

    impl FakeSource {
        fn new(items: Vec<OutboxItem>) -> Self {
            Self {
                unpublished: Mutex::new(items),
                marked: Mutex::new(Vec::new()),
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
                .map(|pending| OutboxItem {
                    id: pending.id,
                    subject: pending.subject.clone(),
                    event_id: pending.event_id.clone(),
                    payload: pending.payload.clone(),
                })
                .collect())
        }

        async fn mark_published(&self, ids: &[i64]) -> Result<(), AppError> {
            self.unpublished
                .lock()
                .unwrap()
                .retain(|pending| !ids.contains(&pending.id));
            self.marked.lock().unwrap().extend_from_slice(ids);
            Ok(())
        }
    }

    /// fake 发布端:记录发布顺序;`fail_event_ids` 中的 event_id 发布时返回 Err
    /// (测试用它模拟"这轮失败、下轮恢复")。
    struct FakePublisher {
        published: Mutex<Vec<String>>,
        fail_event_ids: Mutex<Vec<String>>,
    }

    impl FakePublisher {
        fn new() -> Self {
            Self {
                published: Mutex::new(Vec::new()),
                fail_event_ids: Mutex::new(Vec::new()),
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
        async fn publish(&self, event: OutboundEvent<'_>) -> anyhow::Result<()> {
            let event_id = event.event_id;
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
            .map(|pending| pending.id)
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

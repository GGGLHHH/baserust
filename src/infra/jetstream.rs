//! JetStream 发布端 —— durable events(P1)的投递通道,relay(P3)拉 [`crate::infra::outbox::OutboxSource`]
//! 后调本模块发布。**与 `src/features/widget/events.rs` 的 `NatsEventBus` 是两条平行路径,互不复用**:
//! 那条是 core NATS、fire-and-forget、无回放(SSE 场景够用);这条要durable(consumer 可回放)+
//! server 端去重(`Nats-Msg-Id`),所以上 JetStream —— 语义不同,故意不共享抽象。
//!
//! stream 名 `USER_SEARCH_EVENTS`,收敛 idm/app 两个 schema 的 outbox 事件(subject 前缀
//! `events.idm.>` / `events.app.>`,与 `outbox::build_outbox_item` 拼的 subject 对齐)。

use std::time::Duration;

use anyhow::Context;
use async_nats::jetstream::{self, stream::Config as StreamConfig};
use async_nats::HeaderMap;
use async_trait::async_trait;

use crate::infra::outbox::EventPublisher;

/// JetStream 流名。relay/projector 读同一个流,名字只在这定义一处。
pub(crate) const STREAM_NAME: &str = "USER_SEARCH_EVENTS";

/// 保留窗口:7 天(P1 只保证近期可回放追赶;更长留给下游自己落地存储)。
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// server 端去重窗口:同一 `Nats-Msg-Id` 在此窗口内重复 publish 只落一次 —— relay 崩溃重试的安全网。
const DUPLICATE_WINDOW: Duration = Duration::from_secs(120);

/// JetStream 发布端。持有 `Context`(内部即 `Client` 的 Arc 句柄,廉价 Clone)。
pub struct JetStreamPublisher {
    js: jetstream::Context,
}

impl JetStreamPublisher {
    /// 启动期连接 + **幂等** ensure stream,fail-fast(同 `NatsEventBus::connect` 的哲学:
    /// NATS 挂着进程起不来,好过带着一个连不上的发布端悄悄跑)。
    /// `get_or_create_stream` 已存在则直接拿句柄、不比对/不覆盖配置 —— 多进程/重启并发调用安全。
    pub async fn connect(nats_url: &str) -> anyhow::Result<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .with_context(|| format!("连接 NATS 失败: {nats_url}"))?;
        let js = jetstream::new(client);
        js.get_or_create_stream(StreamConfig {
            name: STREAM_NAME.to_owned(),
            subjects: vec!["events.idm.>".to_owned(), "events.app.>".to_owned()],
            max_age: MAX_AGE,
            duplicate_window: DUPLICATE_WINDOW,
            ..Default::default()
        })
        .await
        .with_context(|| format!("ensure JetStream 流 {STREAM_NAME} 失败"))?;
        Ok(Self { js })
    }

    /// 发布一条事件到 `subject`,带 `Nats-Msg-Id: event_id`(server 端去重键)。
    /// **等 ack**(而非 fire-and-forget):relay 要确认服务端已持久化才能推进水位线 /
    /// `mark_published`,发丢了下一轮还得能重投 —— 与 widget 那条总线的契约不同。
    pub async fn publish(
        &self,
        subject: &str,
        event_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert("Nats-Msg-Id", event_id);
        self.js
            .publish_with_headers(subject.to_owned(), headers, payload.to_vec().into())
            .await
            .with_context(|| format!("发布事件失败(subject={subject})"))?
            .await
            .with_context(|| format!("等待 JetStream ack 失败(subject={subject})"))?;
        Ok(())
    }
}

/// relay(`OutboxRelay`)靠这个 trait 脱离具体客户端单测;此处只转调上面的 inherent 方法。
#[async_trait]
impl EventPublisher for JetStreamPublisher {
    async fn publish(&self, subject: &str, event_id: &str, payload: &[u8]) -> anyhow::Result<()> {
        JetStreamPublisher::publish(self, subject, event_id, payload).await
    }
}

//! auth_event 投影器:消费 JetStream events.idm.auth.*,投影成 auth_event 读模型。
//! 骨架(Envelope/ApplyError/connect/run)镜像 features::search::projector;仅 apply_message 换成 auth 版。

use std::sync::Arc;

use anyhow::Context;
use async_nats::jetstream::{
    self,
    consumer::{pull, AckPolicy},
};
use futures_util::StreamExt;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::events::AuthEventBus;
use super::repo::{to_row, AuthEventRepo};
use super::types::{
    AuthChannel, AuthEventRow, AuthEventType, AuthOutcome, FailureReason, NewAuthEvent,
};
use crate::infra::jetstream::STREAM_NAME;

#[derive(Debug, Deserialize)]
struct Envelope {
    r#type: String,
    seq: i64,
    data: serde_json::Value,
}

/// envelope.data 的形状(handler 发射时组装,见 Task 7)。缺省字段 = null。
#[derive(Debug, Deserialize)]
struct AuthEventData {
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    channel: String,
    outcome: String,
    #[serde(default = "default_method")]
    auth_method: String,
    #[serde(default)]
    user_id: Option<Uuid>,
    #[serde(default)]
    identifier_attempted: Option<String>,
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    failure_reason: Option<String>,
    #[serde(default)]
    ip: Option<std::net::IpAddr>,
    #[serde(default)]
    forwarded_chain: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
}
fn default_method() -> String {
    "password".into()
}

/// `apply_message` 的失败分类 —— 决定 ack 与否(语义同 search projector)。
#[derive(Debug)]
pub enum ApplyError {
    Poison(String),
    Transient(crate::infra::error::AppError),
}

/// JetStream durable pull consumer + 投影仓储。持有装配好的 consumer 句柄,`run` 消费到停。
pub struct AuthEventProjector {
    consumer: jetstream::consumer::Consumer<pull::Config>,
    repo: Arc<dyn AuthEventRepo>,
    /// 落库成功后发布给 SSE 订阅者(`/admin/auth/auth-events/stream`)。`None` = 非 needs_idm 进程。
    bus: Option<AuthEventBus>,
}

impl AuthEventProjector {
    /// 连 NATS + 绑定/创建 durable pull consumer(ack 显式);只收 `events.idm.auth.>` 主题,
    /// 与 search projector(无 filter,收全量)井水不犯河水。
    pub async fn connect(
        nats_url: &str,
        repo: Arc<dyn AuthEventRepo>,
        durable_name: &str,
        bus: Option<AuthEventBus>,
    ) -> anyhow::Result<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .with_context(|| format!("连接 NATS 失败: {nats_url}"))?;
        let js = jetstream::new(client);
        let stream = js
            .get_stream(STREAM_NAME)
            .await
            .with_context(|| format!("获取 JetStream 流 {STREAM_NAME} 失败"))?;
        let consumer = stream
            .get_or_create_consumer(
                durable_name,
                pull::Config {
                    durable_name: Some(durable_name.to_owned()),
                    ack_policy: AckPolicy::Explicit,
                    filter_subject: "events.idm.auth.>".to_owned(), // 只收 auth 主题
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("创建/绑定 durable consumer {durable_name} 失败"))?;
        Ok(Self {
            consumer,
            repo,
            bus,
        })
    }

    /// 后台循环:拉消息 → `apply_message` → 成功 ack,失败留待重投;`shutdown` 置位即退出。
    /// 逐字镜像 `features::search::projector::Projector::run`。
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut messages = match self.consumer.messages().await {
            Ok(messages) => messages,
            Err(err) => {
                tracing::error!(error = %err, "projector 无法建立消息流,退出");
                return;
            }
        };

        loop {
            if *shutdown.borrow() {
                break;
            }

            tokio::select! {
                maybe = messages.next() => {
                    let Some(received) = maybe else { break };
                    let msg = match received {
                        Ok(msg) => msg,
                        Err(err) => {
                            tracing::warn!(error = %err, "projector 拉取消息失败,跳过本条");
                            continue;
                        }
                    };
                    // 成功 / 毒消息 → ack(毒消息永不可投,重投无意义、只会死循环);暂时故障 → 不 ack、等重投。
                    let should_ack = match Self::apply_message(&*self.repo, &msg.payload).await {
                        Ok(row) => {
                            // SSE 推送:发布失败(无订阅者)不影响落库结果,fire-and-forget。
                            if let (Some(bus), Some(row)) = (&self.bus, row) {
                                bus.publish(row);
                            }
                            true
                        }
                        Err(ApplyError::Poison(why)) => {
                            tracing::warn!(poison = %why, "projector 跳过不可投的毒消息(ack,不重投)");
                            true
                        }
                        Err(ApplyError::Transient(err)) => {
                            tracing::warn!(error = %err, "projector apply 暂时失败,不 ack、等重投");
                            false
                        }
                    };
                    if should_ack {
                        if let Err(err) = msg.ack().await {
                            tracing::warn!(error = %err, "projector ack 失败");
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    /// 纯路由逻辑(单测入口,不碰 NATS):解 envelope → 非 `auth.*` 忽略(前向兼容)→
    /// 解 `data` → 组装 `NewAuthEvent` → `repo.insert`。成功落库 → `Some(row)`(供 `run()` 发布 SSE);
    /// 非 auth.* 忽略 → `None`。
    async fn apply_message(
        repo: &dyn AuthEventRepo,
        payload: &[u8],
    ) -> Result<Option<AuthEventRow>, ApplyError> {
        let env: Envelope = serde_json::from_slice(payload)
            .map_err(|e| ApplyError::Poison(format!("envelope 反序列化: {e}")))?;
        if !env.r#type.starts_with("auth.") {
            return Ok(None); // 非 auth 事件,忽略(前向兼容)
        }
        let d: AuthEventData = serde_json::from_value(env.data)
            .map_err(|e| ApplyError::Poison(format!("{} data: {e}", env.r#type)))?;
        // 闭集校验在信任边界:wire 来的串必须落在枚举内,否则 Poison —— 不能等到
        // to_row 的 expect 炸 panic(那些 expect 只为"本仓 emit 写入"的不变量背书)。
        env.r#type
            .parse::<AuthEventType>()
            .map_err(ApplyError::Poison)?;
        d.channel
            .parse::<AuthChannel>()
            .map_err(ApplyError::Poison)?;
        d.outcome
            .parse::<AuthOutcome>()
            .map_err(ApplyError::Poison)?;
        if let Some(r) = &d.failure_reason {
            r.parse::<FailureReason>().map_err(ApplyError::Poison)?;
        }
        let new = NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: env.r#type,
            occurred_at: d.occurred_at,
            channel: d.channel,
            auth_method: d.auth_method,
            user_id: d.user_id,
            identifier_attempted: d.identifier_attempted,
            session_id: d.session_id,
            actor: d.actor,
            outcome: d.outcome,
            failure_reason: d.failure_reason,
            ip: d.ip,
            forwarded_chain: d.forwarded_chain,
            user_agent: d.user_agent,
            request_id: d.request_id,
            event_seq: env.seq,
        };
        let row = to_row(&new);
        let inserted = repo.insert(&new).await.map_err(ApplyError::Transient)?;
        // 重投被幂等吞掉 → 不再 SSE 发布(row.id 是本次新造的,库里根本不存在)。
        Ok(inserted.then_some(row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::auth_audit::InMemoryAuthEventRepo;
    use serde_json::json;
    use std::sync::Arc;

    fn envelope(seq: i64, ev_type: &str, data: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "event_id": format!("idm-{seq}"), "schema": "idm", "type": ev_type,
            "aggregate_id": "00000000-0000-0000-0000-000000000000", "seq": seq, "data": data,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn projects_login_succeeded_and_is_idempotent() {
        let repo = Arc::new(InMemoryAuthEventRepo::new());
        let uid = uuid::Uuid::now_v7();
        let payload = envelope(
            7,
            "auth.login_succeeded",
            json!({
                "occurred_at": "2026-07-08T10:00:00Z", "channel": "public", "outcome": "success",
                "user_id": uid, "session_id": uuid::Uuid::now_v7(), "identifier_attempted": null,
                "failure_reason": null, "ip": null, "forwarded_chain": null, "user_agent": null, "request_id": null,
            }),
        );
        AuthEventProjector::apply_message(repo.as_ref(), &payload)
            .await
            .unwrap();
        AuthEventProjector::apply_message(repo.as_ref(), &payload)
            .await
            .unwrap(); // 同 seq 幂等
        assert_eq!(repo.len(), 1);
    }

    #[tokio::test]
    async fn unknown_type_is_ignored_bad_payload_is_poison() {
        let repo = Arc::new(InMemoryAuthEventRepo::new());
        // 非 auth.* → 忽略(Ok)
        AuthEventProjector::apply_message(repo.as_ref(), &envelope(1, "user.created", json!({})))
            .await
            .unwrap();
        // auth.* 但 data 坏 → Poison
        let bad = envelope(2, "auth.login_succeeded", json!({"channel": 123}));
        assert!(matches!(
            AuthEventProjector::apply_message(repo.as_ref(), &bad).await,
            Err(ApplyError::Poison(_))
        ));
        assert_eq!(repo.len(), 0);
    }

    #[tokio::test]
    async fn semantically_bad_enum_string_is_poison_not_panic() {
        let repo = Arc::new(InMemoryAuthEventRepo::new());
        // 类型上合法(String)但语义非法(不在闭集内)→ Poison,不落库、不 panic。
        let payload = envelope(
            99,
            "auth.login_succeeded",
            json!({
                "occurred_at": "2026-07-08T10:00:00Z", "channel": "totally-bogus", "outcome": "success",
                "user_id": null, "session_id": null, "identifier_attempted": null,
                "failure_reason": null, "ip": null, "forwarded_chain": null, "user_agent": null, "request_id": null,
            }),
        );
        let r = AuthEventProjector::apply_message(repo.as_ref(), &payload).await;
        assert!(matches!(r, Err(ApplyError::Poison(_))));
        assert_eq!(repo.len(), 0);
    }
}

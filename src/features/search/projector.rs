//! projector —— JetStream durable pull consumer:解 P1 的 envelope(`infra::outbox::build_outbox_item`
//! 造的 `{event_id,schema,type,aggregate_id,seq,data}`)→ 按 `type` 路由到 [`SearchIndexRepo`] 对应的
//! 守卫 upsert → 成功才 ack(失败留给 JetStream 重投,幂等靠 repo 的 seq 水位吸收)。
//!
//! [`Projector::apply_message`] 是纯路由逻辑,不碰 NATS —— 单测入口;`connect`/`run` 是唯一接 NATS 的地方。

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

use super::repo::SearchIndexRepo;
use crate::infra::error::AppError;
use crate::infra::jetstream::STREAM_NAME;

/// P1 envelope 的 wire 形状(见 `infra::outbox::build_outbox_item`)。`data` 按 `r#type` 分支再解。
#[derive(Debug, Deserialize)]
struct Envelope {
    #[allow(dead_code)] // 路由只按 r#type 分支,schema 暂无消费者用得上,留字段保 envelope 形状完整
    schema: String,
    r#type: String,
    #[allow(dead_code)]
    // data 里的 user_id 与之相等,路由用 data 里的那份;留字段保 envelope 形状完整
    aggregate_id: Uuid,
    seq: i64,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct UserCreatedData {
    user_id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    roles: Vec<String>,
    created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
struct UserUpdatedData {
    user_id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
}

#[derive(Debug, Deserialize)]
struct RolesSetData {
    user_id: Uuid,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeletedData {
    user_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct ProfileUpdatedData {
    user_id: Uuid,
    display_name: Option<String>,
}

/// JetStream durable pull consumer + 投影仓储。持有装配好的 consumer 句柄,`run` 消费到停。
pub struct Projector {
    consumer: jetstream::consumer::Consumer<pull::Config>,
    repo: Arc<dyn SearchIndexRepo>,
}

/// `apply_message` 的失败分类 —— 决定 ack 与否。
#[derive(Debug)]
enum ApplyError {
    /// **毒消息**:载荷永远无法投影(envelope 或 data 反序列化失败,如流里混入非本格式的消息)。
    /// 重投多少次都还是解不了 → **ack 跳过**(记 warn),否则死循环挤爆 max-ack-pending。
    /// 语义丢失由重建 bin 从源头补(投影是去规范化读模型,非真相源)。
    Poison(String),
    /// **暂时故障**:repo/DB 写失败(如库瞬时不可用)。是可恢复的 → **不 ack、等重投**,
    /// 幂等靠 repo 的 seq 水位吸收。不设 max-deliver:at-least-once 要无限重试到库恢复,绝不丢真事件。
    Transient(AppError),
}

impl Projector {
    /// 连 NATS + 绑定/创建 durable pull consumer(ack 显式)。`get_or_create_consumer` 幂等
    /// ——durable 已存在则直接绑定,不比对/不覆盖配置(与 `JetStreamPublisher::connect` 同哲学)。
    pub async fn connect(
        nats_url: &str,
        repo: Arc<dyn SearchIndexRepo>,
        durable_name: &str,
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
                    // 必须盖过 run() 退避梯子的单次最长 sleep(512s):默认 30s 会让服务端
                    // 在原地重试期间判超时重投,副本绕过"保序"且末尾 ack 消不掉它们。
                    ack_wait: std::time::Duration::from_secs(600),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("创建/绑定 durable consumer {durable_name} 失败"))?;
        Ok(Self { consumer, repo })
    }

    /// 后台循环:拉消息 → `apply_message` → 成功 ack,失败留待重投;`shutdown` 置位即退出。
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
                    // 成功 / 毒消息 → ack(毒消息永不可投,重投无意义、只会死循环);
                    // 暂时故障 → **原地重试、不前进**(保序):若跳过本条继续消费,同用户更大 seq
                    // 先落库推高水位后,ack_wait 重投的本条会被 `idm_seq <` 守卫丢弃,
                    // 其独有字段变更(如 email)静默永久丢失。
                    // 重试有上限:Transient 涵盖 repo 的一切错误,含永久性 DB 错(迁移漂移、
                    // 非法字节),无限重试会让单条坏消息冻结全 stream。指数退避 1s→512s
                    // (共 ~17min,盖住常规 DB 抖动/故障切换),仍失败按毒消息跳过 + error 级告警
                    // (数据可经 bin/rebuild_search 回填)。
                    let mut attempt = 0u32;
                    let should_ack = loop {
                        match Self::apply_message(&*self.repo, &msg.payload).await {
                            Ok(()) => break true,
                            Err(ApplyError::Poison(why)) => {
                                tracing::warn!(poison = %why, "projector 跳过不可投的毒消息(ack,不重投)");
                                break true;
                            }
                            Err(ApplyError::Transient(err)) if attempt >= 10 => {
                                tracing::error!(error = %err, attempt, "projector 重试超限,按毒消息跳过(投影缺口需 rebuild_search 回填)");
                                break true;
                            }
                            Err(ApplyError::Transient(err)) => {
                                let backoff = std::time::Duration::from_secs(1 << attempt.min(9));
                                attempt += 1;
                                tracing::warn!(error = %err, attempt, ?backoff, "projector apply 暂时失败,退避后原地重试(保序)");
                                // 续期 ack_wait(WIP):告诉服务端"还在处理",跨多轮退避不被重投。
                                if let Err(e) = msg.ack_with(jetstream::AckKind::Progress).await {
                                    tracing::warn!(error = %e, "ack Progress 续期失败(重投风险,幂等守卫兜底)");
                                }
                                tokio::select! {
                                    _ = tokio::time::sleep(backoff) => {}
                                    changed = shutdown.changed() => {
                                        if changed.is_err() || *shutdown.borrow() {
                                            break false; // 关停:不 ack,留待重投
                                        }
                                    }
                                }
                            }
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

    /// 纯路由逻辑(单测入口,不碰 NATS):解 envelope → 按 `type` 分支解 `data` → 调对应
    /// `repo.apply_*`(`seq` 用 envelope 的、`user_id` 用 data 里的,= aggregate_id)。
    /// 反序列化失败(envelope 或 data)= [`ApplyError::Poison`](调用方 ack 跳过,永不可投);
    /// repo 写失败 = [`ApplyError::Transient`](调用方不 ack、等重投);未知 type 前向兼容忽略(`Ok`)。
    async fn apply_message(repo: &dyn SearchIndexRepo, payload: &[u8]) -> Result<(), ApplyError> {
        let env: Envelope = serde_json::from_slice(payload)
            .map_err(|e| ApplyError::Poison(format!("envelope 反序列化: {e}")))?;

        match env.r#type.as_str() {
            "user.created" => {
                let d: UserCreatedData = serde_json::from_value(env.data)
                    .map_err(|e| ApplyError::Poison(format!("user.created data: {e}")))?;
                repo.apply_user_created(
                    d.user_id,
                    &d.username,
                    d.email.as_deref(),
                    d.email_verified,
                    &d.roles,
                    d.created_at,
                    env.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            "user.updated" => {
                let d: UserUpdatedData = serde_json::from_value(env.data)
                    .map_err(|e| ApplyError::Poison(format!("user.updated data: {e}")))?;
                repo.apply_user_updated(
                    d.user_id,
                    &d.username,
                    d.email.as_deref(),
                    d.email_verified,
                    env.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            "user.roles_set" => {
                let d: RolesSetData = serde_json::from_value(env.data)
                    .map_err(|e| ApplyError::Poison(format!("user.roles_set data: {e}")))?;
                repo.apply_roles_set(d.user_id, &d.roles, env.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "user.deleted" => {
                let d: DeletedData = serde_json::from_value(env.data)
                    .map_err(|e| ApplyError::Poison(format!("user.deleted data: {e}")))?;
                repo.apply_user_deleted(d.user_id, env.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "profile.updated" => {
                let d: ProfileUpdatedData = serde_json::from_value(env.data)
                    .map_err(|e| ApplyError::Poison(format!("profile.updated data: {e}")))?;
                repo.apply_profile_updated(d.user_id, d.display_name.as_deref(), env.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            other => {
                tracing::debug!(
                    event_type = other,
                    "projector 遇到未知事件类型,忽略(前向兼容)"
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::features::search::repo::InMemorySearchIndexRepo;

    fn created_at_fixture() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("有效时间戳")
    }

    #[tokio::test]
    async fn user_created_upserts_username_and_seq() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "idm",
            "type": "user.created",
            "aggregate_id": user_id,
            "seq": 5,
            "data": {
                "user_id": user_id,
                "username": "alice",
                "email": null,
                "email_verified": false,
                "roles": ["user"],
                "created_at": created_at_fixture(),
            }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        let row = repo.get(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.username.as_deref(), Some("alice"));
        assert_eq!(row.idm_seq, Some(5));
        assert!(!row.deleted);
    }

    #[tokio::test]
    async fn profile_updated_upserts_display_name_and_profile_seq() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "app",
            "type": "profile.updated",
            "aggregate_id": user_id,
            "seq": 2,
            "data": { "user_id": user_id, "display_name": "D" }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        let row = repo.get(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.display_name.as_deref(), Some("D"));
        assert_eq!(row.profile_seq, Some(2));
    }

    #[tokio::test]
    async fn roles_set_upserts_roles() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "idm",
            "type": "user.roles_set",
            "aggregate_id": user_id,
            "seq": 8,
            "data": { "user_id": user_id, "roles": ["admin"] }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        let row = repo.get(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.roles, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn user_deleted_marks_deleted() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "idm",
            "type": "user.deleted",
            "aggregate_id": user_id,
            "seq": 9,
            "data": { "user_id": user_id }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        let row = repo.get(user_id).await.unwrap().expect("行已写入");
        assert!(row.deleted);
    }

    #[tokio::test]
    async fn unknown_type_is_ok_and_noop() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "idm",
            "type": "foo.bar",
            "aggregate_id": user_id,
            "seq": 1,
            "data": { "whatever": "value" }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        assert!(repo.get(user_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stale_seq_is_skipped_by_repo_guard() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let created = json!({
            "schema": "idm",
            "type": "user.created",
            "aggregate_id": user_id,
            "seq": 5,
            "data": {
                "user_id": user_id,
                "username": "alice",
                "email": null,
                "email_verified": false,
                "roles": ["user"],
                "created_at": created_at_fixture(),
            }
        });
        Projector::apply_message(&repo, &serde_json::to_vec(&created).unwrap())
            .await
            .unwrap();

        // 陈旧 seq(3 < 已应用的 5):守卫应跳过,username 不变。
        let stale_update = json!({
            "schema": "idm",
            "type": "user.updated",
            "aggregate_id": user_id,
            "seq": 3,
            "data": {
                "user_id": user_id,
                "username": "bob",
                "email": null,
                "email_verified": false,
            }
        });
        Projector::apply_message(&repo, &serde_json::to_vec(&stale_update).unwrap())
            .await
            .unwrap();

        let row = repo.get(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.username.as_deref(), Some("alice"));
        assert_eq!(row.idm_seq, Some(5));
    }

    #[tokio::test]
    async fn known_type_with_bad_data_is_poison() {
        let repo = InMemorySearchIndexRepo::new();
        let envelope = json!({
            "schema": "idm",
            "type": "user.created",
            "aggregate_id": Uuid::now_v7(),
            "seq": 1,
            "data": { "missing": "required fields" }
        });

        let result = Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap()).await;

        assert!(
            matches!(result, Err(ApplyError::Poison(_))),
            "已知 type 的坏 data 应判毒消息(ack 跳过),而非暂时故障"
        );
    }

    #[tokio::test]
    async fn garbage_payload_is_poison_not_transient() {
        // 流里混入非 envelope 格式的消息(如 smoke 测试载荷 / 别的 producer)→ 判毒消息,
        // 调用方 ack 跳过、不死循环重投(bug 修复前会撑爆 max-ack-pending 挡真事件)。
        let repo = InMemorySearchIndexRepo::new();
        let result = Projector::apply_message(&repo, b"not an envelope at all").await;
        assert!(
            matches!(result, Err(ApplyError::Poison(_))),
            "非 envelope 载荷应判毒消息"
        );
    }
}

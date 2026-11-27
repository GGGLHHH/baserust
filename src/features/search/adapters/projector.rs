//! projector(**驱动侧适配器**)—— JetStream durable pull consumer:解 P1 的 envelope(`infra::outbox::build_outbox_item`
//! 造的 `{event_id,schema,type,aggregate_id,seq,data}`)→ 按 `type` 路由到 [`SearchIndexRepo`] 对应的
//! 守卫 upsert → 成功才 ack(失败留给 JetStream 重投,幂等靠 repo 的 seq 水位吸收)。
//!
//! [`Projector::apply_message`] 是纯路由逻辑,不碰 NATS —— 单测入口;`connect`/`run` 是唯一接 NATS 的地方。

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::consumer::{pull, AckPolicy, Consumer};
use async_nats::jetstream::{self, AckKind, Message};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::watch;
use uuid::Uuid;

use crate::features::search::model::{AccountCreated, AccountUpdated};
use crate::features::search::search_index_repo::SearchIndexRepo;
use crate::infra::jet_stream_publisher::{DurableConsumer, STREAM_NAME};
use crate::infra::monitor::ProjectorOutcome;
use crate::kernel::app_error::AppError;
use crate::kernel::tenant_id::TenantId;

/// P1 envelope 的 wire 形状(见 `infra::outbox::build_outbox_item`),只声明本投影器读的字段(`event_id` /
/// `schema` / `aggregate_id` 等由 serde 忽略)。`data` 按 `r#type` 分支再解。
/// `tenant_id`(多租户)只有租户事件带;`user.*` / `profile.*` 没有,本投影器也不依赖它 —— 成员事件
/// 用 `data.tenant_id`(payload 是权威,信封上那份是它的拷贝)。
#[derive(Debug, Deserialize)]
struct Envelope {
    r#type: String,
    seq: i64,
    data: serde_json::Value,
}

/// 订阅的主题:idm 账号事件 + idm 租户 / 成员事件 + app 资料事件。**排除 events.idm.auth.>**(auth_audit
/// projector 的域,同一 stream 平行消费)。
const FILTER_SUBJECTS: [&str; 3] = ["events.idm.user.>", "events.idm.tenant.>", "events.app.>"];

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

/// `tenant.member_*` 的 data(idm `member_payload`):`status` / `roles` 视事件类型可缺。
/// `tenant_id` 反序列化成 `TenantId`:nil → 解析失败 → 毒消息(nil 永远不是合法租户)。
#[derive(Debug, Deserialize)]
struct MemberData {
    tenant_id: TenantId,
    user_id: Uuid,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    roles: Option<Vec<String>>,
}

/// `tenant.deleted` 的 data(只用得上 tenant_id)。
#[derive(Debug, Deserialize)]
struct TenantData {
    tenant_id: TenantId,
}

/// 成员事件里缺 status 时的默认(`member_added` 一定带;老格式兜底)。
const DEFAULT_MEMBER_STATUS: &str = "active";

/// JetStream durable pull consumer + 投影仓储。持有装配好的 consumer 句柄,`run` 消费到停。
pub struct Projector {
    /// durable 消费者名(指标 / 链路标签)。
    name: String,
    consumer: Consumer<pull::Config>,
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
    /// ——durable 已存在则直接绑定,不比对/不覆盖配置(与 `JetStreamPublisher::try_new` 同哲学)。
    pub async fn try_new(
        consumer: DurableConsumer<'_>,
        repo: Arc<dyn SearchIndexRepo>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;

        let DurableConsumer {
            nats_url,
            durable_name,
        } = consumer;

        let client = async_nats::connect(nats_url)
            .await
            .with_context(|| format!("连接 NATS 失败: {nats_url}"))?;
        let jetstream_context = jetstream::new(client);
        let stream = jetstream_context
            .get_stream(STREAM_NAME)
            .await
            .with_context(|| format!("获取 JetStream 流 {STREAM_NAME} 失败"))?;
        let desired = pull::Config {
            durable_name: Some(durable_name.to_owned()),
            ack_policy: AckPolicy::Explicit,
            // 只订阅本 projector 的域(见 FILTER_SUBJECTS);auth.* 归 auth_audit projector。
            filter_subjects: FILTER_SUBJECTS.iter().map(|s| (*s).to_owned()).collect(),
            // 盖过 run() 退避梯子的单次最长 sleep(512s)。存量 durable 的配置见下方的更新兜底;
            // run() 的退避另切 ≤15s 片、每片发 AckKind::Progress 续期。
            ack_wait: Duration::from_secs(600),
            ..Default::default()
        };
        let mut consumer = stream
            .get_or_create_consumer(durable_name, desired.clone())
            .await
            .with_context(|| format!("创建/绑定 durable consumer {durable_name} 失败"))?;
        // get_or_create 对已存在的 durable 只绑定、不更新配置。多租户之前建的 durable 只过滤
        // user.> / app.>,收不到 tenant.*(成员索引就永远是空的)→ 过滤主题不一致时更新它(NATS 2.10+
        // 允许改 filter_subjects)。没设过滤的老 durable 本就收全量,不动(auth.* 在 apply_message 顶部跳过)。
        let current = &consumer.cached_info().config;
        let has_filter = !current.filter_subjects.is_empty() || !current.filter_subject.is_empty();
        if has_filter && current.filter_subjects != desired.filter_subjects {
            match stream.update_consumer(desired).await {
                Ok(updated) => {
                    tracing::info!(
                        durable = durable_name,
                        "projector durable 的过滤主题已更新(加 tenant.*)"
                    );
                    consumer = updated;
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    durable = durable_name,
                    "更新 projector durable 的过滤主题失败:收不到 tenant.* 事件,成员索引要靠 rebuild_search 回填"
                ),
            }
        }
        Ok(Self {
            name: durable_name.to_owned(),
            consumer,
            repo,
        })
    }

    /// 后台循环:拉消息 → `apply_message` → 成功 ack,失败留待重投;`shutdown` 置位即退出。
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        use futures_util::StreamExt;
        use tokio::time;
        use tracing::Instrument;

        use crate::infra::telemetry;

        let mut messages = match self.consumer.messages().await {
            Ok(messages) => messages,
            Err(error) => {
                tracing::error!(error = %error, "projector 无法建立消息流,退出");
                return;
            }
        };

        let mut pending_tick = time::interval(telemetry::CONSUMER_INFO_INTERVAL);
        loop {
            if *shutdown.borrow() {
                break;
            }

            tokio::select! {
                _ = pending_tick.tick() => {
                    telemetry::record_consumer_pending(&self.consumer, &self.name).await;
                }
                maybe = messages.next() => {
                    let Some(received) = maybe else { break };
                    let message = match received {
                        Ok(message) => message,
                        Err(error) => {
                            tracing::warn!(error = %error, "projector 拉取消息失败,跳过本条");
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
                    let mut outcome = ProjectorOutcome::Ok;
                    let span = telemetry::projector_span(&self.name);
                    let should_ack = 'retry: loop {
                        match Self::apply_with_progress(&*self.repo, &message).instrument(span.clone()).await {
                            Ok(()) => break 'retry true,
                            Err(ApplyError::Poison(why)) => {
                                tracing::warn!(poison = %why, "projector 跳过不可投的毒消息(ack,不重投)");
                                outcome = ProjectorOutcome::Poison;
                                break 'retry true;
                            }
                            Err(ApplyError::Transient(error)) if attempt >= 10 => {
                                tracing::error!(error = %error, attempt, "projector 重试超限,按毒消息跳过(投影缺口需 rebuild_search 回填)");
                                outcome = ProjectorOutcome::Dropped;
                                break 'retry true;
                            }
                            Err(ApplyError::Transient(error)) => {
                                let backoff = Duration::from_secs(1 << attempt.min(9));
                                attempt += 1;
                                tracing::warn!(error = %error, attempt, ?backoff, "projector apply 暂时失败,退避后原地重试(保序)");
                                // 退避切成 ≤15s 片、每片先发 AckKind::Progress 续期(WIP):
                                // 不依赖服务端 ack_wait —— 存量 durable 的配置 get_or_create
                                // 不会更新,仍是默认 30s,整段长 sleep 会被判超时重投副本。
                                let mut remaining = backoff;
                                while !remaining.is_zero() {
                                    let slice = remaining.min(Duration::from_secs(15));
                                    if let Err(error) = message.ack_with(AckKind::Progress).await {
                                        tracing::warn!(error = %error, "ack Progress 续期失败(重投风险,幂等守卫兜底)");
                                    }
                                    tokio::select! {
                                        _ = time::sleep(slice) => {}
                                        changed = shutdown.changed() => {
                                            if changed.is_err() || *shutdown.borrow() {
                                                outcome = ProjectorOutcome::Shutdown;
                                                break 'retry false; // 关停:不 ack,留待重投
                                            }
                                        }
                                    }
                                    remaining -= slice;
                                }
                            }
                        }
                    };
                    telemetry::record_projector_message(&self.name, outcome, &message);
                    if should_ack {
                        if let Err(error) = message.ack().await {
                            tracing::warn!(error = %error, "projector ack 失败");
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

    /// `apply_message` 外套 ack_wait 续期:apply 期间每 ≤15s 发一次 `AckKind::Progress`。
    /// 慢 apply(如 DB 故障切换时 sqlx 默认 acquire ~30s 阻塞)在存量 durable(get_or_create
    /// 不更新已存在配置,仍是默认 ack_wait=30s)下会被判超时重投副本 —— 与 `run` 里退避 sleep
    /// 段的续期同源防御,补上 apply 段这段窗口(见 review round-4)。
    async fn apply_with_progress(
        repo: &dyn SearchIndexRepo,
        message: &Message,
    ) -> Result<(), ApplyError> {
        use tokio::time;

        let mut apply = pin!(Self::apply_message(repo, &message.payload));
        loop {
            tokio::select! {
                result = &mut apply => return result,
                _ = time::sleep(Duration::from_secs(15)) => {
                    if let Err(error) = message.ack_with(AckKind::Progress).await {
                        tracing::warn!(error = %error, "ack Progress 续期失败(apply 期间,重投风险)");
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
        let envelope: Envelope = serde_json::from_slice(payload)
            .map_err(|e| ApplyError::Poison(format!("envelope 反序列化: {e}")))?;

        // auth.* 是 auth_audit projector 的域(同一 stream,它按 events.idm.auth.> 过滤消费)。
        // 本(user-search)projector 只管 user.*/profile.*;存量 durable 没设 filter_subjects
        // 时会一并收到 auth.* —— 显式静默跳过(ack),不当"未知类型"刷 debug。
        if envelope.r#type.starts_with("auth.") {
            return Ok(());
        }

        match envelope.r#type.as_str() {
            "user.created" => {
                let data: UserCreatedData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("user.created data: {e}")))?;
                repo.apply_user_created(
                    AccountCreated {
                        user_id: data.user_id,
                        username: &data.username,
                        email: data.email.as_deref(),
                        email_verified: data.email_verified,
                        roles: &data.roles,
                        created_at: data.created_at,
                    },
                    envelope.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            "user.updated" => {
                let data: UserUpdatedData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("user.updated data: {e}")))?;
                repo.apply_user_updated(
                    AccountUpdated {
                        user_id: data.user_id,
                        username: &data.username,
                        email: data.email.as_deref(),
                        email_verified: data.email_verified,
                    },
                    envelope.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            "user.roles_set" => {
                let data: RolesSetData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("user.roles_set data: {e}")))?;
                repo.apply_roles_set(data.user_id, &data.roles, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "user.deleted" => {
                let data: DeletedData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("user.deleted data: {e}")))?;
                repo.apply_user_deleted(data.user_id, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "profile.updated" => {
                let data: ProfileUpdatedData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("profile.updated data: {e}")))?;
                repo.apply_profile_updated(
                    data.user_id,
                    data.display_name.as_deref(),
                    envelope.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            // ── 租户成员(多租户):成员索引一行 = 一个成员关系 ──
            "tenant.member_added" => {
                let data = member_data(envelope.data, "tenant.member_added")?;
                repo.apply_member_added(
                    data.tenant_id,
                    data.user_id,
                    data.status.as_deref().unwrap_or(DEFAULT_MEMBER_STATUS),
                    &data.roles.unwrap_or_default(),
                    envelope.seq,
                )
                .await
                .map_err(ApplyError::Transient)?;
            }
            "tenant.member_updated" => {
                let data = member_data(envelope.data, "tenant.member_updated")?;
                let status = data.status.ok_or_else(|| {
                    ApplyError::Poison("tenant.member_updated data: 缺 status".to_owned())
                })?;
                repo.apply_member_updated(data.tenant_id, data.user_id, &status, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "tenant.member_roles_set" => {
                let data = member_data(envelope.data, "tenant.member_roles_set")?;
                let roles = data.roles.ok_or_else(|| {
                    ApplyError::Poison("tenant.member_roles_set data: 缺 roles".to_owned())
                })?;
                repo.apply_member_roles_set(data.tenant_id, data.user_id, &roles, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "tenant.member_removed" => {
                let data = member_data(envelope.data, "tenant.member_removed")?;
                repo.apply_member_removed(data.tenant_id, data.user_id, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            "tenant.deleted" => {
                let data: TenantData = serde_json::from_value(envelope.data)
                    .map_err(|e| ApplyError::Poison(format!("tenant.deleted data: {e}")))?;
                repo.apply_tenant_deleted(data.tenant_id, envelope.seq)
                    .await
                    .map_err(ApplyError::Transient)?;
            }
            // 租户建 / 改名 / 停用:成员索引不存租户信息,不用投影(停用租户的成员照样在列表里)。
            "tenant.created" | "tenant.updated" => {}
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

/// 解成员事件的 data;解不开 = 毒消息。
fn member_data(data: serde_json::Value, what: &str) -> Result<MemberData, ApplyError> {
    serde_json::from_value(data).map_err(|e| ApplyError::Poison(format!("{what} data: {e}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::features::search::InMemorySearchIndexRepo;

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

        let row = repo.get_account(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.username.as_deref(), Some("alice"));
        assert_eq!(row.idm_sequence, Some(5));
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

        let row = repo.get_account(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.display_name.as_deref(), Some("D"));
        assert_eq!(row.profile_sequence, Some(2));
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

        let row = repo.get_account(user_id).await.unwrap().expect("行已写入");
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

        let row = repo.get_account(user_id).await.unwrap().expect("行已写入");
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

        assert!(repo.get_account(user_id).await.unwrap().is_none());
    }

    /// auth.* 属 auth_audit projector 的域(同一 stream 平行消费):user-search projector
    /// 顶部显式跳过 —— 不落库、不当"未知类型"刷 debug(存量 durable 无 filter_subjects 时的兜底)。
    #[tokio::test]
    async fn auth_events_are_skipped_noop() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        let envelope = json!({
            "schema": "idm",
            "type": "auth.login_succeeded",
            "aggregate_id": user_id,
            "seq": 1,
            "data": { "occurred_at": "2026-07-12T10:00:00Z", "channel": "public", "outcome": "success" }
        });

        Projector::apply_message(&repo, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        assert!(repo.get_account(user_id).await.unwrap().is_none());
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

        let row = repo.get_account(user_id).await.unwrap().expect("行已写入");
        assert_eq!(row.username.as_deref(), Some("alice"));
        assert_eq!(row.idm_sequence, Some(5));
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

    fn envelope_bytes(
        sequence: i64,
        schema: &str,
        event_type: &str,
        data: serde_json::Value,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": schema,
            "type": event_type,
            "aggregate_id": Uuid::now_v7(),
            "seq": sequence,
            "data": data,
        }))
        .unwrap()
    }

    /// 多租户:`tenant.member_*` 落成员索引(一个成员关系一行,账号列从账号目录抄),
    /// `profile.updated` 刷新该用户在所有租户里的行,`tenant.deleted` 让该租户的成员不再出现。
    #[tokio::test]
    async fn projector_handles_member_events() {
        let repo = InMemorySearchIndexRepo::new();
        let tenant_a = TenantId::try_new(Uuid::now_v7()).unwrap();
        let tenant_b = TenantId::try_new(Uuid::now_v7()).unwrap();
        let user_id = Uuid::now_v7();
        let apply = |bytes: Vec<u8>| {
            let repo = &repo;
            async move { Projector::apply_message(repo, &bytes).await.unwrap() }
        };

        apply(envelope_bytes(
            1,
            "idm",
            "user.created",
            json!({
                "user_id": user_id, "username": "alice", "email": null, "email_verified": false,
                "roles": ["superadmin"], "created_at": created_at_fixture(),
            }),
        ))
        .await;
        // 成员事件的 aggregate_id 是租户 id;信封上也带 tenant_id(投影器用 data 里那份)。
        apply(envelope_bytes(
            2,
            "idm",
            "tenant.member_added",
            json!({
                "tenant_id": tenant_a, "user_id": user_id, "status": "active", "roles": ["admin"],
            }),
        ))
        .await;
        apply(envelope_bytes(
            3,
            "idm",
            "tenant.member_added",
            json!({
                "tenant_id": tenant_b, "user_id": user_id, "status": "active", "roles": ["user"],
            }),
        ))
        .await;
        let row = repo
            .get_member(tenant_a, user_id)
            .await
            .unwrap()
            .expect("a 的成员行");
        assert_eq!(row.username.as_deref(), Some("alice"), "账号列从账号目录抄");
        assert_eq!(
            row.roles,
            vec!["admin".to_owned()],
            "roles 是租户角色,不是平台角色"
        );
        assert_eq!(row.status.as_deref(), Some("active"));
        assert_eq!(row.member_sequence, Some(2));

        apply(envelope_bytes(
            4,
            "idm",
            "tenant.member_roles_set",
            json!({
                "tenant_id": tenant_a, "user_id": user_id, "roles": ["user"],
            }),
        ))
        .await;
        apply(envelope_bytes(
            5,
            "idm",
            "tenant.member_updated",
            json!({
                "tenant_id": tenant_a, "user_id": user_id, "status": "inactive",
            }),
        ))
        .await;
        let row = repo.get_member(tenant_a, user_id).await.unwrap().unwrap();
        assert_eq!(row.roles, vec!["user".to_owned()]);
        assert_eq!(row.status.as_deref(), Some("inactive"));

        // 资料全局:一个 profile.updated 刷新两个租户的行。
        apply(envelope_bytes(
            1,
            "app",
            "profile.updated",
            json!({ "user_id": user_id, "display_name": "Alice" }),
        ))
        .await;
        for tenant in [tenant_a, tenant_b] {
            let row = repo.get_member(tenant, user_id).await.unwrap().unwrap();
            assert_eq!(row.display_name.as_deref(), Some("Alice"));
        }

        apply(envelope_bytes(
            6,
            "idm",
            "tenant.member_removed",
            json!({ "tenant_id": tenant_b, "user_id": user_id }),
        ))
        .await;
        assert!(
            repo.get_member(tenant_b, user_id)
                .await
                .unwrap()
                .unwrap()
                .removed
        );
        apply(envelope_bytes(
            7,
            "idm",
            "tenant.deleted",
            json!({ "tenant_id": tenant_a, "slug": "a" }),
        ))
        .await;
        assert!(
            repo.get_member(tenant_a, user_id)
                .await
                .unwrap()
                .unwrap()
                .removed
        );

        // 租户建 / 改名:成员索引不存租户信息 → 无操作、不报错。
        apply(envelope_bytes(
            8,
            "idm",
            "tenant.created",
            json!({
                "tenant_id": Uuid::now_v7(), "slug": "c", "name": "C", "status": "active",
            }),
        ))
        .await;
    }

    /// 成员事件的 data 坏(nil 租户 / 缺必需字段)= 毒消息(ack 跳过),不是暂时故障。
    #[tokio::test]
    async fn bad_member_events_are_poison() {
        let repo = InMemorySearchIndexRepo::new();
        let user_id = Uuid::now_v7();
        for (event_type, data) in [
            (
                "tenant.member_added",
                json!({ "tenant_id": Uuid::nil(), "user_id": user_id }),
            ),
            (
                "tenant.member_updated",
                json!({ "tenant_id": Uuid::now_v7(), "user_id": user_id }),
            ),
            (
                "tenant.member_roles_set",
                json!({ "tenant_id": Uuid::now_v7(), "user_id": user_id }),
            ),
            ("tenant.member_removed", json!({ "user_id": user_id })),
        ] {
            let result =
                Projector::apply_message(&repo, &envelope_bytes(1, "idm", event_type, data)).await;
            assert!(
                matches!(result, Err(ApplyError::Poison(_))),
                "{event_type} 坏 data 应判毒消息"
            );
        }
    }
}

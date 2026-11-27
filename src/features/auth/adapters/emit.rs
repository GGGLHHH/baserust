//! auth 审计事件的组装 + 发射(写 idm.outbox)。发射失败绝不阻断认证(fire-and-forget,
//! warn 落日志)——审计是旁路观测,不能成为登录/登出的单点故障。
//!
//! `occurred_at` 显式格式化成 RFC3339 字符串,不让 `json!` 走 `OffsetDateTime` 的默认
//! `Serialize`:本仓 `time` 依赖未开 `serde-human-readable`,默认走内部 tuple 表示,
//! 与 `auth_audit::auth_event_projector` 侧 `#[serde(with = "time::serde::rfc3339")]` 的字符串期望
//! 不匹配 —— 不显式格式化会让每条事件在投影时变成 Poison(见 `auth_audit::auth_event_projector::apply_message`)。

use idm::OutboxRepo;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::auth_audit::{AuthChannel, AuthEventType, FailureReason};
use crate::infra::client_context::ClientContext;
use crate::infra::telemetry;

/// 把事件写进 idm.outbox。`outbox` 为 `None`(非 needs_idm 进程 / 测试未装)时静默跳过。
/// `event_type` 收枚举而非裸串 —— 调用点编译期防手滑字面量,枚举 → outbox 要的 `&str` 边界内转换。
/// 调用方持 `Option<Arc<dyn OutboxRepo>>` 时传 `.as_deref()`。
pub async fn emit_auth_event(
    outbox: Option<&dyn OutboxRepo>,
    event_type: AuthEventType,
    aggregate_id: Uuid,
    data: Value,
) {
    let event_type = event_type.as_str();
    metrics::counter!(telemetry::AUTH_EVENTS, "event_type" => event_type).increment(1);
    let Some(outbox) = outbox else { return };
    if let Err(error) = outbox.emit(event_type, aggregate_id, data).await {
        tracing::warn!(error = %error, event_type, "auth 审计事件发射失败(不阻断认证)");
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("OffsetDateTime::now_utc() 格式化 RFC3339 不会失败")
}

/// 成功类事件(注册/登录/刷新等,有确定 `user_id` 时用)的主体字段。
#[derive(Clone, Copy, Debug)]
pub struct SuccessEventData<'event> {
    pub channel: AuthChannel,
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
    /// 展示用用户名(读模型 `AuthEventRow.actor`),未知时 `None`(前端回退展示 `user_id`)。
    pub actor: Option<&'event str>,
    /// 事件所在的租户(登录进入的 / 会话所在的 / 切换后的;平台上下文 `None`),
    /// outbox 信封会把它抄到 `tenant_id` 上,auth_event 据此记租户。
    pub tenant_id: Option<Uuid>,
}

/// 成功类事件 payload。
#[must_use]
pub fn success_data(ctx: &ClientContext, event: SuccessEventData<'_>) -> Value {
    let SuccessEventData {
        channel,
        user_id,
        session_id,
        actor,
        tenant_id,
    } = event;
    json!({
        "occurred_at": now_rfc3339(),
        "channel": channel,
        "outcome": "success",
        "user_id": user_id,
        "session_id": session_id,
        "actor": actor,
        "tenant_id": tenant_id,
        "ip": ctx.ip,
        "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent,
        "request_id": ctx.request_id,
    })
}

/// 失败类事件的主体字段。
#[derive(Clone, Copy, Debug)]
pub struct FailureEventData<'event> {
    pub channel: AuthChannel,
    /// 多数失败场景未知(防枚举,`None`);`admin_access_denied` 例外 —— 验密已过、有确定 user_id。
    pub user_id: Option<Uuid>,
    /// 提交的用户名 / 邮箱原文;payload 的 `actor` 复用它(失败场景没有更可信的展示名)。
    pub identifier: Option<&'event str>,
    pub reason: FailureReason,
    /// 只有 `admin_access_denied`(登录已选定了租户)才有。
    pub tenant_id: Option<Uuid>,
}

/// 失败类事件 payload。
#[must_use]
pub fn failure_data(ctx: &ClientContext, event: FailureEventData<'_>) -> Value {
    let FailureEventData {
        channel,
        user_id,
        identifier,
        reason,
        tenant_id,
    } = event;
    json!({
        "occurred_at": now_rfc3339(),
        "channel": channel,
        "outcome": "failure",
        "user_id": user_id,
        "tenant_id": tenant_id,
        "identifier_attempted": identifier,
        "actor": identifier,
        "failure_reason": reason,
        "ip": ctx.ip,
        "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent,
        "request_id": ctx.request_id,
    })
}

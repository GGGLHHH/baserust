//! auth 审计事件的组装 + 发射(写 idm.outbox)。发射失败绝不阻断认证(fire-and-forget,
//! warn 落日志)——审计是旁路观测,不能成为登录/登出的单点故障。
//!
//! `occurred_at` 显式格式化成 RFC3339 字符串,不让 `json!` 走 `OffsetDateTime` 的默认
//! `Serialize`:本仓 `time` 依赖未开 `serde-human-readable`,默认走内部 tuple 表示,
//! 与 `auth_audit::projector` 侧 `#[serde(with = "time::serde::rfc3339")]` 的字符串期望
//! 不匹配 —— 不显式格式化会让每条事件在投影时变成 Poison(见 `auth_audit::projector::apply_message`)。

use std::sync::Arc;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::auth_audit::{AuthChannel, AuthEventType, FailureReason};
use crate::infra::client_context::ClientContext;

/// 把事件写进 idm.outbox。`outbox` 为 `None`(非 needs_idm 进程 / 测试未装)时静默跳过。
/// `event_type` 收枚举而非裸串 —— 调用点编译期防手滑字面量,枚举 → outbox 要的 `&str` 边界内转换。
pub async fn emit_auth_event(
    outbox: &Option<Arc<dyn idm::OutboxRepo>>,
    event_type: AuthEventType,
    aggregate_id: Uuid,
    data: Value,
) {
    let Some(outbox) = outbox else { return };
    let event_type = event_type.as_str();
    if let Err(e) = outbox.emit(event_type, aggregate_id, data).await {
        tracing::warn!(error = %e, event_type, "auth 审计事件发射失败(不阻断认证)");
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("OffsetDateTime::now_utc() 格式化 RFC3339 不会失败")
}

/// 成功类事件 payload(注册/登录/刷新等,有确定 `user_id` 时用)。`actor` = 展示用用户名
/// (读模型 `AuthEventRow.actor`),未知时传 `None`(前端回退展示 `user_id`)。
pub fn success_data(
    ctx: &ClientContext,
    channel: AuthChannel,
    user_id: Uuid,
    session_id: Option<Uuid>,
    actor: Option<&str>,
) -> Value {
    json!({
        "occurred_at": now_rfc3339(),
        "channel": channel,
        "outcome": "success",
        "user_id": user_id,
        "session_id": session_id,
        "actor": actor,
        "ip": ctx.ip,
        "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent,
        "request_id": ctx.request_id,
    })
}

/// 登出:`AuthService::logout` 现在连 `user_id` 一并返回(被撤会话本身携带),故与
/// `success_data` 分开一个更窄的变体,但 `user_id`/`session_id` 都带,支持按用户查审计历史。
pub fn session_event_data(
    ctx: &ClientContext,
    channel: AuthChannel,
    user_id: Uuid,
    session_id: Uuid,
    actor: Option<&str>,
) -> Value {
    json!({
        "occurred_at": now_rfc3339(),
        "channel": channel,
        "outcome": "success",
        "user_id": user_id,
        "session_id": session_id,
        "actor": actor,
        "ip": ctx.ip,
        "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent,
        "request_id": ctx.request_id,
    })
}

/// 失败类事件 payload。`user_id` 多数失败场景未知(防枚举,传 `None`);
/// `admin_access_denied` 例外 —— 验密已过、有确定 user_id,传 `Some`。`actor` 复用
/// `identifier`(提交的用户名/邮箱原文,失败场景没有更可信的展示名)。
pub fn failure_data(
    ctx: &ClientContext,
    channel: AuthChannel,
    user_id: Option<Uuid>,
    identifier: Option<&str>,
    reason: FailureReason,
) -> Value {
    json!({
        "occurred_at": now_rfc3339(),
        "channel": channel,
        "outcome": "failure",
        "user_id": user_id,
        "identifier_attempted": identifier,
        "actor": identifier,
        "failure_reason": reason,
        "ip": ctx.ip,
        "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent,
        "request_id": ctx.request_id,
    })
}

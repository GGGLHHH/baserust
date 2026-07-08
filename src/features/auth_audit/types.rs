use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// 写模型:projector 从 envelope 组装后交 repo 落库(Phase 1 富化列不在此,DB 默认 null)。
#[derive(Debug, Clone)]
pub struct NewAuthEvent {
    pub id: Uuid,
    pub event_type: String,
    pub occurred_at: OffsetDateTime,
    pub channel: String,
    pub auth_method: String,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub actor: Option<String>,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub event_seq: i64,
}

/// 读模型行(admin 端点返回)。
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AuthEventRow {
    pub id: Uuid,
    pub event_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub channel: String,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub ip: Option<String>, // inet → 文本回传
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// 列表过滤(admin)。空 = 不限。
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub ip: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
}

//! 审计上下文:谁在操作。范式 —— 请求边界产 `AuditContext`(将来接 auth 的**唯一**改动点),
//! 经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 现状无 auth:用户请求 = `Anonymous` → 审计列写 NULL(诚实表达"当时不知道是谁",
//! 不伪造 "system");只有真·系统链路(seeder/job/迁移)= `System` → "system"。
//! 时间戳不在这里管:`created_at` 由 DB default、`updated_at` 由触发器自动维护。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

/// 操作主体。将来接 auth 时只填充 `User` 分支,下游签名不变。
/// System/User 是接 auth/seeder 前的预留分支,当前 extractor 只构造 Anonymous。
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Actor {
    /// 真·系统操作:seeder / 后台 job / 迁移(无人类发起者)。
    System,
    /// 未认证请求 —— 当前所有 HTTP 请求都是这个。
    Anonymous,
    /// 已认证用户(Phase 2 接 auth 后从校验过的 principal 来)。
    User { id: String },
}

impl Actor {
    /// 落到 `created_by`/`updated_by` 的值;不知道是谁就 `None`(写 NULL)。
    pub fn audit_id(&self) -> Option<String> {
        match self {
            Actor::System => Some("system".to_owned()),
            Actor::Anonymous => None,
            Actor::User { id } => Some(id.clone()),
        }
    }
}

/// 请求作用域审计上下文 —— "将来接 auth 平滑替换"的接口。写操作经它取审计主体。
#[derive(Clone, Debug)]
pub struct AuditContext {
    pub actor: Actor,
    /// 关联日志的 request-id(来自 tower-http 设的 x-request-id)。预留:接审计落库/日志关联时消费。
    #[allow(dead_code)]
    pub request_id: Option<String>,
}

impl AuditContext {
    /// 系统链路(无 HTTP 请求):seeder / 后台 job 用。预留接口(暂无调用方)。
    #[allow(dead_code)]
    pub fn system() -> Self {
        Self {
            actor: Actor::System,
            request_id: None,
        }
    }

    pub fn anonymous(request_id: Option<String>) -> Self {
        Self {
            actor: Actor::Anonymous,
            request_id,
        }
    }

    /// 写操作要落库的审计主体(created_by/updated_by)。
    pub fn audit_id(&self) -> Option<String> {
        self.actor.audit_id()
    }
}

/// extractor:现在一律产 `Anonymous` + 串上已有的 request-id(SetRequestIdLayer 设的 header)。
/// Phase 2 接 auth 时,改这里从校验过的 token 构 `Actor::User{id}`,下游 handler 签名不变。
impl<S: Send + Sync> FromRequestParts<S> for AuditContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(AuditContext::anonymous(request_id))
    }
}

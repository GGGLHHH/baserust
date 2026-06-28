//! 审计上下文 + 鉴权身份。范式 —— 请求边界产 `AuditContext`,经 service 下传给 repo,
//! 落到 `created_by`/`updated_by`。
//!
//! 鉴权中间件(idm)验过 JWT 后,在 `request.extensions` 塞一个 [`AuthUser`];
//! `AuditContext` 与 `CurrentUser` 都只**读** extension —— token 校验是单一真相源(中间件),
//! 这两个提取器不碰 JWT。`AuthUser` 定义在 infra(横切),由 idm 填充,避免 infra 依赖 features。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::error::IdmError;

/// 鉴权中间件验过 JWT 后塞进 `request.extensions` 的已认证身份(含角色,供 require_role 判权)。
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
}

/// 操作主体。`User` 由鉴权中间件经 extension 填充;`System` 给 seeder/job;`Anonymous` 给未认证请求。
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Actor {
    /// 真·系统操作:seeder / 后台 job / 迁移(无人类发起者)。
    System,
    /// 未认证请求(无有效 token)。
    Anonymous,
    /// 已认证用户(从 extension 的 `AuthUser` 来)。
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

/// 请求作用域审计上下文 —— 写操作经它取审计主体。
#[derive(Clone, Debug)]
pub struct AuditContext {
    pub actor: Actor,
    /// 关联日志的 request-id(来自 tower-http 设的 x-request-id)。预留:接审计落库/日志关联时消费。
    #[allow(dead_code)]
    pub request_id: Option<String>,
}

impl AuditContext {
    /// 系统链路(无 HTTP 请求):seeder / 后台 job 用。
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

/// extractor:鉴权中间件验过 JWT 会在 extensions 塞 `AuthUser`;有 → `User`,无 → `Anonymous`。
/// 下游 handler 签名不变,审计列(created_by/updated_by)自动从这里灌入。**这是接 auth 的唯一改动点**。
impl<S: Send + Sync> FromRequestParts<S> for AuditContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let actor = match parts.extensions.get::<AuthUser>() {
            Some(u) => Actor::User {
                id: u.id.to_string(),
            },
            None => Actor::Anonymous,
        };
        Ok(Self { actor, request_id })
    }
}

/// 受保护端点提取器:**必须已认证**。读鉴权中间件塞的 `AuthUser`;无(未带/非法 token)→ 401。
pub struct CurrentUser(pub AuthUser);

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = IdmError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(CurrentUser)
            .ok_or(IdmError::Unauthorized)
    }
}

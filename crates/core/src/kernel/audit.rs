//! 审计上下文:写操作的操作主体,经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 核心侧只有数据;从 HTTP 请求里取主体的提取器(`AuditContext` / `CurrentUser`)归 `infra::http::audit`。

/// 操作主体。`User` 由鉴权中间件经 extension 填充;`System` 给 seeder/job;`Anonymous` 给未认证请求。
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
}

impl AuditContext {
    /// 系统链路(无 HTTP 请求):seeder / 后台 job 用。
    pub fn system() -> Self {
        Self {
            actor: Actor::System,
        }
    }

    pub fn anonymous() -> Self {
        Self {
            actor: Actor::Anonymous,
        }
    }

    /// 写操作要落库的审计主体(created_by/updated_by)。
    pub fn audit_id(&self) -> Option<String> {
        self.actor.audit_id()
    }
}

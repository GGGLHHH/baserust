//! 审计上下文:写操作的操作主体,经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 核心侧只有数据;从 HTTP 请求里取主体的提取器(`AuditContext` / `CurrentUser`)归 `infra::http::audit`。

use super::tenant::TenantId;

/// 操作主体。`User` 由鉴权中间件经 extension 填充;`System` 给 seeder/job;`Anonymous` 给未认证请求。
#[derive(Clone, Debug)]
pub enum Actor {
    /// 真·系统操作:seeder / 后台 job / 迁移(无人类发起者)。
    System,
    /// 未认证请求(无有效 token)。
    Anonymous,
    /// 已认证用户(从 extension 的 `AuthUser` 来)。`tenant_id` = 该请求 token 的当前租户
    /// (平台上下文 → `None`),与 [`AuditContext::tenant_id`] 同值。
    User {
        id: String,
        tenant_id: Option<TenantId>,
    },
}

impl Actor {
    /// 落到 `created_by`/`updated_by` 的值;不知道是谁就 `None`(写 NULL)。
    pub fn audit_id(&self) -> Option<String> {
        match self {
            Actor::System => Some("system".to_owned()),
            Actor::Anonymous => None,
            Actor::User { id, .. } => Some(id.clone()),
        }
    }

    /// 操作发生在哪个租户(审计 / 日志用)。系统 / 匿名 / 平台上下文 → `None`。
    pub fn tenant_id(&self) -> Option<TenantId> {
        match self {
            Actor::User { tenant_id, .. } => *tenant_id,
            Actor::System | Actor::Anonymous => None,
        }
    }
}

/// 请求作用域审计上下文 —— 写操作经它取审计主体。
#[derive(Clone, Debug)]
pub struct AuditContext {
    pub actor: Actor,
    /// 请求所在租户(token 的当前租户)。**只作审计记录**:租户级仓储方法的租户参数一律来自
    /// `CurrentTenant` 提取器(缺租户即 403),不从这里兜底取。
    pub tenant_id: Option<TenantId>,
}

impl AuditContext {
    /// 系统链路(无 HTTP 请求):seeder / 后台 job 用。
    pub fn system() -> Self {
        Self {
            actor: Actor::System,
            tenant_id: None,
        }
    }

    pub fn anonymous() -> Self {
        Self {
            actor: Actor::Anonymous,
            tenant_id: None,
        }
    }

    /// 已认证用户(鉴权提取器用)。
    pub fn user(id: String, tenant_id: Option<TenantId>) -> Self {
        Self {
            actor: Actor::User { id, tenant_id },
            tenant_id,
        }
    }

    /// 写操作要落库的审计主体(created_by/updated_by)。
    pub fn audit_id(&self) -> Option<String> {
        self.actor.audit_id()
    }
}

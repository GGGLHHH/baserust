//! auth 的**跨模块需求端口**:切租户要知道「这人属于哪些公司」、以及记下他的选择。
//!
//! 端口归**消费方**(auth 只声明"我要什么",不 import tenants);实现/适配在组合根
//! (`app/adapters/`)。这是 ports-and-adapters 的 port 一侧,与 `widget/port.rs` 同范式。
//!
//! # 为什么切租户归 auth
//!
//! 它是个**认证动作**:重新铸币、轮换会话、发认证审计事件、写认证 cookie。它从 tenants
//! 要的只有两件事 —— 「这人是不是成员」和「记下他选了哪个」。那就是下面这个端口的全部。

use async_trait::async_trait;
use uuid::Uuid;

use crate::infra::error::AppError;

/// 一家公司的**瘦快照** —— 只含 auth 要的字段,不是 tenants 领域实体的全貌(窄接口)。
///
/// **没有 `role`**:切换器需要的是「有哪几家、我现在在哪」,不是「我在这家是什么头衔」。
/// 而「我在这家能干什么」是权限问题,P4/P5 让 `/permissions/me` 按租户回答才是对的形状。
/// 真需要时再加 —— 那时会有真实消费方来告诉我们它要的到底是什么。
pub struct TenantBrief {
    pub id: Uuid,
    /// 机器码 slug(= `tenants.name`)。
    pub name: String,
    pub display_name: String,
}

/// auth 切租户所需的租户目录端口。实现见 `app/adapters`(进程内 / 将来分进程)。
#[async_trait]
pub trait TenantDirectory: Send + Sync {
    /// 此人的全部**有效**成员资格(已过滤停用/软删的租户),**按加入顺序**(最早在前)。
    ///
    /// 顺序是契约不是巧合:0 租户以外的用户,没显式选过时铸币回退到第一个 ——
    /// 它决定了新人默认落进哪家公司。
    async fn memberships_of(&self, user_id: Uuid) -> Result<Vec<TenantBrief>, AppError>;

    /// 记下此人的激活选择。
    ///
    /// **不校验成员资格** —— 调用方必须先自己确认(`memberships_of` 里有没有)。
    /// 故意的:校验与写分开,让 handler 里那句 404 是显式的、看得见的一行,
    /// 而不是藏在这个方法内部的一个你得去读实现才知道的行为。
    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError>;
}

/// 静态实现:预置成员资格 —— 测试用(无需真连 idm 库)。`empty()` = 0 租户的用户。
pub struct StaticTenantDirectory(pub Vec<TenantBrief>);

impl StaticTenantDirectory {
    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

#[async_trait]
impl TenantDirectory for StaticTenantDirectory {
    async fn memberships_of(&self, _user_id: Uuid) -> Result<Vec<TenantBrief>, AppError> {
        Ok(self
            .0
            .iter()
            .map(|t| TenantBrief {
                id: t.id,
                name: t.name.clone(),
                display_name: t.display_name.clone(),
            })
            .collect())
    }

    async fn set_active(&self, _user_id: Uuid, _tenant_id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

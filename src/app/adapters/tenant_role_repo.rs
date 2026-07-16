//! **多租户唯一的脏东西,关在这一个文件里。**
//!
//! `idm::RoleRepo` 的装饰器:在平台角色之上,追加「当前激活租户」的哨兵 + 该租户内的角色。
//!
//! # 为什么非得偷渡
//!
//! 上游 `TokenClaims`(rust-idm/src/token.rs)**没有任何扩展字段**,构造它的 `issue_session`
//! 是**私有方法**,`LoginInput` 也没有 tenant 入口 —— 租户信息没有任何正规路径能从 app
//! 流到 signer。`roles: Vec<String>` 是唯一的可变长字符串通道(spec §2、§4.1)。
//!
//! 而 idm 对 roles 从哪来**零假设**:`RoleRepo` 是 `Arc<dyn RoleRepo>` 注入的
//! (rust-idm/src/service.rs 的 builder)。于是塞这个装饰器进去 —— **rust-idm 一个字节都不用改**。
//!
//! # 为什么租户选择必须状态化
//!
//! `roles_for_user` 只收 `user_id`(rust-idm/src/repo/mod.rs),收不到「哪个租户」——
//! per-request 的租户选择不可能在 idm 内部发生,只能落 `user_active_tenant` 表。
//! register / login / refresh 三个入口**全部汇流到 `issue_session`**,它每次都重查 roles
//! (service.rs)⇒「改 active 表 + 调 refresh()」就是切租户,零上游改动。
//!
//! # 本装饰器的产物只允许流向 signer
//!
//! `idm_roles` 在组合根被**三个消费方**共用,包错就崩(spec §2.4):
//! - `AuthService::builder` ← **包装后的**(只有铸币路径需要哨兵)
//! - `seed::apply` ← **未包装的**(它拿 `roles_for_user` 的结果与角色目录比对,哨兵不在目录里
//!   → 命中 `seed.rs` 的 `bail!("角色 {name} 在 user_roles 里但不在角色目录中")` → **dev 启动就崩**)
//! - `UserAdminService::new` ← **未包装的**(那是平台角色的 CRUD 与目录,租户角色不是它的语料;
//!   包了会把 `t:{uuid}` 哨兵显示给后台)

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::tenants::TenantRepo;
use idm::{IdmError, Role, RoleRepo};

pub struct TenantRoleRepo {
    /// 平台角色目录(superadmin 等)—— 全部方法原样转发给它。
    inner: Arc<dyn RoleRepo>,
    tenants: Arc<dyn TenantRepo>,
}

impl TenantRoleRepo {
    pub fn new(inner: Arc<dyn RoleRepo>, tenants: Arc<dyn TenantRepo>) -> Self {
        Self { inner, tenants }
    }
}

#[async_trait]
impl RoleRepo for TenantRoleRepo {
    /// **唯一加料的方法**:平台角色 + `t:{uuid}` 哨兵 + `tn:{role}` 租户角色。
    /// 哨兵由 `auth/token.rs::split_tenant` 在签名前摘出、还原成真正的 tenant claim。
    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        let mut roles = self.inner.roles_for_user(user_id).await?;

        // memberships 已过滤停用/软删租户(TenantRepo 的契约,spec §4.4)、按 seq 升序
        // (最早加入的在前)。失败不吞:租户读不到就该让登录炸,而不是静默降级成 0 租户
        // —— 那会让「DB 抖一下」变成「用户悄悄掉出所有租户」。
        let ms = self
            .tenants
            .memberships(user_id)
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("读租户成员资格失败: {e}")))?;

        // 「active 未设」与「active 指向已失效租户」已被 memberships 坍缩成同一结果
        // (没有任何 is_active)⇒ 两者都回退到最早加入的那个。成员被踢 / 租户被停用,
        // 下次 refresh 自动掉出。**0 租户 → 不 push 任何东西 → claim 无 tenant**
        // (register 的常规出口,spec §1.1)。
        if let Some(m) = ms.iter().find(|m| m.is_active).or(ms.first()) {
            roles.push(format!("t:{}", m.tenant_id));
            roles.push(m.role.claim().to_owned());
        }
        Ok(roles)
    }

    // ── 以下全部原样转发:平台角色的 CRUD 与目录,租户维度不参与 ──

    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        self.inner.upsert(name, display_name, by).await
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        by: Option<String>,
    ) -> Result<(), IdmError> {
        self.inner.grant(user_id, role_id, by).await
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        self.inner.list().await
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<(), IdmError> {
        self.inner.set_roles(user_id, role_ids, by).await
    }
}

//! 组合根的 `idm::ClaimsExtender`:铸币时把「当前激活租户」填进 `TokenClaims::extra`。
//!
//! 这是**多租户与 idm 的唯一接触面**。它在这里而不在 `features/*`,因为它是唯一同时认识
//! 两边的地方(idm 的端口 + tenants 的仓储)—— 组合根的定义(CLAUDE.md「业务模块彼此零 import」)。
//!
//! # 为什么租户选择必须状态化
//!
//! `extra_for` 只收 `user_id`,收不到「哪个租户」—— 与 `roles_for_user` 同样的形状。
//! per-request 的租户选择不可能在铸币时凭空发生,只能落 `user_active_tenant` 表。
//! register / login / refresh 三个入口**全部汇流到 idm 的 `issue_session`**,它每次都重问
//! 一遍 extender ⇒「改 active 表 + 调 `refresh()`」就是切租户。
//!
//! # 它**只**在铸币路径上跑
//!
//! `ClaimsExtender` 只被 `issue_session` 调用 —— `me()` / `update_me()` 不碰它。
//! 这不是巧合而是重点:`/auth/me` 是全站最热的认证端点,不该为了一个它根本不用的
//! 租户 id 去 join 三张表。(旧的 `RoleRepo` 装饰器方案做不到这点 —— `roles_for_user`
//! 被这三条路径共用,包了它就等于给 `/me` 也加上了那次查库。)

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::auth::ExtraClaims;
use crate::features::tenants::TenantRepo;
use idm::{ClaimsExtender, IdmError};

pub struct TenantClaimsExtender {
    tenants: Arc<dyn TenantRepo>,
}

impl TenantClaimsExtender {
    pub fn new(tenants: Arc<dyn TenantRepo>) -> Self {
        Self { tenants }
    }
}

#[async_trait]
impl ClaimsExtender for TenantClaimsExtender {
    async fn extra_for(&self, user_id: Uuid) -> Result<serde_json::Value, IdmError> {
        // memberships 已过滤停用/软删租户(TenantRepo 的契约,spec §4.4)、按 seq 升序
        // (最早加入的在前)。**失败不吞**:租户读不到就该让登录炸,而不是静默降级成
        // 0 租户 —— 那会让「DB 抖一下」变成「用户悄悄掉出所有租户」。
        let ms = self
            .tenants
            .memberships(user_id)
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("读租户成员资格失败: {e}")))?;

        // 「active 未设」与「active 指向已失效租户」已被 memberships 坍缩成同一结果
        // (没有任何 is_active)⇒ 两者都回退到最早加入的那个。成员被踢 / 租户被停用,
        // 下次 refresh 自动掉出。**0 租户 → None → claim 无 tenant**(register 的常规出口,
        // spec §1.1)。
        let tenant = ms
            .iter()
            .find(|m| m.is_active)
            .or(ms.first())
            .map(|m| m.tenant_id);

        serde_json::to_value(ExtraClaims { tenant })
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("自定义 claim 序列化失败: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tenants::{InMemoryTenantRepo, TenantRole, TenantStatus};

    /// 建一个装了 n 个租户的内存库,返回 (repo, user_id, tenant_ids 按加入顺序)。
    async fn repo_with(n: usize) -> (Arc<dyn TenantRepo>, Uuid, Vec<Uuid>) {
        let repo = Arc::new(InMemoryTenantRepo::new());
        let user = Uuid::now_v7();
        let mut ids = Vec::new();
        for i in 0..n {
            let t = Uuid::now_v7();
            repo.upsert_tenant(t, &format!("t{i}-{t}"), "T", TenantStatus::Active, None)
                .await
                .unwrap();
            repo.upsert_member(user, t, TenantRole::Member, None)
                .await
                .unwrap();
            ids.push(t);
        }
        (repo, user, ids)
    }

    fn tenant_of(v: &serde_json::Value) -> Option<Uuid> {
        v.get("tenant")?.as_str()?.parse().ok()
    }

    /// 0 租户 → extra 里**没有** tenant 键。register 的常规出口,不是错误。
    #[tokio::test]
    async fn no_memberships_yields_no_tenant() {
        let (repo, user, _) = repo_with(0).await;
        let v = TenantClaimsExtender::new(repo)
            .extra_for(user)
            .await
            .unwrap();
        assert_eq!(tenant_of(&v), None, "0 租户是常规状态");
    }

    /// **从没切过租户**(`user_active_tenant` 空)—— 也就是**每个人的初始状态** ——
    /// 回退到**最早加入**的那个,不是最后一个、也不是随机一个。
    ///
    /// 这条钉的是 `.or(ms.first())`:排序键是 `seq`(加入顺序),migration 里为
    /// 「seq 还是 granted_at」专门论证过一段,就是因为它决定了用户默认落进哪家公司。
    #[tokio::test]
    async fn never_switched_falls_back_to_earliest_joined() {
        let (repo, user, ids) = repo_with(3).await;
        let v = TenantClaimsExtender::new(repo)
            .extra_for(user)
            .await
            .unwrap();
        assert_eq!(
            tenant_of(&v),
            Some(ids[0]),
            "没显式选过 → 回退到最早加入的那个"
        );
    }

    /// 显式设过 active → 它赢,压过「最早加入」的回退。
    #[tokio::test]
    async fn explicit_active_wins_over_fallback() {
        let (repo, user, ids) = repo_with(3).await;
        repo.set_active(user, ids[2]).await.unwrap();
        let v = TenantClaimsExtender::new(repo)
            .extra_for(user)
            .await
            .unwrap();
        assert_eq!(tenant_of(&v), Some(ids[2]), "显式 active 必须赢");
    }

    /// active 指向的租户被停用 → **坍缩回退**,而不是签出一个指向死租户的 claim。
    /// (memberships 契约已过滤掉非 active 的租户,所以这里等价于「没设过 active」。)
    #[tokio::test]
    async fn suspended_active_tenant_collapses_to_fallback() {
        let (repo, user, ids) = repo_with(2).await;
        repo.set_active(user, ids[1]).await.unwrap();
        repo.upsert_tenant(
            ids[1],
            &format!("t1-{}", ids[1]),
            "T",
            TenantStatus::Suspended,
            None,
        )
        .await
        .unwrap();
        let v = TenantClaimsExtender::new(repo)
            .extra_for(user)
            .await
            .unwrap();
        assert_eq!(
            tenant_of(&v),
            Some(ids[0]),
            "active 指向的租户停用了 → 回退到仍存活的最早那个,不能签出死租户"
        );
    }
}

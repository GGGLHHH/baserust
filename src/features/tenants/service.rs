//! 租户管理服务(P6)。持 `TenantRepo`(租户/成员事实)+ idm `UserRepo`(解析邀请、富化 username)。
//!
//! **两个消费面,一个服务**:
//! - 平台开通(superadmin):建/列/改租户。
//! - 租户内成员管理(tn:admin):列/邀/移成员 —— 授权靠**活的成员资格事实**(见 `member_role`),
//!   不碰 `RoleName`/`Policy`,提权口保持关闭。
//!
//! username 是 `users` 表(idm)的字段,内存 repo 没有它 ⇒ `members_of` 出原始事实(`TenantMemberFact`),
//! 这里用 `UserRepo::find_by_ids` **一次批量**富化成 `TenantMember`(照 widget 富化 created_by 的
//! cross-module-enrichment 范式:防 N+1、查不到的优雅降级)。

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use super::repo::TenantRepo;
use super::types::{Tenant, TenantMember, TenantRole, TenantStatus};
use crate::infra::error::AppError;
use idm::UserRepo;

#[derive(Clone)]
pub struct TenantAdminService {
    tenants: Arc<dyn TenantRepo>,
    users: Arc<dyn UserRepo>,
}

impl TenantAdminService {
    pub fn new(tenants: Arc<dyn TenantRepo>, users: Arc<dyn UserRepo>) -> Self {
        Self { tenants, users }
    }

    // ── 平台开通(superadmin,gate Perm::TenantsAdmin)──

    /// 开通一个租户,可选带一个初始 admin。
    ///
    /// `admin_identifier` 给了就把该**已有用户**设为 `tn:admin` —— 平台开通即交钥匙,
    /// 之后由租户管理员自助邀请其余人(spec §7)。查无此人 → `NotFound`(建租户已成功,
    /// 但这一步失败;调用方看 404 = "那个初始 admin 不存在")。
    pub async fn create(
        &self,
        name: &str,
        display_name: &str,
        admin_identifier: Option<&str>,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        let id = Uuid::now_v7();
        let tenant = self
            .tenants
            .create_tenant(id, name, display_name, by.clone())
            .await?; // 重名 → Conflict(409)
        if let Some(identifier) = admin_identifier {
            let user_id = self.resolve_user(identifier).await?;
            self.tenants
                .upsert_member(user_id, id, TenantRole::Admin, by)
                .await?;
        }
        Ok(tenant)
    }

    pub async fn list(&self) -> Result<Vec<Tenant>, AppError> {
        self.tenants.list_tenants().await
    }

    /// 全量更新(PUT):替 display_name + status。停用 = status → Suspended
    /// (memberships 契约随即过滤掉它,成员 ≤ TTL 内自动掉出,spec §4.4)。
    pub async fn update(
        &self,
        id: Uuid,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<Tenant, AppError> {
        self.tenants
            .update_tenant(id, display_name, status, by)
            .await
    }

    // ── 成员管理(平台侧按 tenant_id;自助侧按 claim 的 active tenant)──

    /// 列一个租户的成员,**富化上 username**。
    pub async fn members(&self, tenant_id: Uuid) -> Result<Vec<TenantMember>, AppError> {
        let facts = self.tenants.members_of(tenant_id).await?;
        if facts.is_empty() {
            return Ok(vec![]);
        }
        // 一次批量取 username(防 N+1)。查不到的(账号已删等)优雅降级 —— 跳过,不报错。
        let ids: Vec<Uuid> = facts.iter().map(|f| f.user_id).collect();
        let by_id: HashMap<Uuid, String> = self
            .users
            .find_by_ids(&ids)
            .await
            .map_err(AppError::from)?
            .into_iter()
            .map(|u| (u.id, u.username))
            .collect();
        Ok(facts
            .into_iter()
            .filter_map(|f| {
                by_id.get(&f.user_id).map(|username| TenantMember {
                    user_id: f.user_id,
                    username: username.clone(),
                    role: f.role,
                    granted_at: f.granted_at,
                })
            })
            .collect())
    }

    /// 邀请一名成员(按 username/email)。查无此人 → `NotFound`(被邀请者必须先有账号)。
    /// 对已是成员的人 = 改角色(`upsert_member` 语义)。
    pub async fn add_member(
        &self,
        tenant_id: Uuid,
        identifier: &str,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let user_id = self.resolve_user(identifier).await?;
        self.tenants
            .upsert_member(user_id, tenant_id, role, by)
            .await
    }

    pub async fn remove_member(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
        self.tenants.remove_member(user_id, tenant_id).await
    }

    /// 某人在某租户里的角色 —— **自助端点的授权支点**。
    ///
    /// 走 `membership()`,它**过滤停用/软删租户**:停用租户的 admin 拿不到成员资格 ⇒ 管不了人。
    /// 这是**活的事实**(每次查库,不是 claim 里的陈旧角色)—— 提权口因此保持关闭:
    /// 授权靠 `tenant_members.role`,不靠 `RoleName`/`Policy`(那条路径在 P2 被拆掉了)。
    pub async fn member_role(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<TenantRole>, AppError> {
        Ok(self
            .tenants
            .membership(user_id, tenant_id)
            .await?
            .map(|m| m.role))
    }

    /// username/email → user_id。查无此人 → `NotFound`。
    async fn resolve_user(&self, identifier: &str) -> Result<Uuid, AppError> {
        self.users
            .find_by_identifier(identifier)
            .await
            .map_err(AppError::from)?
            .map(|u| u.user.id)
            .ok_or(AppError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tenants::InMemoryTenantRepo;
    use idm::{InMemoryUserRepo, RegisterInput};

    /// 建一个装了 idm 用户的 service。返回 (service, alice_id, bob_id)。
    async fn svc() -> (TenantAdminService, Uuid, Uuid) {
        let users = Arc::new(InMemoryUserRepo::new());
        let mk = |name: &str| RegisterInput {
            username: name.into(),
            email: None,
            password: "x".into(),
        };
        let alice = users
            .create(&mk("alice").username, None, "h", None)
            .await
            .unwrap()
            .id;
        let bob = users
            .create(&mk("bob").username, None, "h", None)
            .await
            .unwrap()
            .id;
        let s = TenantAdminService::new(Arc::new(InMemoryTenantRepo::new()), users);
        (s, alice, bob)
    }

    #[tokio::test]
    async fn create_with_initial_admin_seeds_membership() {
        let (s, alice, _) = svc().await;
        let t = s
            .create("acme", "Acme", Some("alice"), Some("sa".into()))
            .await
            .unwrap();
        // alice 成了这个租户的 admin
        assert_eq!(
            s.member_role(alice, t.id).await.unwrap(),
            Some(TenantRole::Admin),
            "初始 admin 应被设为 tn:admin"
        );
    }

    #[tokio::test]
    async fn create_with_unknown_admin_is_404() {
        let (s, _, _) = svc().await;
        assert!(matches!(
            s.create("acme", "Acme", Some("ghost"), None).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn add_member_enriches_username_and_role() {
        let (s, alice, bob) = svc().await;
        let t = s.create("acme", "Acme", Some("alice"), None).await.unwrap();
        s.add_member(t.id, "bob", TenantRole::Member, None)
            .await
            .unwrap();

        let members = s.members(t.id).await.unwrap();
        assert_eq!(members.len(), 2);
        let by_name: HashMap<_, _> = members
            .iter()
            .map(|m| (m.username.as_str(), m.role))
            .collect();
        assert_eq!(by_name.get("alice"), Some(&TenantRole::Admin));
        assert_eq!(by_name.get("bob"), Some(&TenantRole::Member));
        let _ = (alice, bob);
    }

    #[tokio::test]
    async fn add_unknown_user_is_404() {
        let (s, _, _) = svc().await;
        let t = s.create("acme", "Acme", None, None).await.unwrap();
        assert!(matches!(
            s.add_member(t.id, "ghost", TenantRole::Member, None).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn remove_member_then_gone() {
        let (s, _alice, _) = svc().await;
        let t = s.create("acme", "Acme", Some("alice"), None).await.unwrap();
        s.add_member(t.id, "bob", TenantRole::Member, None)
            .await
            .unwrap();
        let bob_id = s
            .members(t.id)
            .await
            .unwrap()
            .iter()
            .find(|m| m.username == "bob")
            .unwrap()
            .user_id;

        s.remove_member(t.id, bob_id).await.unwrap();
        assert!(s
            .members(t.id)
            .await
            .unwrap()
            .iter()
            .all(|m| m.username != "bob"));
        assert!(matches!(
            s.remove_member(t.id, bob_id).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn member_role_is_none_for_non_member() {
        let (s, _, bob) = svc().await;
        let t = s.create("acme", "Acme", Some("alice"), None).await.unwrap();
        assert_eq!(
            s.member_role(bob, t.id).await.unwrap(),
            None,
            "非成员 → None"
        );
    }
}

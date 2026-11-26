//! `TenantAdminService`:租户与成员管理编排(spec §4.5 / §4.6)。壳套 idm 原语(身份权威在 idm),
//! 成员列表读 search 的租户成员索引投影(没接 search 后端时回退 idm 直查),再批量富化资料。
//!
//! - 原子写靠 idm 侧本地事务(`MemberRepo::add` / `set_roles` 一个方法一个事务);状态变更 + 吊销会话
//!   跨 repo,不组一个 tx(transactions skill):先写,再吊销;吊销失败向上报错(fail-closed,调用方重试幂等)。
//! - 租户从哪来是调用方(HTTP 边界)的事:租户管理员的接口只用 token 的当前租户(`CurrentTenant`),
//!   平台接口用路径里的租户 id(先经 [`TenantAdminService::tenant_scope`] 确认存在)。这里只收 `TenantId`。
//! - 只授**租户角色**:成员关系上授平台角色(superadmin)不生效 → 422(平台角色经账号管理授予)。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::model::{
    AddMember, CreateTenant, ListMembers, MemberStatus, MemberView, TenantStatus, TenantView,
    UpdateTenant,
};
use super::ports::{MemberProfiles, MemberSearchIndex};
use crate::kernel::authz::{holds_platform_role, RoleName};
use crate::kernel::error::AppError;
use crate::kernel::pagination::{Page, PageParams};
use crate::kernel::tenant::TenantId;
use idm::{MemberRepo, RoleRepo, SessionRepo, TenantRepo, UserRepo};

/// 核心分页参数 → idm 列表分页。
fn list_page(page: &PageParams) -> idm::ListPage {
    match page {
        PageParams::Offset {
            page,
            size,
            with_total,
        } => idm::ListPage::Offset {
            offset: (page - 1) * size,
            limit: *size,
            with_total: *with_total,
        },
        PageParams::Cursor { after, limit } => idm::ListPage::Cursor {
            after: *after,
            limit: *limit,
        },
    }
}

/// 结果行 + 分页元信息 → 核心 `Page`(两种分页模式互斥)。
fn into_page<T>(
    items: Vec<T>,
    page: PageParams,
    total: Option<u64>,
    next_after: Option<Uuid>,
) -> Page<T> {
    match page {
        PageParams::Offset { page, size, .. } => Page::offset(items, page, size, total),
        PageParams::Cursor { limit, .. } => Page::cursor(items, limit, next_after),
    }
}

#[derive(Clone)]
pub struct TenantAdminService {
    tenants: Arc<dyn TenantRepo>,
    members: Arc<dyn MemberRepo>,
    users: Arc<dyn UserRepo>,
    roles: Arc<dyn RoleRepo>,
    sessions: Arc<dyn SessionRepo>,
    profiles: Arc<dyn MemberProfiles>,
    /// 租户成员索引(search 投影);None = 未接 search 后端 → 成员列表回退 idm 直查(`q` → 422)。
    search: Option<Arc<dyn MemberSearchIndex>>,
}

impl TenantAdminService {
    pub fn new(
        tenants: Arc<dyn TenantRepo>,
        members: Arc<dyn MemberRepo>,
        users: Arc<dyn UserRepo>,
        roles: Arc<dyn RoleRepo>,
        sessions: Arc<dyn SessionRepo>,
        profiles: Arc<dyn MemberProfiles>,
        search: Option<Arc<dyn MemberSearchIndex>>,
    ) -> Self {
        Self {
            tenants,
            members,
            users,
            roles,
            sessions,
            profiles,
            search,
        }
    }

    // ───────────────────────────── 租户(平台级) ─────────────────────────────

    /// 存活租户列表,按 id(v7 = 创建序)升序。
    pub async fn list_tenants(&self, page: PageParams) -> Result<Page<TenantView>, AppError> {
        let r = self.tenants.list(&list_page(&page)).await?;
        let items = r.rows.into_iter().map(TenantView::from).collect();
        Ok(into_page(items, page, r.total, r.next_after))
    }

    /// 建租户(status = active)。slug 被占(含已软删的)→ 409。
    pub async fn create_tenant(
        &self,
        req: CreateTenant,
        by: Option<String>,
    ) -> Result<TenantView, AppError> {
        req.validate()?;
        Ok(self.tenants.create(&req.slug, &req.name, by).await?.into())
    }

    /// 租户详情。不存在 / 已软删 → 404。
    pub async fn get_tenant(&self, id: Uuid) -> Result<TenantView, AppError> {
        Ok(self.tenants.get(id).await?.into())
    }

    /// 改租户(PUT 全量:名称 + 状态)。只写真变了的字段(省一条 outbox 事件)。
    /// 目标状态是停用时**每次都**吊销该租户的全部会话(幂等;上次吊销失败后重试同一个 PUT 也能补上),
    /// refresh 立即失败;已发出的 access token 到期前仍有效(spec §4.6)。
    pub async fn update_tenant(
        &self,
        id: Uuid,
        req: UpdateTenant,
        by: Option<String>,
    ) -> Result<TenantView, AppError> {
        req.validate()?;
        let mut t = self.tenants.get(id).await?;
        if t.name != req.name {
            t = self.tenants.update_name(id, &req.name, by.clone()).await?;
        }
        if TenantStatus::from(t.status) != req.status {
            t = self.tenants.set_status(id, req.status.into(), by).await?;
        }
        if req.status == TenantStatus::Suspended {
            self.sessions.revoke_for_tenant(id).await?;
        }
        Ok(t.into())
    }

    /// 平台接口用:路径里的租户 id → 存活租户的 `TenantId`(不存在 / 已软删 / nil → 404)。
    pub async fn tenant_scope(&self, id: Uuid) -> Result<TenantId, AppError> {
        let t = self.tenants.get(id).await?;
        TenantId::new(t.id).map_err(|_| AppError::NotFound)
    }

    // ───────────────────────────── 成员 ─────────────────────────────

    /// 某租户的成员列表(已移出的不在;投影路还滤掉已删账号)。有 search 后端 → 读租户成员索引(支持 `q`);
    /// 没有 → 回退 idm 直查(按 user_id 升序;`q` → 422,回退路没有搜索能力;已删账号的成员行跳过)。
    pub async fn list_members(
        &self,
        tenant: TenantId,
        filter: &ListMembers,
        page: PageParams,
    ) -> Result<Page<MemberView>, AppError> {
        let q = filter.q.as_deref().filter(|s| !s.trim().is_empty());
        match &self.search {
            Some(search) => {
                let r = search.query(tenant, q, &page).await?;
                let ids: Vec<Uuid> = r.rows.iter().map(|row| row.user_id).collect();
                let profiles = self.profiles.batch(&ids).await?;
                let platform = self.platform_role_holders(&ids).await?;
                let items = r
                    .rows
                    .into_iter()
                    .map(|row| {
                        Ok(MemberView {
                            id: row.user_id,
                            username: row.username,
                            email: row.email,
                            display_name: row.display_name, // 投影(可搜键)
                            avatar_url: profiles
                                .get(&row.user_id)
                                .and_then(|p| p.avatar_url.clone()),
                            roles: RoleName::parse_lossy(row.roles),
                            status: parse_member_status(row.status.as_deref())?,
                            holds_platform_role: platform.contains(&row.user_id),
                        })
                    })
                    .collect::<Result<Vec<_>, AppError>>()?;
                Ok(into_page(items, page, r.total, r.next_after))
            }
            None => {
                if q.is_some() {
                    return Err(AppError::Validation(
                        "search requires projection backend".into(),
                    ));
                }
                let r = self
                    .members
                    .list_by_tenant(tenant.as_uuid(), &list_page(&page))
                    .await?;
                let ids: Vec<Uuid> = r.rows.iter().map(|m| m.user_id).collect();
                let users: HashMap<Uuid, idm::User> = self
                    .users
                    .find_by_ids(&ids)
                    .await?
                    .into_iter()
                    .map(|u| (u.id, u))
                    .collect();
                let profiles = self.profiles.batch(&ids).await?;
                let platform = self.platform_role_holders(&ids).await?;
                let items = r
                    .rows
                    .into_iter()
                    .filter_map(|m| {
                        // 账号已删(成员行还在)→ 跳过,同投影路的基线过滤
                        let user = users.get(&m.user_id)?;
                        let p = profiles.get(&m.user_id);
                        Some(MemberView {
                            id: m.user_id,
                            username: user.username.clone(),
                            email: user.email.clone(),
                            display_name: p.and_then(|p| p.display_name.clone()),
                            avatar_url: p.and_then(|p| p.avatar_url.clone()),
                            roles: RoleName::parse_lossy(m.roles),
                            status: m.status.into(),
                            holds_platform_role: platform.contains(&m.user_id),
                        })
                    })
                    .collect();
                Ok(into_page(items, page, r.total, r.next_after))
            }
        }
    }

    /// 按**完整用户名**把已有账号加进租户(租户管理员用,spec §4.5)。精确匹配:去掉首尾空白后必须与账号的
    /// username 完全相等(邮箱、大小写不同都不算);查不到 → `AccountNotFound`(404 `account_not_found`)。
    /// 不建账号。已是成员 → 409;授平台角色 / 未知角色 → 422。
    pub async fn add_member(
        &self,
        tenant: TenantId,
        req: AddMember,
        by: Option<String>,
    ) -> Result<MemberView, AppError> {
        let (user_id, role_ids) = self.resolve_add_member(&req).await?;
        self.members
            .add(tenant.as_uuid(), user_id, &role_ids, by)
            .await?;
        self.member_view(tenant, user_id).await
    }

    /// [`Self::add_member`] 的前半段(不写):校验(422)→ 租户角色 id(平台角色 / 未知 → 422)→ 按完整用户名找账号
    /// (查不到 → 404 `account_not_found`)。HTTP 边界先用它拿到目标账号 id 做防接管闸,再调 `add_member`。
    pub async fn resolve_add_member(&self, req: &AddMember) -> Result<(Uuid, Vec<Uuid>), AppError> {
        req.validate()?;
        let role_ids = self.tenant_role_ids(&req.roles).await?;
        let username = req.username.trim();
        // ponytail: find_by_identifier 也按邮箱匹配,所以再比一次 username。极端情况下(某人的 username 恰好等于
        // 另一人的邮箱)它可能先命中邮箱那个人 → 这里判 404;要根治需 idm 加「按用户名精确查」的原语。
        let user = self
            .users
            .find_by_identifier(username)
            .await?
            .map(|u| u.user)
            .filter(|u| u.username == username)
            .ok_or(AppError::AccountNotFound)?;
        Ok((user.id, role_ids))
    }

    /// 平台管理员设某租户的成员(PUT:不是成员则加入,是成员则全量替换租户角色)。账号不存在 → 404。
    pub async fn put_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[RoleName],
        by: Option<String>,
    ) -> Result<MemberView, AppError> {
        let role_ids = self.tenant_role_ids(roles).await?;
        let t = tenant.as_uuid();
        let joined = match self.members.get(t, user_id).await? {
            Some(_) => false,
            // 查完到加入之间被并发加进来了(add → Conflict):照样落成「全量换角色」,PUT 保持幂等。
            None => match self.members.add(t, user_id, &role_ids, by.clone()).await {
                Ok(_) => true,
                Err(idm::IdmError::Conflict(_)) => false,
                Err(e) => return Err(e.into()),
            },
        };
        if !joined {
            self.members.set_roles(t, user_id, &role_ids, by).await?;
        }
        self.member_view(tenant, user_id).await
    }

    /// 全量替换成员在该租户的租户角色(原子)。不是该租户的成员 → 404。
    pub async fn set_member_roles(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[RoleName],
        by: Option<String>,
    ) -> Result<MemberView, AppError> {
        let role_ids = self.tenant_role_ids(roles).await?;
        self.members
            .set_roles(tenant.as_uuid(), user_id, &role_ids, by)
            .await?;
        self.member_view(tenant, user_id).await
    }

    /// 移出成员(连带他在该租户的租户角色)并**立即吊销**他在该租户的会话(spec §4.6;别的租户的会话不动)。
    /// 不是该租户的成员 → 404,但**照样先吊销**他在该租户的会话再报 404:上一次移出成功、吊销失败(500)时,
    /// 重试同一个 DELETE 会走到这里(成员行已没了),靠这一次把漏掉的会话补吊销。吊销幂等,对从没进过
    /// 该租户的人是空操作。其他错误(库故障)不吊销,原样上抛。
    pub async fn remove_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        by: Option<String>,
    ) -> Result<(), AppError> {
        let removed = match self.members.remove(tenant.as_uuid(), user_id, by).await {
            Ok(()) => Ok(()),
            Err(idm::IdmError::NotFound) => Err(AppError::NotFound),
            Err(e) => return Err(e.into()),
        };
        self.sessions
            .revoke_for_member(tenant.as_uuid(), user_id)
            .await?;
        removed
    }

    /// 成员在该租户**现有**的租户角色名(未过滤闭集,提权闸用)。不是该租户的成员 → 404。
    pub async fn member_role_names(
        &self,
        tenant: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        Ok(self
            .members
            .get(tenant.as_uuid(), user_id)
            .await?
            .ok_or(AppError::NotFound)?
            .roles)
    }

    /// 单个成员的视图(写操作的响应)。
    async fn member_view(&self, tenant: TenantId, user_id: Uuid) -> Result<MemberView, AppError> {
        let m = self
            .members
            .get(tenant.as_uuid(), user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let user = self.users.find_by_id(user_id).await?;
        let profiles = self.profiles.batch(&[user_id]).await?;
        let p = profiles.get(&user_id);
        let platform_roles = self.roles.roles_for_user(user_id).await?;
        Ok(MemberView {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: p.and_then(|p| p.display_name.clone()),
            avatar_url: p.and_then(|p| p.avatar_url.clone()),
            roles: RoleName::parse_lossy(m.roles),
            status: m.status.into(),
            holds_platform_role: holds_platform_role(&platform_roles),
        })
    }

    /// 这批账号里哪些持平台角色(口径同 [`holds_platform_role`]:看原始角色名,闭集外的名字算 —— fail-closed)。
    /// 不逐个查(防 N+1):先从角色目录挑出「算平台角色」的名字,再按这些名字列出持有者(通常只有 superadmin +
    /// 几个平台管理员),与本页 id 求交。`roles_any` 只匹配平台角色授予(`user_roles`),组织角色不算。
    async fn platform_role_holders(&self, ids: &[Uuid]) -> Result<HashSet<Uuid>, AppError> {
        if ids.is_empty() {
            return Ok(HashSet::new());
        }
        let names: Vec<String> = self
            .roles
            .list()
            .await?
            .into_iter()
            .map(|r| r.name)
            .filter(|n| holds_platform_role(std::slice::from_ref(n)))
            .collect();
        if names.is_empty() {
            return Ok(HashSet::new());
        }
        let wanted: HashSet<Uuid> = ids.iter().copied().collect();
        let filter = idm::UserListFilter {
            roles_any: names,
            ..Default::default()
        };
        const BATCH: u64 = 200;
        let mut holders = HashSet::new();
        let mut offset = 0;
        loop {
            let page = self
                .users
                .list(
                    &filter,
                    idm::UserSortBy::CreatedAt,
                    idm::SortDir::Asc,
                    &idm::ListPage::Offset {
                        offset,
                        limit: BATCH,
                        with_total: false,
                    },
                )
                .await?;
            let n = page.rows.len() as u64;
            holders.extend(
                page.rows
                    .into_iter()
                    .map(|u| u.id)
                    .filter(|id| wanted.contains(id)),
            );
            if n < BATCH {
                return Ok(holders);
            }
            offset += BATCH;
        }
    }

    /// 租户角色名 → 角色 id(去重保序)。平台角色 → 422(成员关系上授平台角色不生效);
    /// 角色目录里没有(或目录里它不是租户角色)→ 422。
    async fn tenant_role_ids(&self, names: &[RoleName]) -> Result<Vec<Uuid>, AppError> {
        let mut seen = HashSet::new();
        let names: Vec<RoleName> = names.iter().copied().filter(|n| seen.insert(*n)).collect();
        if let Some(n) = names.iter().find(|n| n.scope() != idm::RoleScope::Tenant) {
            return Err(AppError::Validation(format!(
                "role {} is a platform role: grant it through account management, tenant membership only grants tenant roles",
                n.as_str()
            )));
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let catalog: HashMap<String, Uuid> = self
            .roles
            .list()
            .await?
            .into_iter()
            .filter(|r| r.scope == idm::RoleScope::Tenant)
            .map(|r| (r.name, r.id))
            .collect();
        names
            .iter()
            .map(|n| {
                catalog.get(n.as_str()).copied().ok_or_else(|| {
                    AppError::Validation(format!("unknown tenant role: {}", n.as_str()))
                })
            })
            .collect()
    }
}

/// 投影里的成员状态串 → 闭集。缺(成员列还没落地,理论上不出现:成员行由成员事件建)→ active;
/// 闭集外 → 500(单写者:只有我们的投影器写它,出现即数据异常,不静默)。
fn parse_member_status(s: Option<&str>) -> Result<MemberStatus, AppError> {
    match s {
        None => Ok(MemberStatus::Active),
        Some(s) => s
            .parse()
            .map_err(|e: String| AppError::Internal(anyhow::anyhow!(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tenants::memory::StaticMemberProfiles;
    use crate::features::tenants::ports::{MemberSearchPage, MemberSearchRow};
    use idm::{
        InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryTenantRepo,
        InMemoryUserRepo,
    };

    struct Env {
        svc: TenantAdminService,
        users: Arc<InMemoryUserRepo>,
        tenants: Arc<InMemoryTenantRepo>,
        members: Arc<InMemoryMemberRepo>,
        sessions: Arc<InMemorySessionRepo>,
        roles: Arc<InMemoryRoleRepo>,
    }

    /// 内存装配:各 idm 仓储共享存储;角色目录 superadmin(平台)/ admin、user(租户)。
    async fn env_with(search: Option<Arc<dyn MemberSearchIndex>>) -> Env {
        let users = InMemoryUserRepo::new();
        let roles = InMemoryRoleRepo::sharing_with(&users);
        let sessions = InMemorySessionRepo::sharing_with(&users);
        let members = InMemoryMemberRepo::sharing_with(&users);
        let tenants = InMemoryTenantRepo::sharing_with(&users);
        for r in RoleName::ALL {
            roles
                .upsert(r.as_str(), r.display_name(), r.scope(), None)
                .await
                .unwrap();
        }
        let users = Arc::new(users);
        let tenants = Arc::new(tenants);
        let members = Arc::new(members);
        let sessions = Arc::new(sessions);
        let roles = Arc::new(roles);
        let svc = TenantAdminService::new(
            tenants.clone(),
            members.clone(),
            users.clone(),
            roles.clone(),
            sessions.clone(),
            Arc::new(StaticMemberProfiles::empty()),
            search,
        );
        Env {
            svc,
            users,
            tenants,
            members,
            sessions,
            roles,
        }
    }

    async fn account(e: &Env, name: &str) -> Uuid {
        e.users
            .create_with_roles(name, None, "hash", &[], None)
            .await
            .unwrap()
            .id
    }

    async fn tenant(e: &Env, slug: &str) -> TenantId {
        let t = e.tenants.create(slug, slug, None).await.unwrap();
        TenantId::new(t.id).unwrap()
    }

    /// 在 `tenant` 里给 `user` 建一个活跃会话(refresh hash = `hash`)。
    async fn session(e: &Env, user: Uuid, tenant: TenantId, hash: &str) {
        e.sessions
            .create(
                user,
                Some(tenant.as_uuid()),
                hash,
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
                None,
            )
            .await
            .unwrap();
    }

    async fn active(e: &Env, hash: &str) -> bool {
        e.sessions
            .find_active(hash, time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    }

    /// 移出成员 = 吊销他在**该租户**的会话(别的租户的会话不动);重试(成员行已没了)回 404 但照样补吊销。
    #[tokio::test]
    async fn remove_member_revokes_sessions_in_that_tenant_only() {
        let e = env_with(None).await;
        let a = tenant(&e, "a").await;
        let b = tenant(&e, "b").await;
        let bob = account(&e, "bob").await;
        for t in [a, b] {
            e.svc
                .put_member(t, bob, &[RoleName::User], None)
                .await
                .unwrap();
        }
        session(&e, bob, a, "in-a").await;
        session(&e, bob, b, "in-b").await;

        e.svc.remove_member(a, bob, None).await.unwrap();
        assert!(!active(&e, "in-a").await, "该租户的会话应被吊销");
        assert!(active(&e, "in-b").await, "别的租户的会话不动");

        // 模拟「上次移出成功、吊销失败」:成员行已没了、会话还活着 → 重试回 404,但会话被补吊销
        e.members.remove(b.as_uuid(), bob, None).await.unwrap();
        assert!(active(&e, "in-b").await);
        assert!(matches!(
            e.svc.remove_member(b, bob, None).await,
            Err(AppError::NotFound)
        ));
        assert!(!active(&e, "in-b").await, "重试应补吊销");
    }

    /// 成员仓储包装:**第一次** `get` 回 None(模拟「查时还不是成员、加入前被并发加进来」),其余转给内存实现。
    struct StaleGet(Arc<InMemoryMemberRepo>, std::sync::atomic::AtomicBool);

    #[async_trait::async_trait]
    impl MemberRepo for StaleGet {
        async fn add(
            &self,
            t: Uuid,
            u: Uuid,
            r: &[Uuid],
            by: Option<String>,
        ) -> Result<idm::Membership, idm::IdmError> {
            self.0.add(t, u, r, by).await
        }
        async fn remove(&self, t: Uuid, u: Uuid, by: Option<String>) -> Result<(), idm::IdmError> {
            self.0.remove(t, u, by).await
        }
        async fn set_status(
            &self,
            t: Uuid,
            u: Uuid,
            s: idm::MemberStatus,
            by: Option<String>,
        ) -> Result<(), idm::IdmError> {
            self.0.set_status(t, u, s, by).await
        }
        async fn set_roles(
            &self,
            t: Uuid,
            u: Uuid,
            r: &[Uuid],
            by: Option<String>,
        ) -> Result<(), idm::IdmError> {
            self.0.set_roles(t, u, r, by).await
        }
        async fn get(&self, t: Uuid, u: Uuid) -> Result<Option<idm::Membership>, idm::IdmError> {
            if self.1.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Ok(None);
            }
            self.0.get(t, u).await
        }
        async fn list_by_tenant(
            &self,
            t: Uuid,
            p: &idm::ListPage,
        ) -> Result<idm::ListResult<idm::Membership>, idm::IdmError> {
            self.0.list_by_tenant(t, p).await
        }
        async fn memberships_for_user(
            &self,
            u: Uuid,
        ) -> Result<Vec<idm::Membership>, idm::IdmError> {
            self.0.memberships_for_user(u).await
        }
        async fn touch_last_used(&self, t: Uuid, u: Uuid) -> Result<(), idm::IdmError> {
            self.0.touch_last_used(t, u).await
        }
    }

    /// PUT 成员幂等:加入时撞上「已是成员」(并发加入)→ 改走全量换角色,不报 409。
    #[tokio::test]
    async fn put_member_falls_back_to_set_roles_on_conflict() {
        let e = env_with(None).await;
        let t = tenant(&e, "acme").await;
        let carol = account(&e, "carol").await;
        e.svc
            .put_member(t, carol, &[RoleName::Admin], None)
            .await
            .unwrap();
        let racy = TenantAdminService::new(
            e.tenants.clone(),
            Arc::new(StaleGet(
                e.members.clone(),
                std::sync::atomic::AtomicBool::new(true),
            )),
            e.users.clone(),
            e.roles.clone(),
            e.sessions.clone(),
            Arc::new(StaticMemberProfiles::empty()),
            None,
        );
        let m = racy
            .put_member(t, carol, &[RoleName::User], None)
            .await
            .unwrap();
        assert_eq!(m.roles, vec![RoleName::User]);
        let back = e.svc.member_role_names(t, carol).await.unwrap();
        assert_eq!(back, vec!["user".to_string()]);
    }

    /// 停用租户 = 吊销该租户里所有人的会话;别的租户的会话不动;恢复不会让旧会话复活。
    #[tokio::test]
    async fn suspend_tenant_revokes_its_sessions() {
        let e = env_with(None).await;
        let a = tenant(&e, "a").await;
        let b = tenant(&e, "b").await;
        let bob = account(&e, "bob").await;
        let carol = account(&e, "carol").await;
        for (t, u) in [(a, bob), (a, carol), (b, bob)] {
            e.svc.put_member(t, u, &[], None).await.unwrap();
        }
        session(&e, bob, a, "bob-a").await;
        session(&e, carol, a, "carol-a").await;
        session(&e, bob, b, "bob-b").await;
        let put = |status| UpdateTenant {
            name: "a".into(),
            status,
        };
        e.svc
            .update_tenant(a.as_uuid(), put(TenantStatus::Suspended), None)
            .await
            .unwrap();
        e.svc
            .update_tenant(a.as_uuid(), put(TenantStatus::Active), None)
            .await
            .unwrap();
        assert!(!active(&e, "bob-a").await);
        assert!(!active(&e, "carol-a").await);
        assert!(active(&e, "bob-b").await);
    }

    fn page() -> PageParams {
        PageParams::Offset {
            page: 1,
            size: 20,
            with_total: true,
        }
    }

    #[tokio::test]
    async fn add_member_by_exact_username_only() {
        let e = env_with(None).await;
        let t = tenant(&e, "acme").await;
        let alice = e
            .users
            .create_with_roles("alice", Some("alice@x.io"), "hash", &[], None)
            .await
            .unwrap()
            .id;
        let add = |username: &str, roles: Vec<RoleName>| AddMember {
            username: username.into(),
            roles,
        };
        for miss in ["alice@x.io", "Alice", "ali", "nobody"] {
            assert!(
                matches!(
                    e.svc.add_member(t, add(miss, vec![]), None).await,
                    Err(AppError::AccountNotFound)
                ),
                "{miss}"
            );
        }
        // 平台角色 → 422(先于查账号)
        assert!(matches!(
            e.svc
                .add_member(t, add("nobody", vec![RoleName::Superadmin]), None)
                .await,
            Err(AppError::Validation(_))
        ));
        let m = e
            .svc
            .add_member(
                t,
                add(" alice ", vec![RoleName::User, RoleName::User]),
                None,
            )
            .await
            .unwrap();
        assert_eq!(m.id, alice);
        assert_eq!(m.roles, vec![RoleName::User]);
        assert_eq!(m.status, MemberStatus::Active);
        assert!(matches!(
            e.svc.add_member(t, add("alice", vec![]), None).await,
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn members_are_scoped_to_their_tenant() {
        let e = env_with(None).await;
        let a = tenant(&e, "a").await;
        let b = tenant(&e, "b").await;
        let bob = account(&e, "bob").await;
        e.svc
            .put_member(b, bob, &[RoleName::Admin], None)
            .await
            .unwrap();
        assert!(e
            .svc
            .list_members(a, &ListMembers::default(), page())
            .await
            .unwrap()
            .items
            .is_empty());
        for r in [
            e.svc
                .set_member_roles(a, bob, &[RoleName::User], None)
                .await
                .err(),
            e.svc.remove_member(a, bob, None).await.err(),
            e.svc.member_role_names(a, bob).await.err(),
        ] {
            assert!(matches!(r, Some(AppError::NotFound)), "{r:?}");
        }
        // b 里的成员关系没动
        let list = e
            .svc
            .list_members(b, &ListMembers::default(), page())
            .await
            .unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].roles, vec![RoleName::Admin]);
    }

    #[tokio::test]
    async fn put_member_adds_then_replaces_roles() {
        let e = env_with(None).await;
        let t = tenant(&e, "acme").await;
        let carol = account(&e, "carol").await;
        let m = e
            .svc
            .put_member(t, carol, &[RoleName::Admin], None)
            .await
            .unwrap();
        assert_eq!(m.roles, vec![RoleName::Admin]);
        let m = e.svc.put_member(t, carol, &[], None).await.unwrap();
        assert!(m.roles.is_empty());
        assert!(matches!(
            e.svc.put_member(t, Uuid::now_v7(), &[], None).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn update_tenant_renames_and_suspends() {
        let e = env_with(None).await;
        let t = e
            .svc
            .create_tenant(
                CreateTenant {
                    slug: "acme".into(),
                    name: "Acme".into(),
                },
                None,
            )
            .await
            .unwrap();
        let v = e
            .svc
            .update_tenant(
                t.id,
                UpdateTenant {
                    name: "Acme Inc".into(),
                    status: TenantStatus::Suspended,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            (v.name.as_str(), v.status),
            ("Acme Inc", TenantStatus::Suspended)
        );
        assert_eq!(v.slug, "acme");
        assert!(matches!(
            e.svc.get_tenant(Uuid::now_v7()).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            e.svc.tenant_scope(Uuid::nil()).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn list_without_search_backend_rejects_q() {
        let e = env_with(None).await;
        let t = tenant(&e, "acme").await;
        let f = ListMembers {
            q: Some("x".into()),
        };
        assert!(matches!(
            e.svc.list_members(t, &f, page()).await,
            Err(AppError::Validation(_))
        ));
        // 纯空白 q 不算搜索
        let f = ListMembers {
            q: Some("  ".into()),
        };
        assert!(e.svc.list_members(t, &f, page()).await.is_ok());
    }

    /// 假投影:回放预置行(测投影分支的映射,不测查询语义)。
    struct FakeIndex(Vec<MemberSearchRow>);

    #[async_trait::async_trait]
    impl MemberSearchIndex for FakeIndex {
        async fn query(
            &self,
            _tenant: TenantId,
            _q: Option<&str>,
            _page: &PageParams,
        ) -> Result<MemberSearchPage, AppError> {
            Ok(MemberSearchPage {
                rows: self.0.clone(),
                total: Some(self.0.len() as u64),
                next_after: None,
            })
        }
    }

    #[tokio::test]
    async fn list_with_search_backend_maps_projection_rows() {
        let id = Uuid::now_v7();
        let row = |status: Option<&str>| MemberSearchRow {
            user_id: id,
            username: "dora".into(),
            email: None,
            display_name: Some("Dora".into()),
            roles: vec!["admin".into(), "legacy".into()],
            status: status.map(str::to_owned),
        };
        let e = env_with(Some(Arc::new(FakeIndex(vec![row(Some("inactive"))])))).await;
        let t = tenant(&e, "acme").await;
        let f = ListMembers {
            q: Some("do".into()),
        };
        let got = e.svc.list_members(t, &f, page()).await.unwrap();
        assert_eq!(got.items.len(), 1);
        let m = &got.items[0];
        assert_eq!(m.display_name.as_deref(), Some("Dora"));
        assert_eq!(m.roles, vec![RoleName::Admin], "闭集外角色名跳过");
        assert_eq!(m.status, MemberStatus::Inactive);

        let bad = env_with(Some(Arc::new(FakeIndex(vec![row(Some("weird"))])))).await;
        let t = tenant(&bad, "acme").await;
        assert!(matches!(
            bad.svc
                .list_members(t, &ListMembers::default(), page())
                .await,
            Err(AppError::Internal(_))
        ));
    }
}

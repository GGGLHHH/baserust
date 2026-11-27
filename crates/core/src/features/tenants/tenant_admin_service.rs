//! `TenantAdminService`:租户与成员管理编排(spec §4.5 / §4.6)。壳套 idm 原语(身份权威在 idm),
//! 成员列表读 search 的租户成员索引投影(没接 search 后端时回退 idm 直查),再批量富化资料。
//!
//! - 原子写靠 idm 侧本地事务(`MemberRepo::add` / `set_roles` 一个方法一个事务);状态变更 + 吊销会话
//!   跨 repo,不组一个 tx(transactions skill):先写,再吊销;吊销失败向上报错(fail-closed,调用方重试幂等)。
//! - 租户从哪来是调用方(HTTP 边界)的事:租户管理员的接口只用 token 的当前租户(`CurrentTenant`),
//!   平台接口用路径里的租户 id(先经 [`TenantAdminService::tenant_scope`] 确认存在)。这里只收 `TenantId`。
//! - 只授**租户角色**:成员关系上授平台角色(superadmin)不生效 → 422(平台角色经账号管理授予)。

use std::collections::{HashMap, HashSet};
use std::slice;
use std::sync::Arc;

use garde::Validate;
use idm::{
    IdmError, ListPage, MemberKey, MemberRepo, NewTenant, RoleRepo, RoleScope, SessionRepo,
    SortDirection, TenantRepo, User, UserListFilter, UserRepo, UserSortBy,
};
use uuid::Uuid;

use super::model::{
    AddMember, CreateTenant, ListMembers, MemberStatus, MemberView, ResolvedMember, TenantStatus,
    TenantView, UpdateTenant,
};
use super::ports::{MemberProfiles, MemberSearchIndex};
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::{holds_platform_role, RoleName};
use crate::kernel::pagination::{OffsetPosition, Page, PageParams};
use crate::kernel::tenant_id::TenantId;

/// 核心分页参数 → idm 列表分页。
fn list_page(page: &PageParams) -> ListPage {
    match page {
        PageParams::Offset {
            page,
            size,
            with_total,
        } => ListPage::Offset {
            offset: (page - 1) * size,
            limit: *size,
            with_total: *with_total,
        },
        PageParams::Cursor { after, limit } => ListPage::Cursor {
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
        PageParams::Offset { page, size, .. } => {
            Page::new_with_offset(items, OffsetPosition { page, size }, total)
        }
        PageParams::Cursor { limit, .. } => Page::new_with_cursor(items, limit, next_after),
    }
}

/// 租户与成员管理用例(平台管理员管租户 + 任意租户的成员,租户管理员管本租户的成员)。
/// `Clone` 廉价(只 clone `Arc`)。
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
        let listing = self.tenants.list(&list_page(&page)).await?;
        let items = listing.rows.into_iter().map(TenantView::from).collect();
        Ok(into_page(items, page, listing.total, listing.next_after))
    }

    /// 建租户(status = active)。slug 被占(含已软删的)→ 409。
    pub async fn create_tenant(
        &self,
        request: CreateTenant,
        by: Option<&str>,
    ) -> Result<TenantView, AppError> {
        request.validate()?;
        let fields = NewTenant {
            slug: &request.slug,
            name: &request.name,
        };
        Ok(self.tenants.create(fields, by).await?.into())
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
        request: UpdateTenant,
        by: Option<&str>,
    ) -> Result<TenantView, AppError> {
        request.validate()?;
        let mut tenant = self.tenants.get(id).await?;
        if tenant.name != request.name {
            tenant = self.tenants.update_name(id, &request.name, by).await?;
        }
        if TenantStatus::from(tenant.status) != request.status {
            tenant = self
                .tenants
                .set_status(id, idm::TenantStatus::from(request.status), by)
                .await?;
        }
        if request.status == TenantStatus::Suspended {
            self.sessions.revoke_for_tenant(id).await?;
        }
        Ok(tenant.into())
    }

    /// 平台接口用:路径里的租户 id → 存活租户的 `TenantId`(不存在 / 已软删 / nil → 404)。
    pub async fn tenant_scope(&self, id: Uuid) -> Result<TenantId, AppError> {
        let tenant = self.tenants.get(id).await?;
        TenantId::try_new(tenant.id).map_err(|_| AppError::NotFound)
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
        let query = filter.query.as_deref().filter(|s| !s.trim().is_empty());
        match &self.search {
            Some(search) => {
                let listing = search.query(tenant, query, &page).await?;
                let ids: Vec<Uuid> = listing.rows.iter().map(|row| row.user_id).collect();
                let profiles = self.profiles.batch(&ids).await?;
                let platform = self.platform_role_holders(&ids).await?;
                let items: Vec<MemberView> = listing
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
                    .collect::<Result<_, AppError>>()?;
                Ok(into_page(items, page, listing.total, listing.next_after))
            }
            None => {
                if query.is_some() {
                    return Err(AppError::Validation(
                        "search requires projection backend".into(),
                    ));
                }
                let listing = self
                    .members
                    .list_by_tenant(tenant.as_uuid(), &list_page(&page))
                    .await?;
                let ids: Vec<Uuid> = listing.rows.iter().map(|m| m.user_id).collect();
                let users: HashMap<Uuid, User> = self
                    .users
                    .find_by_ids(&ids)
                    .await?
                    .into_iter()
                    .map(|u| (u.id, u))
                    .collect();
                let profiles = self.profiles.batch(&ids).await?;
                let platform = self.platform_role_holders(&ids).await?;
                let items = listing
                    .rows
                    .into_iter()
                    .filter_map(|member| {
                        // 账号已删(成员行还在)→ 跳过,同投影路的基线过滤
                        let user = users.get(&member.user_id)?;
                        let profile = profiles.get(&member.user_id);
                        Some(MemberView {
                            id: member.user_id,
                            username: user.username.clone(),
                            email: user.email.clone(),
                            display_name: profile.and_then(|p| p.display_name.clone()),
                            avatar_url: profile.and_then(|p| p.avatar_url.clone()),
                            roles: RoleName::parse_lossy(member.roles),
                            status: member.status.into(),
                            holds_platform_role: platform.contains(&member.user_id),
                        })
                    })
                    .collect();
                Ok(into_page(items, page, listing.total, listing.next_after))
            }
        }
    }

    /// 按**完整用户名**把已有账号加进租户(租户管理员用,spec §4.5)。精确匹配:去掉首尾空白后必须与账号的
    /// username 完全相等(邮箱、大小写不同都不算);查不到 → `AccountNotFound`(404 `account_not_found`)。
    /// 不建账号。已是成员 → 409;授平台角色 / 未知角色 → 422。
    pub async fn add_member(
        &self,
        tenant: TenantId,
        request: AddMember,
        by: Option<&str>,
    ) -> Result<MemberView, AppError> {
        let ResolvedMember { user_id, role_ids } = self.resolve_add_member(&request).await?;
        self.members
            .add(member_key(tenant, user_id), &role_ids, by)
            .await?;
        self.member_view(tenant, user_id).await
    }

    /// [`Self::add_member`] 的前半段(不写):校验(422)→ 租户角色 id(平台角色 / 未知 → 422)→ 按完整用户名找账号
    /// (查不到 → 404 `account_not_found`)。HTTP 边界先用它拿到目标账号 id 做防接管闸,再调 `add_member`。
    pub async fn resolve_add_member(
        &self,
        request: &AddMember,
    ) -> Result<ResolvedMember, AppError> {
        request.validate()?;
        let role_ids = self.tenant_role_ids(&request.roles).await?;
        let username = request.username.trim();
        // ponytail: find_by_identifier 也按邮箱匹配,所以再比一次 username。极端情况下(某人的 username 恰好等于
        // 另一人的邮箱)它可能先命中邮箱那个人 → 这里判 404;要根治需 idm 加「按用户名精确查」的原语。
        let user = self
            .users
            .find_by_identifier(username)
            .await?
            .map(|u| u.user)
            .filter(|u| u.username == username)
            .ok_or(AppError::AccountNotFound)?;
        Ok(ResolvedMember {
            user_id: user.id,
            role_ids,
        })
    }

    /// 平台管理员设某租户的成员(PUT:不是成员则加入,是成员则全量替换租户角色)。账号不存在 → 404。
    pub async fn put_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[RoleName],
        by: Option<&str>,
    ) -> Result<MemberView, AppError> {
        // 先确认账号存活(不存在 / 已删 → 404),再写成员关系 —— 否则会给不存在的账号落一行成员关系,
        // 最后取视图时才 404,而写已经生效了。
        self.users.find_by_id(user_id).await?;
        let role_ids = self.tenant_role_ids(roles).await?;
        let key = member_key(tenant, user_id);
        let joined = match self.members.get(key).await? {
            Some(_) => false,
            // 查完到加入之间被并发加进来了(add → Conflict):照样落成「全量换角色」,PUT 保持幂等。
            None => match self.members.add(key, &role_ids, by).await {
                Ok(_) => true,
                Err(IdmError::Conflict(_)) => false,
                Err(other) => return Err(other.into()),
            },
        };
        if !joined {
            self.members.set_roles(key, &role_ids, by).await?;
        }
        self.member_view(tenant, user_id).await
    }

    /// 全量替换成员在该租户的租户角色(原子)。不是该租户的成员 → 404。
    pub async fn set_member_roles(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[RoleName],
        by: Option<&str>,
    ) -> Result<MemberView, AppError> {
        let role_ids = self.tenant_role_ids(roles).await?;
        self.members
            .set_roles(member_key(tenant, user_id), &role_ids, by)
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
        by: Option<&str>,
    ) -> Result<(), AppError> {
        let key = member_key(tenant, user_id);
        let removed = match self.members.remove(key, by).await {
            Ok(()) => Ok(()),
            Err(IdmError::NotFound) => Err(AppError::NotFound),
            Err(other) => return Err(other.into()),
        };
        self.sessions.revoke_for_member(key).await?;
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
            .get(member_key(tenant, user_id))
            .await?
            .ok_or(AppError::NotFound)?
            .roles)
    }

    /// 单个成员的视图(写操作的响应)。
    async fn member_view(&self, tenant: TenantId, user_id: Uuid) -> Result<MemberView, AppError> {
        let membership = self
            .members
            .get(member_key(tenant, user_id))
            .await?
            .ok_or(AppError::NotFound)?;
        let user = self.users.find_by_id(user_id).await?;
        let profiles = self.profiles.batch(&[user_id]).await?;
        let profile = profiles.get(&user_id);
        let platform_roles = self.roles.roles_for_user(user_id).await?;
        Ok(MemberView {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: profile.and_then(|p| p.display_name.clone()),
            avatar_url: profile.and_then(|p| p.avatar_url.clone()),
            roles: RoleName::parse_lossy(membership.roles),
            status: membership.status.into(),
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
            .filter(|n| holds_platform_role(slice::from_ref(n)))
            .collect();
        if names.is_empty() {
            return Ok(HashSet::new());
        }
        let wanted: HashSet<Uuid> = ids.iter().copied().collect();
        let filter = UserListFilter {
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
                    UserSortBy::CreatedAt,
                    SortDirection::Ascending,
                    &ListPage::Offset {
                        offset,
                        limit: BATCH,
                        with_total: false,
                    },
                )
                .await?;
            let fetched = page.rows.len() as u64;
            let wanted_holders = page
                .rows
                .into_iter()
                .map(|u| u.id)
                .filter(|id| wanted.contains(id));
            holders.extend(wanted_holders);
            if fetched < BATCH {
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
        if let Some(platform_role) = names.iter().find(|n| n.scope() != RoleScope::Tenant) {
            return Err(AppError::Validation(format!(
                "role {} is a platform role: grant it through account management, tenant membership only grants tenant roles",
                platform_role.as_str()
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
            .filter(|r| r.scope == RoleScope::Tenant)
            .map(|r| (r.name, r.id))
            .collect();
        names
            .iter()
            .map(|name| {
                catalog.get(name.as_str()).copied().ok_or_else(|| {
                    AppError::Validation(format!("unknown tenant role: {}", name.as_str()))
                })
            })
            .collect()
    }
}

/// 租户 + 账号 → idm 的成员复合主键。
fn member_key(tenant: TenantId, user_id: Uuid) -> MemberKey {
    MemberKey {
        tenant_id: tenant.as_uuid(),
        user_id,
    }
}

/// 投影里的成员状态串 → 闭集。缺(成员列还没落地,理论上不出现:成员行由成员事件建)→ active;
/// 闭集外 → 500(单写者:只有我们的投影器写它,出现即数据异常,不静默)。
fn parse_member_status(status: Option<&str>) -> Result<MemberStatus, AppError> {
    match status {
        None => Ok(MemberStatus::Active),
        Some(status) => status
            .parse()
            .map_err(|e: String| AppError::Internal(anyhow::anyhow!(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tenants::static_member_profiles::StaticMemberProfiles;
    use std::sync::atomic::{AtomicBool, Ordering};

    use idm::{
        InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryTenantRepo,
        InMemoryUserRepo, NewRole, NewUser,
    };

    fn new_user<'fields>(username: &'fields str, email: Option<&'fields str>) -> NewUser<'fields> {
        NewUser {
            username,
            email,
            password_hash: "hash",
        }
    }

    use crate::features::tenants::ports::{MemberSearchPage, MemberSearchRow};

    struct Env {
        service: TenantAdminService,
        users: Arc<InMemoryUserRepo>,
        tenants: Arc<InMemoryTenantRepo>,
        members: Arc<InMemoryMemberRepo>,
        sessions: Arc<InMemorySessionRepo>,
        roles: Arc<InMemoryRoleRepo>,
    }

    /// 内存装配:各 idm 仓储共享存储;角色目录 superadmin(平台)/ admin、user(租户)。
    async fn env_with(search: Option<Arc<dyn MemberSearchIndex>>) -> Env {
        let users = InMemoryUserRepo::new();
        let roles = InMemoryRoleRepo::new_shared_with(&users);
        let sessions = InMemorySessionRepo::new_shared_with(&users);
        let members = InMemoryMemberRepo::new_shared_with(&users);
        let tenants = InMemoryTenantRepo::new_shared_with(&users);
        for role in RoleName::ALL {
            roles
                .upsert(
                    NewRole {
                        name: role.as_str(),
                        display_name: role.display_name(),
                        scope: role.scope(),
                    },
                    None,
                )
                .await
                .unwrap();
        }
        let users = Arc::new(users);
        let tenants = Arc::new(tenants);
        let members = Arc::new(members);
        let sessions = Arc::new(sessions);
        let roles = Arc::new(roles);
        let service = TenantAdminService::new(
            tenants.clone(),
            members.clone(),
            users.clone(),
            roles.clone(),
            sessions.clone(),
            Arc::new(StaticMemberProfiles::new()),
            search,
        );
        Env {
            service,
            users,
            tenants,
            members,
            sessions,
            roles,
        }
    }

    async fn account(env: &Env, name: &str) -> Uuid {
        env.users
            .create_with_roles(new_user(name, None), &[], None)
            .await
            .unwrap()
            .id
    }

    async fn tenant(env: &Env, slug: &str) -> TenantId {
        let fields = NewTenant { slug, name: slug };
        let created = env.tenants.create(fields, None).await.unwrap();
        TenantId::try_new(created.id).unwrap()
    }

    /// 在 `tenant` 里给 `user` 建一个活跃会话(refresh hash = `hash`)。
    async fn session(env: &Env, user: Uuid, tenant: TenantId, hash: &str) {
        env.sessions
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

    async fn active(env: &Env, hash: &str) -> bool {
        env.sessions
            .find_active(hash, time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    }

    /// 移出成员 = 吊销他在**该租户**的会话(别的租户的会话不动);重试(成员行已没了)回 404 但照样补吊销。
    #[tokio::test]
    async fn remove_member_revokes_sessions_in_that_tenant_only() {
        let env = env_with(None).await;
        let tenant_a = tenant(&env, "a").await;
        let tenant_b = tenant(&env, "b").await;
        let bob = account(&env, "bob").await;
        for tenant_id in [tenant_a, tenant_b] {
            env.service
                .put_member(tenant_id, bob, &[RoleName::User], None)
                .await
                .unwrap();
        }
        session(&env, bob, tenant_a, "in-a").await;
        session(&env, bob, tenant_b, "in-b").await;

        env.service
            .remove_member(tenant_a, bob, None)
            .await
            .unwrap();
        assert!(!active(&env, "in-a").await, "该租户的会话应被吊销");
        assert!(active(&env, "in-b").await, "别的租户的会话不动");

        // 模拟「上次移出成功、吊销失败」:成员行已没了、会话还活着 → 重试回 404,但会话被补吊销
        env.members
            .remove(member_key(tenant_b, bob), None)
            .await
            .unwrap();
        assert!(active(&env, "in-b").await);
        assert!(matches!(
            env.service.remove_member(tenant_b, bob, None).await,
            Err(AppError::NotFound)
        ));
        assert!(!active(&env, "in-b").await, "重试应补吊销");
    }

    /// 成员仓储包装:**第一次** `get` 回 None(模拟「查时还不是成员、加入前被并发加进来」),其余转给内存实现。
    struct StaleGet {
        inner: Arc<InMemoryMemberRepo>,
        /// 还没回过那一次 None。
        first_get: AtomicBool,
    }

    #[async_trait::async_trait]
    impl MemberRepo for StaleGet {
        async fn add(
            &self,
            member: MemberKey,
            role_ids: &[Uuid],
            by: Option<&str>,
        ) -> Result<idm::Membership, idm::IdmError> {
            self.inner.add(member, role_ids, by).await
        }
        async fn remove(&self, member: MemberKey, by: Option<&str>) -> Result<(), idm::IdmError> {
            self.inner.remove(member, by).await
        }
        async fn set_status(
            &self,
            member: MemberKey,
            status: idm::MemberStatus,
            by: Option<&str>,
        ) -> Result<(), idm::IdmError> {
            self.inner.set_status(member, status, by).await
        }
        async fn set_roles(
            &self,
            member: MemberKey,
            role_ids: &[Uuid],
            by: Option<&str>,
        ) -> Result<(), idm::IdmError> {
            self.inner.set_roles(member, role_ids, by).await
        }
        async fn get(&self, member: MemberKey) -> Result<Option<idm::Membership>, idm::IdmError> {
            if self.first_get.swap(false, Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.get(member).await
        }
        async fn list_by_tenant(
            &self,
            tenant_id: Uuid,
            page: &ListPage,
        ) -> Result<idm::ListResult<idm::Membership>, idm::IdmError> {
            self.inner.list_by_tenant(tenant_id, page).await
        }
        async fn memberships_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<idm::Membership>, idm::IdmError> {
            self.inner.memberships_for_user(user_id).await
        }
        async fn touch_last_used(&self, member: MemberKey) -> Result<(), idm::IdmError> {
            self.inner.touch_last_used(member).await
        }
    }

    /// PUT 成员:账号不存在 / 已删 → 404,且**不落任何成员关系**(先查账号再写)。
    #[tokio::test]
    async fn put_member_unknown_or_deleted_account_is_404_without_writing() {
        let env = env_with(None).await;
        let acme = tenant(&env, "acme").await;
        let ghost = Uuid::now_v7();
        assert!(matches!(
            env.service
                .put_member(acme, ghost, &[RoleName::User], None)
                .await,
            Err(AppError::NotFound)
        ));
        assert!(
            env.members
                .get(member_key(acme, ghost))
                .await
                .unwrap()
                .is_none(),
            "不存在的账号不该落成员关系"
        );

        let dave = account(&env, "dave").await;
        env.users.soft_delete(dave, None).await.unwrap();
        assert!(matches!(
            env.service
                .put_member(acme, dave, &[RoleName::User], None)
                .await,
            Err(AppError::NotFound)
        ));
        assert!(
            env.members
                .get(member_key(acme, dave))
                .await
                .unwrap()
                .is_none(),
            "已删的账号不该落成员关系"
        );
    }

    /// PUT 成员幂等:加入时撞上「已是成员」(并发加入)→ 改走全量换角色,不报 409。
    #[tokio::test]
    async fn put_member_falls_back_to_set_roles_on_conflict() {
        let env = env_with(None).await;
        let acme = tenant(&env, "acme").await;
        let carol = account(&env, "carol").await;
        env.service
            .put_member(acme, carol, &[RoleName::Admin], None)
            .await
            .unwrap();
        let racy = TenantAdminService::new(
            env.tenants.clone(),
            Arc::new(StaleGet {
                inner: env.members.clone(),
                first_get: AtomicBool::new(true),
            }),
            env.users.clone(),
            env.roles.clone(),
            env.sessions.clone(),
            Arc::new(StaticMemberProfiles::new()),
            None,
        );
        let member = racy
            .put_member(acme, carol, &[RoleName::User], None)
            .await
            .unwrap();
        assert_eq!(member.roles, vec![RoleName::User]);
        let back = env.service.member_role_names(acme, carol).await.unwrap();
        assert_eq!(back, vec!["user".to_string()]);
    }

    /// 停用租户 = 吊销该租户里所有人的会话;别的租户的会话不动;恢复不会让旧会话复活。
    #[tokio::test]
    async fn suspend_tenant_revokes_its_sessions() {
        let env = env_with(None).await;
        let tenant_a = tenant(&env, "a").await;
        let tenant_b = tenant(&env, "b").await;
        let bob = account(&env, "bob").await;
        let carol = account(&env, "carol").await;
        for (tenant_id, user_id) in [(tenant_a, bob), (tenant_a, carol), (tenant_b, bob)] {
            env.service
                .put_member(tenant_id, user_id, &[], None)
                .await
                .unwrap();
        }
        session(&env, bob, tenant_a, "bob-a").await;
        session(&env, carol, tenant_a, "carol-a").await;
        session(&env, bob, tenant_b, "bob-b").await;
        let put = |status| UpdateTenant {
            name: "a".into(),
            status,
        };
        env.service
            .update_tenant(tenant_a.as_uuid(), put(TenantStatus::Suspended), None)
            .await
            .unwrap();
        env.service
            .update_tenant(tenant_a.as_uuid(), put(TenantStatus::Active), None)
            .await
            .unwrap();
        assert!(!active(&env, "bob-a").await);
        assert!(!active(&env, "carol-a").await);
        assert!(active(&env, "bob-b").await);
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
        let env = env_with(None).await;
        let acme = tenant(&env, "acme").await;
        let alice = env
            .users
            .create_with_roles(new_user("alice", Some("alice@x.io")), &[], None)
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
                    env.service.add_member(acme, add(miss, vec![]), None).await,
                    Err(AppError::AccountNotFound)
                ),
                "{miss}"
            );
        }
        // 平台角色 → 422(先于查账号)
        assert!(matches!(
            env.service
                .add_member(acme, add("nobody", vec![RoleName::Superadmin]), None)
                .await,
            Err(AppError::Validation(_))
        ));
        let member = env
            .service
            .add_member(
                acme,
                add(" alice ", vec![RoleName::User, RoleName::User]),
                None,
            )
            .await
            .unwrap();
        assert_eq!(member.id, alice);
        assert_eq!(member.roles, vec![RoleName::User]);
        assert_eq!(member.status, MemberStatus::Active);
        assert!(matches!(
            env.service
                .add_member(acme, add("alice", vec![]), None)
                .await,
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn members_are_scoped_to_their_tenant() {
        let env = env_with(None).await;
        let tenant_a = tenant(&env, "a").await;
        let tenant_b = tenant(&env, "b").await;
        let bob = account(&env, "bob").await;
        env.service
            .put_member(tenant_b, bob, &[RoleName::Admin], None)
            .await
            .unwrap();
        assert!(env
            .service
            .list_members(tenant_a, &ListMembers::default(), page())
            .await
            .unwrap()
            .items
            .is_empty());
        for result in [
            env.service
                .set_member_roles(tenant_a, bob, &[RoleName::User], None)
                .await
                .err(),
            env.service.remove_member(tenant_a, bob, None).await.err(),
            env.service.member_role_names(tenant_a, bob).await.err(),
        ] {
            assert!(matches!(result, Some(AppError::NotFound)), "{result:?}");
        }
        // b 里的成员关系没动
        let list = env
            .service
            .list_members(tenant_b, &ListMembers::default(), page())
            .await
            .unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].roles, vec![RoleName::Admin]);
    }

    #[tokio::test]
    async fn put_member_adds_then_replaces_roles() {
        let env = env_with(None).await;
        let acme = tenant(&env, "acme").await;
        let carol = account(&env, "carol").await;
        let member = env
            .service
            .put_member(acme, carol, &[RoleName::Admin], None)
            .await
            .unwrap();
        assert_eq!(member.roles, vec![RoleName::Admin]);
        let member = env
            .service
            .put_member(acme, carol, &[], None)
            .await
            .unwrap();
        assert!(member.roles.is_empty());
        assert!(matches!(
            env.service
                .put_member(acme, Uuid::now_v7(), &[], None)
                .await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn update_tenant_renames_and_suspends() {
        let env = env_with(None).await;
        let created = env
            .service
            .create_tenant(
                CreateTenant {
                    slug: "acme".into(),
                    name: "Acme".into(),
                },
                None,
            )
            .await
            .unwrap();
        let updated = env
            .service
            .update_tenant(
                created.id,
                UpdateTenant {
                    name: "Acme Inc".into(),
                    status: TenantStatus::Suspended,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            (updated.name.as_str(), updated.status),
            ("Acme Inc", TenantStatus::Suspended)
        );
        assert_eq!(updated.slug, "acme");
        assert!(matches!(
            env.service.get_tenant(Uuid::now_v7()).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            env.service.tenant_scope(Uuid::nil()).await,
            Err(AppError::NotFound)
        ));
    }

    #[tokio::test]
    async fn list_without_search_backend_rejects_q() {
        let env = env_with(None).await;
        let acme = tenant(&env, "acme").await;
        let filter = ListMembers {
            query: Some("x".into()),
        };
        assert!(matches!(
            env.service.list_members(acme, &filter, page()).await,
            Err(AppError::Validation(_))
        ));
        // 纯空白 q 不算搜索
        let filter = ListMembers {
            query: Some("  ".into()),
        };
        assert!(env
            .service
            .list_members(acme, &filter, page())
            .await
            .is_ok());
    }

    /// 假投影:回放预置行(测投影分支的映射,不测查询语义)。
    struct FakeIndex(Vec<MemberSearchRow>);

    #[async_trait::async_trait]
    impl MemberSearchIndex for FakeIndex {
        async fn query(
            &self,
            _tenant: TenantId,
            _query: Option<&str>,
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
        let env = env_with(Some(Arc::new(FakeIndex(vec![row(Some("inactive"))])))).await;
        let acme = tenant(&env, "acme").await;
        let filter = ListMembers {
            query: Some("do".into()),
        };
        let got = env
            .service
            .list_members(acme, &filter, page())
            .await
            .unwrap();
        assert_eq!(got.items.len(), 1);
        let member = &got.items[0];
        assert_eq!(member.display_name.as_deref(), Some("Dora"));
        assert_eq!(member.roles, vec![RoleName::Admin], "闭集外角色名跳过");
        assert_eq!(member.status, MemberStatus::Inactive);

        let bad = env_with(Some(Arc::new(FakeIndex(vec![row(Some("weird"))])))).await;
        let acme = tenant(&bad, "acme").await;
        assert!(matches!(
            bad.service
                .list_members(acme, &ListMembers::default(), page())
                .await,
            Err(AppError::Internal(_))
        ));
    }
}

//! idm 默认数据 seed —— **进程内启动时**(`AppState::try_new`,见 [`crate::app::app_state`])或**显式 CLI**
//! (`src/bin/seed.rs`)两条路共用此核心。幂等:role / 租户 upsert、账号 find-or-create、平台角色与成员关系取并集补齐,
//! 可重复跑、可并发。
//!
//! 分工:**角色集 / 权限集 / role→权限默认**是代码闭集(`kernel::authorization::{RoleName, Permission}`,不做动态 CRUD);
//! **租户与账号**(实例数据 + 密码)归 `seed.toml`(编译期 `include_str!` 嵌入,`SEED_FILE` 可覆盖)。
//!
//! 格式(spec §4.7):
//! ```toml
//! [[tenants]]                      # slug = "default" 时 id 固定为默认租户
//! slug = "default"
//! name = "默认组织"
//!
//! [[users]]                        # 旧名 [[accounts]] 仍认
//! username = "superadmin"
//! password = "pwd"
//! platform_roles = ["superadmin"]  # 平台角色(经 user_roles,进 JWT roles)
//! tenants = [{ slug = "default", roles = ["admin"] }]  # 成员关系 + 租户角色
//! ```
//! 旧格式的 `roles = [...]` 仍认:按 `RoleName::scope()` 拆,平台角色进 `platform_roles`,
//! 租户角色进默认租户的成员关系。

use std::collections::{BTreeSet, HashMap};
use std::fs;

use anyhow::Context;
use serde::Deserialize;
use uuid::Uuid;

use crate::features::profile::{ProfileFields, ProfileRepo};
use crate::kernel::authorization::{Permission, Policy, RoleName};
use crate::kernel::tenant_id::DEFAULT_TENANT_ID;
use idm::{
    IdmError, ListPage, MemberKey, MemberRepo, NewRole, NewTenant, NewUser, PasswordHasher,
    RoleRepo, RoleScope, SortDirection, TenantRepo, UserListFilter, UserRepo, UserSortBy,
    UserWithHash,
};

/// 编译期嵌入的默认 seed(仓库根 `seed.toml`)。`SEED_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `seed.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_SEED: &str = include_str!("../../seed.toml");

/// 默认租户的 slug(固定 id = [`DEFAULT_TENANT_ID`])。
pub const DEFAULT_TENANT_SLUG: &str = "default";

/// 外置 seed:**租户 + 账号**(实例数据 + 密码,`SEED_FILE` 可覆盖)。角色集 / 权限集 / role→权限
/// 默认全收进代码枚举(`RoleName` / `Permission`)—— 封闭集、不做动态 CRUD(角色**有哪些权限**才可
/// 运行时改,落 `role_permissions` 表)。
#[derive(Deserialize, Default)]
pub struct SeedData {
    #[serde(default)]
    tenants: Vec<TenantSeed>,
    #[serde(default, alias = "accounts")]
    users: Vec<UserSeed>,
}

/// 一个租户。`slug = "default"` → id 固定为默认租户(写了别的 id 报错);其余不写 id 按 slug 找或建。
#[derive(Deserialize, Clone)]
pub(crate) struct TenantSeed {
    #[serde(default)]
    id: Option<Uuid>,
    slug: String,
    name: String,
}

/// 一个账号(`[[users]]`,旧名 `[[accounts]]`):用户名 / 密码 + 平台角色 + 成员关系。
#[derive(Deserialize, Clone)]
pub(crate) struct UserSeed {
    username: String,
    #[serde(default)]
    email: Option<String>,
    password: String,
    /// 平台角色(`RoleName::scope() == Platform`)。
    #[serde(default)]
    platform_roles: Vec<String>,
    /// 成员关系:在哪些租户(按 slug)、是什么租户角色。
    #[serde(default)]
    tenants: Vec<MembershipSeed>,
    /// **旧格式**(多租户之前的 `[[accounts]].roles`):按角色作用域拆 —— 平台角色并进 `platform_roles`,
    /// 租户角色并进默认租户的成员关系。新文件别用。
    #[serde(default)]
    roles: Vec<String>,
    /// 初始 profile 的显示名(可选)。落 **app schema** 的 profiles 表,只在 app/idm 同进程
    /// (`Mount::Both`)时写 —— 见 [`apply_profiles`]。不设 = 建一行各段为 null 的空资料。
    #[serde(default)]
    display_name: Option<String>,
}

/// 一条成员关系:租户 slug + 该租户里的角色。
#[derive(Deserialize, Clone)]
pub(crate) struct MembershipSeed {
    pub(crate) slug: String,
    #[serde(default)]
    pub(crate) roles: Vec<String>,
}

impl UserSeed {
    /// 生效的平台角色:`platform_roles` ∪ 旧格式 `roles` 里的平台角色(去重保序)。
    fn effective_platform_roles(&self) -> Vec<String> {
        let legacy = self
            .roles
            .iter()
            .filter(|r| role_scope(r) == Some(RoleScope::Platform));
        dedup(self.platform_roles.iter().chain(legacy))
    }

    /// 是否声明了 superadmin(新旧格式都算)。
    pub(crate) fn declares_superadmin(&self) -> bool {
        self.effective_platform_roles()
            .iter()
            .any(|r| r == RoleName::Superadmin.as_str())
    }

    /// 生效的成员关系:`tenants` + 旧格式 `roles` 里的租户角色(并进默认租户)。同 slug 合并、角色去重。
    fn effective_memberships(&self) -> Vec<MembershipSeed> {
        let mut out: Vec<MembershipSeed> = Vec::new();
        let legacy: Vec<String> = self
            .roles
            .iter()
            .filter(|r| role_scope(r) != Some(RoleScope::Platform))
            .cloned()
            .collect();
        let legacy = (!legacy.is_empty()).then(|| MembershipSeed {
            slug: DEFAULT_TENANT_SLUG.to_owned(),
            roles: legacy,
        });
        for membership in self.tenants.iter().cloned().chain(legacy) {
            match out.iter_mut().find(|o| o.slug == membership.slug) {
                Some(existing) => {
                    existing.roles = dedup(existing.roles.iter().chain(membership.roles.iter()))
                }
                None => out.push(MembershipSeed {
                    roles: dedup(membership.roles.iter()),
                    ..membership
                }),
            }
        }
        out
    }
}

fn dedup<'name>(names: impl Iterator<Item = &'name String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if !out.contains(name) {
            out.push(name.clone());
        }
    }
    out
}

/// 闭集内角色的作用域;闭集外 → `None`。
fn role_scope(name: &str) -> Option<RoleScope> {
    let parsed: Result<RoleName, _> = name.parse();
    parsed.ok().map(|r| r.scope())
}

/// 校验 seed 引用的角色:必须是闭集内角色,且作用域对得上(平台角色只能进 `platform_roles`、租户角色只能进成员关系)。
fn check_role(username: &str, role: &str, expect: RoleScope) -> anyhow::Result<()> {
    match role_scope(role) {
        None => anyhow::bail!("账号 {username} 引用了未声明的角色 {role}"),
        Some(scope) if scope != expect => anyhow::bail!(
            "账号 {username} 把角色 {role}({scope:?} 角色)写在了 {expect:?} 的位置:平台角色写 platform_roles,租户角色写 tenants.roles"
        ),
        Some(_) => Ok(()),
    }
}

impl SeedData {
    /// 只有账号(没有租户声明)的 seed —— mock 的演示账号复用 [`apply`] 用(引用的租户须已存在)。
    pub(crate) fn new_with_users(users: Vec<UserSeed>) -> Self {
        Self {
            tenants: Vec::new(),
            users,
        }
    }

    /// 载入:`path`(来自 `Config.seed_file`,即 `SEED_FILE`)指定的外部文件优先,否则用编译期嵌入的默认。
    /// 角色引用 / 作用域 / 默认租户 id 在这里就校验,写错启动即挂。
    pub fn try_new(path: Option<&str>) -> anyhow::Result<Self> {
        let content = match path {
            Some(path) => {
                fs::read_to_string(path).with_context(|| format!("读 SEED_FILE {path} 失败"))?
            }
            None => EMBEDDED_SEED.to_owned(),
        };
        let data: Self = toml::from_str(&content).context("解析 seed 数据失败")?;
        data.validate()?;
        Ok(data)
    }

    /// 校验租户 id、superadmin 唯一、角色引用与作用域(见 [`check_role`])。
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        for tenant in &self.tenants {
            tenant_seed_id(tenant)?;
        }
        // superadmin 只有一个(2026-11-26):只能由 seed 声明,且只能声明给一个账号。
        let roots: Vec<&str> = self
            .users
            .iter()
            .filter(|u| u.declares_superadmin())
            .map(|u| u.username.as_str())
            .collect();
        anyhow::ensure!(
            roots.len() <= 1,
            "superadmin 只能有一个,seed 却声明给了 {} 个账号:{}(平台管理员用 platform_admin)",
            roots.len(),
            roots.join(", ")
        );
        for user in &self.users {
            for role in user.effective_platform_roles() {
                check_role(&user.username, &role, RoleScope::Platform)?;
            }
            for membership in user.effective_memberships() {
                for role in &membership.roles {
                    check_role(&user.username, role, RoleScope::Tenant)?;
                }
            }
        }
        Ok(())
    }

    /// role→权限**默认**映射 → app 内存授权 `Policy`(无 `APP_DB_HOST` 时用)。默认来自 `RoleName` 代码;
    /// `implies` 展开在 `Policy::new`。**permissions 不写进 idm 库**。
    #[must_use]
    pub fn policy(&self) -> Policy {
        Policy::new(
            RoleName::ALL
                .iter()
                .map(|r| (r.as_str().to_owned(), r.default_permissions())),
        )
    }

    /// 账号引用到的角色名(平台 + 租户;供 `Policy::assert_roles_covered` 启动期校验:每个被授予的 role 都得有策略条目)。
    #[must_use]
    pub fn granted_roles(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for user in &self.users {
            set.extend(user.effective_platform_roles());
            for membership in user.effective_memberships() {
                set.extend(membership.roles);
            }
        }
        set.into_iter().collect()
    }

    /// 权限词表(权限 + 说明)—— 供 `policy_repo::seed_authorization` upsert 进 `permissions` 表。源自 `Permission` 代码闭集。
    pub fn permission_catalog(&self) -> impl Iterator<Item = PermissionCatalogEntry> {
        Permission::ALL
            .into_iter()
            .map(|permission| PermissionCatalogEntry {
                permission,
                description: permission.description(),
            })
    }

    /// role→权限**默认**映射(implies 未展开,展开在 `Policy::new`)——
    /// 供 `policy_repo::seed_authorization` bootstrap `role_permissions` 表(`ON CONFLICT DO NOTHING`,不覆盖运行期改动)。
    pub fn role_permission_mappings(&self) -> impl Iterator<Item = RolePermissionMapping> {
        RoleName::ALL.into_iter().map(|role| RolePermissionMapping {
            role_name: role.as_str(),
            permissions: role.default_permissions(),
        })
    }
}

/// [`SeedData::permission_catalog`] 的一项:权限与它的说明。
#[derive(Clone, Copy, Debug)]
pub struct PermissionCatalogEntry {
    pub permission: Permission,
    pub description: &'static str,
}

/// [`SeedData::role_permission_mappings`] 的一项:角色名与它的默认权限(implies 未展开)。
#[derive(Clone, Debug)]
pub struct RolePermissionMapping {
    pub role_name: &'static str,
    pub permissions: Vec<Permission>,
}

/// seed / mock 写 idm 要用的仓储(内存模式须 `new_shared_with` 同一份存储,PG 模式同一个 idm 池)。
#[derive(Clone, Copy)]
pub struct IdmSeedRepos<'repos> {
    pub users: &'repos dyn UserRepo,
    pub roles: &'repos dyn RoleRepo,
    pub tenants: &'repos dyn TenantRepo,
    pub members: &'repos dyn MemberRepo,
}

/// 租户声明的固定 id:`default` 恒为默认租户(写了别的 id → 错);其余用声明的(可无)。
fn tenant_seed_id(tenant: &TenantSeed) -> anyhow::Result<Option<Uuid>> {
    if tenant.slug == DEFAULT_TENANT_SLUG {
        let default = DEFAULT_TENANT_ID.as_uuid();
        anyhow::ensure!(
            tenant.id.is_none_or(|id| id == default),
            "slug = \"default\" 的租户 id 固定为 {default},不能改"
        );
        return Ok(Some(default));
    }
    if let Some(id) = tenant.id {
        anyhow::ensure!(!id.is_nil(), "租户 {} 的 id 不能是 nil UUID", tenant.slug);
    }
    Ok(tenant.id)
}

/// 幂等确保一个租户存在,返回其 id。固定 id → `upsert_fixed`(已存在原样返回,不改名);
/// 否则按 slug 找,找不到再建(并发另一实例抢先建 → 退回按 slug 取)。
pub(crate) async fn ensure_tenant(
    tenants: &dyn TenantRepo,
    tenant: &TenantSeed,
    by: Option<&str>,
) -> anyhow::Result<Uuid> {
    if let Some(id) = tenant_seed_id(tenant)? {
        let got = tenants
            .upsert_fixed(id, tenant_fields(tenant), by)
            .await
            .with_context(|| format!("seed 租户 {} 失败", tenant.slug))?;
        return Ok(got.id);
    }
    match tenants.get_by_slug(&tenant.slug).await {
        Ok(found) => return Ok(found.id),
        Err(IdmError::NotFound) => {}
        Err(error) => return Err(anyhow::anyhow!("查租户 {} 失败: {error:?}", tenant.slug)),
    }
    match tenants.create(tenant_fields(tenant), by).await {
        Ok(created) => Ok(created.id),
        // 并发 seed 抢先建了 → 取它;slug 被**已删除**租户占着(不复用)→ get_by_slug 也 NotFound → 报错
        Err(IdmError::Conflict(_)) => Ok(tenants
            .get_by_slug(&tenant.slug)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "租户 slug {} 已被占用(可能是已删除的租户,slug 不复用): {error:?}",
                    tenant.slug
                )
            })?
            .id),
        Err(error) => Err(anyhow::anyhow!("seed 租户 {} 失败: {error:?}", tenant.slug)),
    }
}

/// seed 里的租户 → idm 建租户的字段。
fn tenant_fields(tenant: &TenantSeed) -> NewTenant<'_> {
    NewTenant {
        slug: &tenant.slug,
        name: &tenant.name,
    }
}

/// 已存在账号的平台角色**幂等补授**。写**并集**(现有平台角色 ∪ seed 声明),经 `set_roles` 落。
///
/// 为什么不是 `grant`:`grant` 只往 `user_roles` 插一行、**不发任何事件** —— idm 库里角色对了,
/// 但 CQRS 投影(账号目录 `account_index.roles`)收不到通知,会永久停在旧值(后台列表角色显示错、
/// `roles_any`/`roles_none` 过滤漏人),只能手工跑 rebuild_search 自愈。这与首建路径当初从
/// `create` + `grant` 改成 `create_with_roles` 是**同一个 bug**,当时只修了兄弟分支。
/// `set_roles` 在事务内 emit `user.roles_set`,投影据此收敛。
///
/// 为什么是并集而非直接写声明集:`set_roles` 是**原子全量替换** —— 直接写声明集会把运行期
/// 授予的平台角色清掉(重启即掉权,另一个 bug)。`grant` 的加性语义是刻意的,这里保住它。
/// 并集与现有相同 → 不写不发事件(幂等重跑无副作用)。
///
/// `current` 来自 `roles_for_user`(**只回平台角色**):`user_roles` 里多租户之前遗留的租户角色行
/// (迁移已复制进默认租户的 `member_roles`,读取时也被过滤)在补授时会被清掉 —— 它们本来就不生效。
async fn ensure_roles_with_event(
    roles: &dyn RoleRepo,
    user_id: Uuid,
    declared: &[String],
    by: Option<&str>,
) -> anyhow::Result<()> {
    let current = roles.roles_for_user(user_id).await?;
    if !declared.iter().any(|d| !current.contains(d)) {
        return Ok(()); // 声明的角色都已在身 → 幂等:无写、无事件
    }
    let union = role_ids_by_name(roles, current.iter().chain(declared.iter())).await?;
    roles.set_roles(user_id, &union, by).await?;
    Ok(())
}

/// 角色名 → id(去重保序)。走 `list()`(**不是**闭集):现有授予可能含闭集外的历史 / 手工角色,
/// 映射不到就会被并集漏掉 —— 那等于把它清掉。存活角色恒在 `list()` 里;真映射不到说明目录与授予
/// 不一致,宁可报错也不静默丢角色。
async fn role_ids_by_name<'name>(
    roles: &dyn RoleRepo,
    names: impl Iterator<Item = &'name String>,
) -> anyhow::Result<Vec<Uuid>> {
    let by_name: HashMap<String, Uuid> = roles
        .list()
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let mut ids: Vec<Uuid> = Vec::new();
    for name in names {
        match by_name.get(name) {
            Some(&id) if !ids.contains(&id) => ids.push(id),
            Some(_) => {}
            None => anyhow::bail!("角色 {name} 已授予但不在角色目录中"),
        }
    }
    Ok(ids)
}

/// [`ensure_membership`] 要确保的一条成员关系。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Membership<'roles> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// 声明的租户角色名。
    pub roles: &'roles [String],
}

/// 幂等确保成员关系 + 租户角色(取**并集**,同平台角色的理由:不清掉运行期授的租户角色)。
/// 不是成员 → `add`(发 `tenant.member_added`);已是成员 → 声明的角色都在身就不动,否则 `set_roles`
/// 写并集(发 `tenant.member_roles_set`)。**不改成员状态**:运行期被停用的成员,重跑 seed 不会被恢复。
pub(crate) async fn ensure_membership(
    repos: IdmSeedRepos<'_>,
    membership: Membership<'_>,
    by: Option<&str>,
) -> anyhow::Result<()> {
    let Membership {
        tenant_id,
        user_id,
        roles: declared,
    } = membership;
    let key = MemberKey { tenant_id, user_id };
    let existing = match repos.members.get(key).await? {
        Some(found) => found,
        None => {
            let ids = role_ids_by_name(repos.roles, declared.iter()).await?;
            match repos.members.add(key, &ids, by).await {
                Ok(_) => return Ok(()),
                // 并发 seed 抢先加了 → 当已是成员走并集
                Err(IdmError::Conflict(_)) => repos
                    .members
                    .get(key)
                    .await?
                    .context("并发 seed 冲突后仍查不到成员关系")?,
                Err(error) => return Err(anyhow::anyhow!("加成员失败: {error:?}")),
            }
        }
    };
    if !declared.iter().any(|d| !existing.roles.contains(d)) {
        return Ok(()); // 幂等:无写、无事件
    }
    let union = role_ids_by_name(repos.roles, existing.roles.iter().chain(declared.iter())).await?;
    repos.members.set_roles(key, &union, by).await?;
    Ok(())
}

/// superadmin 只有一个:库里已经有**别的**账号持有 superadmin 时,拒绝再把它授给 `username`(seed 换了 superadmin 的
/// 用户名、或两份 seed 各声明一个都会撞到这里)。要换人先在库里处理掉旧的 —— seed 不替你剥夺谁的 superadmin。
async fn ensure_sole_superadmin(
    repos: IdmSeedRepos<'_>,
    declared_user: Option<Uuid>,
    username: &str,
) -> anyhow::Result<()> {
    let holders = superadmin_holders(repos.users).await?;
    let others: Vec<&str> = holders
        .iter()
        .filter(|h| Some(h.user_id) != declared_user)
        .map(|h| h.username.as_str())
        .collect();
    anyhow::ensure!(
        others.is_empty(),
        "superadmin 只能有一个:库里已有账号 {} 持有 superadmin,seed 不能再授给 {username}(要换人先处理掉旧的)",
        others.join(", ")
    );
    Ok(())
}

/// 声明的 superadmin 条目**已过时**:库里恰好有一个存活的 superadmin,且不是声明的那个账号(`declared` = 按声明的
/// 用户名查到的账号,查不到为 `None`)→ 返回现有 superadmin 的用户名。零个(首次 seed)/ 就是它 / 多于一个
/// (启动期检查 [`ensure_single_superadmin`] 已拒)→ `None`。
async fn stale_superadmin_declaration(
    users: &dyn UserRepo,
    declared: Option<Uuid>,
) -> anyhow::Result<Option<String>> {
    let holders = superadmin_holders(users).await?;
    Ok(match holders.as_slice() {
        [only] if Some(only.user_id) != declared => Some(only.username.clone()),
        _ => None,
    })
}

/// [`apply`] 的结果:哪些已存在的账号因为**确认不了是运维建的**(密码和 seed 对不上)被跳过了补授。
/// 跳过的账号 [`apply_profiles`] 也不给建初始资料(抢注者不该拿到 seed 里的显示名)。
#[derive(Debug, Default)]
pub struct SeedReport {
    pub skipped: Vec<SkippedGrants>,
}

/// 一个被跳过补授的账号:账号 id + 用户名 + 它缺的、seed 本要补给它的东西(「平台角色 x」「组织 s 的角色 r」「组织 s 的成员关系」)。
/// 判「跳没跳过」只看 `user_id`([`SeedReport::is_skipped`]):用户名是给人看的 —— seed 的用户名经 `find_by_identifier`
/// 也可能命中邮箱等于它的另一个账号,那时两边的用户名对不上。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedGrants {
    pub user_id: Uuid,
    pub username: String,
    pub missing: Vec<String>,
}

impl SeedReport {
    fn is_skipped(&self, user_id: Uuid) -> bool {
        self.skipped.iter().any(|s| s.user_id == user_id)
    }
}

/// seed 要给一个**已存在**的同名账号补授它还没有的东西(平台角色 / 成员关系 / 组织角色)时,先确认这个账号是运维建的:
/// 用 seed 里的密码校验它的密码 hash。对不上 → 返回 `Some(缺的项)`,调用方**跳过这个账号的全部补授**(见
/// [`skip_unverified`]:只警告,不中断启动)。否则公开注册抢注 seed 里的用户名(或 superadmin 自删后被人注册同名)
/// 就能在下次启动时白拿平台角色 / 组织管理员;而报错又会让 idm 起不来(prod 每次启动都跑 seed,运维改过密码、
/// 运行期撤过权都会撞上)。已经都有了 → 不校验(幂等重跑、运维改过密码都不受影响),返回 `None`。
async fn verify_seed_owner(
    repos: IdmSeedRepos<'_>,
    hasher: &dyn PasswordHasher,
    tenant_ids: &HashMap<String, Uuid>,
    existing: &UserWithHash,
    seed: &UserSeed,
    platform_roles: &[String],
    memberships: &[MembershipSeed],
) -> anyhow::Result<Option<SkippedGrants>> {
    let user_id = existing.user.id;
    let mut pending: Vec<String> = Vec::new();
    let current = repos.roles.roles_for_user(user_id).await?;
    for role in platform_roles.iter().filter(|r| !current.contains(r)) {
        pending.push(format!("平台角色 {role}"));
    }
    for membership in memberships {
        let tenant_id = resolve_tenant(repos.tenants, tenant_ids, &membership.slug).await?;
        match repos.members.get(MemberKey { tenant_id, user_id }).await? {
            None => pending.push(format!("组织 {} 的成员关系", membership.slug)),
            Some(have) => {
                for role in membership.roles.iter().filter(|r| !have.roles.contains(r)) {
                    pending.push(format!("组织 {} 的角色 {role}", membership.slug));
                }
            }
        }
    }
    if pending.is_empty() {
        return Ok(None);
    }
    // 库里的哈希串解析不了(坏串 / 不是本实现认得的格式)→ 同样确认不了是运维建的,按对不上处理(调用方走
    // [`skip_unverified`]);报错会让 idm 起不来(prod 每次启动都跑 seed)。
    let matches = match hasher.verify(&seed.password, &existing.password_hash) {
        Ok(matched) => matched,
        Err(error) => {
            tracing::warn!(
                username = %existing.user.username,
                "seed 校验账号 {name} 的密码时,库里存的密码哈希解析失败({error:?}):确认不了是运维建的账号,\
                 按密码对不上处理(跳过补授,启动照常)。查 idm.user_password 里这个账号的 password_hash 是否被改坏",
                name = existing.user.username,
            );
            false
        }
    };
    Ok((!matches).then(|| SkippedGrants {
        user_id,
        username: existing.user.username.clone(),
        missing: pending,
    }))
}

/// 确认不了是运维建的账号([`verify_seed_owner`] 返回了缺的项):**不授任何东西**、记进报告、打一条警告说清
/// 账号名 / 缺什么 / 为什么跳过 / 怎么处理,然后照常启动。声明的是 superadmin 且库里一个 superadmin 都没有时,
/// 日志里另说明后果,并升为 **ERROR**(0 个 superadmin 不拦启动,同 [`ensure_single_superadmin`] 的「最多一个」;
/// 所以只能靠这条 ERROR 让人去看容器日志)。
async fn skip_unverified(
    users: &dyn UserRepo,
    report: &mut SeedReport,
    skip: SkippedGrants,
    declares_superadmin: bool,
) -> anyhow::Result<()> {
    let no_superadmin = declares_superadmin && superadmin_holders(users).await?.is_empty();
    let consequence = if no_superadmin {
        "库里现在没有 superadmin:系统监控、登录日志、任命平台管理员暂时没人能用。"
    } else {
        ""
    };
    // 同一条日志,级别按后果分:库里 0 个 superadmin(系统监控 / 登录日志 / 任命平台管理员没人能用)→ ERROR,
    // 要运维去看容器日志;其余 → WARN。tracing 的级别必须是常量,所以用宏展开两份。
    macro_rules! log_skip {
        ($level:ident) => {
            tracing::$level!(
                username = %skip.username,
                missing = %skip.missing.join("、"),
                "seed 声明的账号 {name} 已存在,但缺 {missing};它的密码和 seed 里写的对不上,确认不了是运维建的账号\
                 (可能是有人公开注册抢注了这个用户名,也可能是自己人运行期改过密码、之后又被撤掉了这些授予),\
                 跳过这个账号的全部补授,启动照常。{consequence}处理:要补授 → 在后台手动授,或把 seed 里 {name} 的 \
                 password 改成它现在的密码再启动;运行期是有意撤掉的 → 从 seed 去掉这些角色 / 成员关系即可消掉这条警告;\
                 账号不是自己人 → 在 idm 库删掉 / 改名它(idm.users)再启动",
                name = skip.username,
                missing = skip.missing.join("、"),
            )
        };
    }
    if no_superadmin {
        log_skip!(error);
    } else {
        log_skip!(warn);
    }
    report.skipped.push(skip);
    Ok(())
}

/// 一个持 superadmin 的存活账号。
#[derive(Debug, PartialEq, Eq)]
struct SuperadminHolder {
    user_id: Uuid,
    username: String,
}

/// 持 superadmin 的存活账号,按建号先后。最多取 50 个(只用来判「多于一个」并列名字)。
async fn superadmin_holders(users: &dyn UserRepo) -> anyhow::Result<Vec<SuperadminHolder>> {
    let filter = UserListFilter {
        roles_any: vec![RoleName::Superadmin.as_str().to_owned()],
        ..Default::default()
    };
    let page = users
        .list(
            &filter,
            UserSortBy::CreatedAt,
            SortDirection::Ascending,
            &ListPage::Offset {
                offset: 0,
                limit: 50,
                with_total: false,
            },
        )
        .await?;
    let holders: Vec<SuperadminHolder> = page
        .rows
        .into_iter()
        .map(|user| SuperadminHolder {
            user_id: user.id,
            username: user.username,
        })
        .collect();
    Ok(holders)
}

/// **启动期不变量**(装配了 idm 的进程每次启动都查,不受 `seed_on_start` 控制):持 superadmin 的存活账号最多一个。
/// 改动之前 superadmin 能经账号接口授给别人,存量库里可能已有第二个;而现在任何接口都撤不掉它 ——
/// 所以这里**拒绝启动**,列出这些账号,指向清理办法(`scripts/prod/README.md`「清理多余的 superadmin」)。
pub async fn ensure_single_superadmin(users: &dyn UserRepo) -> anyhow::Result<()> {
    let holders = superadmin_holders(users).await?;
    let names: Vec<&str> = holders.iter().map(|h| h.username.as_str()).collect();
    anyhow::ensure!(
        holders.len() <= 1,
        "superadmin 只能有一个,库里却有 {} 个账号持有:{}。接口撤不掉 superadmin —— 先决定保留哪一个,\
         按 scripts/prod/README.md「清理多余的 superadmin」在 idm 库删掉其余账号的 superadmin 授予(idm.user_roles),再启动",
        holders.len(),
        names.join(", ")
    );
    Ok(())
}

/// 按 slug 解析租户 id:先看本次声明的,再去库里找(引用了别处建好的租户)。
async fn resolve_tenant(
    tenants: &dyn TenantRepo,
    declared: &HashMap<String, Uuid>,
    slug: &str,
) -> anyhow::Result<Uuid> {
    if let Some(id) = declared.get(slug) {
        return Ok(*id);
    }
    tenants
        .get_by_slug(slug)
        .await
        .map(|t| t.id)
        .map_err(|error| {
            anyhow::anyhow!("引用了不存在的租户 slug {slug}(先在 [[tenants]] 声明): {error:?}")
        })
}

/// 幂等应用 seed:upsert role(按 `RoleName::scope()`)→ upsert 租户 → find-or-create 账号 →
/// 补授平台角色 → 补齐成员关系与租户角色。`by` = 审计主体(seeder 用 "system")。
/// **并发安全**:账号 / 租户 / 成员撞唯一约束(另一实例已建)→ 退回查已存在的,收敛不报错。
/// **已存在的账号缺声明的东西、密码又和 seed 对不上**(抢注 / 运维改过密码后运行期撤了权)→ 警告并跳过它的补授,
/// 不报错(见 [`verify_seed_owner`]);跳过了谁在返回的 [`SeedReport`] 里,把它交给 [`apply_profiles`]。
pub async fn apply(
    repos: IdmSeedRepos<'_>,
    hasher: &dyn PasswordHasher,
    data: &SeedData,
    by: Option<&str>,
) -> anyhow::Result<SeedReport> {
    data.validate()?;
    let mut report = SeedReport::default();
    // 1. 角色(幂等 upsert,作用域按代码闭集;已有库里迁移默认的 `tenant` 在这里收敛)。
    let mut role_ids: HashMap<&'static str, Uuid> = HashMap::new();
    for role in RoleName::ALL {
        let id = repos
            .roles
            .upsert(
                NewRole {
                    name: role.as_str(),
                    display_name: role.display_name(),
                    scope: role.scope(),
                },
                by,
            )
            .await
            .with_context(|| format!("seed role {} 失败", role.as_str()))?;
        role_ids.insert(role.as_str(), id);
    }

    // 2. 租户(默认租户固定 id)。
    let mut tenant_ids: HashMap<String, Uuid> = HashMap::new();
    for tenant in &data.tenants {
        let id = ensure_tenant(repos.tenants, tenant, by).await?;
        tenant_ids.insert(tenant.slug.clone(), id);
    }

    // 3. 账号(幂等:已存在则取,否则建)。新建走 **create_with_roles** —— 让 `user.created`
    //    事件**带上平台角色**,CQRS 投影据此落 `account_index.roles`。
    let mut memberships = 0usize;
    for user_seed in &data.users {
        let username = user_seed.username.trim().to_lowercase();
        let email = user_seed.email.as_deref().map(|e| e.trim().to_lowercase());
        let platform_roles = user_seed.effective_platform_roles();
        let resolved: anyhow::Result<Vec<Uuid>> = platform_roles
            .iter()
            .map(|name| {
                role_ids
                    .get(name.as_str())
                    .copied()
                    .with_context(|| format!("账号 {username} 引用了未声明的角色 {name}"))
            })
            .collect();
        let platform_role_ids = resolved?;

        let memberships_declared = user_seed.effective_memberships();
        let existing = repos.users.find_by_identifier(&username).await?;
        if user_seed.declares_superadmin() {
            let declared = existing.as_ref().map(|u| u.user.id);
            // 库里已有唯一的 superadmin、却不是这个声明的账号:多半是 superadmin 经 PUT /frontend/auth/me 改了用户名
            // (或旧用户名被人注册了)。这条声明已过时 —— 跳过(不建第二个、也不把 superadmin 授给占了旧名的账号),
            // 不报错:prod 每次启动都跑 seed,报错 = idm 起不来。
            if let Some(holder) = stale_superadmin_declaration(repos.users, declared).await? {
                tracing::warn!(
                    declared = %username,
                    holder = %holder,
                    "seed 声明的 superadmin 账号 {username} 不是库里现有的 superadmin({holder},可能改过用户名):\
                     跳过这条声明(不建第二个 superadmin,也不动它的成员关系)。把 seed 里 superadmin 的 username 改成 {holder} \
                     可消掉这条警告;真要换人,先按 scripts/prod/README.md 处理掉旧的"
                );
                continue;
            }
            ensure_sole_superadmin(repos, declared, &username).await?;
        }
        let user_id = match existing {
            // 已存在(幂等再跑):补齐平台角色 —— 走 set_roles(并集)而非 grant(见 ensure_roles_with_event)。
            // 要补授它还没有的东西时,先确认这个同名账号是运维建的(见 verify_seed_owner);确认不了 → 警告、
            // 跳过它的全部补授(平台角色 + 成员关系),不中断启动。
            Some(existing_user) => {
                if let Some(skip) = verify_seed_owner(
                    repos,
                    hasher,
                    &tenant_ids,
                    &existing_user,
                    user_seed,
                    &platform_roles,
                    &memberships_declared,
                )
                .await?
                {
                    skip_unverified(
                        repos.users,
                        &mut report,
                        skip,
                        user_seed.declares_superadmin(),
                    )
                    .await?;
                    continue;
                }
                ensure_roles_with_event(repos.roles, existing_user.user.id, &platform_roles, by)
                    .await?;
                existing_user.user.id
            }
            None => {
                let hash = hasher
                    .hash(&user_seed.password)
                    .map_err(|e| anyhow::anyhow!("argon2 hash 失败: {e:?}"))?;
                match repos
                    .users
                    .create_with_roles(
                        NewUser {
                            username: &username,
                            email: email.as_deref(),
                            password_hash: &hash,
                        },
                        &platform_role_ids,
                        by,
                    )
                    .await
                {
                    Ok(created) => created.id,
                    // 并发 seed:另一实例已抢先建 → 退回补齐角色(幂等收敛,同上走 set_roles)。
                    Err(IdmError::Conflict(_)) => {
                        let existing_user = repos
                            .users
                            .find_by_identifier(&username)
                            .await?
                            .context("并发 seed 冲突后仍查不到用户")?;
                        if let Some(skip) = verify_seed_owner(
                            repos,
                            hasher,
                            &tenant_ids,
                            &existing_user,
                            user_seed,
                            &platform_roles,
                            &memberships_declared,
                        )
                        .await?
                        {
                            skip_unverified(
                                repos.users,
                                &mut report,
                                skip,
                                user_seed.declares_superadmin(),
                            )
                            .await?;
                            continue;
                        }
                        let user = existing_user.user;
                        ensure_roles_with_event(repos.roles, user.id, &platform_roles, by).await?;
                        user.id
                    }
                    Err(error) => {
                        return Err(anyhow::anyhow!("seed account {username} 失败: {error:?}"))
                    }
                }
            }
        };

        // 4. 成员关系 + 租户角色(并集)。
        for membership_seed in memberships_declared {
            let tenant_id =
                resolve_tenant(repos.tenants, &tenant_ids, &membership_seed.slug).await?;
            let membership = Membership {
                tenant_id,
                user_id,
                roles: &membership_seed.roles,
            };
            ensure_membership(repos, membership, by)
                .await
                .with_context(|| {
                    format!(
                        "seed 账号 {username} 在租户 {} 的成员关系失败",
                        membership_seed.slug
                    )
                })?;
            memberships += 1;
        }
    }

    tracing::info!(
        roles = RoleName::ALL.len(),
        tenants = data.tenants.len(),
        accounts = data.users.len(),
        memberships,
        "idm seed 已应用(幂等)"
    );
    Ok(report)
}

/// seed 账号的**初始 profile**(1:1 挂 user)。跟在 [`apply`] 之后跑 —— 那时账号已在,username 才解析得到。
///
/// **跨模块、不跨 schema**:username → idm `UserRepo` 解析 user_id(标识引用),数据写 app `ProfileRepo`。
/// 同 [`crate::app::mock_data::apply`] 的范式,组合根是唯一能同时握两边的地方。
///
/// **只在 app/idm 同进程(`Mount::Both`)调**:纯 idm 进程的 `profile_repo` 是内存占位
/// (`app_pool=None`),写进去会静默丢、重启蒸发 —— 同 `router.rs` 不给纯 idm 进程挂后台资料端点的理由。
/// 分进程拓扑下初始 profile 由用户自己 PUT 建(`/profiles/me` 未建时回空资料,不阻断)。
///
/// **find-or-create,已有行绝不覆盖**:`upsert` 是全量替换,而 seed 每次启动都跑 —— 直接 upsert
/// 会把用户运行期改的 display_name/phone 清回 seed 值、连头像绑定一起解掉(每次重启资料重置)。
/// 这与 `apply` 里账号"已存在则不动密码"、角色 / 成员关系写并集是同一条铁律:
/// **seed 只负责把东西 bootstrap 出来,不负责把它按回初始值**。
///
/// `report` = 同一份 seed 的 [`apply`] 结果:被跳过补授的账号(密码对不上 seed)不建资料。
pub async fn apply_profiles(
    profiles: &dyn ProfileRepo,
    users: &dyn UserRepo,
    data: &SeedData,
    report: &SeedReport,
    by: Option<String>,
) -> anyhow::Result<()> {
    let mut created = 0usize;
    for user_seed in &data.users {
        let username = user_seed.username.trim().to_lowercase();
        let found = users.find_by_identifier(&username).await?;
        // 过时的 superadmin 声明(superadmin 改过用户名):`apply` 已跳过它,这里同样跳过 —— 不报错,
        // 也不给占了旧名的别人建资料。
        if user_seed.declares_superadmin()
            && stale_superadmin_declaration(users, found.as_ref().map(|u| u.user.id))
                .await?
                .is_some()
        {
            continue;
        }
        let user = found
            .with_context(|| format!("seed profile 的账号 {username} 在 idm 不存在(apply 先跑)"))?
            .user;
        // `apply` 因为确认不了是运维建的而跳过补授的账号(多半是抢注):同样不建 —— 不让它拿到 seed 里的显示名。
        // 按 id 判(不按用户名:seed 的用户名可能经邮箱命中另一个账号,见 [`SkippedGrants`])。
        if report.is_skipped(user.id) {
            continue;
        }
        if profiles.get(user.id).await?.is_some() {
            continue; // 幂等:已有资料 → 保持用户的现值,不按回 seed
        }
        profiles
            .upsert(
                user.id,
                ProfileFields {
                    display_name: user_seed.display_name.clone(),
                    ..Default::default()
                },
                by.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("建 seed profile({username})失败: {e:?}"))?;
        created += 1;
    }
    tracing::info!(
        accounts = data.users.len(),
        profiles_created = created,
        "seed 账号的初始 profile 已应用(幂等)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::features::profile::InMemoryProfileRepo;
    use crate::kernel::authorization::{PermissionScope, RoleNames};
    use idm::{
        Argon2Hasher, FakeHasher, InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo,
        InMemoryTenantRepo, InMemoryUserRepo, OutboxRepo, RoleGrant,
    };

    /// 共享存储的一套内存 idm 仓储(等价于 PG 共表)。
    struct Idm {
        users: InMemoryUserRepo,
        roles: InMemoryRoleRepo,
        tenants: InMemoryTenantRepo,
        members: InMemoryMemberRepo,
        outbox: InMemoryOutboxRepo,
    }

    impl Idm {
        fn new() -> Self {
            let users = InMemoryUserRepo::new();
            Self {
                roles: InMemoryRoleRepo::new_shared_with(&users),
                tenants: InMemoryTenantRepo::new_shared_with(&users),
                members: InMemoryMemberRepo::new_shared_with(&users),
                outbox: InMemoryOutboxRepo::new_shared_with(&users),
                users,
            }
        }

        fn repos(&self) -> IdmSeedRepos<'_> {
            IdmSeedRepos {
                users: &self.users,
                roles: &self.roles,
                tenants: &self.tenants,
                members: &self.members,
            }
        }

        async fn apply(&self, data: &SeedData) {
            let report = apply(self.repos(), &FakeHasher, data, Some("system"))
                .await
                .unwrap();
            assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        }

        async fn user_id_of(&self, name: &str) -> Uuid {
            self.users
                .find_by_identifier(name)
                .await
                .unwrap()
                .unwrap()
                .user
                .id
        }

        async fn events(&self, event_type: &str) -> usize {
            self.outbox
                .poll_unpublished(1000)
                .await
                .unwrap()
                .iter()
                .filter(|e| e.event_type == event_type)
                .count()
        }
    }

    fn parse(toml: &str) -> SeedData {
        let data: SeedData = toml::from_str(toml).unwrap();
        data.validate().unwrap();
        data
    }

    /// 嵌入的 seed.toml 能解析、校验通过,且账号引用的角色都是已知 `RoleName`(拼错 → 这里挂)。
    /// 声明了默认租户,每个账号都至少在一个租户里(内存模式登录也直接进默认租户)。
    #[test]
    fn embedded_seed_accounts_reference_known_roles() {
        let data = SeedData::try_new(None).unwrap();
        let known: HashSet<&str> = RoleName::ALL.iter().map(|r| r.as_str()).collect();
        for role in data.granted_roles() {
            assert!(known.contains(role.as_str()), "账号引用了未知角色 `{role}`");
        }
        assert!(data.tenants.iter().any(|t| t.slug == DEFAULT_TENANT_SLUG));
        for user in &data.users {
            assert!(
                !user.effective_memberships().is_empty(),
                "{} 应是某个租户的成员",
                user.username
            );
        }
    }

    /// role→权限默认映射能建成 `Policy`:superadmin 当平台角色持全部平台级权限,
    /// admin 当租户角色持后台准入。
    #[test]
    fn default_policy_superadmin_has_all_platform_perms() {
        let policy = SeedData::default().policy();
        let permissions = policy.permissions_for(RoleNames {
            platform: &["superadmin".to_owned()],
            tenant: &[],
        });
        for permission in Permission::ALL {
            let platform = permission.scope() == PermissionScope::Platform;
            assert_eq!(
                permissions.contains(&permission),
                platform,
                "{permission:?}"
            );
        }
        assert!(policy
            .permissions_for(RoleNames {
                platform: &[],
                tenant: &["admin".to_owned()],
            })
            .contains(&Permission::AdminLogin));
    }

    /// 作用域写错位置 / 未知角色 / 默认租户改 id → 校验报错(启动即挂)。
    #[test]
    fn validation_rejects_misplaced_roles() {
        let bad = |text: &str| {
            let data: SeedData = toml::from_str(text).unwrap();
            assert!(data.validate().is_err(), "应拒:{text}");
        };
        bad(r#"[[users]]
username = "a"
password = "p"
platform_roles = ["admin"]"#);
        bad(r#"[[users]]
username = "a"
password = "p"
tenants = [{ slug = "default", roles = ["superadmin"] }]"#);
        bad(r#"[[users]]
username = "a"
password = "p"
platform_roles = ["root"]"#);
        // platform_admin 是平台角色,写进组织角色位置 → 拒
        bad(r#"[[users]]
username = "a"
password = "p"
tenants = [{ slug = "default", roles = ["platform_admin"] }]"#);
        bad(r#"[[tenants]]
id = "00000000-0000-0000-0000-000000000009"
slug = "default"
name = "x""#);
    }

    /// superadmin 只有一个:seed 声明给多个账号(新旧格式混着写也算)→ 载入即报错;声明 platform_admin 不受限。
    #[test]
    fn seed_rejects_multiple_superadmins() {
        let data: SeedData = toml::from_str(
            r#"[[users]]
username = "root1"
password = "p"
platform_roles = ["superadmin"]
[[users]]
username = "root2"
password = "p"
roles = ["superadmin"]"#,
        )
        .unwrap();
        let error = data.validate().unwrap_err().to_string();
        assert!(error.contains("superadmin 只能有一个"), "{error}");
        assert!(
            error.contains("root1") && error.contains("root2"),
            "{error}"
        );

        // 一个 superadmin + 多个平台管理员:合法
        parse(
            r#"[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]
[[users]]
username = "pa1"
password = "p"
platform_roles = ["platform_admin"]
[[users]]
username = "pa2"
password = "p"
platform_roles = ["platform_admin"]"#,
        );
    }

    const ROOT_SEED: &str = r#"[[tenants]]
slug = "default"
name = "默认组织"
[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]
tenants = [{ slug = "default", roles = ["admin"] }]"#;

    /// 库里已有唯一的 superadmin、但 seed 声明的是另一个用户名(seed 换了名 / superadmin 自己改了名)→ 跳过这条
    /// 声明,不报错、不建第二个;同一个账号重跑照常幂等。
    #[tokio::test]
    async fn seed_skips_superadmin_declared_under_another_name() {
        let idm = Idm::new();
        let first = parse(ROOT_SEED);
        idm.apply(&first).await;
        idm.apply(&first).await; // 同一账号:幂等

        let renamed = parse(
            r#"[[users]]
username = "newroot"
password = "p"
platform_roles = ["superadmin"]"#,
        );
        apply(idm.repos(), &FakeHasher, &renamed, None)
            .await
            .expect("声明过时应跳过而不是报错");
        assert!(
            idm.users
                .find_by_identifier("newroot")
                .await
                .unwrap()
                .is_none(),
            "没建出第二个 superadmin 账号"
        );
        assert_eq!(superadmin_holders(&idm.users).await.unwrap().len(), 1);
    }

    /// superadmin 经 `PUT /frontend/auth/me` 改了用户名 → 下次启动 seed 按旧名找不到它:不能报错(prod 每次启动都跑
    /// seed,报错 = idm 起不来),也不能再建一个旧名的 superadmin。改名后的账号照旧是唯一的 superadmin。
    #[tokio::test]
    async fn seed_tolerates_renamed_superadmin() {
        let idm = Idm::new();
        let data = parse(ROOT_SEED);
        idm.apply(&data).await;
        let root = idm.user_id_of("root").await;
        idm.users.update(root, "boss", None, None).await.unwrap();

        apply(idm.repos(), &FakeHasher, &data, None)
            .await
            .expect("superadmin 改名后重跑 seed 不应报错");
        let profiles = InMemoryProfileRepo::new();
        apply_profiles(&profiles, &idm.users, &data, &SeedReport::default(), None)
            .await
            .expect("初始资料这一步同样跳过过时的声明");
        assert!(
            idm.users
                .find_by_identifier("root")
                .await
                .unwrap()
                .is_none(),
            "不应按旧名再建账号"
        );
        let holders = superadmin_holders(&idm.users).await.unwrap();
        assert_eq!(
            holders,
            vec![SuperadminHolder {
                user_id: root,
                username: "boss".to_owned(),
            }]
        );
        ensure_single_superadmin(&idm.users).await.unwrap();

        // 旧名随后被人公开注册了:同样跳过 —— 不授 superadmin、不加成员关系,也不因此起不来。
        let squatter = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "root",
                    email: None,
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        apply(idm.repos(), &FakeHasher, &data, None)
            .await
            .expect("旧名被占也不应让启动失败");
        assert!(idm
            .roles
            .roles_for_user(squatter.id)
            .await
            .unwrap()
            .is_empty());
        assert!(idm
            .members
            .get(MemberKey {
                tenant_id: DEFAULT_TENANT_ID.as_uuid(),
                user_id: squatter.id
            })
            .await
            .unwrap()
            .is_none());
        apply_profiles(&profiles, &idm.users, &data, &SeedReport::default(), None)
            .await
            .unwrap();
        assert!(
            profiles.get(squatter.id).await.unwrap().is_none(),
            "不给占了旧名的账号建 seed 资料"
        );
    }

    /// 同名账号已存在、seed 要给它补授它还没有的平台角色 / 组织角色 / 成员关系,密码对不上 seed(抢注)→ 不报错
    /// (prod 每次启动都跑 seed,报错 = idm 起不来),跳过补授并记进报告:什么都不授、也不给它建 seed 资料;
    /// 声明的 superadmin 被抢注 → 库里 0 个 superadmin,启动检查照常放行。对得上 → 照常补授。
    #[tokio::test]
    async fn seed_skips_grants_to_squatted_account() {
        let idm = Idm::new();
        // 空库上有人先注册了 seed 里的用户名(公开注册;密码不是 seed 里的)
        let superadmin = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "root",
                    email: None,
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let platform_admin = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "ops",
                    email: None,
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let admin = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "admin",
                    email: None,
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let tenant = DEFAULT_TENANT_ID.as_uuid();
        let profiles = InMemoryProfileRepo::new();
        let cases = [
            (superadmin.id, "root", ROOT_SEED, "平台角色 superadmin"),
            (
                platform_admin.id,
                "ops",
                r#"[[users]]
username = "ops"
password = "p"
display_name = "运维"
platform_roles = ["platform_admin"]"#,
                "平台角色 platform_admin",
            ),
            (
                admin.id,
                "admin",
                r#"[[tenants]]
slug = "default"
name = "默认组织"
[[users]]
username = "admin"
password = "p"
display_name = "管理员"
tenants = [{ slug = "default", roles = ["admin"] }]"#,
                "组织 default 的成员关系",
            ),
        ];
        for (id, name, seed, what) in cases {
            let data = parse(seed);
            let report = apply(idm.repos(), &FakeHasher, &data, None)
                .await
                .expect("密码对不上应跳过而不是报错");
            assert_eq!(report.skipped.len(), 1, "{what}");
            assert_eq!(report.skipped[0].username, name);
            assert!(
                report.skipped[0].missing.iter().any(|m| m == what),
                "{what}: {:?}",
                report.skipped[0].missing
            );
            assert!(
                idm.roles.roles_for_user(id).await.unwrap().is_empty(),
                "{what}"
            );
            assert!(
                idm.members
                    .get(MemberKey {
                        tenant_id: tenant,
                        user_id: id
                    })
                    .await
                    .unwrap()
                    .is_none(),
                "{what}"
            );
            apply_profiles(&profiles, &idm.users, &data, &report, None)
                .await
                .unwrap();
            assert!(
                profiles.get(id).await.unwrap().is_none(),
                "不给抢注的账号建 seed 资料({what})"
            );
        }
        // 声明的 superadmin 被抢注、被跳过 → 库里 0 个 superadmin:启动检查(≤ 1)照常放行
        assert!(superadmin_holders(&idm.users).await.unwrap().is_empty());
        ensure_single_superadmin(&idm.users).await.unwrap();

        // 密码对得上 seed(运维先建的号)→ 照常补授,报告为空
        let mine = parse(
            r#"[[users]]
username = "ops"
password = "attacker"
platform_roles = ["platform_admin"]"#,
        );
        let report = apply(idm.repos(), &FakeHasher, &mine, None).await.unwrap();
        assert!(report.skipped.is_empty());
        assert_eq!(
            idm.roles.roles_for_user(platform_admin.id).await.unwrap(),
            vec!["platform_admin".to_owned()]
        );
    }

    /// 库里存的密码哈希串解析不了(坏串 / 非 PHC,如手工改库、换过哈希实现)→ 不让启动失败,
    /// 按「确认不了是运维建的」处理:跳过这个账号的全部补授、记进报告,其余照常。
    #[tokio::test]
    async fn seed_skips_grants_when_stored_hash_unparseable() {
        let idm = Idm::new();
        let broken = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "ops",
                    email: None,
                    password_hash: "not-a-phc-string",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let data = parse(
            r#"[[users]]
username = "ops"
password = "p"
platform_roles = ["platform_admin"]"#,
        );
        // 真哈希实现:坏串在 PHC 解析这一步就 Err(FakeHasher 永不 Err,测不到)
        let report = apply(idm.repos(), &Argon2Hasher, &data, None)
            .await
            .expect("哈希串解析失败不应让启动失败");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].user_id, broken.id);
        assert_eq!(report.skipped[0].username, "ops");
        assert_eq!(report.skipped[0].missing, vec!["平台角色 platform_admin"]);
        assert!(idm
            .roles
            .roles_for_user(broken.id)
            .await
            .unwrap()
            .is_empty());
    }

    /// 跳过判定按 user_id:seed 的用户名经 `find_by_identifier` 命中的是**另一个**账号(它的邮箱恰好等于这个用户名)、
    /// 被跳过了补授 → `apply_profiles` 同样不给它建 seed 资料。按用户名比较时报告里记的是那个账号自己的用户名,
    /// 和 seed 的对不上 → 漏判,抢注者拿到 seed 的显示名。
    #[tokio::test]
    async fn profiles_skip_is_keyed_by_user_id() {
        let idm = Idm::new();
        let eve = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "eve",
                    email: Some("ops"),
                    password_hash: "fake$attacker",
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let data = parse(
            r#"[[users]]
username = "ops"
password = "p"
display_name = "运维"
platform_roles = ["platform_admin"]"#,
        );
        let report = apply(idm.repos(), &FakeHasher, &data, None).await.unwrap();
        assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
        assert_eq!(report.skipped[0].user_id, eve.id);
        let profiles = InMemoryProfileRepo::new();
        apply_profiles(&profiles, &idm.users, &data, &report, None)
            .await
            .unwrap();
        assert!(
            profiles.get(eve.id).await.unwrap().is_none(),
            "被跳过的账号不该拿到 seed 资料"
        );
    }

    /// 已经持有声明的角色 / 成员关系 → 不校验密码:运维运行期改过密码,重跑 seed 照常(幂等,不报错)。
    #[tokio::test]
    async fn seed_skips_password_check_when_nothing_to_grant() {
        let idm = Idm::new();
        let data = parse(ROOT_SEED);
        idm.apply(&data).await;
        let root = idm.user_id_of("root").await;
        idm.users
            .update_password(root, "fake$rotated")
            .await
            .unwrap();
        let report = apply(idm.repos(), &FakeHasher, &data, None).await.unwrap();
        assert!(report.skipped.is_empty(), "什么都不缺 → 不校验、不跳过");
        assert_eq!(
            idm.roles.roles_for_user(root).await.unwrap(),
            vec!["superadmin".to_owned()]
        );

        // 但改过密码后 seed 再多声明一个组织角色 → 要补授 → 密码对不上 → 跳过补授(不报错),报告里写明缺什么
        let more = parse(
            r#"[[tenants]]
slug = "default"
name = "默认组织"
[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]
tenants = [{ slug = "default", roles = ["admin", "user"] }]"#,
        );
        let report = apply(idm.repos(), &FakeHasher, &more, None)
            .await
            .expect("改过密码不应让启动失败");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].username, "root");
        assert_eq!(report.skipped[0].missing, vec!["组织 default 的角色 user"]);
        let member = idm
            .members
            .get(MemberKey {
                tenant_id: DEFAULT_TENANT_ID.as_uuid(),
                user_id: root,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.roles, vec!["admin".to_owned()], "没补授 user");
    }

    /// 运维改过密码、运行期又被撤掉了 seed 声明的东西(平台角色 / 组织角色 / 被移出组织)→ 重启 seed 不报错、
    /// **不补授**(撤权在重启后仍然有效),报告里列出缺的项;库里的其他东西原样不动。
    #[tokio::test]
    async fn seed_does_not_regrant_runtime_revocations_after_password_change() {
        let idm = Idm::new();
        let data = parse(
            r#"[[tenants]]
slug = "default"
name = "默认组织"
[[tenants]]
slug = "acme"
name = "Acme"
[[users]]
username = "lead"
password = "p"
platform_roles = ["platform_admin"]
tenants = [{ slug = "default", roles = ["admin"] }, { slug = "acme", roles = ["user"] }]"#,
        );
        idm.apply(&data).await;
        let lead = idm.user_id_of("lead").await;
        let default = DEFAULT_TENANT_ID.as_uuid();
        let acme = idm.tenants.get_by_slug("acme").await.unwrap().id;
        idm.users
            .update_password(lead, "fake$rotated")
            .await
            .unwrap();
        // 运行期:superadmin 撤掉平台管理员、组织里把 admin 降成 user、从 acme 移出
        idm.roles.set_roles(lead, &[], None).await.unwrap();
        let user_role = role_ids_by_name(&idm.roles, ["user".to_owned()].iter())
            .await
            .unwrap();
        idm.members
            .set_roles(
                MemberKey {
                    tenant_id: default,
                    user_id: lead,
                },
                &user_role,
                None,
            )
            .await
            .unwrap();
        idm.members
            .remove(
                MemberKey {
                    tenant_id: acme,
                    user_id: lead,
                },
                None,
            )
            .await
            .unwrap();

        let report = apply(idm.repos(), &FakeHasher, &data, None)
            .await
            .expect("改过密码 + 运行期撤权,重启 seed 不应报错");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].username, "lead");
        assert_eq!(
            report.skipped[0].missing,
            vec![
                "平台角色 platform_admin",
                "组织 default 的角色 admin",
                "组织 acme 的成员关系",
            ]
        );
        assert!(idm.roles.roles_for_user(lead).await.unwrap().is_empty());
        assert_eq!(
            idm.members
                .get(MemberKey {
                    tenant_id: default,
                    user_id: lead
                })
                .await
                .unwrap()
                .unwrap()
                .roles,
            vec!["user".to_owned()]
        );
        assert!(idm
            .members
            .get(MemberKey {
                tenant_id: acme,
                user_id: lead
            })
            .await
            .unwrap()
            .is_none());
    }

    /// 声明的 superadmin 改过密码、其 superadmin 授予又被删掉了(按 README 清理时删错 / 直接改库)→ 重启 seed 不报错、
    /// 不补授:库里 0 个 superadmin,启动检查(≤ 1)照常放行;要恢复按警告里的办法(seed 填现在的密码再启动)。
    #[tokio::test]
    async fn seed_skips_superadmin_regrant_when_password_differs() {
        let idm = Idm::new();
        let data = parse(ROOT_SEED);
        idm.apply(&data).await;
        let root = idm.user_id_of("root").await;
        idm.users
            .update_password(root, "fake$rotated")
            .await
            .unwrap();
        idm.roles.set_roles(root, &[], None).await.unwrap();

        ensure_single_superadmin(&idm.users).await.unwrap();
        let report = apply(idm.repos(), &FakeHasher, &data, None)
            .await
            .expect("不应让 idm 起不来");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].missing, vec!["平台角色 superadmin"]);
        assert!(idm.roles.roles_for_user(root).await.unwrap().is_empty());
        assert!(superadmin_holders(&idm.users).await.unwrap().is_empty());
        ensure_single_superadmin(&idm.users).await.unwrap();

        // 按警告处理:seed 里填上它现在的密码 → 补授回来
        let fixed = parse(&ROOT_SEED.replace(r#"password = "p""#, r#"password = "rotated""#));
        let report = apply(idm.repos(), &FakeHasher, &fixed, None).await.unwrap();
        assert!(report.skipped.is_empty());
        assert_eq!(
            idm.roles.roles_for_user(root).await.unwrap(),
            vec!["superadmin".to_owned()]
        );
    }

    /// 启动期检查:库里持 superadmin 的存活账号多于一个(改动前经接口授出的存量)→ 报错并列出用户名、指向清理办法;
    /// 一个 / 零个照常;被删掉的账号不算。
    #[tokio::test]
    async fn startup_rejects_store_with_multiple_superadmins() {
        let idm = Idm::new();
        ensure_single_superadmin(&idm.users).await.unwrap(); // 空库
        idm.apply(&parse(
            r#"[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]"#,
        ))
        .await;
        ensure_single_superadmin(&idm.users).await.unwrap(); // 一个
                                                             // 模拟改动前经账号接口授出的第二个 superadmin(seed 现在不会这样做,直接写库)
        let superadmin_role = role_ids_by_name(&idm.roles, ["superadmin".to_owned()].iter())
            .await
            .unwrap();
        let second = idm
            .users
            .create_with_roles(
                NewUser {
                    username: "legacy-root",
                    email: None,
                    password_hash: "h",
                },
                &superadmin_role,
                None,
            )
            .await
            .unwrap();
        let error = ensure_single_superadmin(&idm.users)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("root") && error.contains("legacy-root"),
            "{error}"
        );
        assert!(error.contains("scripts/prod/README.md"), "{error}");
        // 清理(删号)后恢复
        idm.users.soft_delete(second.id, None).await.unwrap();
        ensure_single_superadmin(&idm.users).await.unwrap();
    }

    /// 旧格式 `[[accounts]].roles` 仍认:平台角色进 platform_roles,租户角色进默认租户。
    #[test]
    fn legacy_accounts_roles_are_split_by_scope() {
        let data = parse(
            r#"[[accounts]]
username = "old"
password = "p"
roles = ["superadmin", "admin"]"#,
        );
        let user = &data.users[0];
        assert_eq!(
            user.effective_platform_roles(),
            vec!["superadmin".to_owned()]
        );
        let memberships = user.effective_memberships();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].slug, DEFAULT_TENANT_SLUG);
        assert_eq!(memberships[0].roles, vec!["admin".to_owned()]);
    }

    const TENANT_SEED: &str = r#"
[[tenants]]
slug = "default"
name = "默认组织"

[[tenants]]
slug = "acme"
name = "Acme"

[[users]]
username = "boss"
password = "p"
platform_roles = ["superadmin"]
tenants = [{ slug = "default", roles = ["admin"] }]

[[users]]
username = "alice"
password = "p"
tenants = [{ slug = "default", roles = ["user"] }, { slug = "acme", roles = ["admin"] }]
"#;

    /// seed 幂等:租户按固定 id / slug upsert(不重复建)、成员关系与租户角色补齐;重跑不再写、不再发事件。
    #[tokio::test]
    async fn seed_is_idempotent_with_tenants() {
        let idm = Idm::new();
        let data = parse(TENANT_SEED);
        idm.apply(&data).await;
        idm.apply(&data).await;

        // 租户:default 是固定 id(内存存储自带,不重复建),acme 只建一次
        let page = idm
            .tenants
            .list(&ListPage::Offset {
                offset: 0,
                limit: 100,
                with_total: true,
            })
            .await
            .unwrap();
        let slugs: Vec<String> = page.rows.iter().map(|t| t.slug.clone()).collect();
        assert_eq!(slugs.len(), 2, "{slugs:?}");
        assert!(slugs.contains(&"default".to_owned()) && slugs.contains(&"acme".to_owned()));
        assert_eq!(idm.events("tenant.created").await, 1, "只建一次 acme");

        // boss:平台角色 superadmin + 默认租户 admin
        let boss = idm.user_id_of("boss").await;
        assert_eq!(
            idm.roles.roles_for_user(boss).await.unwrap(),
            vec!["superadmin".to_owned()]
        );
        let member = idm
            .members
            .get(MemberKey {
                tenant_id: DEFAULT_TENANT_ID.as_uuid(),
                user_id: boss,
            })
            .await
            .unwrap()
            .expect("boss 应是默认租户成员");
        assert_eq!(member.roles, vec!["admin".to_owned()]);

        // alice:两个租户,各自的角色;没有平台角色
        let alice = idm.user_id_of("alice").await;
        assert!(idm.roles.roles_for_user(alice).await.unwrap().is_empty());
        let mut memberships: Vec<(String, Vec<String>)> = idm
            .members
            .memberships_for_user(alice)
            .await
            .unwrap()
            .into_iter()
            .map(|m| (m.tenant.slug, m.roles))
            .collect();
        memberships.sort();
        assert_eq!(
            memberships,
            vec![
                ("acme".to_owned(), vec!["admin".to_owned()]),
                ("default".to_owned(), vec!["user".to_owned()]),
            ]
        );
        assert_eq!(
            idm.events("tenant.member_added").await,
            3,
            "三条成员关系各加一次"
        );
        assert_eq!(idm.events("tenant.member_roles_set").await, 0, "重跑不再写");
    }

    /// 已是成员:声明里多了角色 → 写并集(保留运行期授的租户角色)并发一条 member_roles_set;再跑不再发。
    #[tokio::test]
    async fn rerun_unions_tenant_roles_and_keeps_runtime_grants() {
        let idm = Idm::new();
        idm.apply(&parse(
            r#"[[tenants]]
slug = "default"
name = "默认组织"
[[users]]
username = "alice"
password = "p"
tenants = [{ slug = "default", roles = ["user"] }]"#,
        ))
        .await;
        let alice = idm.user_id_of("alice").await;
        let tenant = DEFAULT_TENANT_ID.as_uuid();
        // 运行期:租户管理员给 alice 加了一个闭集外的租户角色 editor
        let editor = idm
            .roles
            .upsert(
                NewRole {
                    name: "editor",
                    display_name: "编辑",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let user_role = role_ids_by_name(&idm.roles, ["user".to_owned()].iter())
            .await
            .unwrap();
        idm.members
            .set_roles(
                MemberKey {
                    tenant_id: tenant,
                    user_id: alice,
                },
                &[user_role[0], editor],
                None,
            )
            .await
            .unwrap();
        let before = idm.events("tenant.member_roles_set").await;

        let data = parse(
            r#"[[tenants]]
slug = "default"
name = "默认组织"
[[users]]
username = "alice"
password = "p"
tenants = [{ slug = "default", roles = ["user", "admin"] }]"#,
        );
        idm.apply(&data).await;
        let member = idm
            .members
            .get(MemberKey {
                tenant_id: tenant,
                user_id: alice,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            member.roles,
            vec!["admin".to_owned(), "editor".to_owned(), "user".to_owned()],
            "并集:补上 admin,保留运行期的 editor"
        );
        assert_eq!(idm.events("tenant.member_roles_set").await, before + 1);
        idm.apply(&data).await;
        assert_eq!(
            idm.events("tenant.member_roles_set").await,
            before + 1,
            "幂等重跑不应再发事件"
        );
    }

    /// 平台角色补授**必须发事件**(`grant` 零事件 → 搜索投影永久陈旧),且写**并集**(不清运行期授的平台角色)。
    #[tokio::test]
    async fn rerun_emits_roles_set_and_keeps_runtime_platform_grants() {
        let idm = Idm::new();
        let first = parse(
            r#"[[users]]
username = "alice"
password = "p""#,
        );
        idm.apply(&first).await;
        let alice = idm.user_id_of("alice").await;
        // 运行期授了一个闭集外的平台角色 auditor
        let auditor = idm
            .roles
            .upsert(
                NewRole {
                    name: "auditor",
                    display_name: "审计员",
                    scope: RoleScope::Platform,
                },
                None,
            )
            .await
            .unwrap();
        idm.roles
            .grant(
                RoleGrant {
                    user_id: alice,
                    role_id: auditor,
                },
                None,
            )
            .await
            .unwrap();

        let data = parse(
            r#"[[users]]
username = "alice"
password = "p"
platform_roles = ["superadmin"]"#,
        );
        idm.apply(&data).await;
        let mut names = idm.roles.roles_for_user(alice).await.unwrap();
        names.sort();
        assert_eq!(names, vec!["auditor".to_owned(), "superadmin".to_owned()]);
        let roles_set: Vec<_> = idm
            .outbox
            .poll_unpublished(100)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == "user.roles_set")
            .collect();
        assert_eq!(roles_set.len(), 1, "补授必须发一条 user.roles_set");
        assert_eq!(
            roles_set[0].payload["roles"],
            serde_json::json!(["auditor", "superadmin"])
        );
        idm.apply(&data).await;
        assert_eq!(
            idm.events("user.roles_set").await,
            1,
            "幂等重跑不应再发事件"
        );
    }

    /// 角色作用域按代码闭集写进 idm(Task 1 的过渡做法是一律 platform)。
    #[tokio::test]
    async fn roles_are_upserted_with_their_scope() {
        let idm = Idm::new();
        idm.apply(&SeedData::default()).await;
        for role in idm.roles.list().await.unwrap() {
            let parsed: RoleName = role.name.parse().unwrap();
            let expect = parsed.scope();
            assert_eq!(role.scope, expect, "{}", role.name);
        }
    }

    /// 初始 profile:建号后带出 display_name;**重跑绝不按回** —— `upsert` 是全量替换而 seed 每次
    /// 启动都跑,不先查就写会把用户改过的资料清回 seed 值、连头像一起解绑(每次重启资料重置)。
    #[tokio::test]
    async fn profiles_created_once_and_never_reset_on_rerun() {
        let idm = Idm::new();
        let profiles = InMemoryProfileRepo::new();
        let by = Some("system".to_owned());
        let data = parse(
            r#"[[users]]
username = "alice"
password = "pwd"
display_name = "Alice"
tenants = [{ slug = "default", roles = ["user"] }]"#,
        );

        idm.apply(&data).await;
        apply_profiles(
            &profiles,
            &idm.users,
            &data,
            &SeedReport::default(),
            by.clone(),
        )
        .await
        .unwrap();
        let user_id = idm.user_id_of("alice").await;
        let profile = profiles
            .get(user_id)
            .await
            .unwrap()
            .expect("初始 profile 应已建");
        assert_eq!(profile.display_name.as_deref(), Some("Alice"));

        // 用户运行期改名 + 绑头像
        let avatar = Uuid::now_v7();
        profiles
            .upsert(
                user_id,
                ProfileFields {
                    display_name: Some("Alice Liddell".to_owned()),
                    phone: Some("13800000000".to_owned()),
                    avatar_content_id: Some(avatar),
                },
                by.clone(),
            )
            .await
            .unwrap();

        // 重跑(= 每次容器重启)
        apply_profiles(&profiles, &idm.users, &data, &SeedReport::default(), by)
            .await
            .unwrap();
        let profile = profiles.get(user_id).await.unwrap().unwrap();
        assert_eq!(
            profile.display_name.as_deref(),
            Some("Alice Liddell"),
            "重跑不得把用户改的名按回 seed 值"
        );
        assert_eq!(
            profile.avatar_content_id,
            Some(avatar),
            "重跑不得解掉头像绑定"
        );
    }
}

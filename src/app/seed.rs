//! idm 默认数据 seed —— **进程内启动时**(`AppState::new`,见 [`crate::app::state`])或**显式 CLI**
//! (`src/bin/seed.rs`)两条路共用此核心。幂等:role / 租户 upsert、账号 find-or-create、平台角色与成员关系取并集补齐,
//! 可重复跑、可并发。
//!
//! 分工:**角色集 / 权限集 / role→权限默认**是代码闭集(`authz::{RoleName, Perm}`,不做动态 CRUD);
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

use anyhow::Context;
use serde::Deserialize;
use uuid::Uuid;

use crate::features::profile::{ProfileFields, ProfileRepo};
use crate::kernel::authz::{Perm, Policy, RoleName};
use crate::kernel::tenant::DEFAULT_TENANT_ID;
use idm::{IdmError, MemberRepo, PwHasher, RoleRepo, RoleScope, TenantRepo, UserRepo};

/// 编译期嵌入的默认 seed(仓库根 `seed.toml`)。`SEED_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `seed.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_SEED: &str = include_str!("../../seed.toml");

/// 默认租户的 slug(固定 id = [`DEFAULT_TENANT_ID`])。
pub const DEFAULT_TENANT_SLUG: &str = "default";

/// 外置 seed:**租户 + 账号**(实例数据 + 密码,`SEED_FILE` 可覆盖)。角色集 / 权限集 / role→权限
/// 默认全收进代码枚举(`RoleName` / `Perm`)—— 封闭集、不做动态 CRUD(角色**有哪些权限**才可
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
        for m in self.tenants.iter().cloned().chain(legacy) {
            match out.iter_mut().find(|o| o.slug == m.slug) {
                Some(o) => o.roles = dedup(o.roles.iter().chain(m.roles.iter())),
                None => out.push(MembershipSeed {
                    roles: dedup(m.roles.iter()),
                    ..m
                }),
            }
        }
        out
    }
}

fn dedup<'a>(names: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        if !out.contains(n) {
            out.push(n.clone());
        }
    }
    out
}

/// 闭集内角色的作用域;闭集外 → `None`。
fn role_scope(name: &str) -> Option<RoleScope> {
    name.parse::<RoleName>().ok().map(|r| r.scope())
}

/// 校验 seed 引用的角色:必须是闭集内角色,且作用域对得上(平台角色只能进 `platform_roles`、租户角色只能进成员关系)。
fn check_role(username: &str, role: &str, expect: RoleScope) -> anyhow::Result<()> {
    match role_scope(role) {
        None => anyhow::bail!("账号 {username} 引用了未声明的角色 {role}"),
        Some(s) if s != expect => anyhow::bail!(
            "账号 {username} 把角色 {role}({s:?} 角色)写在了 {expect:?} 的位置:平台角色写 platform_roles,租户角色写 tenants.roles"
        ),
        Some(_) => Ok(()),
    }
}

impl SeedData {
    /// 只有账号(没有租户声明)的 seed —— mock 的演示账号复用 [`apply`] 用(引用的租户须已存在)。
    pub(crate) fn accounts(users: Vec<UserSeed>) -> Self {
        Self {
            tenants: Vec::new(),
            users,
        }
    }

    /// 载入:`path`(来自 `Config.seed_file`,即 `SEED_FILE`)指定的外部文件优先,否则用编译期嵌入的默认。
    /// 角色引用 / 作用域 / 默认租户 id 在这里就校验,写错启动即挂。
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let content = match path {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("读 SEED_FILE {path} 失败"))?,
            None => EMBEDDED_SEED.to_owned(),
        };
        let data: Self = toml::from_str(&content).context("解析 seed 数据失败")?;
        data.validate()?;
        Ok(data)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        for t in &self.tenants {
            tenant_seed_id(t)?;
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
        for u in &self.users {
            for r in u.effective_platform_roles() {
                check_role(&u.username, &r, RoleScope::Platform)?;
            }
            for m in u.effective_memberships() {
                for r in &m.roles {
                    check_role(&u.username, r, RoleScope::Tenant)?;
                }
            }
        }
        Ok(())
    }

    /// role→权限**默认**映射 → app 内存授权 `Policy`(无 `APP_DB_HOST` 时用)。默认来自 `RoleName` 代码;
    /// `implies` 展开在 `Policy::from_roles`。**permissions 不写进 idm 库**。
    pub fn policy(&self) -> Policy {
        Policy::from_roles(
            RoleName::ALL
                .iter()
                .map(|r| (r.as_str().to_owned(), r.default_permissions())),
        )
    }

    /// 账号引用到的角色名(平台 + 租户;供 `Policy::assert_roles_covered` 启动期校验:每个被授予的 role 都得有策略条目)。
    pub fn granted_roles(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for u in &self.users {
            set.extend(u.effective_platform_roles());
            for m in u.effective_memberships() {
                set.extend(m.roles);
            }
        }
        set.into_iter().collect()
    }

    /// 权限词表(key, description)—— 供 `policy_repo::seed_authz` upsert 进 `permissions` 表。源自 `Perm` 代码闭集。
    pub fn permission_catalog(&self) -> impl Iterator<Item = (Perm, &'static str)> {
        Perm::ALL.into_iter().map(|p| (p, p.description()))
    }

    /// role→权限**默认**映射(implies 未展开,展开在 `Policy::from_roles`)——
    /// 供 `policy_repo::seed_authz` bootstrap `role_permissions` 表(`ON CONFLICT DO NOTHING`,不覆盖运行期改动)。
    pub fn role_permission_mappings(&self) -> impl Iterator<Item = (&'static str, Vec<Perm>)> {
        RoleName::ALL
            .into_iter()
            .map(|r| (r.as_str(), r.default_permissions()))
    }
}

/// seed / mock 写 idm 要用的仓储(内存模式须 `sharing_with` 同一份存储,PG 模式同一个 idm 池)。
#[derive(Clone, Copy)]
pub struct IdmSeedRepos<'a> {
    pub users: &'a dyn UserRepo,
    pub roles: &'a dyn RoleRepo,
    pub tenants: &'a dyn TenantRepo,
    pub members: &'a dyn MemberRepo,
}

/// 租户声明的固定 id:`default` 恒为默认租户(写了别的 id → 错);其余用声明的(可无)。
fn tenant_seed_id(t: &TenantSeed) -> anyhow::Result<Option<Uuid>> {
    if t.slug == DEFAULT_TENANT_SLUG {
        let default = DEFAULT_TENANT_ID.as_uuid();
        anyhow::ensure!(
            t.id.is_none_or(|id| id == default),
            "slug = \"default\" 的租户 id 固定为 {default},不能改"
        );
        return Ok(Some(default));
    }
    if let Some(id) = t.id {
        anyhow::ensure!(!id.is_nil(), "租户 {} 的 id 不能是 nil UUID", t.slug);
    }
    Ok(t.id)
}

/// 幂等确保一个租户存在,返回其 id。固定 id → `upsert_fixed`(已存在原样返回,不改名);
/// 否则按 slug 找,找不到再建(并发另一实例抢先建 → 退回按 slug 取)。
pub(crate) async fn ensure_tenant(
    tenants: &dyn TenantRepo,
    t: &TenantSeed,
    by: Option<String>,
) -> anyhow::Result<Uuid> {
    if let Some(id) = tenant_seed_id(t)? {
        let got = tenants
            .upsert_fixed(id, &t.slug, &t.name, by)
            .await
            .with_context(|| format!("seed 租户 {} 失败", t.slug))?;
        return Ok(got.id);
    }
    match tenants.get_by_slug(&t.slug).await {
        Ok(found) => return Ok(found.id),
        Err(IdmError::NotFound) => {}
        Err(e) => return Err(anyhow::anyhow!("查租户 {} 失败: {e:?}", t.slug)),
    }
    match tenants.create(&t.slug, &t.name, by).await {
        Ok(created) => Ok(created.id),
        // 并发 seed 抢先建了 → 取它;slug 被**已删除**租户占着(不复用)→ get_by_slug 也 NotFound → 报错
        Err(IdmError::Conflict(_)) => Ok(tenants
            .get_by_slug(&t.slug)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "租户 slug {} 已被占用(可能是已删除的租户,slug 不复用): {e:?}",
                    t.slug
                )
            })?
            .id),
        Err(e) => Err(anyhow::anyhow!("seed 租户 {} 失败: {e:?}", t.slug)),
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
    by: Option<String>,
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
async fn role_ids_by_name<'a>(
    roles: &dyn RoleRepo,
    names: impl Iterator<Item = &'a String>,
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

/// 幂等确保成员关系 + 租户角色(取**并集**,同平台角色的理由:不清掉运行期授的租户角色)。
/// 不是成员 → `add`(发 `tenant.member_added`);已是成员 → 声明的角色都在身就不动,否则 `set_roles`
/// 写并集(发 `tenant.member_roles_set`)。**不改成员状态**:运行期被停用的成员,重跑 seed 不会被恢复。
pub(crate) async fn ensure_membership(
    repos: IdmSeedRepos<'_>,
    tenant_id: Uuid,
    user_id: Uuid,
    declared: &[String],
    by: Option<String>,
) -> anyhow::Result<()> {
    let existing = match repos.members.get(tenant_id, user_id).await? {
        Some(m) => m,
        None => {
            let ids = role_ids_by_name(repos.roles, declared.iter()).await?;
            match repos
                .members
                .add(tenant_id, user_id, &ids, by.clone())
                .await
            {
                Ok(_) => return Ok(()),
                // 并发 seed 抢先加了 → 当已是成员走并集
                Err(IdmError::Conflict(_)) => repos
                    .members
                    .get(tenant_id, user_id)
                    .await?
                    .context("并发 seed 冲突后仍查不到成员关系")?,
                Err(e) => return Err(anyhow::anyhow!("加成员失败: {e:?}")),
            }
        }
    };
    if !declared.iter().any(|d| !existing.roles.contains(d)) {
        return Ok(()); // 幂等:无写、无事件
    }
    let union = role_ids_by_name(repos.roles, existing.roles.iter().chain(declared.iter())).await?;
    repos
        .members
        .set_roles(tenant_id, user_id, &union, by)
        .await?;
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
        .filter(|(id, _)| Some(*id) != declared_user)
        .map(|(_, name)| name.as_str())
        .collect();
    anyhow::ensure!(
        others.is_empty(),
        "superadmin 只能有一个:库里已有账号 {} 持有 superadmin,seed 不能再授给 {username}(要换人先处理掉旧的)",
        others.join(", ")
    );
    Ok(())
}

/// 持 superadmin 的存活账号 (id, username),按建号先后。最多取 50 个(只用来判「多于一个」并列名字)。
async fn superadmin_holders(users: &dyn UserRepo) -> anyhow::Result<Vec<(Uuid, String)>> {
    let filter = idm::UserListFilter {
        roles_any: vec![RoleName::Superadmin.as_str().to_owned()],
        ..Default::default()
    };
    let page = users
        .list(
            &filter,
            idm::UserSortBy::CreatedAt,
            idm::SortDir::Asc,
            &idm::ListPage::Offset {
                offset: 0,
                limit: 50,
                with_total: false,
            },
        )
        .await?;
    Ok(page.rows.into_iter().map(|u| (u.id, u.username)).collect())
}

/// **启动期不变量**(装配了 idm 的进程每次启动都查,不受 `seed_on_start` 控制):持 superadmin 的存活账号最多一个。
/// 改动之前 superadmin 能经账号接口授给别人,存量库里可能已有第二个;而现在任何接口都撤不掉它 ——
/// 所以这里**拒绝启动**,列出这些账号,指向清理办法(`scripts/prod/README.md`「清理多余的 superadmin」)。
pub async fn ensure_single_superadmin(users: &dyn UserRepo) -> anyhow::Result<()> {
    let holders = superadmin_holders(users).await?;
    anyhow::ensure!(
        holders.len() <= 1,
        "superadmin 只能有一个,库里却有 {} 个账号持有:{}。接口撤不掉 superadmin —— 先决定保留哪一个,\
         按 scripts/prod/README.md「清理多余的 superadmin」在 idm 库删掉其余账号的 superadmin 授予(idm.user_roles),再启动",
        holders.len(),
        holders
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
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
    tenants.get_by_slug(slug).await.map(|t| t.id).map_err(|e| {
        anyhow::anyhow!("引用了不存在的租户 slug {slug}(先在 [[tenants]] 声明): {e:?}")
    })
}

/// 幂等应用 seed:upsert role(按 `RoleName::scope()`)→ upsert 租户 → find-or-create 账号 →
/// 补授平台角色 → 补齐成员关系与租户角色。`by` = 审计主体(seeder 用 "system")。
/// **并发安全**:账号 / 租户 / 成员撞唯一约束(另一实例已建)→ 退回查已存在的,收敛不报错。
pub async fn apply(
    repos: IdmSeedRepos<'_>,
    hasher: &dyn PwHasher,
    data: &SeedData,
    by: Option<String>,
) -> anyhow::Result<()> {
    data.validate()?;
    // 1. 角色(幂等 upsert,作用域按代码闭集;已有库里迁移默认的 `tenant` 在这里收敛)。
    let mut role_ids: HashMap<&'static str, Uuid> = HashMap::new();
    for r in RoleName::ALL {
        let id = repos
            .roles
            .upsert(r.as_str(), r.display_name(), r.scope(), by.clone())
            .await
            .with_context(|| format!("seed role {} 失败", r.as_str()))?;
        role_ids.insert(r.as_str(), id);
    }

    // 2. 租户(默认租户固定 id)。
    let mut tenant_ids: HashMap<String, Uuid> = HashMap::new();
    for t in &data.tenants {
        let id = ensure_tenant(repos.tenants, t, by.clone()).await?;
        tenant_ids.insert(t.slug.clone(), id);
    }

    // 3. 账号(幂等:已存在则取,否则建)。新建走 **create_with_roles** —— 让 `user.created`
    //    事件**带上平台角色**,CQRS 投影据此落 `account_index.roles`。
    let mut memberships = 0usize;
    for a in &data.users {
        let username = a.username.trim().to_lowercase();
        let email = a.email.as_deref().map(|e| e.trim().to_lowercase());
        let platform_roles = a.effective_platform_roles();
        let platform_role_ids: Vec<Uuid> = platform_roles
            .iter()
            .map(|name| {
                role_ids
                    .get(name.as_str())
                    .copied()
                    .with_context(|| format!("账号 {username} 引用了未声明的角色 {name}"))
            })
            .collect::<anyhow::Result<_>>()?;

        let existing = repos.users.find_by_identifier(&username).await?;
        if a.declares_superadmin() {
            ensure_sole_superadmin(repos, existing.as_ref().map(|u| u.user.id), &username).await?;
        }
        let user_id = match existing {
            // 已存在(幂等再跑):补齐平台角色 —— 走 set_roles(并集)而非 grant(见 ensure_roles_with_event)。
            Some(uwh) => {
                ensure_roles_with_event(repos.roles, uwh.user.id, &platform_roles, by.clone())
                    .await?;
                uwh.user.id
            }
            None => {
                let hash = hasher
                    .hash(&a.password)
                    .map_err(|e| anyhow::anyhow!("argon2 hash 失败: {e:?}"))?;
                match repos
                    .users
                    .create_with_roles(
                        &username,
                        email.as_deref(),
                        &hash,
                        &platform_role_ids,
                        by.clone(),
                    )
                    .await
                {
                    Ok(u) => u.id,
                    // 并发 seed:另一实例已抢先建 → 退回补齐角色(幂等收敛,同上走 set_roles)。
                    Err(IdmError::Conflict(_)) => {
                        let user = repos
                            .users
                            .find_by_identifier(&username)
                            .await?
                            .context("并发 seed 冲突后仍查不到用户")?
                            .user;
                        ensure_roles_with_event(repos.roles, user.id, &platform_roles, by.clone())
                            .await?;
                        user.id
                    }
                    Err(e) => return Err(anyhow::anyhow!("seed account {username} 失败: {e:?}")),
                }
            }
        };

        // 4. 成员关系 + 租户角色(并集)。
        for m in a.effective_memberships() {
            let tenant_id = resolve_tenant(repos.tenants, &tenant_ids, &m.slug).await?;
            ensure_membership(repos, tenant_id, user_id, &m.roles, by.clone())
                .await
                .with_context(|| {
                    format!("seed 账号 {username} 在租户 {} 的成员关系失败", m.slug)
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
    Ok(())
}

/// seed 账号的**初始 profile**(1:1 挂 user)。跟在 [`apply`] 之后跑 —— 那时账号已在,username 才解析得到。
///
/// **跨模块、不跨 schema**:username → idm `UserRepo` 解析 user_id(标识引用),数据写 app `ProfileRepo`。
/// 同 [`crate::app::mock::apply`] 的范式,组合根是唯一能同时握两边的地方。
///
/// **只在 app/idm 同进程(`Mount::Both`)调**:纯 idm 进程的 `profile_repo` 是内存占位
/// (`app_pool=None`),写进去会静默丢、重启蒸发 —— 同 `router.rs` 不给纯 idm 进程挂后台资料端点的理由。
/// 分进程拓扑下初始 profile 由用户自己 PUT 建(`/profiles/me` 未建时回空资料,不阻断)。
///
/// **find-or-create,已有行绝不覆盖**:`upsert` 是全量替换,而 seed 每次启动都跑 —— 直接 upsert
/// 会把用户运行期改的 display_name/phone 清回 seed 值、连头像绑定一起解掉(每次重启资料重置)。
/// 这与 `apply` 里账号"已存在则不动密码"、角色 / 成员关系写并集是同一条铁律:
/// **seed 只负责把东西 bootstrap 出来,不负责把它按回初始值**。
pub async fn apply_profiles(
    profiles: &dyn ProfileRepo,
    users: &dyn UserRepo,
    data: &SeedData,
    by: Option<String>,
) -> anyhow::Result<()> {
    let mut created = 0usize;
    for a in &data.users {
        let username = a.username.trim().to_lowercase();
        let user = users
            .find_by_identifier(&username)
            .await?
            .with_context(|| format!("seed profile 的账号 {username} 在 idm 不存在(apply 先跑)"))?
            .user;
        if profiles.get(user.id).await?.is_some() {
            continue; // 幂等:已有资料 → 保持用户的现值,不按回 seed
        }
        profiles
            .upsert(
                user.id,
                ProfileFields {
                    display_name: a.display_name.clone(),
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
    use idm::{
        InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo, InMemoryTenantRepo,
        InMemoryUserRepo, OutboxRepo,
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
                roles: InMemoryRoleRepo::sharing_with(&users),
                tenants: InMemoryTenantRepo::sharing_with(&users),
                members: InMemoryMemberRepo::sharing_with(&users),
                outbox: InMemoryOutboxRepo::sharing_with(&users),
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
            apply(
                self.repos(),
                &idm::FakeHasher,
                data,
                Some("system".to_owned()),
            )
            .await
            .unwrap();
        }

        async fn uid(&self, name: &str) -> Uuid {
            self.users
                .find_by_identifier(name)
                .await
                .unwrap()
                .unwrap()
                .user
                .id
        }

        async fn events(&self, ty: &str) -> usize {
            self.outbox
                .poll_unpublished(1000)
                .await
                .unwrap()
                .iter()
                .filter(|e| e.event_type == ty)
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
        let data = SeedData::load(None).unwrap();
        let known: HashSet<&str> = RoleName::ALL.iter().map(|r| r.as_str()).collect();
        for role in data.granted_roles() {
            assert!(known.contains(role.as_str()), "账号引用了未知角色 `{role}`");
        }
        assert!(data.tenants.iter().any(|t| t.slug == DEFAULT_TENANT_SLUG));
        for u in &data.users {
            assert!(
                !u.effective_memberships().is_empty(),
                "{} 应是某个租户的成员",
                u.username
            );
        }
    }

    /// role→权限默认映射能建成 `Policy`:superadmin 当平台角色持全部平台级权限,
    /// admin 当租户角色持后台准入。
    #[test]
    fn default_policy_superadmin_has_all_platform_perms() {
        let policy = SeedData::default().policy();
        let perms = policy.perms_for(&["superadmin".to_owned()], &[]);
        for p in Perm::ALL {
            let platform = p.scope() == crate::kernel::authz::PermScope::Platform;
            assert_eq!(perms.contains(&p), platform, "{p:?}");
        }
        assert!(policy
            .perms_for(&[], &["admin".to_owned()])
            .contains(&Perm::AdminLogin));
    }

    /// 作用域写错位置 / 未知角色 / 默认租户改 id → 校验报错(启动即挂)。
    #[test]
    fn validation_rejects_misplaced_roles() {
        let bad = |s: &str| {
            let data: SeedData = toml::from_str(s).unwrap();
            assert!(data.validate().is_err(), "应拒:{s}");
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
        let err = data.validate().unwrap_err().to_string();
        assert!(err.contains("superadmin 只能有一个"), "{err}");
        assert!(err.contains("root1") && err.contains("root2"), "{err}");

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

    /// 库里已有别的账号持 superadmin(如 seed 换了 superadmin 的用户名)→ apply 报错,不给出第二个;
    /// 同一个账号重跑照常幂等。
    #[tokio::test]
    async fn seed_rejects_second_superadmin_in_store() {
        let idm = Idm::new();
        let first = parse(
            r#"[[users]]
username = "root"
password = "p"
platform_roles = ["superadmin"]"#,
        );
        idm.apply(&first).await;
        idm.apply(&first).await; // 同一账号:幂等

        let renamed = parse(
            r#"[[users]]
username = "newroot"
password = "p"
platform_roles = ["superadmin"]"#,
        );
        let err = apply(idm.repos(), &idm::FakeHasher, &renamed, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("superadmin 只能有一个"), "{err}");
        assert!(
            idm.users
                .find_by_identifier("newroot")
                .await
                .unwrap()
                .is_none(),
            "没建出第二个 superadmin 账号"
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
        let sa_role = role_ids_by_name(&idm.roles, ["superadmin".to_owned()].iter())
            .await
            .unwrap();
        let second = idm
            .users
            .create_with_roles("legacy-root", None, "h", &sa_role, None)
            .await
            .unwrap();
        let err = ensure_single_superadmin(&idm.users)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("root") && err.contains("legacy-root"), "{err}");
        assert!(err.contains("scripts/prod/README.md"), "{err}");
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
        let u = &data.users[0];
        assert_eq!(u.effective_platform_roles(), vec!["superadmin".to_owned()]);
        let ms = u.effective_memberships();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].slug, DEFAULT_TENANT_SLUG);
        assert_eq!(ms[0].roles, vec!["admin".to_owned()]);
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
            .list(&idm::ListPage::Offset {
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
        let boss = idm.uid("boss").await;
        assert_eq!(
            idm.roles.roles_for_user(boss).await.unwrap(),
            vec!["superadmin".to_owned()]
        );
        let m = idm
            .members
            .get(DEFAULT_TENANT_ID.as_uuid(), boss)
            .await
            .unwrap()
            .expect("boss 应是默认租户成员");
        assert_eq!(m.roles, vec!["admin".to_owned()]);

        // alice:两个租户,各自的角色;没有平台角色
        let alice = idm.uid("alice").await;
        assert!(idm.roles.roles_for_user(alice).await.unwrap().is_empty());
        let mut ms: Vec<(String, Vec<String>)> = idm
            .members
            .memberships_for_user(alice)
            .await
            .unwrap()
            .into_iter()
            .map(|m| (m.tenant.slug, m.roles))
            .collect();
        ms.sort();
        assert_eq!(
            ms,
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
        let alice = idm.uid("alice").await;
        let tenant = DEFAULT_TENANT_ID.as_uuid();
        // 运行期:租户管理员给 alice 加了一个闭集外的租户角色 editor
        let editor = idm
            .roles
            .upsert("editor", "编辑", RoleScope::Tenant, None)
            .await
            .unwrap();
        let user_role = role_ids_by_name(&idm.roles, ["user".to_owned()].iter())
            .await
            .unwrap();
        idm.members
            .set_roles(tenant, alice, &[user_role[0], editor], None)
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
        let m = idm.members.get(tenant, alice).await.unwrap().unwrap();
        assert_eq!(
            m.roles,
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
        let alice = idm.uid("alice").await;
        // 运行期授了一个闭集外的平台角色 auditor
        let auditor = idm
            .roles
            .upsert("auditor", "审计员", RoleScope::Platform, None)
            .await
            .unwrap();
        idm.roles.grant(alice, auditor, None).await.unwrap();

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
            let expect = role.name.parse::<RoleName>().unwrap().scope();
            assert_eq!(role.scope, expect, "{}", role.name);
        }
    }

    /// 初始 profile:建号后带出 display_name;**重跑绝不按回** —— `upsert` 是全量替换而 seed 每次
    /// 启动都跑,不先查就写会把用户改过的资料清回 seed 值、连头像一起解绑(每次重启资料重置)。
    #[tokio::test]
    async fn profiles_created_once_and_never_reset_on_rerun() {
        use crate::features::profile::InMemoryProfileRepo;

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
        apply_profiles(&profiles, &idm.users, &data, by.clone())
            .await
            .unwrap();
        let uid = idm.uid("alice").await;
        let p = profiles
            .get(uid)
            .await
            .unwrap()
            .expect("初始 profile 应已建");
        assert_eq!(p.display_name.as_deref(), Some("Alice"));

        // 用户运行期改名 + 绑头像
        let avatar = Uuid::now_v7();
        profiles
            .upsert(
                uid,
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
        apply_profiles(&profiles, &idm.users, &data, by)
            .await
            .unwrap();
        let p = profiles.get(uid).await.unwrap().unwrap();
        assert_eq!(
            p.display_name.as_deref(),
            Some("Alice Liddell"),
            "重跑不得把用户改的名按回 seed 值"
        );
        assert_eq!(p.avatar_content_id, Some(avatar), "重跑不得解掉头像绑定");
    }
}

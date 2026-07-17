//! idm 默认数据 seed —— **进程内启动时**(`AppState::new`,见 [`crate::app::state`])或**显式 CLI**
//! (`src/bin/seed.rs`)两条路共用此核心。幂等:role upsert / 账号 find-or-create / grant,可重复跑、可并发。
//!
//! 分工:**角色集 / 权限集 / role→权限默认**是代码闭集(`authz::{RoleName, Perm}`,不做动态 CRUD);
//! **账号**(实例数据 + 密码)仍归 `seed.toml`(编译期 `include_str!` 嵌入,`SEED_FILE` 可覆盖)。
//! 改默认账号编辑 `seed.toml`;增删角色/权限改 `authz.rs` 枚举。

use std::collections::HashMap;

use anyhow::Context;
use serde::Deserialize;

use crate::features::profile::{ProfileFields, ProfileRepo};
use crate::features::tenants::{TenantRepo, TenantRole, TenantStatus};
use crate::infra::authz::{Perm, Policy, RoleName};
use idm::{IdmError, PwHasher, RoleRepo, UserRepo};

/// 编译期嵌入的默认 seed(仓库根 `seed.toml`)。`SEED_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `seed.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_SEED: &str = include_str!("../../seed.toml");

/// 外置 seed 只剩**账号**(实例数据 + 密码,`SEED_FILE` 可覆盖)。角色集 / 权限集 / role→权限
/// 默认全收进代码枚举(`RoleName` / `Perm`)—— 封闭集、不做动态 CRUD(角色**有哪些权限**才可
/// 运行时改,落 `role_permissions` 表)。
#[derive(Deserialize)]
pub struct SeedData {
    #[serde(default)]
    accounts: Vec<AccountSeed>,
    /// 租户 + 成员(**dev 样例数据**)。prod 用 `SEED_FILE` 覆盖成不含 `[[tenants]]` 的文件 ——
    /// 真实租户由平台后台开通,不走 seed(spec §1:平台开通 + 租户内部邀请)。
    ///
    /// 它在这里的理由是**可验证性**:没有它,全仓没有任何代码能创建租户,整条铸币链
    /// 在任何跑得起来的配置下都是死的 —— 开发者没法验证自己刚合的功能,冒烟只能靠手插 SQL
    /// (P2 第一版就是这么"验"绿的)。
    #[serde(default)]
    tenants: Vec<TenantSeed>,
}

#[derive(Deserialize)]
struct TenantSeed {
    /// 机器码 slug(= `idm.tenants.name`)。**租户 id 由它派生**(见 `tenant_id_for`)。
    name: String,
    display_name: String,
    #[serde(default)]
    members: Vec<MemberSeed>,
}

#[derive(Deserialize)]
struct MemberSeed {
    /// 引用 `[[accounts]]` 里的 username(标识引用,非 FK —— 跨 schema 不用 FK)。
    username: String,
    role: TenantRole,
}

/// 租户 slug → 稳定 id。
///
/// **必须确定性**:`upsert_tenant` 按 id 冲突,而 seed 每次启动都重跑 —— 随机 id 会让每次
/// 重启都新建一家同名公司(然后撞上 `tenants_name_alive_uidx` 报错)。v5 还顺带让 dev/CI/
/// 每个同事的机器上租户 id 一致,写测试和排查时能直接照抄。
fn tenant_id_for(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, name.as_bytes())
}

#[derive(Deserialize)]
struct AccountSeed {
    username: String,
    #[serde(default)]
    email: Option<String>,
    password: String,
    #[serde(default)]
    roles: Vec<String>,
    /// 初始 profile 的显示名(可选)。落 **app schema** 的 profiles 表,只在 app/idm 同进程
    /// (`Mount::Both`)时写 —— 见 [`apply_profiles`]。不设 = 建一行各段为 null 的空资料。
    #[serde(default)]
    display_name: Option<String>,
}

impl SeedData {
    /// 载入:`path`(来自 `Config.seed_file`,即 `SEED_FILE`)指定的外部文件优先,否则用编译期嵌入的默认。
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let content = match path {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("读 SEED_FILE {path} 失败"))?,
            None => EMBEDDED_SEED.to_owned(),
        };
        toml::from_str(&content).context("解析 seed 数据失败")
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

    /// 账号引用到的角色名(供 `Policy::assert_roles_covered` 启动期校验:每个被授予的 role 都得有策略条目)。
    pub fn granted_roles(&self) -> impl Iterator<Item = &str> {
        self.accounts
            .iter()
            .flat_map(|a| a.roles.iter().map(String::as_str))
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

/// 已存在账号的**幂等补授**。写**并集**(现有 ∪ seed 声明),经 `set_roles` 落。
///
/// 为什么不是 `grant`:`grant` 只往 `user_roles` 插一行、**不发任何事件** —— idm 库里角色对了,
/// 但 CQRS 投影(`admin_user_index.roles`)收不到通知,会永久停在旧值(后台列表角色显示错、
/// `roles_any`/`roles_none` 过滤漏人),只能手工跑 rebuild_search 自愈。这与首建路径当初从
/// `create` + `grant` 改成 `create_with_roles` 是**同一个 bug**,当时只修了兄弟分支。
/// `set_roles` 在事务内 emit `user.roles_set`,投影据此收敛。
///
/// 为什么是并集而非直接写声明集:`set_roles` 是**原子全量替换** —— 直接写声明集会把运行期
/// admin 授予的角色清掉(重启即掉权,另一个 bug)。`grant` 的加性语义是刻意的,这里保住它。
/// 并集与现有相同 → 不写不发事件(幂等重跑无副作用)。
async fn ensure_roles_with_event(
    roles: &dyn RoleRepo,
    user_id: uuid::Uuid,
    declared: &[String],
    by: Option<String>,
) -> anyhow::Result<()> {
    let current = roles.roles_for_user(user_id).await?;
    if !declared.iter().any(|d| !current.contains(d)) {
        return Ok(()); // 声明的角色都已在身 → 幂等:无写、无事件
    }
    // name → id 走 list()(**不是**闭集 role_ids):`current` 可能含闭集外的历史/手工角色,
    // 映射不到就会被并集漏掉 —— 那等于把它清掉,正是上面要避免的。
    let by_name: HashMap<String, uuid::Uuid> = roles
        .list()
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let mut union: Vec<uuid::Uuid> = Vec::new();
    for name in current.iter().chain(declared.iter()) {
        match by_name.get(name) {
            Some(&id) if !union.contains(&id) => union.push(id),
            Some(_) => {}
            // 存活角色恒在 list() 里(roles_for_user 同样只回存活的),故走不到;
            // 真走到了说明目录与授予不一致 —— 宁可报错也不静默把该角色从并集里丢掉。
            None => anyhow::bail!("角色 {name} 在 user_roles 里但不在角色目录中"),
        }
    }
    roles.set_roles(user_id, &union, by).await?;
    Ok(())
}

/// 幂等应用 seed:upsert role → find-or-create account → 补授角色。`by` = 审计主体(seeder 用 "system")。
/// **并发安全**:账号 create 撞唯一约束(另一实例已建)→ 退回查已存在的,收敛不报错。
pub async fn apply(
    users: &dyn UserRepo,
    roles: &dyn RoleRepo,
    tenants: &dyn TenantRepo,
    hasher: &dyn PwHasher,
    data: &SeedData,
    by: Option<String>,
) -> anyhow::Result<()> {
    // 1. 角色(幂等 upsert),记 name -> id 供账号授予引用。角色集是代码闭集(`RoleName`)。
    // `idm.roles` 是**可授予的平台角色目录**:进了这里的角色就能经 `GET /admin/auth/roles`
    // 出现在后台候选集、经 `PUT /users/{id}/roles` 授给任意用户 —— 所以 `RoleName` 里只准
    // 有平台角色(见它的 doc)。租户角色是 `TenantRole`,靠 `tenant_members` 的成员资格获得,
    // 根本不经过这条路。
    let mut role_ids: HashMap<&'static str, uuid::Uuid> = HashMap::new();
    for r in RoleName::ALL {
        let id = roles
            .upsert(r.as_str(), r.display_name(), by.clone())
            .await
            .with_context(|| format!("seed role {} 失败", r.as_str()))?;
        role_ids.insert(r.as_str(), id);
    }

    // 2. 账号(幂等:已存在则取,否则建)。新建走 **create_with_roles** —— 让 `user.created`
    //    事件**带上角色**,CQRS 投影(search projector)据此落 `admin_user_index.roles`。
    //    旧写法 `create` + `grant` 有 bug:`create` 发的 user.created 是空 roles、`grant` 又不发
    //    任何事件,导致 seed 出来的账号在搜索投影里角色恒为空(admin 用户列表 roles=[])。
    for a in &data.accounts {
        let username = a.username.trim().to_lowercase();
        let email = a.email.as_deref().map(|e| e.trim().to_lowercase());
        // 账号引用的角色名 → id(未声明角色即报错)。create_with_roles 与幂等补授共用。
        let account_role_ids: Vec<uuid::Uuid> = a
            .roles
            .iter()
            .map(|role_name| {
                role_ids
                    .get(role_name.as_str())
                    .copied()
                    .with_context(|| format!("账号 {username} 引用了未声明的角色 {role_name}"))
            })
            .collect::<anyhow::Result<_>>()?;

        match users.find_by_identifier(&username).await? {
            // 已存在(幂等再跑):补齐角色 —— 走 set_roles(并集)而非 grant,否则补出来的角色
            // 不发事件、投影永久陈旧(见 ensure_roles_with_event)。
            Some(uwh) => {
                ensure_roles_with_event(roles, uwh.user.id, &a.roles, by.clone()).await?;
            }
            None => {
                let hash = hasher
                    .hash(&a.password)
                    .map_err(|e| anyhow::anyhow!("argon2 hash 失败: {e:?}"))?;
                match users
                    .create_with_roles(
                        &username,
                        email.as_deref(),
                        &hash,
                        &account_role_ids,
                        by.clone(),
                    )
                    .await
                {
                    Ok(_) => {}
                    // 并发 seed:另一实例已抢先建 → 退回补齐角色(幂等收敛,同上走 set_roles)。
                    Err(IdmError::Conflict(_)) => {
                        let user = users
                            .find_by_identifier(&username)
                            .await?
                            .context("并发 seed 冲突后仍查不到用户")?
                            .user;
                        ensure_roles_with_event(roles, user.id, &a.roles, by.clone()).await?;
                    }
                    Err(e) => return Err(anyhow::anyhow!("seed account {username} 失败: {e:?}")),
                }
            }
        }
    }

    // 3. 租户 + 成员(幂等)。**必须在账号之后** —— 成员靠 username 引用账号。
    // 没有这一段,全仓就没有任何代码能创建租户:`memberships()` 对每个人恒返回 `[]`,
    // 每枚 token 都不带租户 claim,`GET /auth/tenants` 恒空,切换端点恒 404 ——
    // 整条链在任何跑得起来的配置下都是死的。
    let mut members = 0usize;
    for t in &data.tenants {
        let id = tenant_id_for(&t.name);
        tenants
            .upsert_tenant(
                id,
                &t.name,
                &t.display_name,
                TenantStatus::Active,
                by.clone(),
            )
            .await
            .with_context(|| format!("seed tenant {} 失败", t.name))?;
        for m in &t.members {
            let username = m.username.trim().to_lowercase();
            // 标识引用(username → user_id),不是 FK —— 跨 schema 不用 FK(CLAUDE.md)。
            // 查不到就报错而非跳过:seed.toml 写错人名该在启动时炸,不该静默少一个成员。
            let user = users
                .find_by_identifier(&username)
                .await?
                .with_context(|| format!("租户 {} 的成员 {username} 不存在于 accounts", t.name))?
                .user;
            tenants
                .upsert_member(user.id, id, m.role, by.clone())
                .await
                .with_context(|| format!("seed member {username}@{} 失败", t.name))?;
            members += 1;
        }
    }

    tracing::info!(
        roles = RoleName::ALL.len(),
        accounts = data.accounts.len(),
        tenants = data.tenants.len(),
        members,
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
/// 这与 `apply` 里账号"已存在则不动密码"、`ensure_roles_with_event` 写并集是同一条铁律:
/// **seed 只负责把东西 bootstrap 出来,不负责把它按回初始值**。
pub async fn apply_profiles(
    profiles: &dyn ProfileRepo,
    users: &dyn UserRepo,
    data: &SeedData,
    by: Option<String>,
) -> anyhow::Result<()> {
    let mut created = 0usize;
    for a in &data.accounts {
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
        accounts = data.accounts.len(),
        profiles_created = created,
        "seed 账号的初始 profile 已应用(幂等)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// 嵌入的 seed.toml 能解析,且账号引用的角色都是已知角色(拼错 → 这里挂)。
    /// 角色集/权限集已是代码闭集,其自身正确性由 `authz::role_name_wire_matches` 等守;这里只守账号引用。
    #[test]
    fn embedded_seed_accounts_reference_known_platform_roles() {
        let data = SeedData::load(None).unwrap();
        let known: HashSet<&str> = RoleName::ALL.iter().map(|r| r.as_str()).collect();
        for role in data.granted_roles() {
            assert!(known.contains(role), "账号引用了未知角色 `{role}`");
        }
    }

    /// 嵌入 seed 里的租户成员引用的 username 必须真的存在于 `[[accounts]]` ——
    /// 拼错 → `apply` 会在启动时 bail。这条让它在**测试期**就报。
    #[test]
    fn embedded_seed_tenant_members_reference_known_accounts() {
        let data = SeedData::load(None).unwrap();
        let accounts: HashSet<String> = data
            .accounts
            .iter()
            .map(|a| a.username.trim().to_lowercase())
            .collect();
        for t in &data.tenants {
            for m in &t.members {
                assert!(
                    accounts.contains(&m.username.trim().to_lowercase()),
                    "租户 {} 的成员 `{}` 不在 accounts 里",
                    t.name,
                    m.username
                );
            }
        }
    }

    /// 租户 id 由 slug **确定性**派生 —— seed 每次启动都重跑,随机 id 会让每次重启都新建
    /// 一家同名公司(然后撞 `tenants_name_alive_uidx`)。
    #[test]
    fn tenant_id_is_stable_across_runs() {
        assert_eq!(tenant_id_for("acme"), tenant_id_for("acme"));
        assert_ne!(tenant_id_for("acme"), tenant_id_for("globex"));
    }

    /// **端到端**:跑一遍 seed,`user` 就真的有两家公司了。
    ///
    /// 这条钉的是「链是活的」—— P2 第一版整条铸币链在任何跑得起来的配置下都是死的
    /// (没有任何代码创建租户),而冒烟"验"绿是因为数据是手工 SQL 插的。
    /// 这条测试会在那种情况下报红。
    #[tokio::test]
    async fn seeded_tenants_give_the_user_real_memberships() {
        let users = idm::InMemoryUserRepo::new();
        let roles = idm::InMemoryRoleRepo::sharing_with(&users);
        let tenants = crate::features::tenants::InMemoryTenantRepo::new();
        let data = SeedData::load(None).unwrap(); // 嵌入的真 seed.toml
        apply(
            &users,
            &roles,
            &tenants,
            &idm::FakeHasher,
            &data,
            Some("system".to_owned()),
        )
        .await
        .unwrap();

        let uid = users
            .find_by_identifier("user")
            .await
            .unwrap()
            .expect("seed 应建出 user")
            .user
            .id;
        let ms = tenants.memberships(uid).await.unwrap();
        assert_eq!(
            ms.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            vec!["acme", "globex"],
            "seed 后 user 该同时属于两家公司(按 seq 升序)—— 这是 1:N 切换的样例数据"
        );
        assert_eq!(ms[0].role, TenantRole::Admin, "user 是 Acme 的 admin");
        assert_eq!(ms[1].role, TenantRole::Member, "user 是 Globex 的 member");

        // 幂等:重跑不重复、不换 id
        apply(
            &users,
            &roles,
            &tenants,
            &idm::FakeHasher,
            &data,
            Some("system".to_owned()),
        )
        .await
        .unwrap();
        let again = tenants.memberships(uid).await.unwrap();
        assert_eq!(again.len(), 2, "重跑 seed 不该重复建成员");
        assert_eq!(again[0].tenant_id, ms[0].tenant_id, "重跑不该换租户 id");
    }

    /// role→权限默认映射能建成 `Policy`,且 superadmin 持全权闭集(bootstrap 正确性)。
    #[test]
    fn default_policy_superadmin_has_all_perms() {
        let policy = SeedData {
            accounts: vec![],
            tenants: vec![],
        }
        .policy();
        let perms = policy.perms_for(&["superadmin".to_owned()]);
        for p in Perm::ALL {
            assert!(perms.contains(&p), "{p:?} superadmin 应持有");
        }
    }

    fn account(username: &str, roles: &[&str]) -> AccountSeed {
        AccountSeed {
            username: username.to_owned(),
            email: None,
            password: "pwd".to_owned(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            display_name: None,
        }
    }

    /// 初始 profile:建号后带出 display_name;**重跑绝不按回** —— `upsert` 是全量替换而 seed 每次
    /// 启动都跑,不先查就写会把用户改过的资料清回 seed 值、连头像一起解绑(每次重启资料重置)。
    #[tokio::test]
    async fn profiles_created_once_and_never_reset_on_rerun() {
        use crate::features::profile::InMemoryProfileRepo;

        let users = idm::InMemoryUserRepo::new();
        let roles = idm::InMemoryRoleRepo::sharing_with(&users);
        let profiles = InMemoryProfileRepo::new();
        let hasher = idm::FakeHasher;
        let by = Some("system".to_owned());
        let data = SeedData {
            accounts: vec![AccountSeed {
                display_name: Some("Alice".to_owned()),
                ..account("alice", &["user"])
            }],
            tenants: vec![],
        };

        apply(
            &users,
            &roles,
            &crate::features::tenants::InMemoryTenantRepo::new(),
            &hasher,
            &data,
            by.clone(),
        )
        .await
        .unwrap();
        apply_profiles(&profiles, &users, &data, by.clone())
            .await
            .unwrap();
        let uid = users
            .find_by_identifier("alice")
            .await
            .unwrap()
            .unwrap()
            .user
            .id;
        let p = profiles
            .get(uid)
            .await
            .unwrap()
            .expect("初始 profile 应已建");
        assert_eq!(p.display_name.as_deref(), Some("Alice"));

        // 用户运行期改名 + 绑头像
        let avatar = uuid::Uuid::now_v7();
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
        apply_profiles(&profiles, &users, &data, by).await.unwrap();
        let p = profiles.get(uid).await.unwrap().unwrap();
        assert_eq!(
            p.display_name.as_deref(),
            Some("Alice Liddell"),
            "重跑不得把用户改的名按回 seed 值"
        );
        assert_eq!(p.avatar_content_id, Some(avatar), "重跑不得解掉头像绑定");
    }

    async fn role_names(roles: &idm::InMemoryRoleRepo, uid: uuid::Uuid) -> Vec<String> {
        let mut v = roles.roles_for_user(uid).await.unwrap();
        v.sort();
        v
    }

    /// 幂等重跑补授**必须发事件**(旧写法用 `grant`,只插 user_roles、零事件 → 搜索投影
    /// `admin_user_index.roles` 永久陈旧),且必须写**并集** —— `set_roles` 是全量替换,
    /// 直接写声明集会把运行期 admin 授予、seed.toml 没声明的角色清掉(重启即掉权)。
    #[tokio::test]
    async fn rerun_emits_roles_set_and_keeps_runtime_grants() {
        use idm::OutboxRepo;
        let users = idm::InMemoryUserRepo::new();
        // 共享角色/授予/发件箱存储:内存双 repo 才等价于 PG 的共表语义(独立 new() 各自一份,
        // create_with_roles 会看不见这边 upsert 的角色,发件箱也各记各的)。
        let roles = idm::InMemoryRoleRepo::sharing_with(&users);
        let outbox = idm::InMemoryOutboxRepo::sharing_with(&users);
        let hasher = idm::FakeHasher;
        let by = Some("system".to_owned());

        // 首建:只声明 user
        let data = SeedData {
            accounts: vec![account("alice", &["user"])],
            tenants: vec![],
        };
        let tenants = crate::features::tenants::InMemoryTenantRepo::new();
        apply(&users, &roles, &tenants, &hasher, &data, by.clone())
            .await
            .unwrap();
        let uid = users
            .find_by_identifier("alice")
            .await
            .unwrap()
            .unwrap()
            .user
            .id;
        assert_eq!(role_names(&roles, uid).await, vec!["user".to_owned()]);

        // 运行期 admin 手工授予 superadmin(seed.toml 里没有)
        let sa = roles
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.name == "superadmin")
            .unwrap()
            .id;
        roles.grant(uid, sa, by.clone()).await.unwrap();

        // 重跑 seed,声明里多加一个 admin:应补上 admin,且**不动**运行期的 superadmin
        let data = SeedData {
            accounts: vec![account("alice", &["user", "admin"])],
            tenants: vec![],
        };
        apply(&users, &roles, &tenants, &hasher, &data, by.clone())
            .await
            .unwrap();
        // 事件是重点:没有它,idm 里角色对了但投影永远停在旧值(只能手工 rebuild_search 自愈)。
        let roles_set: Vec<_> = outbox
            .poll_unpublished(100)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == "user.roles_set")
            .collect();
        assert_eq!(
            roles_set.len(),
            1,
            "补授必须发一条 user.roles_set(grant 不发事件 → 投影永久陈旧)"
        );
        assert_eq!(
            roles_set[0].payload["roles"],
            serde_json::json!(["admin", "superadmin", "user"]),
            "事件载荷应是并集(投影据此落 roles)"
        );
        assert_eq!(
            role_names(&roles, uid).await,
            vec![
                "admin".to_owned(),
                "superadmin".to_owned(),
                "user".to_owned()
            ],
            "并集:补上声明的 admin,保留运行期授予的 superadmin"
        );

        // 再重跑(声明集已全在身)→ 收敛:不写、**不再发事件**(否则每次重启都刷一条噪声)
        apply(&users, &roles, &tenants, &hasher, &data, by)
            .await
            .unwrap();
        assert_eq!(
            role_names(&roles, uid).await,
            vec![
                "admin".to_owned(),
                "superadmin".to_owned(),
                "user".to_owned()
            ],
            "幂等:重跑结果稳定"
        );
        assert_eq!(
            outbox
                .poll_unpublished(100)
                .await
                .unwrap()
                .iter()
                .filter(|e| e.event_type == "user.roles_set")
                .count(),
            1,
            "幂等重跑不应再发事件"
        );
    }
}

//! idm 默认数据 seed —— **进程内启动时**(`AppState::new`,见 [`crate::app::state`])或**显式 CLI**
//! (`src/bin/seed.rs`)两条路共用此核心。幂等:role upsert / 账号 find-or-create / grant,可重复跑、可并发。
//!
//! 分工:**角色集 / 权限集 / role→权限默认**是代码闭集(`authz::{RoleName, Perm}`,不做动态 CRUD);
//! **账号**(实例数据 + 密码)仍归 `seed.toml`(编译期 `include_str!` 嵌入,`SEED_FILE` 可覆盖)。
//! 改默认账号编辑 `seed.toml`;增删角色/权限改 `authz.rs` 枚举。

use std::collections::HashMap;

use anyhow::Context;
use serde::Deserialize;

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
}

#[derive(Deserialize)]
struct AccountSeed {
    username: String,
    #[serde(default)]
    email: Option<String>,
    password: String,
    #[serde(default)]
    roles: Vec<String>,
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
    hasher: &dyn PwHasher,
    data: &SeedData,
    by: Option<String>,
) -> anyhow::Result<()> {
    // 1. 角色(幂等 upsert),记 name -> id 供账号授予引用。角色集是代码闭集(`RoleName`)。
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

    tracing::info!(
        roles = RoleName::ALL.len(),
        accounts = data.accounts.len(),
        "idm seed 已应用(幂等)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// 嵌入的 seed.toml 能解析,且账号引用的角色都是已知 `RoleName`(拼错 → 这里挂)。
    /// 角色集/权限集已是代码闭集,其自身正确性由 `authz::role_name_wire_matches` 等守;这里只守账号引用。
    #[test]
    fn embedded_seed_accounts_reference_known_roles() {
        let data = SeedData::load(None).unwrap();
        let known: HashSet<&str> = RoleName::ALL.iter().map(|r| r.as_str()).collect();
        for role in data.granted_roles() {
            assert!(known.contains(role), "账号引用了未知角色 `{role}`");
        }
    }

    /// role→权限默认映射能建成 `Policy`,且 superadmin 持全权闭集(bootstrap 正确性)。
    #[test]
    fn default_policy_superadmin_has_all_perms() {
        let policy = SeedData { accounts: vec![] }.policy();
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
        }
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
        };
        apply(&users, &roles, &hasher, &data, by.clone())
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
        };
        apply(&users, &roles, &hasher, &data, by.clone())
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
        apply(&users, &roles, &hasher, &data, by).await.unwrap();
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

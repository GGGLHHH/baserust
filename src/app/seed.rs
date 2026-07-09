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

/// 幂等应用 seed:upsert role → find-or-create account → grant。`by` = 审计主体(seeder 用 "system")。
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

    // 2. 账号(幂等:已存在则取,否则建)+ 授予角色(幂等)。
    for a in &data.accounts {
        let username = a.username.trim().to_lowercase();
        let email = a.email.as_deref().map(|e| e.trim().to_lowercase());
        let user = match users.find_by_identifier(&username).await? {
            Some(uwh) => uwh.user,
            None => {
                let hash = hasher
                    .hash(&a.password)
                    .map_err(|e| anyhow::anyhow!("argon2 hash 失败: {e:?}"))?;
                match users
                    .create(&username, email.as_deref(), &hash, by.clone())
                    .await
                {
                    Ok(u) => u,
                    // 并发 seed:另一实例已抢先建 → 退回查已存在的(幂等收敛)。
                    Err(IdmError::Conflict(_)) => {
                        users
                            .find_by_identifier(&username)
                            .await?
                            .context("并发 seed 冲突后仍查不到用户")?
                            .user
                    }
                    Err(e) => return Err(anyhow::anyhow!("seed account {username} 失败: {e:?}")),
                }
            }
        };
        for role_name in &a.roles {
            let role_id = role_ids
                .get(role_name.as_str())
                .copied()
                .with_context(|| format!("账号 {username} 引用了未声明的角色 {role_name}"))?;
            roles.grant(user.id, role_id, by.clone()).await?;
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
}

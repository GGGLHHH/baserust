//! idm 默认数据 seed —— **进程内启动时**(`AppState::new`,见 [`crate::app::state`])或**显式 CLI**
//! (`src/bin/seed.rs`)两条路共用此核心。幂等:role upsert / 账号 find-or-create / grant,可重复跑、可并发。
//!
//! 数据归数据:默认来自仓库根 `seed.toml`(编译期 `include_str!` 嵌入,**二进制自带、无需挂文件**),
//! 设 `SEED_FILE` 则读外部文件覆盖。改默认角色/账号编辑 `seed.toml`,不动代码。

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use serde::Deserialize;

use crate::infra::authz::{Perm, Policy};
use idm::{IdmError, PwHasher, RoleRepo, UserRepo};

/// 编译期嵌入的默认 seed(仓库根 `seed.toml`)。`SEED_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `seed.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_SEED: &str = include_str!("../../seed.toml");

#[derive(Deserialize)]
pub struct SeedData {
    /// 权限词表(catalog)。**enum 是 enforcement 真相**,这是其可读镜像;启动期校验 == `Perm` 闭集。
    #[serde(default)]
    permissions: Vec<PermSeed>,
    #[serde(default)]
    roles: Vec<RoleSeed>,
    #[serde(default)]
    accounts: Vec<AccountSeed>,
}

/// 权限词表的一条声明。`key` 必须对应 [`Perm`] 闭集变体(未知串 → 反序列化失败,fail-fast);
/// `description` 是人读说明(供权限清单/admin 后台;落 `permissions` 表)。
#[derive(Deserialize)]
struct PermSeed {
    key: Perm,
    description: String,
}

/// role 权限声明的原始形态:显式 `Perm` 串,或整表通配 `"*"`。
/// untagged:先试 `Perm`,再试 `"*"`;两者都不中的未知串照样解析失败(fail-fast 保住,
/// 代价是报错措辞从"unknown variant"退化成"did not match any variant"——可接受)。
#[derive(Deserialize)]
#[serde(untagged)]
enum PermEntry {
    Perm(Perm),
    Wildcard(Wildcard),
}

/// `"*"` 的类型化落点(untagged 需要一个可命中的反序列化目标)。
#[derive(Deserialize)]
enum Wildcard {
    #[serde(rename = "*")]
    Star,
}

/// 解析后的 role 声明:`permissions` 已是**展开后的具体 `Perm` 集**(`"*"` 在 [`TryFrom`] 里
/// 展开成 `Perm::ALL`)——下游(`policy()` / PG 落库)只见具体权限,通配符不出解析层。
#[derive(Deserialize)]
#[serde(try_from = "RoleSeedRaw")]
struct RoleSeed {
    name: String,
    display_name: String,
    permissions: Vec<Perm>,
}

#[derive(Deserialize)]
struct RoleSeedRaw {
    name: String,
    display_name: String,
    /// role→权限映射(app 授权策略)。`apply()` 不读它(permissions 不进 idm 库);app 组合根经
    /// [`SeedData::policy`] 读它建内存 `Policy`。省略 = 空权限(`#[serde(default)]`),seed 仍正常。
    /// `["*"]` = 全权(随 `Perm` 闭集自动增长,消除"加权限忘补 superadmin"的漂移)。
    #[serde(default)]
    permissions: Vec<PermEntry>,
}

impl TryFrom<RoleSeedRaw> for RoleSeed {
    type Error = String;

    fn try_from(raw: RoleSeedRaw) -> Result<Self, Self::Error> {
        let has_star = raw
            .permissions
            .iter()
            .any(|e| matches!(e, PermEntry::Wildcard(_)));
        let permissions = if has_star {
            // `"*"` 只许单独出现:要么 `["*"]` 全权、要么全显式列。混用是含混配置
            // ("*都有了还列别的是什么意思"),按 fail-fast 哲学拒启动。
            if raw.permissions.len() != 1 {
                return Err(format!(
                    "角色 `{}`:通配 \"*\" 不可与显式权限混用(要么 [\"*\"] 要么全显式列)",
                    raw.name
                ));
            }
            Perm::ALL.to_vec()
        } else {
            raw.permissions
                .iter()
                .map(|e| match e {
                    PermEntry::Perm(p) => *p,
                    PermEntry::Wildcard(_) => unreachable!("has_star 已排除"),
                })
                .collect()
        };
        Ok(Self {
            name: raw.name,
            display_name: raw.display_name,
            permissions,
        })
    }
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

    /// role→权限映射 → app 内存授权 `Policy`(组合根 `AppState::new` 建)。**permissions 不写进 idm 库**。
    pub fn policy(&self) -> Policy {
        Policy::from_roles(
            self.roles
                .iter()
                .map(|r| (r.name.clone(), r.permissions.clone())),
        )
    }

    /// 账号引用到的角色名(供 `Policy::assert_roles_covered` 启动期校验:每个被授予的 role 都得有策略条目)。
    pub fn granted_roles(&self) -> impl Iterator<Item = &str> {
        self.accounts
            .iter()
            .flat_map(|a| a.roles.iter().map(String::as_str))
    }

    /// 启动期校验:seed.toml 的 `[[permissions]]` 词表 **== 代码 `Perm` 闭集**(多/漏/重复即 fail-fast)。
    /// **enum 是 enforcement 唯一真相**,seed 是其可读镜像 —— 校验杜绝"声明了无变体兜底的死权限"或漏声明。
    /// 同 `assert_roles_covered` 的 fail-fast 哲学:词表与代码漂移在启动期就炸,不留到运行期。
    pub fn assert_permission_catalog(&self) -> anyhow::Result<()> {
        let declared: HashSet<Perm> = self.permissions.iter().map(|p| p.key).collect();
        for p in Perm::ALL {
            anyhow::ensure!(
                declared.contains(&p),
                "权限 {p:?}(代码 Perm 闭集)未在 seed.toml [[permissions]] 声明"
            );
        }
        anyhow::ensure!(
            self.permissions.len() == Perm::ALL.len(),
            "seed.toml [[permissions]] 条数 {} ≠ Perm 闭集 {}(有多余/重复声明)",
            self.permissions.len(),
            Perm::ALL.len()
        );
        for ps in &self.permissions {
            tracing::debug!(key = ?ps.key, description = %ps.description, "权限词表条目");
        }
        Ok(())
    }

    /// 权限词表(key, description)—— 供 `policy_repo::seed_authz` upsert 进 `permissions` 表。
    pub fn permission_catalog(&self) -> impl Iterator<Item = (Perm, &str)> {
        self.permissions
            .iter()
            .map(|p| (p.key, p.description.as_str()))
    }

    /// role→权限**原始**映射(implies 未展开,展开在 `Policy::from_roles`)——
    /// 供 `policy_repo::seed_authz` upsert 进 `role_permissions` 表。
    pub fn role_permission_mappings(&self) -> impl Iterator<Item = (&str, &[Perm])> {
        self.roles
            .iter()
            .map(|r| (r.name.as_str(), r.permissions.as_slice()))
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
    // 1. 角色(幂等 upsert),记 name -> id 供账号授予引用。
    let mut role_ids: HashMap<String, uuid::Uuid> = HashMap::new();
    for r in &data.roles {
        let id = roles
            .upsert(&r.name, &r.display_name, by.clone())
            .await
            .with_context(|| format!("seed role {} 失败", r.name))?;
        role_ids.insert(r.name.clone(), id);
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
                .get(role_name)
                .copied()
                .with_context(|| format!("账号 {username} 引用了未声明的角色 {role_name}"))?;
            roles.grant(user.id, role_id, by.clone()).await?;
        }
    }

    tracing::info!(
        roles = data.roles.len(),
        accounts = data.accounts.len(),
        "idm seed 已应用(幂等)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 嵌入的 seed.toml 权限词表必须与代码 `Perm` 闭集严格对齐(加 `Perm` 变体忘了在 seed 声明 → 这里挂)。
    #[test]
    fn embedded_seed_permission_catalog_matches_enum() {
        SeedData::load(None)
            .unwrap()
            .assert_permission_catalog()
            .unwrap();
    }

    /// `["*"]` 载入期展开成 Perm 闭集全量 —— 加新 Perm 变体,通配角色自动持有(无需改 seed)。
    #[test]
    fn wildcard_expands_to_full_perm_closure() {
        let data: SeedData = toml::from_str(
            r#"
            [[roles]]
            name = "root"
            display_name = "R"
            permissions = ["*"]
            "#,
        )
        .unwrap();
        let policy = data.policy();
        let perms = policy.perms_for(&["root".to_owned()]);
        for p in Perm::ALL {
            assert!(perms.contains(&p), "{p:?} 应随通配自动持有");
        }
    }

    /// `"*"` 与显式权限混用 = 含混配置 → 解析期拒绝(fail-fast)。
    #[test]
    fn wildcard_mixed_with_explicit_is_rejected() {
        let err = toml::from_str::<SeedData>(
            r#"
            [[roles]]
            name = "root"
            display_name = "R"
            permissions = ["*", "widgets:read"]
            "#,
        )
        .err()
        .expect("混用应解析失败");
        assert!(err.to_string().contains("混用"), "{err}");
    }

    /// 未知权限串:两个 untagged 分支都不中 → 解析失败(fail-fast 没被通配支持削弱)。
    #[test]
    fn unknown_perm_string_still_fails_fast() {
        assert!(toml::from_str::<SeedData>(
            r#"
            [[roles]]
            name = "root"
            display_name = "R"
            permissions = ["widgets:frobnicate"]
            "#,
        )
        .is_err());
    }
}

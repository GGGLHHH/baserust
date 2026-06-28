//! seed:初始化 idm 默认数据 —— 读 `seed.toml`,经 idm 的 repo(业务代码)幂等创建。
//!
//! **幂等**:已存在则跳过/取用,可重复跑。连 idm schema(idm role,`IDM_DATABASE_URL`);
//! 先 `just migrate-idm` 建表。数据归 toml、不写进迁移(迁移只管结构)。
//! 审计主体 = `Actor::System` → created_by/granted_by 落 "system"(audit.rs 承诺 seeder 用 system)。

use std::collections::HashMap;

use anyhow::Context;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use xchangeai::features::idm::{
    Argon2Hasher, PgRoleRepo, PgUserRepo, PwHasher, RoleRepo, UserRepo,
};
use xchangeai::infra::audit::AuditContext;

#[derive(Deserialize)]
struct SeedData {
    #[serde(default)]
    roles: Vec<RoleSeed>,
    #[serde(default)]
    accounts: Vec<AccountSeed>,
}

#[derive(Deserialize)]
struct RoleSeed {
    name: String,
    display_name: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("IDM_DATABASE_URL")
        .context("需设 IDM_DATABASE_URL(指向 idm schema,idm role 连接)")?;
    let path = std::env::var("SEED_FILE").unwrap_or_else(|_| "seed.toml".to_owned());
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("读 seed 文件 {path} 失败"))?;
    let data: SeedData = toml::from_str(&content).with_context(|| format!("解析 {path} 失败"))?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("连接 idm 数据库失败")?;
    let user_repo = PgUserRepo::new(pool.clone());
    let role_repo = PgRoleRepo::new(pool);
    let hasher = Argon2Hasher;
    let by = AuditContext::system().audit_id(); // Some("system")

    // 1. 角色(幂等 upsert),记下 name -> id 供账号授予引用。
    let mut role_ids: HashMap<String, uuid::Uuid> = HashMap::new();
    for r in &data.roles {
        let id = role_repo
            .upsert(&r.name, &r.display_name, by.clone())
            .await
            .with_context(|| format!("seed role {} 失败", r.name))?;
        role_ids.insert(r.name.clone(), id);
        println!("  role:    {} ({})", r.name, r.display_name);
    }

    // 2. 账号(幂等:已存在则取,否则建 user + password)+ 授予角色(幂等)。
    for a in &data.accounts {
        let username = a.username.trim().to_lowercase();
        let email = a.email.as_deref().map(|e| e.trim().to_lowercase());
        let user = match user_repo.find_by_identifier(&username).await? {
            Some(uwh) => uwh.user,
            None => {
                let hash = hasher
                    .hash(&a.password)
                    .map_err(|e| anyhow::anyhow!("argon2 hash 失败: {e:?}"))?;
                user_repo
                    .create(&username, email.as_deref(), &hash, by.clone())
                    .await
                    .with_context(|| format!("seed account {username} 失败"))?
            }
        };
        for role_name in &a.roles {
            let role_id = role_ids.get(role_name).copied().with_context(|| {
                format!("账号 {username} 引用了未在 [[roles]] 声明的角色 {role_name}")
            })?;
            role_repo.grant(user.id, role_id, by.clone()).await?;
        }
        println!("  account: {username}  roles={:?}", a.roles);
    }

    println!(
        "✅ seed 完成({} roles, {} accounts)",
        data.roles.len(),
        data.accounts.len()
    );
    Ok(())
}

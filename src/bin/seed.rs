//! seed CLI:显式把默认数据写进 PG。幂等核心在 `xchangeai::app::{seed, policy_repo}`,**与进程内启动 seed 共用**。
//!
//! 平时 dev 不用它 —— 进程内 seed(非 prod 默认开)已够。此 CLI 留给 **prod 受控 seed**:
//! - **idm schema**(`IDM_DATABASE_URL`):users/roles/accounts(先 `just migrate-idm`)。
//! - **app schema**(`APP_DATABASE_URL`,可选):authz 表 permissions/role_permissions(先 `just migrate-app`)。
//!
//! 数据见 `seed.toml`(`SEED_FILE` 可覆盖)。`just seed` 即调它。

use anyhow::Context;
use idm::{Argon2Hasher, PgRoleRepo, PgUserRepo};
use sqlx::postgres::PgPoolOptions;
use xchangeai::app::policy_repo;
use xchangeai::app::seed::{apply, SeedData};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init(); // 让 apply 的 info!(应用了几条)可见
    let data = SeedData::load()?;
    data.assert_permission_catalog()?; // 词表 == Perm 闭集,先校验再写

    // idm schema:users/roles/accounts。
    let idm_url = std::env::var("IDM_DATABASE_URL")
        .context("需设 IDM_DATABASE_URL(指向 idm schema,idm role 连接)")?;
    let idm_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&idm_url)
        .await
        .context("连接 idm 数据库失败")?;
    apply(
        &PgUserRepo::new(idm_pool.clone()),
        &PgRoleRepo::new(idm_pool),
        &Argon2Hasher,
        &data,
        Some("system".to_owned()),
    )
    .await?;

    // app schema(可选):authz 表 permissions + role_permissions。设了 APP_DATABASE_URL 才 seed。
    if let Ok(app_url) = std::env::var("APP_DATABASE_URL") {
        let app_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&app_url)
            .await
            .context("连接 app 数据库失败")?;
        policy_repo::seed_authz(&app_pool, &data).await?;
    }

    println!("✅ seed 完成");
    Ok(())
}

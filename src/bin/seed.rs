//! seed CLI:显式把 idm 默认数据写进 PG。幂等核心在 `xchangeai::app::seed`,**与进程内启动 seed 共用**。
//!
//! 平时 dev 不用它 —— 进程内 seed(非 prod 默认开)已够。此 CLI 留给 **prod 受控 seed**:
//! 连 idm schema(idm role,`IDM_DATABASE_URL`),先 `just migrate-idm` 建表。数据见 `seed.toml`
//! (`SEED_FILE` 可覆盖)。`just seed` 即调它。

use anyhow::Context;
use idm::{Argon2Hasher, PgRoleRepo, PgUserRepo};
use sqlx::postgres::PgPoolOptions;
use xchangeai::app::seed::{apply, SeedData};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init(); // 让 apply 的 info!(应用了几条)可见

    let url = std::env::var("IDM_DATABASE_URL")
        .context("需设 IDM_DATABASE_URL(指向 idm schema,idm role 连接)")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("连接 idm 数据库失败")?;
    let users = PgUserRepo::new(pool.clone());
    let roles = PgRoleRepo::new(pool);

    let data = SeedData::load()?;
    apply(
        &users,
        &roles,
        &Argon2Hasher,
        &data,
        Some("system".to_owned()),
    )
    .await?;
    println!("✅ seed 完成");
    Ok(())
}

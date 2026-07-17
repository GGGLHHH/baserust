//! seed CLI:显式把默认数据写进 PG。幂等核心在 `baserust::app::{seed, policy_repo}`,**与进程内启动 seed 共用**。
//!
//! 平时 dev 不用它 —— 进程内 seed(非 prod 默认开)已够。此 CLI 留给 **prod 受控 seed**:
//! - **idm schema**(`IDM_DB_HOST` 等,与 app 进程同一套 Config 字段):users/roles/accounts(先 `just migrate-idm`)。
//! - **app schema**(`APP_DB_HOST`,可选):authz 表 permissions/role_permissions + 账号的初始 profile
//!   (先 `just migrate-app`)。
//!
//! 数据见 `seed.toml`(`SEED_FILE` 可覆盖)。`just seed` 即调它。配置全经 `Config`(.env + 环境变量)。

use anyhow::Context;
use baserust::app::policy_repo;
use baserust::app::seed::{apply, apply_profiles, SeedData};
use baserust::features::profile::PgProfileRepo;
use baserust::features::tenants::PgTenantRepo;
use baserust::infra::config::Config;
use idm::{Argon2Hasher, PgRoleRepo, PgUserRepo};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::from_path(".env"); // 与 app 进程同源:.env + 环境变量,读取/默认全在 Config
    let config = Config::load()?;
    // 日志过滤也走 Config(不用 fmt::init() 直读 RUST_LOG)—— env 读取全收口在 Config。
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(config.log_filter()))
        .init();
    let data = SeedData::load(config.seed_file.as_deref())?; // seed 只含账号;角色/权限是代码闭集

    // idm schema:users/roles/accounts。
    let idm_url = config
        .idm_database_url()
        .context("需设 IDM_DB_HOST(idm role 连 idm schema)")?;
    let idm_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&idm_url)
        .await
        .context("连接 idm 数据库失败")?;
    apply(
        &PgUserRepo::new(idm_pool.clone()),
        &PgRoleRepo::new(idm_pool.clone()),
        &PgTenantRepo::new(idm_pool.clone()),
        &Argon2Hasher,
        &data,
        Some("system".to_owned()),
    )
    .await?;

    // app schema(可选):authz 表 permissions + role_permissions,以及账号的初始 profile。
    // 设了 APP_DB_HOST 才 seed。
    if let Some(app_url) = config.app_database_url() {
        let app_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&app_url)
            .await
            .context("连接 app 数据库失败")?;
        policy_repo::seed_authz(&app_pool, &data).await?;
        // 初始 profile:username 经 idm 解析成 user_id(标识引用),数据写 app —— 两个 pool 各连各的
        // schema,不跨 schema join。已有资料的账号跳过(不把用户改过的资料按回 seed 值)。
        apply_profiles(
            &PgProfileRepo::new(app_pool),
            &PgUserRepo::new(idm_pool),
            &data,
            Some("system".to_owned()),
        )
        .await?;
    }

    println!("✅ seed 完成");
    Ok(())
}

//! 重建/回填 CLI:从 idm + profile 的**当前状态**(非事件流)全量灌注 `admin_user_index`。
//! 两个场景:bootstrap(早于事件投影接线就存在的用户)、漂移恢复(projector 挂了/丢消息后拉回一致)。
//!
//! 核心逻辑在 `baserust::features::search::rebuild`(零 DB 单测覆盖);本文件只做装配:连三个
//! schema 的 pool、读各自 outbox 的快照水位、建 PG 仓储、调 `rebuild`、打印结果。
//! **前提是配好**——idm/app/search 的 `*_DB_HOST` 都须设(rebuild 天然需要三个真实源),缺一即报错退出。

use anyhow::Context;
use baserust::app::adapters::ProfileDisplayNames;
use baserust::app::state::{connect_for_schema, Schema};
use baserust::features::profile::PgProfileRepo;
use baserust::features::search::{rebuild, PgSearchIndexRepo};
use baserust::infra::config::Config;
use idm::PgUserRepo;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::from_path(".env"); // 与 app/seed 同源:.env + 环境变量,读取/默认全在 Config
    let config = Config::load()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(config.log_filter()))
        .init();

    let idm_pool = connect_for_schema(&config, Schema::Idm)
        .await?
        .context("需设 IDM_DB_HOST(重建读 idm.users 全量)")?;
    let app_pool = connect_for_schema(&config, Schema::App)
        .await?
        .context("需设 APP_DB_HOST(重建读 app.profiles 全量)")?;
    let search_pool = connect_for_schema(&config, Schema::Search)
        .await?
        .context("需设 SEARCH_DB_HOST(重建写 admin_user_index)")?;

    // 快照水位:**先读 P、再读数据**(P 是回填时刻各 outbox 的 max id,下界;之后 id>P 的新事件
    // 才会再覆写投影行,旧重投被 projector 的守卫挡住)。search_path 令 `outbox` 落各自 schema。
    let p_idm: i64 = sqlx::query_scalar("select coalesce(max(id), 0) from outbox")
        .fetch_one(&idm_pool)
        .await
        .context("读 idm outbox 水位失败")?;
    let p_app: i64 = sqlx::query_scalar("select coalesce(max(id), 0) from outbox")
        .fetch_one(&app_pool)
        .await
        .context("读 app outbox 水位失败")?;

    let users = PgUserRepo::new(idm_pool);
    let profiles = ProfileDisplayNames::new(std::sync::Arc::new(PgProfileRepo::new(app_pool)));
    let index = PgSearchIndexRepo::new(search_pool);

    let count = rebuild(&users, &profiles, &index, p_idm, p_app).await?;
    println!("✅ rebuild_search 完成:回填 {count} 条(idm_seq={p_idm}, profile_seq={p_app})");
    Ok(())
}

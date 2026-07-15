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

    // 快照水位:**先读 P、再读数据**(P 是回填时刻各 outbox 的水位,**下界**;之后 id>P 的新事件
    // 才会再覆写投影行,旧重投被 projector 的守卫挡住)。search_path 令 `outbox` 落各自 schema。
    let p_idm = read_outbox_watermark(&idm_pool, "idm").await?;
    let p_app = read_outbox_watermark(&app_pool, "app").await?;

    let users = PgUserRepo::new(idm_pool);
    let profiles = ProfileDisplayNames::new(std::sync::Arc::new(PgProfileRepo::new(app_pool)));
    let index = PgSearchIndexRepo::new(search_pool);

    let count = rebuild(&users, &profiles, &index, p_idm, p_app).await?;
    println!("✅ rebuild_search 完成:回填 {count} 条(idm_seq={p_idm}, profile_seq={p_app})");
    Ok(())
}

/// 读某 schema 的 outbox 水位 P,并保证 **P 真的是下界**:≤P 的 id 全部已提交,此后新分配的 id 必 >P。
///
/// 裸 `select max(id)` 给不了这个保证:`outbox.id` 是 `bigserial`,INSERT 时由 nextval 取号、
/// **提交时才可见**。于是比 max(id) 小的 id 完全可能仍在未提交事务里、晚于本次读才落地 ——
/// 而写方确实这么干(`PgProfileRepo::upsert` 在同一个事务里做业务 upsert + `emit_outbox`)。
///
/// 那种情况下会**永久丢事件**:Tx-A 取号 50 未提交,Tx-B 取号 51 提交,rebuild 读到 P=51;
/// 回填时读 profile 又看不见 Tx-A 未提交的新值 → 写进旧值 + `profile_seq=51`;随后 Tx-A 提交、
/// relay 发出 seq=50 的真事件,projector 的 `seq > profile_seq` 守卫把它丢弃 —— 投影永远停在旧值,
/// 且再跑一次 rebuild 也修不回(除非那个用户又有新事件)。
///
/// `lock table ... in exclusive mode` 与 INSERT 持的 ROW EXCLUSIVE 冲突:拿到锁 = 在途插入全部落定、
/// 新插入被挡在门外,此刻的 max(id) 才是真下界。锁只**持**到这条主键聚合查询结束(很快)。
///
/// 但危险的是**等**锁那半:写方在整个业务事务期间都握着 `outbox` 的 ROW EXCLUSIVE(锁到事务结束,
/// 不只是 INSERT 那一瞬),只要有一个慢事务/idle-in-transaction,这个 EXCLUSIVE 请求就得排队;
/// 而 PG 的锁队列是 **FIFO** —— 排队期间**新来的 INSERT 也得排在它后面**,哪怕彼此本不冲突。
/// 即:不设超时的话,本 CLI 会把该 schema 的写入整体拖停(emit_outbox 在每条业务写的事务里)。
/// 故 `set local lock_timeout`:等不到就**快速失败**退出,让运维等阻塞事务散了再重跑,
/// 而不是把生产写入拽下水。`set local` = 只作用本事务,提交即还原。
async fn read_outbox_watermark(pool: &sqlx::PgPool, what: &str) -> anyhow::Result<i64> {
    let mut tx = pool
        .begin()
        .await
        .with_context(|| format!("开启 {what} 水位事务失败"))?;
    sqlx::query("set local lock_timeout = '5s'")
        .execute(&mut *tx)
        .await
        .with_context(|| format!("设 {what} lock_timeout 失败"))?;
    sqlx::query("lock table outbox in exclusive mode")
        .execute(&mut *tx)
        .await
        .with_context(|| {
            format!(
                "锁 {what} outbox 失败(需 UPDATE 权限;或 5s 内没等到锁 —— \
                 有长事务占着 outbox,散了再重跑,别让本次重建拖停写入)"
            )
        })?;
    let p: i64 = sqlx::query_scalar("select coalesce(max(id), 0) from outbox")
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("读 {what} outbox 水位失败"))?;
    tx.commit()
        .await
        .with_context(|| format!("提交 {what} 水位事务失败"))?;
    Ok(p)
}

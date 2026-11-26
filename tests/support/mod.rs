//! conformance 测试的 PG 侧辅助:在 #[sqlx::test] 给的干净临时库里复刻 prod 的建库。
//! (放 tests/support/ 子目录 → 不是独立 test target,由各 conformance `#[path]` 引入。)
//! idm 的 conformance + bootstrap 已随 idm crate 迁出(见 crates/idm/tests),此处只剩 app 侧。
//!
//! 账号拆分(spec §4.4)之后的形状:`#[sqlx::test]` 用 `DATABASE_URL` = **app_owner** 建临时库、跑迁移
//! ([`bootstrap_app_schema`]);仓储用**运行时账号**(`APP_DB_USER`,非 owner、NOBYPASSRLS、只有 DML)
//! 连同一个临时库([`runtime_pool`])—— 和生产一样,RLS 对它真的生效。

use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, Executor, PgPool};

/// 编译期内嵌 migrations/app(相对 CARGO_MANIFEST_DIR)。唯一迁移真源,不复制 SQL。
static APP_MIGRATOR: Migrator = sqlx::migrate!("migrations/app");

/// 把 sqlx::test 的空临时库还原成 prod 形态:建 app schema + 跑 migrations/app(以 owner 账号)。
/// 无 schema 前缀的 SQL 靠连接 role 的 search_path=app 落位(10-tenancy-roles.sh `alter role app_owner set search_path`)。
pub async fn bootstrap_app_schema(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("create schema if not exists app")
        .execute(pool)
        .await?;
    APP_MIGRATOR.run(pool).await?;
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// 给运行时账号授临时库里 app schema 的 USAGE + 全部表 DML + 序列,再以它连同一个临时库。
///
/// 生产库靠 `ALTER DEFAULT PRIVILEGES` 自动授权,但默认权限是**按库**存的,临时库里没有 ——
/// 所以迁移之后照 10-tenancy-roles.sh 第 4 步显式授一遍。账号是集群级的(运行时账号由建库脚本建好)。
/// 用完 `close().await`,免得 sqlx 删临时库时还有连接挂着。
pub async fn runtime_pool(owner: &PgPool) -> anyhow::Result<PgPool> {
    let user = env_or("APP_DB_USER", "app");
    let password = env_or("APP_DB_PASSWORD", "pwd");
    let ident = format!("\"{}\"", user.replace('"', "\"\""));
    owner
        .execute(AssertSqlSafe(format!(
            "grant usage on schema app to {ident};
             grant select, insert, update, delete on all tables in schema app to {ident};
             grant usage, select on all sequences in schema app to {ident};"
        )))
        .await?;
    let opts = owner
        .connect_options()
        .as_ref()
        .clone()
        .username(&user)
        .password(&password);
    let rt = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    // 防呆:连上的必须是非 owner、不能绕过 RLS 的账号,否则这套 conformance 测的不是生产形状。
    let (is_owner, bypass): (bool, bool) = sqlx::query_as(
        "select exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
                         where n.nspname = 'app' and c.relowner = (select oid from pg_roles where rolname = current_user)),
                (select rolbypassrls or rolsuper from pg_roles where rolname = current_user)",
    )
    .fetch_one(&rt)
    .await?;
    anyhow::ensure!(
        !is_owner && !bypass,
        "运行时账号 {user} 不该拥有表 / 绕过 RLS(owner={is_owner} bypass={bypass})"
    );
    Ok(rt)
}

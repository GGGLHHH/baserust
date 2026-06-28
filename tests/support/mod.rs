//! conformance 测试的 PG 侧辅助:在 #[sqlx::test] 给的干净临时库里复刻 prod 的两步建库。
//! (放 tests/support/ 子目录 → 不是独立 test target,由 conformance 测试 `#[path]` 引入。)

use sqlx::migrate::Migrator;
use sqlx::PgPool;

/// 编译期内嵌 migrations/app(相对 CARGO_MANIFEST_DIR)。唯一迁移真源,不复制 SQL。
static APP_MIGRATOR: Migrator = sqlx::migrate!("migrations/app");

/// 把 sqlx::test 的空临时库还原成 prod 形态:
///   ① initdb 等价:建 app schema(prod 由 scripts/initdb 一次建,临时库每次现建)
///   ② just migrate-app 等价:跑 migrations/app(无 schema 前缀的 SQL 靠连接的 search_path=app 落位)
///
/// 前提:连接 role 的 search_path=app —— 路径 A 用 app role(initdb 已 `alter role app set search_path`),
/// 临时库继承该 role 级配置,故建表/查表都落在 app schema。
pub async fn bootstrap_app_schema(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("create schema if not exists app")
        .execute(pool)
        .await?;
    APP_MIGRATOR.run(pool).await?;
    Ok(())
}

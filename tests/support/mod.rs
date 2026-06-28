//! conformance 测试的 PG 侧辅助:在 #[sqlx::test] 给的干净临时库里复刻 prod 的建库。
//! (放 tests/support/ 子目录 → 不是独立 test target,由 widget conformance `#[path]` 引入。)
//! idm 的 conformance + bootstrap 已随 idm crate 迁出(见 crates/idm/tests),此处只剩 app 侧。

use sqlx::migrate::Migrator;
use sqlx::PgPool;

/// 编译期内嵌 migrations/app(相对 CARGO_MANIFEST_DIR)。唯一迁移真源,不复制 SQL。
static APP_MIGRATOR: Migrator = sqlx::migrate!("migrations/app");

/// 把 sqlx::test 的空临时库还原成 prod 形态:建 app schema + 跑 migrations/app。
/// 无 schema 前缀的 SQL 靠连接 role 的 search_path=app 落位(initdb 已 `alter role app set search_path`)。
pub async fn bootstrap_app_schema(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("create schema if not exists app")
        .execute(pool)
        .await?;
    APP_MIGRATOR.run(pool).await?;
    Ok(())
}

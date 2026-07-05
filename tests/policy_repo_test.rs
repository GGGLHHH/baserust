//! authz 持久化 PG 测试:`seed_authz` 写 → `load_policy` 读回,与 seed.toml 的内存 `Policy` 一致 + 幂等。
//! 仅 `--features pg-conformance`(需 DATABASE_URL 连 app role + 跑着的 pg),用 `just test-pg`。
//! 无 feature 时整文件 cfg 掉 → 0 测试(默认 `cargo test` 零 DB 不受影响)。
#![cfg(feature = "pg-conformance")]

// support 与 widget conformance 共用(各 test target 独立编译,各自 `#[path]` 引入不冲突)。
#[path = "support/mod.rs"]
mod support;

use baserust::app::policy_repo;
use baserust::app::seed::SeedData;
use baserust::infra::authz::Perm;

#[sqlx::test(migrations = false)]
async fn seed_authz_then_load_policy_roundtrips(pool: sqlx::PgPool) -> sqlx::Result<()> {
    support::bootstrap_app_schema(&pool)
        .await
        .expect("bootstrap app schema + 跑 migrations/app(含 0002 authz 表)");

    let seed = SeedData::load(None).unwrap();
    policy_repo::seed_authz(&pool, &seed).await.unwrap();
    policy_repo::seed_authz(&pool, &seed).await.unwrap(); // 二次:幂等,不报错/不重复(PK 冲突 DO NOTHING)

    let policy = policy_repo::load_policy(&pool).await.unwrap();

    // DB 读回的 Policy 与 seed.toml 内存路径一致:superadmin 全权 + implies 展开。
    let su = policy.perms_for(&["superadmin".to_owned()]);
    assert!(su.contains(&Perm::WidgetReadAll));
    assert!(su.contains(&Perm::WidgetRead)); // read:all ⇒ read(from_roles 展开)
    assert!(su.contains(&Perm::UsersAdmin));

    // user 只 read、无写/越权读。
    let u = policy.perms_for(&["user".to_owned()]);
    assert!(u.contains(&Perm::WidgetRead));
    assert!(!u.contains(&Perm::WidgetWrite));
    assert!(!u.contains(&Perm::WidgetReadAll));
    Ok(())
}

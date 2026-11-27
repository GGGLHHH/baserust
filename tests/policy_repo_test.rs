//! authz 持久化 PG 测试:`seed_authorization` 写 → `load_policy` 读回,与 seed.toml 的内存 `Policy` 一致 + 幂等。
//! 仅 `--features pg-conformance`(DATABASE_URL 连 app_owner 建库迁移、读写走运行时账号 app + 跑着的 pg),用 `just test-pg`。
//! 无 feature 时整文件 cfg 掉 → 0 测试(默认 `cargo test` 零 DB 不受影响)。
#![cfg(feature = "pg-conformance")]

// support 与 widget conformance 共用(各 test target 独立编译,各自 `#[path]` 引入不冲突)。
#[path = "support/mod.rs"]
mod support;

use baserust::app::policy_repo;
use baserust::app::seed::SeedData;
use baserust::kernel::authorization::{Permission, RoleNames};
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn seed_authorization_then_load_policy_roundtrips(pool: PgPool) -> sqlx::Result<()> {
    support::bootstrap_app_schema(&pool)
        .await
        .expect("bootstrap app schema + 跑 migrations/app(含 0002 authz 表)");

    // 启动期 seed_authorization / load_policy 在生产里跑在运行时账号上(只有 DML):这里同样。
    let runtime_pool = support::runtime_pool(&pool)
        .await
        .expect("运行时账号连临时库");
    let seed = SeedData::try_new(None).unwrap();
    policy_repo::seed_authorization(&runtime_pool, &seed)
        .await
        .unwrap();
    policy_repo::seed_authorization(&runtime_pool, &seed)
        .await
        .unwrap(); // 二次:幂等,不报错/不重复(PK 冲突 DO NOTHING)

    let policy = policy_repo::load_policy(&runtime_pool).await.unwrap();
    runtime_pool.close().await;

    // DB 读回的 Policy 与 seed.toml 内存路径一致:superadmin(平台角色)全部平台级权限;
    // admin(租户角色)越权读 + implies 展开 + 后台准入。
    let superadmin_permissions = policy.permissions_for(RoleNames {
        platform: &["superadmin".to_owned()],
        tenant: &[],
    });
    assert!(superadmin_permissions.contains(&Permission::UsersAdmin));
    assert!(superadmin_permissions.contains(&Permission::TenantsAdmin));
    assert!(
        !superadmin_permissions.contains(&Permission::WidgetRead),
        "平台角色不给租户级权限"
    );
    let admin = policy.permissions_for(RoleNames {
        platform: &[],
        tenant: &["admin".to_owned()],
    });
    assert!(admin.contains(&Permission::WidgetReadAll));
    assert!(admin.contains(&Permission::WidgetRead)); // read:all ⇒ read(from_roles 展开)
    assert!(admin.contains(&Permission::AdminLogin));
    assert!(!admin.contains(&Permission::UsersAdmin));

    // user 只 read、无写/越权读。
    let user_permissions = policy.permissions_for(RoleNames {
        platform: &[],
        tenant: &["user".to_owned()],
    });
    assert!(user_permissions.contains(&Permission::WidgetRead));
    assert!(!user_permissions.contains(&Permission::WidgetWrite));
    assert!(!user_permissions.contains(&Permission::WidgetReadAll));
    Ok(())
}

/// 存量部署升级(2026-11-26 角色补充):旧库里 role_permissions 没有新权限(ops:read / audit:read / platform:roles)
/// 也没有 platform_admin 的行 —— 重启时 `seed_authorization`(ON CONFLICT DO NOTHING)按代码默认补上,无需迁移:
/// superadmin 拿到三项独占权限,platform_admin 拿到「平台级减独占」那一份。
#[sqlx::test(migrations = false)]
async fn reseed_adds_new_perms_and_platform_admin_to_existing_store(
    pool: PgPool,
) -> sqlx::Result<()> {
    support::bootstrap_app_schema(&pool)
        .await
        .expect("bootstrap app schema + 跑 migrations/app");
    let runtime_pool = support::runtime_pool(&pool)
        .await
        .expect("运行时账号连临时库");
    let seed = SeedData::try_new(None).unwrap();
    policy_repo::seed_authorization(&runtime_pool, &seed)
        .await
        .unwrap();
    // 模拟升级前的库:去掉新权限的映射和 platform_admin 的全部行
    sqlx::query(
        "DELETE FROM role_permissions
         WHERE role_name = 'platform_admin'
            OR permission IN ('ops:read', 'audit:read', 'platform:roles')",
    )
    .execute(&runtime_pool)
    .await?;
    let before = policy_repo::load_policy(&runtime_pool).await.unwrap();
    assert!(!before
        .permissions_for(RoleNames {
            platform: &["superadmin".to_owned()],
            tenant: &[],
        })
        .contains(&Permission::OpsRead));

    policy_repo::seed_authorization(&runtime_pool, &seed)
        .await
        .unwrap(); // 升级后重启
    let policy = policy_repo::load_policy(&runtime_pool).await.unwrap();
    runtime_pool.close().await;

    let superadmin_permissions = policy.permissions_for(RoleNames {
        platform: &["superadmin".to_owned()],
        tenant: &[],
    });
    for permission in [
        Permission::OpsRead,
        Permission::AuditRead,
        Permission::PlatformRoles,
        Permission::UsersAdmin,
    ] {
        assert!(
            superadmin_permissions.contains(&permission),
            "superadmin 应有 {permission:?}"
        );
    }
    let platform_admin_permissions = policy.permissions_for(RoleNames {
        platform: &["platform_admin".to_owned()],
        tenant: &[],
    });
    for permission in [
        Permission::UsersAdmin,
        Permission::TenantsAdmin,
        Permission::ProfileWriteAll,
    ] {
        assert!(
            platform_admin_permissions.contains(&permission),
            "platform_admin 应有 {permission:?}"
        );
    }
    for permission in [
        Permission::OpsRead,
        Permission::AuditRead,
        Permission::PlatformRoles,
    ] {
        assert!(
            !platform_admin_permissions.contains(&permission),
            "platform_admin 不该有 {permission:?}"
        );
    }
    Ok(())
}

/// 迁移 app/0007:删掉闭集内角色的**跨作用域**存量行(旧版 seed 给 superadmin 的租户级权限、给 admin 的平台级权限),
/// 同作用域的行和闭集外角色的行不动。迁移在 bootstrap 时已跑过一次(空表),这里先造旧数据再按迁移原文重跑一遍。
#[sqlx::test(migrations = false)]
async fn cleanup_migration_deletes_legacy_cross_scope_rows(pool: PgPool) -> sqlx::Result<()> {
    support::bootstrap_app_schema(&pool)
        .await
        .expect("bootstrap app schema + 跑 migrations/app");
    let runtime_pool = support::runtime_pool(&pool)
        .await
        .expect("运行时账号连临时库");
    policy_repo::seed_authorization(&runtime_pool, &SeedData::try_new(None).unwrap())
        .await
        .unwrap();
    let legacy = [
        ("superadmin", "widgets:read"),
        ("superadmin", "admin:login"),
        ("admin", "users:admin"),
        ("admin", "profiles:write:all"),
        ("user", "profiles:read"),
    ];
    let kept = [
        ("superadmin", "users:admin"),
        ("admin", "widgets:read"),
        ("admin", "members:admin"),
        ("user", "widgets:read"),
        ("editor", "users:admin"), // 闭集外角色:作用域未知,不动
    ];
    let all_grants = legacy.iter().chain(kept.iter());
    for (role, permission) in all_grants {
        sqlx::query(
            "INSERT INTO role_permissions (role_name, permission, granted_by) VALUES ($1, $2, 'test')
             ON CONFLICT DO NOTHING",
        )
        .bind(role)
        .bind(permission)
        .execute(&runtime_pool)
        .await?;
    }
    sqlx::raw_sql(include_str!(
        "../migrations/app/0007_role_permissions_scope_cleanup.up.sql"
    ))
    .execute(&pool)
    .await?;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT role_name, permission FROM role_permissions")
            .fetch_all(&runtime_pool)
            .await?;
    runtime_pool.close().await;
    let has = |role: &str, permission: &str| {
        rows.iter()
            .any(|(row_role, row_permission)| row_role == role && row_permission == permission)
    };
    for (role, permission) in legacy {
        assert!(
            !has(role, permission),
            "跨作用域行 {role} → {permission} 应被删"
        );
    }
    for (role, permission) in kept {
        assert!(has(role, permission), "{role} → {permission} 不该被删");
    }
    Ok(())
}

/// 库里手工改出 / 旧版 seed 留下的**跨作用域**行(superadmin → widgets:read、admin → users:admin)
/// 启动载入时 WARN 并忽略(spec §6.1):平台角色拿不到租户级权限,租户角色拿不到平台级权限。
#[sqlx::test(migrations = false)]
async fn cross_scope_rows_are_ignored_on_load(pool: PgPool) -> sqlx::Result<()> {
    support::bootstrap_app_schema(&pool)
        .await
        .expect("bootstrap app schema + 跑 migrations/app(含 0002 authz 表)");
    let runtime_pool = support::runtime_pool(&pool)
        .await
        .expect("运行时账号连临时库");
    policy_repo::seed_authorization(&runtime_pool, &SeedData::try_new(None).unwrap())
        .await
        .unwrap();
    for (role, permission) in [("superadmin", "widgets:read"), ("admin", "users:admin")] {
        sqlx::query(
            "INSERT INTO role_permissions (role_name, permission, granted_by) VALUES ($1, $2, 'test')
             ON CONFLICT DO NOTHING",
        )
        .bind(role)
        .bind(permission)
        .execute(&runtime_pool)
        .await?;
    }
    let policy = policy_repo::load_policy(&runtime_pool).await.unwrap();
    runtime_pool.close().await;

    // 当成哪一类角色用都拿不到跨作用域的那一行
    for (platform, tenant) in [
        (vec!["superadmin".to_owned()], vec![]),
        (vec![], vec!["superadmin".to_owned()]),
    ] {
        assert!(!policy
            .permissions_for(RoleNames {
                platform: &platform,
                tenant: &tenant,
            })
            .contains(&Permission::WidgetRead));
    }
    for (platform, tenant) in [
        (vec!["admin".to_owned()], vec![]),
        (vec![], vec!["admin".to_owned()]),
    ] {
        assert!(!policy
            .permissions_for(RoleNames {
                platform: &platform,
                tenant: &tenant,
            })
            .contains(&Permission::UsersAdmin));
    }
    Ok(())
}

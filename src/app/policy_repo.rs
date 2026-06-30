//! app 授权策略的 **Postgres 持久化**(`migrations/app/0002`)。设 `APP_DB_HOST` 时 `Policy` 读这两张表
//! (role→权限可运行时改),否则读 seed.toml(内存)—— 同 widget 的可拔插范式。
//!
//! **`Perm` enum 仍是 enforcement 真相**:DB 读出的权限串经 serde 反序列化校验 ∈ 闭集(非法即 fail);
//! wire 串**单一来源 = enum 的 serde `rename`**(不另造 `wire()` 投影,避免第二份真相)。

use std::collections::HashMap;

use anyhow::Context;
use sqlx::PgPool;

use super::seed::SeedData;
use crate::infra::authz::{Perm, Policy};

/// `Perm` → wire 串(经 serde rename;单一来源)。
fn perm_wire(p: Perm) -> String {
    serde_json::to_value(p)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("Perm 必序列化成字符串")
}

/// wire 串 → `Perm`(校验 ∈ 闭集;未知 → Err,启动期暴露)。
fn perm_from_wire(s: &str) -> anyhow::Result<Perm> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .with_context(|| format!("role_permissions 含未知权限串 `{s}`(不在 Perm 闭集)"))
}

/// 幂等把 seed.toml 的权限词表 + role→权限映射写进 app schema 两张表。可重复跑、可并发。
/// 顺序:先 `permissions`(catalog,被 FK 引用方),后 `role_permissions`。
/// **`ON CONFLICT DO NOTHING`**:不覆盖运行期改动 —— 引导默认值,不与 admin 后台的运行时编辑相争。
pub async fn seed_authz(pool: &PgPool, seed: &SeedData) -> anyhow::Result<()> {
    for (perm, description) in seed.permission_catalog() {
        sqlx::query(
            "INSERT INTO permissions (key, description) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description",
        )
        .bind(perm_wire(perm))
        .bind(description)
        .execute(pool)
        .await
        .context("upsert permissions 失败")?;
    }
    for (role_name, perms) in seed.role_permission_mappings() {
        for perm in perms {
            sqlx::query(
                "INSERT INTO role_permissions (role_name, permission, granted_by)
                 VALUES ($1, $2, 'system')
                 ON CONFLICT (role_name, permission) DO NOTHING",
            )
            .bind(role_name)
            .bind(perm_wire(*perm))
            .execute(pool)
            .await
            .context("upsert role_permissions 失败")?;
        }
    }
    tracing::info!("authz 表已 seed(permissions + role_permissions,幂等)");
    Ok(())
}

/// 从 `role_permissions` 表读出 role→权限,建内存 `Policy`(`implies` 由 `from_roles` 展开,同内存路径)。
pub async fn load_policy(pool: &PgPool) -> anyhow::Result<Policy> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT role_name, permission FROM role_permissions")
            .fetch_all(pool)
            .await
            .context("读 role_permissions 失败")?;
    let mut by_role: HashMap<String, Vec<Perm>> = HashMap::new();
    for (role, perm) in rows {
        by_role
            .entry(role)
            .or_default()
            .push(perm_from_wire(&perm)?);
    }
    Ok(Policy::from_roles(by_role))
}

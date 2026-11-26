//! RLS 审计(spec §4.4 / §4.9):打真 PG 的**已迁移库**,查系统目录 `pg_class` / `pg_policies` / `pg_roles`,
//! 钉死多租户隔离的两条底线 ——
//!
//! 1. app / content / search 里**每张表**要么按租户隔离(ENABLE + FORCE ROW LEVEL SECURITY + 至少一条策略),
//!    要么显式列在 [`GLOBAL_TABLES`](全局表白名单)里;两样都不是 → 测试失败。
//!    下游项目同步底座后自己加的表也会被它拦下:加租户隔离,或进白名单(这是有意的提醒)。
//! 2. 运行时账号(`<schema>`)不是任何表的 owner、没有 BYPASSRLS(否则 RLS 对它形同虚设);
//!    `<schema>_owner` 拥有 schema 与表;`<schema>_system` 有 BYPASSRLS(后台任务 / 平台级读)。
//!
//! [`PENDING_TABLES`] 是**过渡清单**:还没改造成租户隔离的业务表。后续任务每改造一张就删一行,
//! 全部改完时必须为空;已经改造好却还挂在清单里的表同样判失败(清单不许虚报)。
//!
//! 仅 `--features pg-conformance`(`just test-pg`)。每个用例先以 owner 账号幂等跑一遍 app / content /
//! search 的迁移(`*_OWNER_DATABASE_URL`,CI 的全新库也能审),再连 `APP_DATABASE_URL`(运行时 app 账号即可:
//! 只读系统目录,不碰业务表)。缺省都回退本地 compose 的账号。
#![cfg(feature = "pg-conformance")]

use std::collections::BTreeSet;

use baserust::app::state::{connect_system_for_schema, Schema};
use baserust::infra::config::Config;
use baserust::infra::pg::tenant_tx;
use baserust::kernel::tenant::TenantId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use uuid::Uuid;

/// 受审计的 schema(= 拆了账号的三个 schema;idm、ops 不拆、不审)。
const SCHEMAS: &[&str] = &["app", "content", "search"];

/// 全局表白名单:不按租户隔离、不开 RLS(spec §4.4)。
/// 资料全局一份(profiles)、权限词表、所有 outbox(payload 里带 tenant_id)、迁移台账;
/// auth_event 平台级、只走 system 池(plan Task 8);account_index 是账号目录投影(账号全局,一个账号一行,
/// 成员索引的账号列从它抄)。这两张 —— **只有 system 账号能写**,运行时账号只读(迁移 search/0003 与 10-tenancy-roles.sh
/// 第 6 步收回运行时账号的 INSERT / UPDATE / DELETE,[`system_only_write_tables`] 守着)。
const GLOBAL_TABLES: &[&str] = &[
    "app._sqlx_migrations",
    "app.outbox",
    "app.permissions",
    "app.profiles",
    "app.role_permissions",
    "content._sqlx_migrations",
    "search._sqlx_migrations",
    "search.account_index",
    "search.auth_event",
];

/// 尚未改造成租户隔离的业务表(过渡清单)。每改造一张删一行;全部完成时必须为空。
const PENDING_TABLES: &[&str] = &[];

/// 某 schema 的三个账号名:运行时 / owner / system。名字跟部署脚本同一套环境变量与缺省
/// (`<SCHEMA>_DB_USER`,owner / system 缺省是它加 `_owner` / `_system` 后缀)。
struct Roles {
    runtime: String,
    owner: String,
    system: String,
}

fn roles_for(schema: &str) -> Roles {
    let up = schema.to_uppercase();
    let env = |k: String| std::env::var(k).ok().filter(|v| !v.is_empty());
    let runtime = env(format!("{up}_DB_USER")).unwrap_or_else(|| schema.to_owned());
    Roles {
        owner: env(format!("{up}_DB_OWNER_USER")).unwrap_or_else(|| format!("{runtime}_owner")),
        system: env(format!("{up}_DB_SYSTEM_USER")).unwrap_or_else(|| format!("{runtime}_system")),
        runtime,
    }
}

fn app_url() -> String {
    std::env::var("APP_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://app:pwd@localhost:5821/baserust?sslmode=disable".into())
}

fn owner_url(schema: &str) -> String {
    let up = schema.to_uppercase();
    std::env::var(format!("{up}_OWNER_DATABASE_URL")).unwrap_or_else(|_| {
        format!("postgres://{schema}_owner:pwd@localhost:5821/baserust?sslmode=disable")
    })
}

/// 以 owner 账号把三个 schema 迁到最新(幂等;sqlx 迁移带 advisory lock,并发用例互不踩)。
async fn migrate_all() {
    let migrators = [
        ("app", sqlx::migrate!("migrations/app")),
        ("content", sqlx::migrate!("migrations/content")),
        ("search", sqlx::migrate!("migrations/search")),
    ];
    for (schema, migrator) in migrators {
        let owner = PgPool::connect(&owner_url(schema))
            .await
            .unwrap_or_else(|e| {
                panic!("连 {schema} 的 owner 账号失败(先 `just up` + `just db-ensure-roles`): {e}")
            });
        migrator
            .run(&owner)
            .await
            .unwrap_or_else(|e| panic!("以 owner 跑 migrations/{schema} 失败: {e}"));
        owner.close().await;
    }
}

async fn connect() -> PgPool {
    migrate_all().await;
    PgPool::connect(&app_url())
        .await
        .expect("连 app 运行时账号失败(先 `just up` + `just db-ensure-roles`)")
}

/// 一张表的 RLS 状态(`schema.table` 全名)。
#[derive(sqlx::FromRow)]
struct TableRls {
    name: String,
    rls: bool,
    force: bool,
    policies: i64,
    owner: String,
}

async fn tables(pool: &PgPool) -> Vec<TableRls> {
    let schemas: Vec<String> = SCHEMAS.iter().map(|s| (*s).to_owned()).collect();
    sqlx::query_as::<_, TableRls>(
        "select n.nspname || '.' || c.relname as name,
                c.relrowsecurity as rls,
                c.relforcerowsecurity as force,
                (select count(*) from pg_policies p
                  where p.schemaname = n.nspname and p.tablename = c.relname) as policies,
                pg_get_userbyid(c.relowner)::text as owner
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('r', 'p') and n.nspname = any($1)
          order by 1",
    )
    .bind(schemas)
    .fetch_all(pool)
    .await
    .expect("查 pg_class")
}

fn isolated(t: &TableRls) -> bool {
    t.rls && t.force && t.policies > 0
}

#[tokio::test]
async fn every_table_is_tenant_isolated_or_whitelisted() {
    let pool = connect().await;
    let all = tables(&pool).await;
    assert!(
        !all.is_empty(),
        "一张表都没查到:库没迁移?(先 `just migrate`)"
    );
    let names: BTreeSet<&str> = all.iter().map(|t| t.name.as_str()).collect();
    let global: BTreeSet<&str> = GLOBAL_TABLES.iter().copied().collect();
    let pending: BTreeSet<&str> = PENDING_TABLES.iter().copied().collect();

    let mut errs = Vec::new();
    for both in global.intersection(&pending) {
        errs.push(format!("{both}:同时在 GLOBAL_TABLES 和 PENDING_TABLES 里"));
    }
    for listed in global.iter().chain(pending.iter()) {
        if !names.contains(listed) {
            errs.push(format!(
                "{listed}:清单里有、库里没有(表改名 / 删了就从清单删掉)"
            ));
        }
    }
    for t in &all {
        let name = t.name.as_str();
        if global.contains(name) {
            continue;
        }
        if pending.contains(name) {
            if isolated(t) {
                errs.push(format!("{name}:已经租户隔离了,从 PENDING_TABLES 删掉"));
            }
            continue;
        }
        if !isolated(t) {
            errs.push(format!(
                "{name}:既没租户隔离(rls={} force={} policies={}),也不在 GLOBAL_TABLES",
                t.rls, t.force, t.policies
            ));
        }
    }
    assert!(errs.is_empty(), "RLS 审计不通过:\n  {}", errs.join("\n  "));
}

/// 账号属性:rolsuper / rolbypassrls。
async fn role_attrs(pool: &PgPool, role: &str) -> Option<(bool, bool)> {
    sqlx::query_as::<_, (bool, bool)>(
        "select rolsuper, rolbypassrls from pg_roles where rolname = $1",
    )
    .bind(role)
    .fetch_optional(pool)
    .await
    .expect("查 pg_roles")
}

/// 该账号在整个库里拥有的表 / 视图 / 序列(`schema.name`)。
async fn owned_relations(pool: &PgPool, role: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "select n.nspname || '.' || c.relname
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('r', 'p', 'v', 'm', 'S', 'f')
            and c.relowner = (select oid from pg_roles where rolname = $1)
          order by 1",
    )
    .bind(role)
    .fetch_all(pool)
    .await
    .expect("查 owner")
}

/// `role` 在 `schema` 里缺哪些业务表的 DML(select/insert/update/delete 任一缺即列出;迁移台账除外)。
async fn missing_dml(pool: &PgPool, role: &str, schema: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "select n.nspname || '.' || c.relname
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('r', 'p') and n.nspname = $2
            and c.relname <> '_sqlx_migrations' -- 迁移台账只许 owner 写,单独断言
            and not (has_table_privilege($1, c.oid, 'select')
                 and has_table_privilege($1, c.oid, 'insert')
                 and has_table_privilege($1, c.oid, 'update')
                 and has_table_privilege($1, c.oid, 'delete'))
          order by 1",
    )
    .bind(role)
    .bind(schema)
    .fetch_all(pool)
    .await
    .expect("查表权限")
    .into_iter()
    // 只许 system 写的表(运行时账号只读)单独断言,见 system_only_write_tables。
    .filter(|name| {
        !SYSTEM_WRITE_ONLY
            .iter()
            .any(|(s, t)| *name == format!("{s}.{t}"))
    })
    .collect()
}

#[tokio::test]
async fn runtime_roles_are_not_owners_and_cannot_bypass_rls() {
    let pool = connect().await;
    let mut errs = Vec::new();
    for schema in SCHEMAS {
        let r = roles_for(schema);
        match role_attrs(&pool, &r.runtime).await {
            None => errs.push(format!("运行时账号 {} 不存在", r.runtime)),
            Some((sup, bypass)) => {
                if sup || bypass {
                    errs.push(format!(
                        "运行时账号 {} 不能是超级用户 / BYPASSRLS(super={sup} bypassrls={bypass})",
                        r.runtime
                    ));
                }
            }
        }
        let owned = owned_relations(&pool, &r.runtime).await;
        if !owned.is_empty() {
            errs.push(format!("运行时账号 {} 不能拥有表:{owned:?}", r.runtime));
        }
        let missing = missing_dml(&pool, &r.runtime, schema).await;
        if !missing.is_empty() {
            errs.push(format!("运行时账号 {} 缺 DML 权限:{missing:?}", r.runtime));
        }
        // 运行时账号不能在自己的 schema 里建表(只有 DML)。
        let can_create: bool = sqlx::query_scalar("select has_schema_privilege($1, $2, 'create')")
            .bind(&r.runtime)
            .bind(*schema)
            .fetch_one(&pool)
            .await
            .expect("查 schema 权限");
        if can_create {
            errs.push(format!(
                "运行时账号 {} 不该有 schema {schema} 的 CREATE",
                r.runtime
            ));
        }
    }
    assert!(
        errs.is_empty(),
        "运行时账号审计不通过:\n  {}",
        errs.join("\n  ")
    );
}

#[tokio::test]
async fn owner_roles_own_schemas_and_tables() {
    let pool = connect().await;
    let mut errs = Vec::new();
    for schema in SCHEMAS {
        let r = roles_for(schema);
        if role_attrs(&pool, &r.owner).await.is_none() {
            errs.push(format!("owner 账号 {} 不存在", r.owner));
            continue;
        }
        let schema_owner: Option<String> = sqlx::query_scalar(
            "select pg_get_userbyid(nspowner)::text from pg_namespace where nspname = $1",
        )
        .bind(*schema)
        .fetch_optional(&pool)
        .await
        .expect("查 schema owner");
        if schema_owner.as_deref() != Some(r.owner.as_str()) {
            errs.push(format!(
                "schema {schema} 的 owner 应是 {},实际 {schema_owner:?}",
                r.owner
            ));
        }
        for t in tables(&pool).await {
            if t.name.starts_with(&format!("{schema}.")) && t.owner != r.owner {
                errs.push(format!(
                    "{} 的 owner 应是 {},实际 {}",
                    t.name, r.owner, t.owner
                ));
            }
        }
    }
    assert!(
        errs.is_empty(),
        "owner 账号审计不通过:\n  {}",
        errs.join("\n  ")
    );
}

#[tokio::test]
async fn system_roles_bypass_rls_with_dml_only() {
    let pool = connect().await;
    let mut errs = Vec::new();
    for schema in SCHEMAS {
        let r = roles_for(schema);
        match role_attrs(&pool, &r.system).await {
            None => {
                errs.push(format!("system 账号 {} 不存在", r.system));
                continue;
            }
            Some((sup, bypass)) => {
                if sup || !bypass {
                    errs.push(format!(
                        "system 账号 {} 应是非超级用户 + BYPASSRLS(super={sup} bypassrls={bypass})",
                        r.system
                    ));
                }
            }
        }
        let owned = owned_relations(&pool, &r.system).await;
        if !owned.is_empty() {
            errs.push(format!("system 账号 {} 不能拥有表:{owned:?}", r.system));
        }
        let missing = missing_dml(&pool, &r.system, schema).await;
        if !missing.is_empty() {
            errs.push(format!("system 账号 {} 缺 DML 权限:{missing:?}", r.system));
        }
    }
    assert!(
        errs.is_empty(),
        "system 账号审计不通过:\n  {}",
        errs.join("\n  ")
    );
}

/// `tenant_tx`:事务内能读到 `app.tenant_id`;commit 后**同一条连接**上不再有租户(事务级,不串请求)。
#[tokio::test]
async fn tenant_tx_sets_a_transaction_local_tenant() {
    // 单连接池:commit 后的查询必然落在刚才那条连接上。
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&app_url())
        .await
        .expect("连 app 运行时账号");
    let tenant = TenantId::new(Uuid::now_v7()).unwrap();

    let mut tx = tenant_tx(&pool, tenant).await.unwrap();
    let inside: Option<String> =
        sqlx::query_scalar("select current_setting('app.tenant_id', true)")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(inside, Some(tenant.to_string()), "事务内应能读到租户");
    tx.commit().await.unwrap();

    let after: Option<String> = sqlx::query_scalar("select current_setting('app.tenant_id', true)")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        after.as_deref().unwrap_or_default().is_empty(),
        "commit 后连接上不该残留租户(必须是事务级 set_config),实际 {after:?}"
    );
}

/// AppState 的 system 池(`connect_system_for_schema`):按 Config 连上的是 `<schema>_system`,且确实 BYPASSRLS。
#[tokio::test]
async fn system_pools_connect_as_bypassrls_roles() {
    let _ = connect().await; // 迁移 + 确认库在
    let opts: PgConnectOptions = app_url().parse().expect("APP_DATABASE_URL");
    let host = opts.get_host().to_owned();
    let port = opts.get_port();
    let db = opts.get_database().unwrap_or("baserust").to_owned();
    let (app, content, search) = (roles_for("app"), roles_for("content"), roles_for("search"));
    let pw = |k: &str| std::env::var(k).unwrap_or_else(|_| "pwd".into());
    let cfg = Config {
        app_db_host: Some(host.clone()),
        app_db_port: port,
        app_db_database: db.clone(),
        app_db_user: app.runtime.clone(),
        app_db_system_user: Some(app.system.clone()),
        app_db_system_password: pw("APP_DB_SYSTEM_PASSWORD"),
        content_db_host: Some(host.clone()),
        content_db_port: port,
        content_db_database: db.clone(),
        content_db_user: content.runtime.clone(),
        content_db_system_user: Some(content.system.clone()),
        content_db_system_password: pw("CONTENT_DB_SYSTEM_PASSWORD"),
        search_db_host: Some(host),
        search_db_port: port,
        search_db_database: db,
        search_db_user: search.runtime.clone(),
        search_db_system_user: Some(search.system.clone()),
        search_db_system_password: pw("SEARCH_DB_SYSTEM_PASSWORD"),
        ..Config::default()
    };
    for (schema, expected) in [
        (Schema::App, &app.system),
        (Schema::Content, &content.system),
        (Schema::Search, &search.system),
    ] {
        let pool = connect_system_for_schema(&cfg, schema)
            .await
            .unwrap_or_else(|e| panic!("{schema:?} system 池连不上: {e:#}"))
            .unwrap_or_else(|| panic!("{schema:?} 配了 host 却没有 system 池"));
        let (who, bypass): (String, bool) = sqlx::query_as(
            "select current_user::text, rolbypassrls from pg_roles where rolname = current_user",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(&who, expected, "{schema:?} system 池的账号");
        assert!(bypass, "{schema:?} system 池的账号应 BYPASSRLS");
        pool.close().await;
    }
}

/// 迁移台账 `_sqlx_migrations` 只有 owner 能写:运行时 / system 账号对它没有 INSERT / UPDATE / DELETE
/// (10-tenancy-roles.sh 第 5 步;全新库上台账由脚本先建,迁移时 sqlx 直接复用)。
#[tokio::test]
async fn migration_ledger_is_writable_only_by_owner() {
    let pool = connect().await;
    let mut errs = Vec::new();
    for schema in SCHEMAS {
        let r = roles_for(schema);
        let table = format!("{schema}._sqlx_migrations");
        for (who, role) in [
            ("运行时", &r.runtime),
            ("system", &r.system),
            ("owner", &r.owner),
        ] {
            let (ins, upd, del): (bool, bool, bool) = sqlx::query_as(
                // 按 oid 查(文本表名要解析 schema,审计用的 app 账号没有别的 schema 的 USAGE)。
                "select has_table_privilege($1, c.oid, 'insert'),
                        has_table_privilege($1, c.oid, 'update'),
                        has_table_privilege($1, c.oid, 'delete')
                   from pg_class c join pg_namespace n on n.oid = c.relnamespace
                  where n.nspname = $2 and c.relname = '_sqlx_migrations'",
            )
            .bind(role)
            .bind(*schema)
            .fetch_one(&pool)
            .await
            .expect("查台账权限");
            let can_write = ins || upd || del;
            if who == "owner" && !can_write {
                errs.push(format!("owner 账号 {role} 应能写 {table}"));
            }
            if who != "owner" && can_write {
                errs.push(format!(
                    "{who}账号 {role} 不该能写 {table}(insert={ins} update={upd} delete={del})"
                ));
            }
        }
    }
    assert!(
        errs.is_empty(),
        "迁移台账权限审计不通过:\n  {}",
        errs.join("\n  ")
    );
}

/// 只许 system 账号写的全局读模型:运行时账号只有 SELECT,system 账号能写(投影器 / rebuild_search 用它)。
const SYSTEM_WRITE_ONLY: &[(&str, &str)] = &[("search", "account_index"), ("search", "auth_event")];

#[tokio::test]
async fn system_only_write_tables() {
    let pool = connect().await;
    let mut errs = Vec::new();
    for (schema, table) in SYSTEM_WRITE_ONLY {
        let r = roles_for(schema);
        for (who, role, should_write) in
            [("运行时", &r.runtime, false), ("system", &r.system, true)]
        {
            let (sel, ins, upd, del): (bool, bool, bool, bool) = sqlx::query_as(
                "select has_table_privilege($1, c.oid, 'select'),
                        has_table_privilege($1, c.oid, 'insert'),
                        has_table_privilege($1, c.oid, 'update'),
                        has_table_privilege($1, c.oid, 'delete')
                   from pg_class c join pg_namespace n on n.oid = c.relnamespace
                  where n.nspname = $2 and c.relname = $3",
            )
            .bind(role)
            .bind(*schema)
            .bind(*table)
            .fetch_one(&pool)
            .await
            .expect("查表权限");
            if !sel {
                errs.push(format!("{who}账号 {role} 应能读 {schema}.{table}"));
            }
            let writes = ins || upd || del;
            if writes != should_write {
                errs.push(format!(
                    "{who}账号 {role} 对 {schema}.{table} 的写权限应为 {should_write}(insert={ins} update={upd} delete={del})"
                ));
            }
        }
    }
    assert!(
        errs.is_empty(),
        "只许 system 写的表权限不对:\n  {}",
        errs.join("\n  ")
    );
}

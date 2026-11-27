//! RLS 审计(spec §4.4 / §4.9):打真 PG 的**已迁移库**,查系统目录 `pg_class` / `pg_policies` / `pg_roles`,
//! 钉死多租户隔离的两条底线 ——
//!
//! 1. app / content / search 里**每张表**要么按租户隔离(ENABLE + FORCE ROW LEVEL SECURITY + 至少一条策略),
//!    要么显式列在 [`GLOBAL_TABLES`](全局表白名单)里;两样都不是 → 测试失败。
//!    下游项目同步底座后自己加的表也会被它拦下:加租户隔离,或进白名单(这是有意的提醒)。
//!    隔离表上的**每条**策略(USING 与 WITH CHECK 都算)都得按 `app.tenant_id` 判;唯一允许的另一支是 content 的
//!    个人内容(`tenant_id IS NULL` 且 `app.personal_scope`)—— 多一条 `USING (true)` 之类的宽松策略也会被拦下
//!    (宽松策略之间是 OR,一条放水就全放水)。
//! 2. 运行时账号(`<schema>`)不是任何表的 owner、没有 BYPASSRLS(否则 RLS 对它形同虚设),也不是
//!    `<schema>_owner` / `<schema>_system` 的成员(`pg_auth_members`,含间接:成员能 SET ROLE 过去,等于拿到它的权);
//!    `<schema>_owner` 拥有 schema 与表;`<schema>_system` 有 BYPASSRLS(后台任务 / 平台级读)。
//!
//! 仅 `--features pg-conformance`(`just test-pg`)。每个用例先以 owner 账号幂等跑一遍 app / content /
//! search 的迁移(`*_OWNER_DATABASE_URL`,CI 的全新库也能审),再连 `APP_DATABASE_URL`(运行时 app 账号即可:
//! 只读系统目录,不碰业务表)。缺省都回退本地 compose 的账号。
#![cfg(feature = "pg-conformance")]

use sqlx::FromRow;
use std::collections::BTreeSet;
use std::env;

use baserust::app::app_state::{connect_system_for_schema, Schema};
use baserust::infra::config::Config;
use baserust::infra::pg::tenant_transaction;
use baserust::kernel::tenant_id::TenantId;
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

/// 某 schema 的三个账号名:运行时 / owner / system。名字跟部署脚本同一套环境变量与缺省
/// (`<SCHEMA>_DB_USER`,owner / system 缺省是它加 `_owner` / `_system` 后缀)。
struct Roles {
    runtime: String,
    owner: String,
    system: String,
}

fn roles_for(schema: &str) -> Roles {
    let upper_schema = schema.to_uppercase();
    let env = |name: String| env::var(name).ok().filter(|v| !v.is_empty());
    let runtime = env(format!("{upper_schema}_DB_USER")).unwrap_or_else(|| schema.to_owned());
    Roles {
        owner: env(format!("{upper_schema}_DB_OWNER_USER"))
            .unwrap_or_else(|| format!("{runtime}_owner")),
        system: env(format!("{upper_schema}_DB_SYSTEM_USER"))
            .unwrap_or_else(|| format!("{runtime}_system")),
        runtime,
    }
}

fn app_url() -> String {
    env::var("APP_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://app:pwd@localhost:5821/baserust?sslmode=disable".into())
}

fn owner_url(schema: &str) -> String {
    let upper_schema = schema.to_uppercase();
    env::var(format!("{upper_schema}_OWNER_DATABASE_URL")).unwrap_or_else(|_| {
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
            .unwrap_or_else(|error| {
                panic!(
                    "连 {schema} 的 owner 账号失败(先 `just up` + `just db-ensure-roles`): {error}"
                )
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
#[derive(FromRow)]
struct TableRls {
    name: String,
    rls: bool,
    force: bool,
    policies: i64,
    owner: String,
}

async fn tables(pool: &PgPool) -> Vec<TableRls> {
    let schemas: Vec<String> = SCHEMAS.iter().map(|s| (*s).to_owned()).collect();
    sqlx::query_as(
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

fn isolated(table: &TableRls) -> bool {
    table.rls && table.force && table.policies > 0
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

    let mut errors = Vec::new();
    for listed in &global {
        if !names.contains(listed) {
            errors.push(format!(
                "{listed}:GLOBAL_TABLES 里有、库里没有(表改名 / 删了就从白名单删掉)"
            ));
        }
    }
    for table in &all {
        let name = table.name.as_str();
        if global.contains(name) {
            continue;
        }
        if !isolated(table) {
            errors.push(format!(
                "{name}:既没租户隔离(rls={} force={} policies={}),也不在 GLOBAL_TABLES",
                table.rls, table.force, table.policies
            ));
        }
    }
    assert!(
        errors.is_empty(),
        "RLS 审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

/// 一条 RLS 策略(`pg_policies`)。`qual` = USING,`with_check` = WITH CHECK(没写为 NULL)。
#[derive(FromRow)]
struct Policy {
    name: String,
    policy: String,
    permissive: String,
    qual: Option<String>,
    with_check: Option<String>,
}

async fn policies(pool: &PgPool) -> Vec<Policy> {
    let schemas: Vec<String> = SCHEMAS.iter().map(|s| (*s).to_owned()).collect();
    sqlx::query_as(
        "select schemaname || '.' || tablename as name, policyname::text as policy, permissive,
                qual, with_check
           from pg_policies where schemaname = any($1) order by 1, 2",
    )
    .bind(schemas)
    .fetch_all(pool)
    .await
    .expect("查 pg_policies")
}

/// 策略表达式(PG 反解析出来的文本)是否只按租户放行:
/// - 必须有 `tenant_id = …current_setting('app.tenant_id'…` 这一支;
/// - 不许有别的 OR 分支 —— 唯一例外是 content 的个人内容:`tenant_id IS NULL AND current_setting('app.personal_scope'…) = 'on'`。
fn tenant_bound(schema: &str, expression: &str) -> Result<(), String> {
    let lowered = expression.to_lowercase();
    if !(lowered.contains("tenant_id =") && lowered.contains("current_setting('app.tenant_id'")) {
        return Err("没按 app.tenant_id 判".into());
    }
    let or_count = lowered.matches(" or ").count();
    if or_count == 0 {
        return Ok(());
    }
    let personal = schema == "content"
        && or_count == 1
        && lowered.contains("tenant_id is null")
        && lowered.contains("current_setting('app.personal_scope'");
    if personal {
        Ok(())
    } else {
        Err("除了按租户判,还有别的放行分支".into())
    }
}

#[tokio::test]
async fn isolation_policies_are_bound_to_tenant_id() {
    let pool = connect().await;
    let global: BTreeSet<&str> = GLOBAL_TABLES.iter().copied().collect();
    let all = policies(&pool).await;
    let mut errors = Vec::new();
    let mut checked = 0usize;
    for table in tables(&pool).await {
        if global.contains(table.name.as_str()) || !isolated(&table) {
            continue; // 白名单表不审;没隔离的表由 every_table_is_tenant_isolated_or_whitelisted 报
        }
        let schema = table.name.split('.').next().unwrap_or_default();
        let table_policies = all.iter().filter(|p| p.name == table.name);
        for policy in table_policies {
            let expressions: Vec<(&str, &str)> =
                [("USING", &policy.qual), ("WITH CHECK", &policy.with_check)]
                    .into_iter()
                    .filter_map(|(k, v)| v.as_deref().map(|v| (k, v)))
                    .collect();
            if expressions.is_empty() {
                errors.push(format!(
                    "{} 的策略 {}:既没有 USING 也没有 WITH CHECK",
                    table.name, policy.policy
                ));
            }
            for (kind, expression) in expressions {
                checked += 1;
                if let Err(why) = tenant_bound(schema, expression) {
                    errors.push(format!(
                        "{} 的策略 {}({}){kind} {why}:{expression}",
                        table.name, policy.policy, policy.permissive
                    ));
                }
            }
        }
    }
    assert!(checked > 0, "一条策略表达式都没审到:库没迁移?");
    assert!(
        errors.is_empty(),
        "RLS 策略审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

/// 判据自测(不连库):PG 反解析出的真实策略文本该过的过、该拦的拦。
#[test]
fn tenant_bound_accepts_tenant_policies_and_rejects_escapes() {
    let tenant =
        "(tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid)";
    let personal = "((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid) OR ((tenant_id IS NULL) AND (current_setting('app.personal_scope'::text, true) = 'on'::text)))";
    assert!(tenant_bound("app", tenant).is_ok());
    assert!(tenant_bound("content", personal).is_ok());
    assert!(
        tenant_bound("app", personal).is_err(),
        "个人分支只给 content"
    );
    assert!(tenant_bound("app", "true").is_err());
    assert!(tenant_bound("app", &format!("({tenant} OR true)")).is_err());
    assert!(tenant_bound("app", "(owner_id = current_user)").is_err());
}

/// `member` 是否(直接或间接)是 `role` 的成员 —— 递归查 `pg_auth_members`。
async fn is_member_of(pool: &PgPool, member: &str, role: &str) -> bool {
    sqlx::query_scalar(
        "with recursive up(oid) as (
             select roleid from pg_auth_members
              where member = (select oid from pg_roles where rolname = $1)
             union
             select m.roleid from pg_auth_members m join up on m.member = up.oid
         )
         select exists (select 1 from up where oid = (select oid from pg_roles where rolname = $2))",
    )
    .bind(member)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("查 pg_auth_members")
}

/// 运行时账号不是 owner / system 账号的成员(否则 SET ROLE 过去就绕开了 RLS / 拿到 DDL);system 也不是 owner 的成员。
#[tokio::test]
async fn runtime_roles_are_not_members_of_owner_or_system() {
    let pool = connect().await;
    let mut errors = Vec::new();
    for schema in SCHEMAS {
        let roles = roles_for(schema);
        for (member, role) in [
            (&roles.runtime, &roles.owner),
            (&roles.runtime, &roles.system),
            (&roles.system, &roles.owner),
        ] {
            if is_member_of(&pool, member, role).await {
                errors.push(format!("{member} 是 {role} 的成员(pg_auth_members)"));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "账号成员关系审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

/// 账号属性(`pg_roles` 的 rolsuper / rolbypassrls)。
struct RoleAttributes {
    superuser: bool,
    bypass_rls: bool,
}

/// 查账号属性;账号不存在 → `None`。
async fn role_attributes(pool: &PgPool, role: &str) -> Option<RoleAttributes> {
    let row: Option<(bool, bool)> =
        sqlx::query_as("select rolsuper, rolbypassrls from pg_roles where rolname = $1")
            .bind(role)
            .fetch_optional(pool)
            .await
            .expect("查 pg_roles");
    row.map(|(superuser, bypass_rls)| RoleAttributes {
        superuser,
        bypass_rls,
    })
}

/// 该账号在整个库里拥有的表 / 视图 / 序列(`schema.name`)。
async fn owned_relations(pool: &PgPool, role: &str) -> Vec<String> {
    sqlx::query_scalar(
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
    sqlx::query_scalar(
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
    let mut errors = Vec::new();
    for schema in SCHEMAS {
        let roles = roles_for(schema);
        match role_attributes(&pool, &roles.runtime).await {
            None => errors.push(format!("运行时账号 {} 不存在", roles.runtime)),
            Some(RoleAttributes {
                superuser,
                bypass_rls,
            }) => {
                if superuser || bypass_rls {
                    errors.push(format!(
                        "运行时账号 {} 不能是超级用户 / BYPASSRLS(super={superuser} bypassrls={bypass_rls})",
                        roles.runtime
                    ));
                }
            }
        }
        let owned = owned_relations(&pool, &roles.runtime).await;
        if !owned.is_empty() {
            errors.push(format!("运行时账号 {} 不能拥有表:{owned:?}", roles.runtime));
        }
        let missing = missing_dml(&pool, &roles.runtime, schema).await;
        if !missing.is_empty() {
            errors.push(format!(
                "运行时账号 {} 缺 DML 权限:{missing:?}",
                roles.runtime
            ));
        }
        // 运行时账号不能在自己的 schema 里建表(只有 DML)。
        let can_create: bool = sqlx::query_scalar("select has_schema_privilege($1, $2, 'create')")
            .bind(&roles.runtime)
            .bind(*schema)
            .fetch_one(&pool)
            .await
            .expect("查 schema 权限");
        if can_create {
            errors.push(format!(
                "运行时账号 {} 不该有 schema {schema} 的 CREATE",
                roles.runtime
            ));
        }
    }
    assert!(
        errors.is_empty(),
        "运行时账号审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

#[tokio::test]
async fn owner_roles_own_schemas_and_tables() {
    let pool = connect().await;
    let mut errors = Vec::new();
    for schema in SCHEMAS {
        let roles = roles_for(schema);
        if role_attributes(&pool, &roles.owner).await.is_none() {
            errors.push(format!("owner 账号 {} 不存在", roles.owner));
            continue;
        }
        let schema_owner: Option<String> = sqlx::query_scalar(
            "select pg_get_userbyid(nspowner)::text from pg_namespace where nspname = $1",
        )
        .bind(*schema)
        .fetch_optional(&pool)
        .await
        .expect("查 schema owner");
        if schema_owner.as_deref() != Some(roles.owner.as_str()) {
            errors.push(format!(
                "schema {schema} 的 owner 应是 {},实际 {schema_owner:?}",
                roles.owner
            ));
        }
        for table in tables(&pool).await {
            if table.name.starts_with(&format!("{schema}.")) && table.owner != roles.owner {
                errors.push(format!(
                    "{} 的 owner 应是 {},实际 {}",
                    table.name, roles.owner, table.owner
                ));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "owner 账号审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

#[tokio::test]
async fn system_roles_bypass_rls_with_dml_only() {
    let pool = connect().await;
    let mut errors = Vec::new();
    for schema in SCHEMAS {
        let roles = roles_for(schema);
        match role_attributes(&pool, &roles.system).await {
            None => {
                errors.push(format!("system 账号 {} 不存在", roles.system));
                continue;
            }
            Some(RoleAttributes {
                superuser,
                bypass_rls,
            }) => {
                if superuser || !bypass_rls {
                    errors.push(format!(
                        "system 账号 {} 应是非超级用户 + BYPASSRLS(super={superuser} bypassrls={bypass_rls})",
                        roles.system
                    ));
                }
            }
        }
        let owned = owned_relations(&pool, &roles.system).await;
        if !owned.is_empty() {
            errors.push(format!("system 账号 {} 不能拥有表:{owned:?}", roles.system));
        }
        let missing = missing_dml(&pool, &roles.system, schema).await;
        if !missing.is_empty() {
            errors.push(format!(
                "system 账号 {} 缺 DML 权限:{missing:?}",
                roles.system
            ));
        }
    }
    assert!(
        errors.is_empty(),
        "system 账号审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

/// `tenant_transaction`:事务内能读到 `app.tenant_id`;commit 后**同一条连接**上不再有租户(事务级,不串请求)。
#[tokio::test]
async fn tenant_transaction_sets_a_transaction_local_tenant() {
    // 单连接池:commit 后的查询必然落在刚才那条连接上。
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&app_url())
        .await
        .expect("连 app 运行时账号");
    let tenant = TenantId::try_new(Uuid::now_v7()).unwrap();

    let mut transaction = tenant_transaction(&pool, tenant).await.unwrap();
    let inside: Option<String> =
        sqlx::query_scalar("select current_setting('app.tenant_id', true)")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
    assert_eq!(inside, Some(tenant.to_string()), "事务内应能读到租户");
    transaction.commit().await.unwrap();

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
    let options: PgConnectOptions = app_url().parse().expect("APP_DATABASE_URL");
    let host = options.get_host().to_owned();
    let port = options.get_port();
    let db = options.get_database().unwrap_or("baserust").to_owned();
    let (app, content, search) = (roles_for("app"), roles_for("content"), roles_for("search"));
    let password = |name: &str| env::var(name).unwrap_or_else(|_| "pwd".into());
    let config = Config {
        app_db_host: Some(host.clone()),
        app_db_port: port,
        app_db_database: db.clone(),
        app_db_user: app.runtime.clone(),
        app_db_system_user: Some(app.system.clone()),
        app_db_system_password: password("APP_DB_SYSTEM_PASSWORD"),
        content_db_host: Some(host.clone()),
        content_db_port: port,
        content_db_database: db.clone(),
        content_db_user: content.runtime.clone(),
        content_db_system_user: Some(content.system.clone()),
        content_db_system_password: password("CONTENT_DB_SYSTEM_PASSWORD"),
        search_db_host: Some(host),
        search_db_port: port,
        search_db_database: db,
        search_db_user: search.runtime.clone(),
        search_db_system_user: Some(search.system.clone()),
        search_db_system_password: password("SEARCH_DB_SYSTEM_PASSWORD"),
        ..Config::default()
    };
    for (schema, expected) in [
        (Schema::App, &app.system),
        (Schema::Content, &content.system),
        (Schema::Search, &search.system),
    ] {
        let pool = connect_system_for_schema(&config, schema)
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
    let mut errors = Vec::new();
    for schema in SCHEMAS {
        let roles = roles_for(schema);
        let table = format!("{schema}._sqlx_migrations");
        for (who, role) in [
            ("运行时", &roles.runtime),
            ("system", &roles.system),
            ("owner", &roles.owner),
        ] {
            let (can_insert, can_update, can_delete): (bool, bool, bool) = sqlx::query_as(
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
            let can_write = can_insert || can_update || can_delete;
            if who == "owner" && !can_write {
                errors.push(format!("owner 账号 {role} 应能写 {table}"));
            }
            if who != "owner" && can_write {
                errors.push(format!(
                    "{who}账号 {role} 不该能写 {table}(insert={can_insert} update={can_update} delete={can_delete})"
                ));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "迁移台账权限审计不通过:\n  {}",
        errors.join("\n  ")
    );
}

/// 只许 system 账号写的全局读模型:运行时账号只有 SELECT,system 账号能写(投影器 / rebuild_search 用它)。
const SYSTEM_WRITE_ONLY: &[(&str, &str)] = &[("search", "account_index"), ("search", "auth_event")];

#[tokio::test]
async fn system_only_write_tables() {
    let pool = connect().await;
    let mut errors = Vec::new();
    for (schema, table) in SYSTEM_WRITE_ONLY {
        let roles = roles_for(schema);
        for (who, role, should_write) in [
            ("运行时", &roles.runtime, false),
            ("system", &roles.system, true),
        ] {
            let (can_select, can_insert, can_update, can_delete): (bool, bool, bool, bool) =
                sqlx::query_as(
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
            if !can_select {
                errors.push(format!("{who}账号 {role} 应能读 {schema}.{table}"));
            }
            let writes = can_insert || can_update || can_delete;
            if writes != should_write {
                errors.push(format!(
                    "{who}账号 {role} 对 {schema}.{table} 的写权限应为 {should_write}(insert={can_insert} update={can_update} delete={can_delete})"
                ));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "只许 system 写的表权限不对:\n  {}",
        errors.join("\n  ")
    );
}

//! 旧头像修复(`app::avatar_repair`)打真 PG:迁移 0003 把历史头像(当年写的 nil 租户)回填进了默认租户;
//! 修复步骤按 app.profiles 引用到的头像 content id,把这些 content 及其子行(元数据 / 对象 / 对象元数据 /
//! 派生)改成个人内容(tenant_id NULL)。断言:头像整棵转成个人、对象 key 不搬家、非头像内容不动、重复跑幂等。
//!
//! 仅 `--features pg-conformance`(`just test-pg`)。用**已迁移的共享测试库**(同 rls_audit):先以 owner 账号
//! 幂等迁移 app / content,再用 app 运行时账号写资料、content system 账号(BYPASSRLS)铺旧形状的数据。
//! 数据都用随机 id,并打上 [`MARKER`](content.name / profiles.display_name):开头先按标记清掉上次残留,
//! 结束(含断言失败 panic)由 [`Cleanup`] 的 drop 再清一次 —— 失败也不在共享库里留脏数据。
#![cfg(feature = "pg-conformance")]

use baserust::app::avatar_repair::{repair_legacy_avatars, AvatarRepairPools};
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, PgPool};
use std::{env, thread};
use tokio::runtime::Builder;
use uuid::Uuid;

const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

/// 本测试铺的数据的标记(content.name / profiles.display_name)。
const MARKER: &str = "avatar_repair_pg";

fn env_or(key: &str, default: impl FnOnce() -> String) -> String {
    env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(default)
}

fn app_url() -> String {
    env_or("APP_DATABASE_URL", || {
        "postgres://app:pwd@localhost:5821/baserust?sslmode=disable".into()
    })
}

/// 与 app 运行时账号同 host / 库,换成别的账号。
fn sibling_url(user: &str, password: &str) -> String {
    let options: PgConnectOptions = app_url().parse().expect("APP_DATABASE_URL");
    format!(
        "postgres://{user}:{password}@{}:{}/{}?sslmode=disable",
        options.get_host(),
        options.get_port(),
        options.get_database().unwrap_or("baserust")
    )
}

fn owner_url(schema: &str) -> String {
    env_or(
        &format!("{}_OWNER_DATABASE_URL", schema.to_uppercase()),
        || sibling_url(&format!("{schema}_owner"), "pwd"),
    )
}

fn content_system_url() -> String {
    env_or("CONTENT_SYSTEM_DATABASE_URL", || {
        sibling_url("content_system", "pwd")
    })
}

async fn migrate() {
    for (schema, migrator) in [
        ("app", sqlx::migrate!("migrations/app")),
        ("content", sqlx::migrate!("migrations/content")),
    ] {
        let owner = PgPool::connect(&owner_url(schema))
            .await
            .unwrap_or_else(|e| panic!("连 {schema} owner 失败: {e}"));
        migrator
            .run(&owner)
            .await
            .unwrap_or_else(|e| panic!("迁移 {schema} 失败: {e}"));
        owner.close().await;
    }
}

/// 一条旧形状的内容:content + content_metadata + object + object_metadata,全在 `tenant`;content.name 打 [`MARKER`]。
async fn legacy_content(system_pool: &PgPool, tenant: Uuid, owner: Uuid) -> LegacyContent {
    let (content_id, object_id) = (Uuid::now_v7(), Uuid::now_v7());
    let key = format!("{content_id}/legacy-{object_id}");
    sqlx::query(
        "insert into content (id, tenant_id, owner_id, status, name) values ($1, $2, $3, 'uploaded', $4)",
    )
    .bind(content_id)
    .bind(tenant)
    .bind(owner)
    .bind(MARKER)
    .execute(system_pool)
    .await
    .unwrap();
    sqlx::query("insert into content_metadata (content_id, tenant_id, mime_type) values ($1, $2, 'image/png')")
        .bind(content_id)
        .bind(tenant)
        .execute(system_pool)
        .await
        .unwrap();
    sqlx::query(
        "insert into object (id, tenant_id, content_id, storage_backend_name, object_key, status)
         values ($1, $2, $3, 'memory', $4, 'uploaded')",
    )
    .bind(object_id)
    .bind(tenant)
    .bind(content_id)
    .bind(&key)
    .execute(system_pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into object_metadata (object_id, tenant_id, size_bytes) values ($1, $2, 12)",
    )
    .bind(object_id)
    .bind(tenant)
    .execute(system_pool)
    .await
    .unwrap();
    LegacyContent {
        content: content_id,
        object: object_id,
        key,
    }
}

/// [`legacy_content`] 造出的一条旧形状内容。
struct LegacyContent {
    content: Uuid,
    object: Uuid,
    /// 对象存储 key。
    key: String,
}

/// 一行的 tenant_id(行必须存在)。
async fn tenant_of(system_pool: &PgPool, table: &str, column: &str, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "select tenant_id from {table} where {column} = $1"
    )))
    .bind(id)
    .fetch_one(system_pool)
    .await
    .unwrap_or_else(|e| panic!("{table}.{column} = {id} 应有一行: {e}"))
}

/// 一条派生关系(parent → child)的 tenant_id。
async fn link_tenant(system_pool: &PgPool, parent: Uuid, child: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(
        "select tenant_id from content_derived where parent_id = $1 and content_id = $2",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(system_pool)
    .await
    .expect("派生关系应有一行")
}

async fn derive(system_pool: &PgPool, parent: Uuid, child: Uuid, tenant: Uuid) {
    sqlx::query(
        "insert into content_derived (parent_id, content_id, variant, derivation_type, tenant_id)
         values ($1, $2, 'thumb', 'resize', $3)",
    )
    .bind(parent)
    .bind(child)
    .bind(tenant)
    .execute(system_pool)
    .await
    .unwrap();
}

async fn profile(app: &PgPool, user: Uuid, avatar: Uuid) {
    sqlx::query(
        "insert into profiles (user_id, display_name, avatar_content_id) values ($1, $2, $3)",
    )
    .bind(user)
    .bind(MARKER)
    .bind(avatar)
    .execute(app)
    .await
    .unwrap();
}

/// 按标记删掉本测试铺的行(子表随 content 级联删)。
async fn cleanup(app: &PgPool, system_pool: &PgPool) {
    sqlx::query("delete from profiles where display_name = $1")
        .bind(MARKER)
        .execute(app)
        .await
        .expect("清理 profiles");
    sqlx::query("delete from content where name = $1")
        .bind(MARKER)
        .execute(system_pool)
        .await
        .expect("清理 content");
}

/// drop 时(正常结束或断言 panic)按标记清理:另起线程 + 自己的运行时,不依赖测试的运行时还活着。
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = thread::spawn(|| {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("清理用运行时");
            runtime.block_on(async {
                let app = PgPool::connect(&app_url()).await.expect("连 app");
                let system_pool = PgPool::connect(&content_system_url())
                    .await
                    .expect("连 content system");
                cleanup(&app, &system_pool).await;
            });
        })
        .join();
    }
}

#[tokio::test]
async fn legacy_avatars_become_personal_idempotently() {
    migrate().await;
    let app = PgPool::connect(&app_url())
        .await
        .expect("连 app 运行时账号");
    let system_pool = PgPool::connect(&content_system_url())
        .await
        .expect("连 content system 账号(BYPASSRLS)");
    cleanup(&app, &system_pool).await; // 上次异常退出的残留
    let _guard = Cleanup;

    let (alice, bob, carol, dave) = (
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    // 旧头像(默认租户)+ 它的派生缩略图;缩略图再派生一张(孙)—— 孙那一层不跟着转。
    let LegacyContent {
        content: avatar,
        object: avatar_object,
        key: avatar_key,
    } = legacy_content(&system_pool, DEFAULT_TENANT, alice).await;
    let LegacyContent {
        content: thumb,
        object: thumb_object,
        ..
    } = legacy_content(&system_pool, DEFAULT_TENANT, alice).await;
    derive(&system_pool, avatar, thumb, DEFAULT_TENANT).await;
    let LegacyContent {
        content: grand,
        object: grand_object,
        ..
    } = legacy_content(&system_pool, DEFAULT_TENANT, alice).await;
    derive(&system_pool, thumb, grand, DEFAULT_TENANT).await;
    // 头像派生出、但 owner 不是 alice 的子内容 → 不转(连同那条派生关系)
    let LegacyContent {
        content: foreign_child,
        ..
    } = legacy_content(&system_pool, DEFAULT_TENANT, dave).await;
    derive(&system_pool, avatar, foreign_child, DEFAULT_TENANT).await;
    // 同主人的普通内容;另一个租户里的内容;carol 的资料引用了 dave 的内容(owner 对不上)
    let LegacyContent {
        content: doc,
        object: doc_object,
        ..
    } = legacy_content(&system_pool, DEFAULT_TENANT, alice).await;
    let other_tenant = Uuid::now_v7();
    let LegacyContent {
        content: foreign, ..
    } = legacy_content(&system_pool, other_tenant, bob).await;
    let LegacyContent {
        content: daves,
        object: daves_object,
        ..
    } = legacy_content(&system_pool, DEFAULT_TENANT, dave).await;

    profile(&app, alice, avatar).await;
    profile(&app, bob, foreign).await;
    profile(&app, carol, daves).await;

    let first = repair_legacy_avatars(AvatarRepairPools {
        app: &app,
        content_system: &system_pool,
    })
    .await
    .expect("修复");
    assert!(first.contents >= 2, "旧头像 + 派生至少两条: {first:?}");
    assert!(
        first.owner_mismatch >= 1,
        "carol → dave 的引用应计为 owner 不一致: {first:?}"
    );

    for id in [avatar, thumb] {
        assert_eq!(
            tenant_of(&system_pool, "content", "id", id).await,
            None,
            "content {id}"
        );
        assert_eq!(
            tenant_of(&system_pool, "content_metadata", "content_id", id).await,
            None
        );
    }
    for object_id in [avatar_object, thumb_object] {
        assert_eq!(
            tenant_of(&system_pool, "object", "id", object_id).await,
            None
        );
        assert_eq!(
            tenant_of(&system_pool, "object_metadata", "object_id", object_id).await,
            None
        );
    }
    assert_eq!(
        link_tenant(&system_pool, avatar, thumb).await,
        None,
        "头像 → 缩略图的关系转成个人"
    );
    let key: String = sqlx::query_scalar("select object_key from object where id = $1")
        .bind(avatar_object)
        .fetch_one(&system_pool)
        .await
        .unwrap();
    assert_eq!(key, avatar_key, "对象 key 不搬家");

    // 孙一层不动:缩略图 → 孙的关系、孙本身都还在默认租户(不出现「关系是个人、内容在租户」的错配)
    assert_eq!(
        link_tenant(&system_pool, thumb, grand).await,
        Some(DEFAULT_TENANT),
        "子 → 孙的派生关系不该被转"
    );
    assert_eq!(
        tenant_of(&system_pool, "content", "id", grand).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&system_pool, "object", "id", grand_object).await,
        Some(DEFAULT_TENANT)
    );
    // owner 不是头像主人的派生子内容不转,关系也不转
    assert_eq!(
        tenant_of(&system_pool, "content", "id", foreign_child).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        link_tenant(&system_pool, avatar, foreign_child).await,
        Some(DEFAULT_TENANT)
    );
    // 非头像内容、别的租户的内容、owner 对不上的引用都不动
    assert_eq!(
        tenant_of(&system_pool, "content", "id", doc).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&system_pool, "object", "id", doc_object).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&system_pool, "content", "id", foreign).await,
        Some(other_tenant)
    );
    assert_eq!(
        tenant_of(&system_pool, "content", "id", daves).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&system_pool, "object", "id", daves_object).await,
        Some(DEFAULT_TENANT)
    );

    // 转完之后个人作用域读得到(仓储按 Personal 查)
    let repo = content::PgContentRepo::new(system_pool.clone());
    let got = content::ContentRepo::get(&repo, content::ContentScope::Personal, avatar)
        .await
        .expect("个人作用域应读得到旧头像");
    assert_eq!(got.tenant_id, None);
    assert_eq!(got.owner_id, alice);

    // 幂等:再跑一次什么都不改
    let second = repair_legacy_avatars(AvatarRepairPools {
        app: &app,
        content_system: &system_pool,
    })
    .await
    .expect("再修一次");
    assert_eq!(second.rows(), 0, "第二次不该再改: {second:?}");
}

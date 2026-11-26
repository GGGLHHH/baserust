//! 旧头像修复(`app::avatar_repair`)打真 PG:迁移 0003 把历史头像(当年写的 nil 租户)回填进了默认租户;
//! 修复步骤按 app.profiles 引用到的头像 content id,把这些 content 及其子行(元数据 / 对象 / 对象元数据 /
//! 派生)改成个人内容(tenant_id NULL)。断言:头像整棵转成个人、对象 key 不搬家、非头像内容不动、重复跑幂等。
//!
//! 仅 `--features pg-conformance`(`just test-pg`)。用**已迁移的共享测试库**(同 rls_audit):先以 owner 账号
//! 幂等迁移 app / content,再用 app 运行时账号写资料、content system 账号(BYPASSRLS)铺旧形状的数据。
//! 数据都用随机 id,并打上 [`MARKER`](content.name / profiles.display_name):开头先按标记清掉上次残留,
//! 结束(含断言失败 panic)由 [`Cleanup`] 的 drop 再清一次 —— 失败也不在共享库里留脏数据。
#![cfg(feature = "pg-conformance")]

use baserust::app::avatar_repair::repair_legacy_avatars;
use sqlx::postgres::PgConnectOptions;
use sqlx::PgPool;
use uuid::Uuid;

const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

/// 本测试铺的数据的标记(content.name / profiles.display_name)。
const MARKER: &str = "avatar_repair_pg";

fn env_or(k: &str, default: impl FnOnce() -> String) -> String {
    std::env::var(k)
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
    let opts: PgConnectOptions = app_url().parse().expect("APP_DATABASE_URL");
    format!(
        "postgres://{user}:{password}@{}:{}/{}?sslmode=disable",
        opts.get_host(),
        opts.get_port(),
        opts.get_database().unwrap_or("baserust")
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

/// 一条旧形状的内容:content + content_metadata + object + object_metadata,全在 `tenant`;content.name 打 [`MARKER`]。返回 (content id, object id, key)。
async fn legacy_content(sys: &PgPool, tenant: Uuid, owner: Uuid) -> (Uuid, Uuid, String) {
    let (cid, oid) = (Uuid::now_v7(), Uuid::now_v7());
    let key = format!("{cid}/legacy-{oid}");
    sqlx::query(
        "insert into content (id, tenant_id, owner_id, status, name) values ($1, $2, $3, 'uploaded', $4)",
    )
    .bind(cid)
    .bind(tenant)
    .bind(owner)
    .bind(MARKER)
    .execute(sys)
    .await
    .unwrap();
    sqlx::query("insert into content_metadata (content_id, tenant_id, mime_type) values ($1, $2, 'image/png')")
        .bind(cid)
        .bind(tenant)
        .execute(sys)
        .await
        .unwrap();
    sqlx::query(
        "insert into object (id, tenant_id, content_id, storage_backend_name, object_key, status)
         values ($1, $2, $3, 'memory', $4, 'uploaded')",
    )
    .bind(oid)
    .bind(tenant)
    .bind(cid)
    .bind(&key)
    .execute(sys)
    .await
    .unwrap();
    sqlx::query(
        "insert into object_metadata (object_id, tenant_id, size_bytes) values ($1, $2, 12)",
    )
    .bind(oid)
    .bind(tenant)
    .execute(sys)
    .await
    .unwrap();
    (cid, oid, key)
}

/// 一行的 tenant_id(行必须存在)。
async fn tenant_of(sys: &PgPool, table: &str, col: &str, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>(sqlx::AssertSqlSafe(format!(
        "select tenant_id from {table} where {col} = $1"
    )))
    .bind(id)
    .fetch_one(sys)
    .await
    .unwrap_or_else(|e| panic!("{table}.{col} = {id} 应有一行: {e}"))
}

/// 一条派生关系(parent → child)的 tenant_id。
async fn link_tenant(sys: &PgPool, parent: Uuid, child: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "select tenant_id from content_derived where parent_id = $1 and content_id = $2",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(sys)
    .await
    .expect("派生关系应有一行")
}

async fn derive(sys: &PgPool, parent: Uuid, child: Uuid, tenant: Uuid) {
    sqlx::query(
        "insert into content_derived (parent_id, content_id, variant, derivation_type, tenant_id)
         values ($1, $2, 'thumb', 'resize', $3)",
    )
    .bind(parent)
    .bind(child)
    .bind(tenant)
    .execute(sys)
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
async fn cleanup(app: &PgPool, sys: &PgPool) {
    sqlx::query("delete from profiles where display_name = $1")
        .bind(MARKER)
        .execute(app)
        .await
        .expect("清理 profiles");
    sqlx::query("delete from content where name = $1")
        .bind(MARKER)
        .execute(sys)
        .await
        .expect("清理 content");
}

/// drop 时(正常结束或断言 panic)按标记清理:另起线程 + 自己的运行时,不依赖测试的运行时还活着。
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("清理用运行时");
            rt.block_on(async {
                let app = PgPool::connect(&app_url()).await.expect("连 app");
                let sys = PgPool::connect(&content_system_url())
                    .await
                    .expect("连 content system");
                cleanup(&app, &sys).await;
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
    let sys = PgPool::connect(&content_system_url())
        .await
        .expect("连 content system 账号(BYPASSRLS)");
    cleanup(&app, &sys).await; // 上次异常退出的残留
    let _guard = Cleanup;

    let (alice, bob, carol, dave) = (
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    // 旧头像(默认租户)+ 它的派生缩略图;缩略图再派生一张(孙)—— 孙那一层不跟着转。
    let (avatar, avatar_obj, avatar_key) = legacy_content(&sys, DEFAULT_TENANT, alice).await;
    let (thumb, thumb_obj, _) = legacy_content(&sys, DEFAULT_TENANT, alice).await;
    derive(&sys, avatar, thumb, DEFAULT_TENANT).await;
    let (grand, grand_obj, _) = legacy_content(&sys, DEFAULT_TENANT, alice).await;
    derive(&sys, thumb, grand, DEFAULT_TENANT).await;
    // 头像派生出、但 owner 不是 alice 的子内容 → 不转(连同那条派生关系)
    let (foreign_child, _, _) = legacy_content(&sys, DEFAULT_TENANT, dave).await;
    derive(&sys, avatar, foreign_child, DEFAULT_TENANT).await;
    // 同主人的普通内容;另一个租户里的内容;carol 的资料引用了 dave 的内容(owner 对不上)
    let (doc, doc_obj, _) = legacy_content(&sys, DEFAULT_TENANT, alice).await;
    let other_tenant = Uuid::now_v7();
    let (foreign, _, _) = legacy_content(&sys, other_tenant, bob).await;
    let (daves, daves_obj, _) = legacy_content(&sys, DEFAULT_TENANT, dave).await;

    profile(&app, alice, avatar).await;
    profile(&app, bob, foreign).await;
    profile(&app, carol, daves).await;

    let first = repair_legacy_avatars(&app, &sys).await.expect("修复");
    assert!(first.contents >= 2, "旧头像 + 派生至少两条: {first:?}");
    assert!(
        first.owner_mismatch >= 1,
        "carol → dave 的引用应计为 owner 不一致: {first:?}"
    );

    for id in [avatar, thumb] {
        assert_eq!(
            tenant_of(&sys, "content", "id", id).await,
            None,
            "content {id}"
        );
        assert_eq!(
            tenant_of(&sys, "content_metadata", "content_id", id).await,
            None
        );
    }
    for oid in [avatar_obj, thumb_obj] {
        assert_eq!(tenant_of(&sys, "object", "id", oid).await, None);
        assert_eq!(
            tenant_of(&sys, "object_metadata", "object_id", oid).await,
            None
        );
    }
    assert_eq!(
        link_tenant(&sys, avatar, thumb).await,
        None,
        "头像 → 缩略图的关系转成个人"
    );
    let key: String = sqlx::query_scalar("select object_key from object where id = $1")
        .bind(avatar_obj)
        .fetch_one(&sys)
        .await
        .unwrap();
    assert_eq!(key, avatar_key, "对象 key 不搬家");

    // 孙一层不动:缩略图 → 孙的关系、孙本身都还在默认租户(不出现「关系是个人、内容在租户」的错配)
    assert_eq!(
        link_tenant(&sys, thumb, grand).await,
        Some(DEFAULT_TENANT),
        "子 → 孙的派生关系不该被转"
    );
    assert_eq!(
        tenant_of(&sys, "content", "id", grand).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&sys, "object", "id", grand_obj).await,
        Some(DEFAULT_TENANT)
    );
    // owner 不是头像主人的派生子内容不转,关系也不转
    assert_eq!(
        tenant_of(&sys, "content", "id", foreign_child).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        link_tenant(&sys, avatar, foreign_child).await,
        Some(DEFAULT_TENANT)
    );
    // 非头像内容、别的租户的内容、owner 对不上的引用都不动
    assert_eq!(
        tenant_of(&sys, "content", "id", doc).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&sys, "object", "id", doc_obj).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&sys, "content", "id", foreign).await,
        Some(other_tenant)
    );
    assert_eq!(
        tenant_of(&sys, "content", "id", daves).await,
        Some(DEFAULT_TENANT)
    );
    assert_eq!(
        tenant_of(&sys, "object", "id", daves_obj).await,
        Some(DEFAULT_TENANT)
    );

    // 转完之后个人作用域读得到(仓储按 Personal 查)
    let repo = content::PgContentRepo::new(sys.clone());
    let got = content::ContentRepo::get(&repo, content::ContentScope::Personal, avatar)
        .await
        .expect("个人作用域应读得到旧头像");
    assert_eq!(got.tenant_id, None);
    assert_eq!(got.owner_id, alice);

    // 幂等:再跑一次什么都不改
    let second = repair_legacy_avatars(&app, &sys).await.expect("再修一次");
    assert_eq!(second.rows(), 0, "第二次不该再改: {second:?}");
}

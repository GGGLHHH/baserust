//! idm repo 契约一致性:**同一批断言对内存与 PG 的三个 repo 各跑一遍**,钉死行为 parity。
//! user(create/find/update/soft_delete/password)+ session(create/find_active/revoke)+ role(upsert/grant/roles)。
//! "内存绿不保证 PG 绿"的漂移,全靠这套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`just test-pg-idm`(需 DATABASE_URL 连 idm role + 跑着的 pg)。

use idm::IdmError;
use idm::{RoleRepo, SessionRepo, UserRepo};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 契约唯一真相源。三个 repo 协作(user → session → role),内存与 PG 都调它。
/// PG 有 FK(sessions/user_roles → users),故必须先建 user 再建 session/grant。
async fn idm_repo_contract(users: &dyn UserRepo, sessions: &dyn SessionRepo, roles: &dyn RoleRepo) {
    // ── user:create + find(username/email)+ 重复 → Conflict + password_hash ──
    let u = users
        .create("alice", Some("a@b.com"), "hash1", Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(u.username, "alice");
    assert!(users.find_by_identifier("alice").await.unwrap().is_some());
    assert!(users.find_by_identifier("a@b.com").await.unwrap().is_some());
    assert!(users.find_by_identifier("nobody").await.unwrap().is_none());
    assert_eq!(users.find_by_id(u.id).await.unwrap().username, "alice");
    assert!(matches!(
        users.create("alice", None, "h", None).await,
        Err(IdmError::Conflict(_))
    ));
    assert_eq!(
        users.password_hash(u.id).await.unwrap().as_deref(),
        Some("hash1")
    );

    // ── find_by_ids:批量富化根原语,内存↔PG parity(命中 + 缺席 + 空集 + 软删过滤)──
    let bob = users.create("bob", None, "h2", None).await.unwrap();
    assert_eq!(users.find_by_ids(&[u.id, bob.id]).await.unwrap().len(), 2);
    let missing = Uuid::now_v7();
    assert_eq!(users.find_by_ids(&[u.id, missing]).await.unwrap().len(), 1); // 不存在的缺席
    assert!(users.find_by_ids(&[]).await.unwrap().is_empty()); // 空集 → 空
    users.soft_delete(bob.id, None).await.unwrap();
    assert!(users.find_by_ids(&[bob.id]).await.unwrap().is_empty()); // 软删后消失(富化降级依据)

    // ── role:upsert 幂等 + grant 幂等 + roles_for_user ──
    let rid = roles
        .upsert("admin", "管理员", Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(roles.upsert("admin", "管理员", None).await.unwrap(), rid); // 幂等返同 id
    assert!(roles.roles_for_user(u.id).await.unwrap().is_empty());
    roles.grant(u.id, rid, Some("sys".into())).await.unwrap();
    roles.grant(u.id, rid, None).await.unwrap(); // 幂等:不重复授予
    assert_eq!(
        roles.roles_for_user(u.id).await.unwrap(),
        vec!["admin".to_string()]
    );

    // ── session:create + find_active + 过期 + revoke + revoke_all ──
    let now = OffsetDateTime::now_utc();
    let future = now + Duration::days(7);
    let s = sessions
        .create(u.id, "tokhash1", future, Some("sys".into()))
        .await
        .unwrap();
    assert!(sessions
        .find_active("tokhash1", now)
        .await
        .unwrap()
        .is_some());
    // 过期(now 推到 expires 之后)→ 不活跃
    assert!(sessions
        .find_active("tokhash1", future + Duration::seconds(1))
        .await
        .unwrap()
        .is_none());
    // revoke → 不活跃
    sessions.revoke(s.id).await.unwrap();
    assert!(sessions
        .find_active("tokhash1", now)
        .await
        .unwrap()
        .is_none());
    // revoke_all:撤销该用户全部
    sessions
        .create(u.id, "tokhash2", future, None)
        .await
        .unwrap();
    sessions
        .create(u.id, "tokhash3", future, None)
        .await
        .unwrap();
    sessions.revoke_all(u.id, None).await.unwrap();
    assert!(sessions
        .find_active("tokhash2", now)
        .await
        .unwrap()
        .is_none());
    assert!(sessions
        .find_active("tokhash3", now)
        .await
        .unwrap()
        .is_none());

    // ── update + update_password + soft_delete(幂等)──
    let upd = users
        .update(u.id, "alice2", None, Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(upd.username, "alice2");
    users.update_password(u.id, "hash2").await.unwrap();
    assert_eq!(
        users.password_hash(u.id).await.unwrap().as_deref(),
        Some("hash2")
    );
    users.soft_delete(u.id, None).await.unwrap();
    assert!(matches!(
        users.find_by_id(u.id).await,
        Err(IdmError::NotFound)
    ));
    assert!(users.find_by_identifier("alice2").await.unwrap().is_none()); // 软删后查不到
    assert!(matches!(
        users.soft_delete(u.id, None).await,
        Err(IdmError::NotFound)
    )); // 二次删幂等
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_idm_contract() {
    use idm::{InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};
    idm_repo_contract(
        &InMemoryUserRepo::new(),
        &InMemorySessionRepo::new(),
        &InMemoryRoleRepo::new(),
    )
    .await;
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 idm role + 跑着的 pg)──
// bootstrap 内联在本文件(不走 #[path] include):sqlx::migrate! 在被 include 的文件里会按
// "相对当前文件目录"解析路径(sqlx 不支持),内联后它相对 idm crate 的 CARGO_MANIFEST_DIR、稳。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::idm_repo_contract;
    use sqlx::migrate::Migrator;

    /// 编译期内嵌 crates/idm/migrations(相对 idm crate 的 CARGO_MANIFEST_DIR)。
    static IDM_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

    /// #[sqlx::test] 的干净临时库:建 idm schema + 跑 idm crate 自带 migrations。
    async fn bootstrap_idm(pool: &sqlx::PgPool) -> anyhow::Result<()> {
        sqlx::query("create schema if not exists idm")
            .execute(pool)
            .await?;
        IDM_MIGRATOR.run(pool).await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_idm_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = idm::PgUserRepo::new(pool.clone());
        let sessions = idm::PgSessionRepo::new(pool.clone());
        let roles = idm::PgRoleRepo::new(pool);
        idm_repo_contract(&users, &sessions, &roles).await;
        Ok(())
    }
}

//! TenantRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//! 钉:memberships 过滤停用租户(status=suspended)、granted_at 升序、membership 非成员回 None、
//!    set_active upsert、active 回环。
//! 注:软删租户(deleted_at)的过滤同样在契约里,但 TenantRepo 无「软删租户」方法,
//!    内存侧此处造不出该状态 → 由 Task 3 的 PG 入口用 raw SQL 直接 update deleted_at 补验。
//!
//! **本测试连 idm role**(非 `#[sqlx::test]` 默认的 app role/`DATABASE_URL`)——
//! tenants 表在 idm schema,app role 的 search_path=app 物理碰不到。形状照
//! `search_repo_conformance.rs`,不是 widget/profile。
//!
//! **无每测试隔离的临时库**(表跨测试运行共享)⇒ 契约里恒用全新 `Uuid::now_v7()` 造数据,
//! 且**绝不断言全表 count/total**。

use baserust::features::tenants::{TenantRepo, TenantRole, TenantStatus};
use uuid::Uuid;

/// 契约本体。
/// `user_id` 由调用方准备 —— PG 侧 `tenant_members.user_id` 有 FK 到 `users`,
/// 必须先插一行真 user;内存侧没有 FK,随便一个 uuid 即可。
async fn tenant_repo_contract(repo: &dyn TenantRepo, user_id: Uuid) {
    // ── 全新 id:表跨运行共享,不能撞行 ──
    let t_alive = Uuid::now_v7();
    let t_suspended = Uuid::now_v7();

    // 空态:什么都没有
    assert_eq!(repo.memberships(user_id).await.unwrap(), vec![]);
    assert_eq!(repo.active(user_id).await.unwrap(), None);
    assert_eq!(repo.membership(user_id, t_alive).await.unwrap(), None);

    // 建两个租户:一个 active、一个 suspended
    repo.upsert_tenant(
        t_alive,
        &format!("acme-{t_alive}"),
        "Acme",
        TenantStatus::Active,
        None,
    )
    .await
    .unwrap();
    repo.upsert_tenant(
        t_suspended,
        &format!("dead-{t_suspended}"),
        "Dead Corp",
        TenantStatus::Suspended,
        None,
    )
    .await
    .unwrap();

    // 两个都加成员
    repo.upsert_member(user_id, t_alive, TenantRole::Admin, None)
        .await
        .unwrap();
    repo.upsert_member(user_id, t_suspended, TenantRole::Member, None)
        .await
        .unwrap();

    // ── 契约核心:**停用的租户不出现在 memberships 里** ──
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 1, "suspended 租户必须被过滤掉");
    assert_eq!(ms[0].tenant_id, t_alive);
    assert_eq!(ms[0].display_name, "Acme");
    assert_eq!(ms[0].role, TenantRole::Admin);

    // membership 单查同样过滤
    assert!(repo.membership(user_id, t_alive).await.unwrap().is_some());
    assert_eq!(
        repo.membership(user_id, t_suspended).await.unwrap(),
        None,
        "suspended 租户的 membership 单查也必须回 None"
    );

    // ── set_active / active 回环 ──
    repo.set_active(user_id, t_alive).await.unwrap();
    assert_eq!(repo.active(user_id).await.unwrap(), Some(t_alive));
    // upsert 语义:再设一次覆盖,不是插第二行
    repo.set_active(user_id, t_suspended).await.unwrap();
    assert_eq!(repo.active(user_id).await.unwrap(), Some(t_suspended));

    // ── upsert_member 是替换,不是插重 ──
    repo.upsert_member(user_id, t_alive, TenantRole::Member, None)
        .await
        .unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 1, "同 (user,tenant) 再 upsert 必须替换而非新增");
    assert_eq!(ms[0].role, TenantRole::Member);

    // ── granted_at 升序(TenantRoleRepo 的 .or(ms.first()) 回退依赖它)──
    let t_second = Uuid::now_v7();
    repo.upsert_tenant(
        t_second,
        &format!("beta-{t_second}"),
        "Beta",
        TenantStatus::Active,
        None,
    )
    .await
    .unwrap();
    repo.upsert_member(user_id, t_second, TenantRole::Member, None)
        .await
        .unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 2);
    assert_eq!(
        ms[0].tenant_id, t_alive,
        "先加入的必须在前(granted_at 升序)"
    );
    assert_eq!(ms[1].tenant_id, t_second);
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_tenant_contract() {
    let repo = baserust::features::tenants::InMemoryTenantRepo::new();
    tenant_repo_contract(&repo, Uuid::now_v7()).await;
}

// ── 入口 2:PG(需 --features pg-conformance + idm role 跑着的 pg)──
// **不用 `#[sqlx::test]`**:它建临时库并用 `DATABASE_URL`(`just test-pg` 里连的是 app role),
// 而 tenants 在 idm schema、须以 idm role 连接 —— 显式建池,读 IDM_DATABASE_URL
// (缺省回退本地 compose 的 idm role)。镜像 search_repo_conformance 的 harness。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::tenant_repo_contract;
    use baserust::features::tenants::{PgTenantRepo, TenantRepo};
    use uuid::Uuid;

    async fn connect() -> sqlx::PgPool {
        let url = std::env::var("IDM_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://idm:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let pool = sqlx::PgPool::connect(&url)
            .await
            .expect("连 idm role 失败(先 `just up` + `just migrate-idm`)");
        sqlx::migrate!("migrations/idm")
            .run(&pool)
            .await
            .expect("跑 migrations/idm 失败(幂等,应可重复跑)");
        pool
    }

    /// `tenant_members.user_id` 有 FK 到 `users` —— PG 侧必须先插一行真 user。
    /// 内存侧没有 FK,故这一步只在 PG 入口。
    async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query("insert into users (id, username, email_verified) values ($1, $2, false)")
            .bind(id)
            .bind(format!("tenant-contract-{id}"))
            .execute(pool)
            .await
            .expect("插测试 user 失败");
        id
    }

    #[tokio::test]
    async fn pg_satisfies_tenant_contract() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool);
        tenant_repo_contract(&repo, user_id).await;
    }

    /// **软删过滤补验(只 PG 侧)** —— 内存契约验不了这一半:`TenantRepo` 没有「软删租户」
    /// 方法(P1 的 seed/切换都用不上,YAGNI 没加),内存的 MemStore 又是私有的,测试造不出
    /// `deleted_at` 状态。PG 侧可以用 raw SQL 直接盖 `deleted_at` 绕过 trait 造出该状态。
    /// (镜像 profile_repo_conformance 用临时 CHECK 约束造写入失败来测回滚的手法 ——
    /// PG-only 的断言允许单独加在 `mod pg` 里,不进共享契约。)
    #[tokio::test]
    async fn pg_memberships_filters_soft_deleted_tenant() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());

        let t = Uuid::now_v7();
        repo.upsert_tenant(
            t,
            &format!("softdel-{t}"),
            "Soon Deleted",
            baserust::features::tenants::TenantStatus::Active,
            None,
        )
        .await
        .unwrap();
        repo.upsert_member(
            user_id,
            t,
            baserust::features::tenants::TenantRole::Admin,
            None,
        )
        .await
        .unwrap();

        // 软删前:可见
        assert!(repo.membership(user_id, t).await.unwrap().is_some());

        // raw SQL 直接软删(绕过 trait —— trait 刻意没有这个方法)
        sqlx::query("update tenants set deleted_at = (now() at time zone 'utc') where id = $1")
            .bind(t)
            .execute(&pool)
            .await
            .expect("软删 tenant 失败");

        // 软删后:memberships 和 membership 都必须过滤掉它
        assert_eq!(
            repo.membership(user_id, t).await.unwrap(),
            None,
            "软删的租户 membership 单查必须回 None"
        );
        assert!(
            repo.memberships(user_id)
                .await
                .unwrap()
                .iter()
                .all(|m| m.tenant_id != t),
            "软删的租户不得出现在 memberships 里"
        );
    }
}

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

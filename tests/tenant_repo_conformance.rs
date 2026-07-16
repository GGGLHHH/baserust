//! TenantRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//!
//! **共享契约钉**(两侧同跑):memberships 过滤停用租户(status=suspended)、granted_at 升序
//! 且不因改角色而重置、membership 非成员回 None、set_active upsert、active 回环。
//!
//! **只 PG 侧能验的**(`TenantRepo` 无「软删租户」方法、`MemStore` 私有,内存造不出该状态,
//! PG 可用 raw SQL 绕过 trait 造):
//! - `pg_memberships_filters_soft_deleted_tenant` —— 软删的租户不出现在 memberships
//! - `pg_upsert_tenant_does_not_revive_soft_deleted` —— upsert 不把 deleted_at 改回 null
//!
//! **两侧刻意不同、各自钉住的**(见 `repo/mod.rs` trait doc 的「已知分歧」):
//! - `memory_does_not_enforce_referential_integrity` / `pg_enforces_referential_integrity_and_name_uniqueness`
//!   —— FK 与 name 唯一性只在 PG 侧强制。两条一起守着 doc,任一侧行为变了就红。
//!
//! **本测试连 idm role**(非 `#[sqlx::test]` 默认的 app role/`DATABASE_URL`)——
//! tenants 表在 idm schema,app role 的 search_path=app 物理碰不到。形状照
//! `search_repo_conformance.rs`,不是 widget/profile。
//!
//! **无每测试隔离的临时库**(表跨测试运行共享)⇒ 契约里恒用全新 `Uuid::now_v7()` 造数据、
//! **绝不断言全表 count/total**,且 PG 入口跑完自己 `cleanup`(断言失败时故意不清,留现场)。

use baserust::features::tenants::{Membership, TenantRepo, TenantRole, TenantStatus};
use uuid::Uuid;

/// `granted_at` 取自墙钟(内存 `OffsetDateTime::now_utc()` / PG `clock_timestamp()`),两者都
/// **不是**单调钟。相邻两次授予若落进同一时刻,排序会掉到 tenant_id tiebreak —— 而下面的顺序
/// 用例刻意让 tenant_id 序与授予序**相反**,平局会让断言必然失败而不是降级。
/// 故授予之间留一个远大于时钟分辨率的真实间隔(PG 的 timestamptz 是微秒级)。
///
/// 用 `std::thread::sleep` 而非 `tokio::time::sleep`:`Cargo.toml` 的 tokio **没开 `time`
/// feature**,后者根本编译不过。`#[tokio::test]` 是 current_thread runtime、本测试内无并发
/// 任务,阻塞 2ms 无影响 —— 别"顺手改成" async sleep。
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(2));
}

/// 契约本体。返回它建的租户 id —— PG 入口据此清理(表跨运行共享,见文件头)。
/// `user_id` 由调用方准备 —— PG 侧 `tenant_members.user_id` 有 FK 到 `users`,
/// 必须先插一行真 user;内存侧没有 FK,随便一个 uuid 即可。
async fn tenant_repo_contract(repo: &dyn TenantRepo, user_id: Uuid) -> Vec<Uuid> {
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

    // ── granted_at 升序,且不能是同义反复(TenantRoleRepo 的 .or(ms.first()) 回退依赖它)──
    // 陷阱 1:`Uuid::now_v7()` 按生成顺序单调递增 —— 若按生成顺序把新 uuid 的租户排在
    //   后面才授予成员资格,`order by granted_at` 与 `order by tenant_id` 结论恒一致,
    //   测不出真按 granted_at 排序。破法:生成两个 uuid、比较大小,**故意让 uuid 更大
    //   的那个先被授予成员资格**——granted_at 序与 tenant_id 序因此相反,
    //   `order by tenant_id` 单独就会给出错误结果。
    let x = Uuid::now_v7();
    let y = Uuid::now_v7();
    let (t_early, t_late) = if x > y { (x, y) } else { (y, x) };
    // t_early:tenant_id 更大,但先被授予成员资格 → granted_at 更早,契约要求它排前面
    repo.upsert_tenant(
        t_early,
        &format!("early-{t_early}"),
        "Early",
        TenantStatus::Active,
        None,
    )
    .await
    .unwrap();
    repo.upsert_tenant(
        t_late,
        &format!("late-{t_late}"),
        "Late",
        TenantStatus::Active,
        None,
    )
    .await
    .unwrap();
    repo.upsert_member(user_id, t_early, TenantRole::Member, None)
        .await
        .unwrap();
    tick(); // 见 tick() 的 doc:平局会让下面的断言必然红,不能靠时钟侥幸
    repo.upsert_member(user_id, t_late, TenantRole::Member, None)
        .await
        .unwrap();

    let pos = |ms: &[Membership], id: Uuid| ms.iter().position(|m| m.tenant_id == id).unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert!(
        pos(&ms, t_early) < pos(&ms, t_late),
        "granted_at 升序:先授予的必须排在前,即便它的 tenant_id 更大\
         (排除 order by tenant_id 的同义反复)"
    );

    // 陷阱 2:若在只有一个存活成员时重置它的 granted_at,顺序断言观察不到差异
    //   (重置后的时间戳仍早于之后才加入的第二个成员)。破法:把 re-upsert 挪到
    //   t_late 已经存在、已经被授予**之后**——若 upsert_member 重置了 t_early 的
    //   granted_at,它会晚于 t_late 的授予时间,顺序翻转,可被观察到。
    tick(); // 同上:重置若发生,新 granted_at 必须可分辨地晚于 t_late 的
    repo.upsert_member(user_id, t_early, TenantRole::Admin, None)
        .await
        .unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(
        ms.len(),
        3,
        "t_alive + t_early + t_late,t_suspended 仍被过滤"
    );
    assert_eq!(
        ms.iter().find(|m| m.tenant_id == t_early).unwrap().role,
        TenantRole::Admin,
        "角色必须被替换"
    );
    assert!(
        pos(&ms, t_early) < pos(&ms, t_late),
        "upsert_member 替换角色不得重置 granted_at(顺序不该因为改角色而翻转)"
    );

    vec![t_alive, t_suspended, t_early, t_late]
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_tenant_contract() {
    let repo = baserust::features::tenants::InMemoryTenantRepo::new();
    // 返回的租户 id 只有 PG 入口要(清理用),内存进程结束即散
    let _ = tenant_repo_contract(&repo, Uuid::now_v7()).await;
}

/// 「已知分歧」的内存侧守卫 —— 与 `pg_enforces_referential_integrity_and_name_uniqueness` 成对。
/// `repo/mod.rs` 的 trait doc 白纸黑字断言「内存 → 静默成功 / 静默接受」;没有测试守着,
/// 哪天有人觉得「内存该更严谨」补上校验,那段 doc 就静默变成谎言而 CI 全绿。
#[tokio::test]
async fn memory_does_not_enforce_referential_integrity() {
    let repo = baserust::features::tenants::InMemoryTenantRepo::new();

    // 不存在的 user / tenant:内存不校验(PG 侧是 FK 违约,见成对的 pg 用例)
    assert!(
        repo.set_active(Uuid::now_v7(), Uuid::now_v7())
            .await
            .is_ok(),
        "内存不校验引用完整性 —— 若这条红了,trait doc 的「已知分歧」要跟着改"
    );
    assert!(
        repo.upsert_member(Uuid::now_v7(), Uuid::now_v7(), TenantRole::Admin, None)
            .await
            .is_ok(),
        "同上"
    );

    // 同名两个存活租户:内存允许(PG 侧是 tenants_name_alive_uidx 违约)
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    repo.upsert_tenant(a, "dup", "A", TenantStatus::Active, None)
        .await
        .unwrap();
    assert!(
        repo.upsert_tenant(b, "dup", "B", TenantStatus::Active, None)
            .await
            .is_ok(),
        "内存不校验 name 唯一性 —— 若这条红了,trait doc 的「已知分歧」要跟着改"
    );
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

    /// 表跨测试运行共享(见文件头)⇒ 不清理就是每跑一次 `just test-pg` 往 dev 的 idm 库
    /// 永久留下一批 `tenant-contract-*` 用户和 `acme-*`/`dead-*` 租户。
    /// 顺序:先删 user —— `tenant_members.user_id` 与 `user_active_tenant.user_id` 都是
    /// `on delete cascade`,连带清掉引用;租户才不再被引用、可删(tenant_id 侧刻意无 cascade)。
    /// **这个顺序是唯一的清理入口** —— 没建 user 的用例传 `None`,别在别处手抄一遍 delete。
    /// 断言失败时 panic 会跳过清理 —— 那正好:现场留给你查。
    async fn cleanup(pool: &sqlx::PgPool, user_id: Option<Uuid>, tenant_ids: &[Uuid]) {
        if let Some(id) = user_id {
            sqlx::query("delete from users where id = $1")
                .bind(id)
                .execute(pool)
                .await
                .expect("清理测试 user 失败");
        }
        sqlx::query("delete from tenants where id = any($1)")
            .bind(tenant_ids)
            .execute(pool)
            .await
            .expect("清理测试 tenants 失败");
    }

    #[tokio::test]
    async fn pg_satisfies_tenant_contract() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());
        let tenants = tenant_repo_contract(&repo, user_id).await;
        cleanup(&pool, Some(user_id), &tenants).await;
    }

    /// 「已知分歧」的 PG 侧对照 —— 与 `memory_does_not_enforce_referential_integrity` 成对。
    /// 两条一起把 `repo/mod.rs` trait doc 的「PG → 违约;内存 → 静默成功」钉住:
    /// 任一侧行为漂了,对应那条就红,doc 不会静默变谎。
    #[tokio::test]
    async fn pg_enforces_referential_integrity_and_name_uniqueness() {
        let pool = connect().await;
        let repo = PgTenantRepo::new(pool.clone());

        // 不存在的 user / tenant → FK 违约(内存侧是静默成功)
        assert!(
            repo.set_active(Uuid::now_v7(), Uuid::now_v7())
                .await
                .is_err(),
            "PG 靠 FK 拒绝不存在的 user/tenant"
        );
        assert!(
            repo.upsert_member(
                Uuid::now_v7(),
                Uuid::now_v7(),
                baserust::features::tenants::TenantRole::Admin,
                None
            )
            .await
            .is_err(),
            "同上"
        );

        // 同名两个存活租户 → tenants_name_alive_uidx 违约(内存侧允许重名)
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let name = format!("dup-{a}");
        repo.upsert_tenant(
            a,
            &name,
            "A",
            baserust::features::tenants::TenantStatus::Active,
            None,
        )
        .await
        .unwrap();
        assert!(
            repo.upsert_tenant(
                b,
                &name,
                "B",
                baserust::features::tenants::TenantStatus::Active,
                None
            )
            .await
            .is_err(),
            "PG 的 partial unique index 拒绝同名存活租户"
        );

        cleanup(&pool, None, &[a, b]).await;
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

        cleanup(&pool, Some(user_id), &[t]).await;
    }

    /// **`upsert_tenant` 不复活软删租户(只 PG 侧)** —— 软删是 spec §4.4 当作安全控制的
    /// 机制,而 P2 的 `seed::apply` 每次启动都会按 id 重新 `upsert_tenant`;若 upsert 把
    /// `deleted_at` 悄悄改回 null,运维手工做的停用决定会在下次重启被无声撤销。
    /// 内存侧验不了(同上,MemStore 私有、trait 无软删方法),故 raw SQL 直接查
    /// `deleted_at` 列绕过 trait 断言。
    #[tokio::test]
    async fn pg_upsert_tenant_does_not_revive_soft_deleted() {
        let pool = connect().await;
        let repo = PgTenantRepo::new(pool.clone());

        let t = Uuid::now_v7();
        repo.upsert_tenant(
            t,
            &format!("revive-{t}"),
            "Maybe Revived",
            baserust::features::tenants::TenantStatus::Active,
            None,
        )
        .await
        .unwrap();

        // raw SQL 直接软删
        sqlx::query("update tenants set deleted_at = (now() at time zone 'utc') where id = $1")
            .bind(t)
            .execute(&pool)
            .await
            .expect("软删 tenant 失败");

        // 模拟 seed::apply 每次启动都重跑的 upsert_tenant(同 id,内容不变)
        repo.upsert_tenant(
            t,
            &format!("revive-{t}"),
            "Maybe Revived",
            baserust::features::tenants::TenantStatus::Active,
            None,
        )
        .await
        .unwrap();

        // 直接查列:必须仍是软删的,upsert_tenant 不得把 deleted_at 改回 null
        let deleted_at: Option<time::OffsetDateTime> =
            sqlx::query_scalar("select deleted_at from tenants where id = $1")
                .bind(t)
                .fetch_one(&pool)
                .await
                .expect("查 deleted_at 失败");
        assert!(
            deleted_at.is_some(),
            "upsert_tenant 不得静默复活软删租户(deleted_at 被清空了)"
        );

        cleanup(&pool, None, &[t]).await; // 本测试没建 user
    }
}

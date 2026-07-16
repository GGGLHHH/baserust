//! TenantRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//!
//! **共享契约钉**(两侧同跑):memberships 过滤停用租户、seq 升序且不因改角色而重置、
//! membership 单查的**完整内容**、is_active 标记、set_active upsert、空态。
//!
//! **只 PG 侧能验的**(内存有等价覆盖,见 `repo/memory.rs` 的 `#[cfg(test)] mod tests` ——
//! 那边靠 cfg(test) 口子造软删,集成测试链接的是正常编译的 lib、看不见 cfg(test)):
//! - `pg_memberships_filters_soft_deleted_tenant` —— 软删的租户不出现在两条读路径里
//! - `pg_upsert_tenant_does_not_revive_soft_deleted` —— upsert 不把 deleted_at 改回 null
//! - `pg_set_active_updated_at_is_trigger_maintained` —— updated_at 归触发器、且值未变不推进
//! - `pg_audit_columns` —— created_by 替时保留 / updated_by 按 by 覆盖 / granted_by 改角色时冻结
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

/// 建租户的 setup helper —— 契约里建 4 个租户,每个 7 行样板不值得手抄 4 遍。
async fn mk_tenant(repo: &dyn TenantRepo, id: Uuid, prefix: &str, display: &str, s: TenantStatus) {
    repo.upsert_tenant(id, &format!("{prefix}-{id}"), display, s, None)
        .await
        .unwrap();
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
    assert_eq!(repo.membership(user_id, t_alive).await.unwrap(), None);

    mk_tenant(repo, t_alive, "acme", "Acme", TenantStatus::Active).await;
    mk_tenant(
        repo,
        t_suspended,
        "dead",
        "Dead Corp",
        TenantStatus::Suspended,
    )
    .await;
    repo.upsert_member(user_id, t_alive, TenantRole::Admin, None)
        .await
        .unwrap();
    repo.upsert_member(user_id, t_suspended, TenantRole::Member, None)
        .await
        .unwrap();

    // ── 契约核心:停用的租户不出现在 memberships 里 + **复数路径也断言完整内容** ──
    // 单复数走**两条独立 SQL + 独立解码**,谁的内容断言都接不住对方 —— 两边都得断全等。
    // (P2 的 §4.9 租户列表端点吃的正是复数路径。)
    assert_eq!(
        repo.memberships(user_id).await.unwrap(),
        vec![Membership {
            tenant_id: t_alive,
            name: format!("acme-{t_alive}"),
            display_name: "Acme".into(),
            role: TenantRole::Admin,
            is_active: false, // 还没 set_active
        }],
        "suspended 租户必须被过滤掉,且存活那条的每个字段都要对"
    );

    // ── membership 单查:**断言完整内容**,不只是 is_some() ──
    // 真正的风险是**别名写反**(`t.display_name as name`)—— `Membership` 派生 sqlx::FromRow,
    // 按**列名**取值,所以 select 里的**列序对调是无害的**(实测:对调后 8/8 全绿)。
    // 单数走独立 SQL + 独立解码,复数版的内容断言接不住它;而它正是 P2 切租户端点的安全支点。
    assert_eq!(
        repo.membership(user_id, t_alive).await.unwrap(),
        Some(Membership {
            tenant_id: t_alive,
            name: format!("acme-{t_alive}"),
            display_name: "Acme".into(),
            role: TenantRole::Admin,
            is_active: false,
        })
    );
    assert_eq!(
        repo.membership(user_id, t_suspended).await.unwrap(),
        None,
        "suspended 租户的 membership 单查也必须回 None"
    );

    // ── set_active / is_active 回环 ──
    repo.set_active(user_id, t_alive).await.unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert!(ms[0].is_active, "set_active 后该条必须带激活标记");
    assert!(
        repo.membership(user_id, t_alive)
            .await
            .unwrap()
            .unwrap()
            .is_active,
        "单查也要带 is_active"
    );

    // active 指向一个**已失效**(此处:停用)的租户 → 刻意与「未设 active」坍缩成同一结果:
    // 没有任何一条 is_active(spec §4.1 的回退对两者处理相同,都退到 .first())
    repo.set_active(user_id, t_suspended).await.unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    // 先钉长度再断言标记 —— `.all()` 对**空列表恒真**,单用它区分不了「恰好没有激活标记」
    // 与「memberships 整体失效返回空」。
    assert_eq!(ms.len(), 1, "t_alive 仍在(t_suspended 被过滤)");
    assert!(
        !ms[0].is_active,
        "active 指向已失效租户 ⇒ 没有任何一条带激活标记"
    );

    // ── upsert_member 是替换,不是插重 ──
    repo.upsert_member(user_id, t_alive, TenantRole::Member, None)
        .await
        .unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 1, "同 (user,tenant) 再 upsert 必须替换而非新增");
    assert_eq!(ms[0].role, TenantRole::Member);

    // ── seq 升序,且不能是同义反复(TenantRoleRepo 的 .or(ms.first()) 回退依赖它)──
    // 陷阱:`Uuid::now_v7()` 按生成顺序单调递增 —— 若按生成顺序把新 uuid 的租户排在后面才
    //   授予成员资格,`order by seq` 与 `order by tenant_id` 结论恒一致,测不出真按 seq 排序。
    //   破法:生成两个 uuid、比较大小,**故意让 tenant_id 更大的那个先被授予** ——
    //   seq 序与 tenant_id 序因此相反,`order by tenant_id` 单独就会给出错误结果。
    // 注:不需要 sleep —— seq 是 `Uuid::now_v7()`,同进程内严格全序、不会打平
    //   (旧实现拿墙钟 granted_at 排序时必须 sleep 2ms 才能拉开,见 migration 注释)。
    let (x, y) = (Uuid::now_v7(), Uuid::now_v7());
    let (t_early, t_late) = if x > y { (x, y) } else { (y, x) };
    mk_tenant(repo, t_early, "early", "Early", TenantStatus::Active).await;
    mk_tenant(repo, t_late, "late", "Late", TenantStatus::Active).await;
    repo.upsert_member(user_id, t_early, TenantRole::Member, None)
        .await
        .unwrap();
    repo.upsert_member(user_id, t_late, TenantRole::Member, None)
        .await
        .unwrap();

    let pos = |ms: &[Membership], id: Uuid| ms.iter().position(|m| m.tenant_id == id).unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert!(
        pos(&ms, t_early) < pos(&ms, t_late),
        "seq 升序:先授予的必须排在前,即便它的 tenant_id 更大(排除 order by tenant_id 的同义反复)"
    );

    // 改角色不得重置 seq —— re-upsert 挪到 t_late 已被授予**之后**:若 seq 被重置,
    // t_early 会排到 t_late 后面,顺序翻转、可观察。
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
        "upsert_member 替换角色不得重置 seq(顺序不该因为改角色而翻转)"
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

    // 文本列的存储约束:PG 拒 NUL、拒超长高熵 name(btree 索引行上限);内存一概接受
    assert!(
        repo.upsert_tenant(Uuid::now_v7(), "a\0b", "c\0d", TenantStatus::Active, None)
            .await
            .is_ok(),
        "内存接受 NUL 字节(Rust String 合法容纳 U+0000)—— PG 侧是 null character not permitted"
    );
    let long: String = std::iter::repeat_with(fastrand_alnum).take(4000).collect();
    assert!(
        repo.upsert_tenant(Uuid::now_v7(), &long, "Long", TenantStatus::Active, None)
            .await
            .is_ok(),
        "内存接受超长 name —— PG 侧撞 tenants_name_alive_uidx 的 btree 行上限"
    );
}

/// 造高熵字符 —— 全 'x' 那种可压缩内容会被 TOAST 压掉、**测不出** btree 行上限。
/// 不引第三方 rng:用 uuid 的随机位当熵源(本就已依赖 uuid)。
fn fastrand_alnum() -> char {
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let b = Uuid::new_v4().as_bytes()[0];
    ALNUM[b as usize % ALNUM.len()] as char
}

// ── 入口 2:PG(需 --features pg-conformance + idm role 跑着的 pg)──
// **不用 `#[sqlx::test]`**:它建临时库并用 `DATABASE_URL`(`just test-pg` 里连的是 app role),
// 而 tenants 在 idm schema、须以 idm role 连接 —— 显式建池,读 IDM_DATABASE_URL
// (缺省回退本地 compose 的 idm role)。镜像 search_repo_conformance 的 harness。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{fastrand_alnum, mk_tenant, tenant_repo_contract};
    use baserust::features::tenants::{PgTenantRepo, TenantRepo, TenantRole, TenantStatus};
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

    async fn soft_delete_tenant(pool: &sqlx::PgPool, id: Uuid) {
        sqlx::query("update tenants set deleted_at = now() where id = $1")
            .bind(id)
            .execute(pool)
            .await
            .expect("软删 tenant 失败");
    }

    /// 表跨测试运行共享(见文件头)⇒ 不清理就是每跑一次 `just test-pg` 往 dev 的 idm 库
    /// 永久留下一批 `tenant-contract-*` 用户和 `acme-*`/`dead-*` 租户。
    /// 顺序:先删 user —— `tenant_members.user_id` 与 `user_active_tenant.user_id` 都是
    /// `on delete cascade`,连带清掉引用;租户才不再被引用、可删(tenant_id 侧刻意无 cascade)。
    /// **这是唯一的清理入口** —— 没建 user 的用例传 `None`,别在别处手抄一遍 delete。
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
    /// 两条一起把 trait doc 的「PG → 违约;内存 → 静默成功」钉住:任一侧行为漂了就红。
    #[tokio::test]
    async fn pg_enforces_referential_integrity_and_name_uniqueness() {
        let pool = connect().await;
        let repo = PgTenantRepo::new(pool.clone());

        // 不存在的 user / tenant → FK 违约(内存侧静默成功)
        assert!(
            repo.set_active(Uuid::now_v7(), Uuid::now_v7())
                .await
                .is_err(),
            "PG 靠 FK 拒绝不存在的 user/tenant"
        );
        assert!(
            repo.upsert_member(Uuid::now_v7(), Uuid::now_v7(), TenantRole::Admin, None)
                .await
                .is_err(),
            "同上"
        );

        // 同名两个存活租户 → tenants_name_alive_uidx 违约(内存侧允许重名)
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let name = format!("dup-{a}");
        repo.upsert_tenant(a, &name, "A", TenantStatus::Active, None)
            .await
            .unwrap();
        assert!(
            repo.upsert_tenant(b, &name, "B", TenantStatus::Active, None)
                .await
                .is_err(),
            "PG 的 partial unique index 拒绝同名存活租户"
        );

        // NUL 字节 → PG text 列拒(内存接受)
        assert!(
            repo.upsert_tenant(Uuid::now_v7(), "a\0b", "C", TenantStatus::Active, None)
                .await
                .is_err(),
            "PG: null character not permitted"
        );
        // 超长**高熵** name → 撞 btree 索引行上限(可压缩内容会被 TOAST 压掉、测不出来)
        let long: String = std::iter::repeat_with(fastrand_alnum).take(4000).collect();
        assert!(
            repo.upsert_tenant(Uuid::now_v7(), &long, "D", TenantStatus::Active, None)
                .await
                .is_err(),
            "PG: index row size exceeds btree maximum"
        );

        cleanup(&pool, None, &[a, b]).await;
    }

    /// 软删过滤(spec §4.4 的「安全支点」)—— 内存侧的等价覆盖在 `repo/memory.rs` 的
    /// `#[cfg(test)] mod tests`(那边靠 cfg(test) 口子造软删;集成测试看不见 cfg(test))。
    #[tokio::test]
    async fn pg_memberships_filters_soft_deleted_tenant() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());

        let t = Uuid::now_v7();
        mk_tenant(&repo, t, "softdel", "Soon Deleted", TenantStatus::Active).await;
        repo.upsert_member(user_id, t, TenantRole::Admin, None)
            .await
            .unwrap();
        assert!(repo.membership(user_id, t).await.unwrap().is_some());

        soft_delete_tenant(&pool, t).await;

        assert_eq!(
            repo.membership(user_id, t).await.unwrap(),
            None,
            "软删的租户 membership 单查必须回 None"
        );
        // 用 assert_eq!(.., vec![]) 而非 .all(|m| m.tenant_id != t) —— 后者对空列表恒真,
        // 区分不了「恰好过滤掉这一条」与「查询整体失效返回空」。该用户只有 t 这一个成员资格。
        assert_eq!(
            repo.memberships(user_id).await.unwrap(),
            vec![],
            "软删的租户不得出现在 memberships 里"
        );

        cleanup(&pool, Some(user_id), &[t]).await;
    }

    /// `upsert_tenant` 不复活软删租户 —— seed::apply 每次启动都重跑,不能让一次重启
    /// 无声撤销运维手工做的停用决定。内存侧等价覆盖见 `repo/memory.rs` 的单元测试。
    #[tokio::test]
    async fn pg_upsert_tenant_does_not_revive_soft_deleted() {
        let pool = connect().await;
        let repo = PgTenantRepo::new(pool.clone());

        let t = Uuid::now_v7();
        mk_tenant(&repo, t, "revive", "Maybe Revived", TenantStatus::Active).await;
        soft_delete_tenant(&pool, t).await;

        // 模拟 seed::apply 每次启动都重跑的 upsert_tenant(同 id,内容不变)
        mk_tenant(&repo, t, "revive", "Maybe Revived", TenantStatus::Active).await;

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

        cleanup(&pool, None, &[t]).await;
    }

    /// `user_active_tenant.updated_at` 归触发器维护(SQL 里不写它),且**值未变时不推进**。
    /// 没有这条,谁把 trigger 弄丢(改名/迁移重排)都不会红 —— trait 上没有读 updated_at 的方法,
    /// 只能 raw SQL 直接查。
    #[tokio::test]
    async fn pg_set_active_updated_at_is_trigger_maintained() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        mk_tenant(&repo, a, "tz-a", "A", TenantStatus::Active).await;
        mk_tenant(&repo, b, "tz-b", "B", TenantStatus::Active).await;

        let read = |p: sqlx::PgPool, u: Uuid| async move {
            sqlx::query_scalar::<_, time::OffsetDateTime>(
                "select updated_at from user_active_tenant where user_id = $1",
            )
            .bind(u)
            .fetch_one(&p)
            .await
            .expect("查 updated_at 失败")
        };

        repo.set_active(user_id, a).await.unwrap();
        let t0 = read(pool.clone(), user_id).await;

        // 同一个值再设一次 → `is distinct from` 守卫拦住,不 UPDATE ⇒ 触发器不触发 ⇒ 时间戳不动。
        // (没有守卫的话 PG 的 BEFORE UPDATE 触发器会无条件触发 —— 它不比较 NEW/OLD。)
        repo.set_active(user_id, a).await.unwrap();
        assert_eq!(
            read(pool.clone(), user_id).await,
            t0,
            "值未变 ⇒ updated_at 不该动"
        );

        // 换个值 → 真的 UPDATE ⇒ 触发器把 updated_at 推进(SQL 里没写这一列)
        repo.set_active(user_id, b).await.unwrap();
        assert!(
            read(pool.clone(), user_id).await > t0,
            "值变了 ⇒ 触发器必须推进 updated_at(丢了 trigger 这条会红)"
        );

        cleanup(&pool, Some(user_id), &[a, b]).await;
    }

    /// 审计列:created_by 替时保留 / updated_by 按 by 覆盖(含 None → NULL)/
    /// granted_by 改角色时冻结。trait 上没有读回这些列的方法,只能 raw SQL 查 ——
    /// 没有这条,把 `$5, $5` 的绑定写错或让 granted_by 随写覆盖都不会红。
    /// 内存侧等价覆盖见 `repo/memory.rs` 的 `by_preserve_semantics_match_pg`。
    #[tokio::test]
    async fn pg_audit_columns() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());
        let t = Uuid::now_v7();

        repo.upsert_tenant(
            t,
            &format!("audit-{t}"),
            "Audit",
            TenantStatus::Active,
            Some("carol".into()),
        )
        .await
        .unwrap();
        repo.upsert_member(user_id, t, TenantRole::Admin, Some("carol".into()))
            .await
            .unwrap();

        let tenant_audit = |p: sqlx::PgPool| async move {
            sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "select created_by, updated_by from tenants where id = $1",
            )
            .bind(t)
            .fetch_one(&p)
            .await
            .expect("查 tenants 审计列失败")
        };
        let member_audit = |p: sqlx::PgPool| async move {
            sqlx::query_as::<_, (Option<String>, time::OffsetDateTime)>(
                "select granted_by, granted_at from tenant_members \
                 where user_id = $1 and tenant_id = $2",
            )
            .bind(user_id)
            .bind(t)
            .fetch_one(&p)
            .await
            .expect("查 tenant_members 审计列失败")
        };

        // 建时:两列都落 by。**这一点不能省** —— 只断「替换后是 NULL」的话,一个压根没接线
        // updated_by 的实现(该列可空、无 default ⇒ 天然恒 NULL)照样绿,区分不出来。
        let (created_by, updated_by) = tenant_audit(pool.clone()).await;
        assert_eq!(
            created_by.as_deref(),
            Some("carol"),
            "建时 created_by 落 by"
        );
        assert_eq!(
            updated_by.as_deref(),
            Some("carol"),
            "建时 updated_by 落 by"
        );
        let (granted_by_0, granted_at_0) = member_audit(pool.clone()).await;
        assert_eq!(granted_by_0.as_deref(), Some("carol"));

        // 替换:created_by 保留、updated_by 按 by 覆盖 —— None 就是写 NULL,不是「保持不变」
        // (与 profile/repo/postgres.rs 的 UPSERT_SQL 同口径;coalesce 会宣称 carol 做了
        //  这次她没做的更新,那是说谎。见 repo/mod.rs 的「by 的语义」)
        repo.upsert_tenant(
            t,
            &format!("audit-{t}"),
            "Audit Inc",
            TenantStatus::Active,
            None,
        )
        .await
        .unwrap();
        let (created_by, updated_by) = tenant_audit(pool.clone()).await;
        assert_eq!(created_by.as_deref(), Some("carol"), "created_by 替时保留");
        assert_eq!(updated_by, None, "updated_by 按 by 覆盖,None 就是 NULL");

        // 改角色:granted_by **与 granted_at 都**冻结 —— 与 seq 同属「何时被谁加进来」这一次事件。
        // 只钉 granted_by 不够:doc 声称三者全冻结,granted_at 也得有断言,否则它裸奔。
        repo.upsert_member(user_id, t, TenantRole::Member, Some("bob".into()))
            .await
            .unwrap();
        let (granted_by, granted_at) = member_audit(pool.clone()).await;
        assert_eq!(
            granted_by.as_deref(),
            Some("carol"),
            "改角色不得改 granted_by —— 否则是从未发生过的审计事件"
        );
        assert_eq!(granted_at, granted_at_0, "改角色不得重置 granted_at");

        cleanup(&pool, Some(user_id), &[t]).await;
    }
}

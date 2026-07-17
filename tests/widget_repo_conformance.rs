//! WidgetRepo 契约一致性:**同一批断言对 InMemoryWidgetRepo 与 PgWidgetRepo 各跑一遍**,
//! 钉死两实现的行为 parity —— 软删过滤 / 排序 / keyset / offset / with_total / 幂等 / 审计字段透传。
//! "内存绿不保证 PG 绿"的漂移,全靠这一套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`cargo test --features pg-conformance`(需 DATABASE_URL 连 app role + 跑着的 pg),用 `just test-pg`。

use baserust::features::widget::{WidgetRepo, WidgetSortField};
use baserust::infra::authz::TenantId;
use baserust::infra::error::AppError;
use baserust::infra::pagination::{decode_cursor, PageInfo, PageParams};
use baserust::infra::sort::SortOrder;
use uuid::Uuid;

/// 契约唯一真相源。内存与 PG 都调它 —— 加实现/加断言只改这一处。
/// 只断言顺序·相对关系(updated_at >= created_at)·可见性,绝不断言绝对时间戳
/// (PG `now()` ≠ memory `now_utc()`,断绝对值必假漂移)。
async fn widget_repo_contract(repo: &dyn WidgetRepo) {
    // 本契约固定在**一个**租户 T 内跑 —— 它测的是软删/排序/分页/审计的 parity,不是隔离。
    // 跨租户隔离由 `tenant_isolation_contract`(下面)单独钉,memory 与 PG 同样各跑一遍。
    let t = TenantId::from_claim(Uuid::from_u128(0x7));

    // ── create:审计字段透传(created_by = updated_by = by)──
    let a = repo
        .create(t, "alpha".into(), Some("tester".into()))
        .await
        .unwrap();
    assert_eq!(a.created_by.as_deref(), Some("tester"));
    assert_eq!(a.updated_by.as_deref(), Some("tester"));

    // ── get 回环 + 不存在 → NotFound ──
    assert_eq!(repo.get(t, a.id).await.unwrap().name, "alpha");
    assert!(matches!(
        repo.get(t, Uuid::now_v7()).await,
        Err(AppError::NotFound)
    ));

    // 再造两行(uuid v7 单调递增:a.id < b.id < c.id)
    let b = repo.create(t, "bravo".into(), None).await.unwrap();
    let c = repo.create(t, "charlie".into(), None).await.unwrap();

    // ── offset:ORDER BY id DESC,with_total 计存活数 ──
    let p1 = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 2,
                with_total: true,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        p1.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![c.id, b.id]
    );
    assert!(matches!(
        p1.page_info,
        PageInfo::Offset { total: Some(3), .. }
    ));
    let p2 = repo
        .list(
            t,
            &PageParams::Offset {
                page: 2,
                size: 2,
                with_total: false,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        p2.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![a.id]
    );

    // ── cursor keyset:首页 has_more,next_cursor 解码后续翻 ──
    let cur1 = repo
        .list(
            t,
            &PageParams::Cursor {
                after: None,
                limit: 2,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        cur1.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![c.id, b.id]
    );
    let next = match cur1.page_info {
        PageInfo::Cursor {
            has_more,
            next_cursor,
            ..
        } => {
            assert!(has_more);
            next_cursor.unwrap()
        }
        _ => panic!("应是 cursor 模式"),
    };
    let cur2 = repo
        .list(
            t,
            &PageParams::Cursor {
                after: Some(decode_cursor(&next).unwrap()),
                limit: 2,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        cur2.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![a.id]
    );
    assert!(matches!(
        cur2.page_info,
        PageInfo::Cursor {
            has_more: false,
            ..
        }
    ));

    // ── ownership 过滤:owner=Some 只列该 created_by 的行,total 也按 owner 算(memory↔PG parity)──
    let mine = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
            Some("tester"), // a 的 created_by;b/c 是 None
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        mine.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![a.id]
    );
    assert!(matches!(
        mine.page_info,
        PageInfo::Offset { total: Some(1), .. }
    ));

    // ── update:改名 + updated_by + updated_at 推进;软删行不可改 ──
    let upd = repo
        .update(t, a.id, "alpha2".into(), Some("editor".into()))
        .await
        .unwrap();
    assert_eq!(upd.name, "alpha2");
    assert_eq!(upd.updated_by.as_deref(), Some("editor"));
    assert!(upd.updated_at >= upd.created_at); // 触发器 / now_utc() 都须满足

    // ── soft_delete 幂等 + 软删后不可见 ──
    repo.soft_delete(t, a.id, None).await.unwrap();
    assert!(matches!(repo.get(t, a.id).await, Err(AppError::NotFound)));
    assert!(matches!(
        repo.soft_delete(t, a.id, None).await,
        Err(AppError::NotFound)
    )); // 二次删幂等
    assert!(matches!(
        repo.update(t, a.id, "x".into(), None).await,
        Err(AppError::NotFound)
    )); // 改软删行
    let after = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(after.items.iter().all(|w| w.id != a.id)); // list 不含软删行
    assert!(matches!(
        after.page_info,
        PageInfo::Offset { total: Some(2), .. }
    ));

    // ── name 存活行内唯一 → DB 约束违例下钻成 Conflict(409),memory↔PG parity ──
    // 此刻存活:b(bravo)、c(charlie);a(alpha2)已软删。
    assert!(
        matches!(
            repo.create(t, "bravo".into(), None).await,
            Err(AppError::Conflict(_))
        ),
        "重名 create 应 Conflict"
    );
    assert!(
        matches!(
            repo.update(t, c.id, "bravo".into(), None).await,
            Err(AppError::Conflict(_))
        ),
        "改名撞已有存活名应 Conflict"
    );
    // a 此前叫 alpha2 且已软删 → 同名可被新行复用(部分唯一索引 WHERE deleted_at IS NULL)。
    repo.create(t, "alpha2".into(), None)
        .await
        .expect("软删行的名字应可复用");

    // NotFound 先于 Conflict:对已软删的 a 改成**存活名**(bravo)→ NotFound,不因撞名变 Conflict。
    // (PG 靠 WHERE deleted_at IS NULL 不命中软删行;memory 须先判存活再判唯一 —— 此用例钉死该顺序。)
    assert!(
        matches!(
            repo.update(t, a.id, "bravo".into(), None).await,
            Err(AppError::NotFound)
        ),
        "软删行 + 撞存活名应 NotFound(先判存活,再判唯一)"
    );
    // self-rename no-op:改成自己当前的名 → Ok 且名不变(唯一检查须排己 r.id != id,不误判 Conflict)。
    let same = repo
        .update(t, c.id, "charlie".into(), None)
        .await
        .expect("改成自己当前的名应 Ok(no-op rename)");
    assert_eq!(same.name, "charlie");

    // ── 父子双表事务:全有或全无(单条语句演示不出的东西)──
    // 成功:一笔里建 widget(父)+ 2 个 tag(子),回读 tag(label 升序)。
    let p = repo
        .create_with_tags(
            t,
            "tx-ok".into(),
            vec!["red".into(), "blue".into()],
            Some("u".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        repo.tags_of(t, p.id).await.unwrap(),
        vec!["blue".to_owned(), "red".to_owned()]
    );
    assert_eq!(repo.get(t, p.id).await.unwrap().name, "tx-ok");

    // **原子性**:批内重复 label → 子表 (widget_id,label) 唯一违例 → 整笔回滚,**widget 父行也不该存在**。
    // PG:父先插、子失败 → ROLLBACK 撤掉父;memory:先校验后落盘 → 父根本没插。两者外部都是"全有或全无"。
    let before = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        repo.create_with_tags(
            t,
            "tx-rollback".into(),
            vec!["dup".into(), "dup".into()],
            None
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    let after = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        before.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        after.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        "事务失败必须全回滚:widget 父行不该出现"
    );

    // ── name 排序 parity:大小写混排必须字节序(PG COLLATE "C" == 内存 str::cmp)。否则 locale
    //    collation(en_US.utf8 等)会把 "apple" 排到 "Banana" 前,内存↔PG 分叉。──
    repo.create(t, "Banana".into(), None).await.unwrap();
    repo.create(t, "apple".into(), None).await.unwrap();
    let by_name = repo
        .list(
            t,
            &PageParams::Offset {
                page: 1,
                size: 100,
                with_total: false,
            },
            None,
            WidgetSortField::Name,
            SortOrder::Asc,
        )
        .await
        .unwrap();
    let names: Vec<&str> = by_name.items.iter().map(|w| w.name.as_str()).collect();
    let bi = names.iter().position(|n| *n == "Banana").unwrap();
    let ai = names.iter().position(|n| *n == "apple").unwrap();
    assert!(
        bi < ai,
        "name 排序必须字节序('B'=66 < 'a'=97 → Banana 在 apple 前),实际: {names:?}"
    );
}

/// **跨租户隔离契约**:A 永远看不到 B —— 这是多租户的核心断言,memory 与 PG 都必须过。
///
/// 单独成一个契约(而非塞进上面那个),因为上面测的是「一个租户内的 parity」,这里测的是
/// 「两个租户之间的墙」。两者用同一批 repo 方法,但断言的东西正交。
async fn tenant_isolation_contract(repo: &dyn WidgetRepo) {
    let a = TenantId::from_claim(Uuid::from_u128(0xA));
    let b = TenantId::from_claim(Uuid::from_u128(0xB));
    let page = || PageParams::Offset {
        page: 1,
        size: 100,
        with_total: true,
    };

    // A 建一行,B 建一行(**同名** —— 证明唯一约束是租户内的)。
    let wa = repo
        .create(a, "shared-name".into(), Some("alice".into()))
        .await
        .unwrap();
    let wb = repo
        .create(b, "shared-name".into(), Some("bob".into()))
        .await
        .unwrap();
    assert_ne!(wa.id, wb.id, "同名不同租户 → 两行,不是一行");

    // ── list:各租户只看得见自己的,total 也只算自己的 ──
    let la = repo
        .list(
            a,
            &page(),
            None,
            WidgetSortField::default(),
            SortOrder::default(),
        )
        .await
        .unwrap();
    assert_eq!(la.items.len(), 1);
    assert_eq!(la.items[0].id, wa.id, "A 的列表里绝不能出现 B 的行");
    if let PageInfo::Offset { total, .. } = la.page_info {
        assert_eq!(total, Some(1), "total 必须只算本租户 —— 泄露计数也是泄露");
    }

    // ── get:复合键。**B 拿着 A 的真实 id → NotFound**,与不存在无法区分 ──
    assert_eq!(repo.get(a, wa.id).await.unwrap().id, wa.id);
    assert!(
        matches!(repo.get(b, wa.id).await, Err(AppError::NotFound)),
        "B 用 A 的 id get → 必须 NotFound(不是 403,不泄露存在)"
    );

    // ── update / soft_delete:B 改不动、删不掉 A 的行 ──
    assert!(
        matches!(
            repo.update(b, wa.id, "hijacked".into(), None).await,
            Err(AppError::NotFound)
        ),
        "B 改 A 的行 → NotFound"
    );
    assert!(
        matches!(
            repo.soft_delete(b, wa.id, None).await,
            Err(AppError::NotFound)
        ),
        "B 删 A 的行 → NotFound"
    );
    // A 的行原封不动
    assert_eq!(
        repo.get(a, wa.id).await.unwrap().name,
        "shared-name",
        "越界写必须没有任何效果"
    );

    // ── tags_of:子表也隔离(B 拿 A 的 widget id → 空,不泄露标签)──
    let wt = repo
        .create_with_tags(a, "tagged".into(), vec!["secret".into()], None)
        .await
        .unwrap();
    assert_eq!(
        repo.tags_of(a, wt.id).await.unwrap(),
        vec!["secret"],
        "A 读得到自己的标签"
    );
    assert!(
        repo.tags_of(b, wt.id).await.unwrap().is_empty(),
        "B 拿 A 的 widget id 读标签 → 空"
    );
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_widget_contract() {
    use baserust::features::widget::InMemoryWidgetRepo;
    widget_repo_contract(&InMemoryWidgetRepo::new()).await;
}

/// 隔离契约的内存入口。**默认 cargo test 就跑** —— 这是最要紧的断言,不该只在 PG 下才验。
#[tokio::test]
async fn memory_isolates_tenants() {
    use baserust::features::widget::InMemoryWidgetRepo;
    tenant_isolation_contract(&InMemoryWidgetRepo::new()).await;
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 app role + 跑着的 pg)──
// support 提到顶层声明:#[path] 基目录是 tests/,正确指向 tests/support/mod.rs
// (放进 mod pg 内会被推成 tests/pg/support/mod.rs)。
#[cfg(feature = "pg-conformance")]
#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{support, tenant_isolation_contract, widget_repo_contract};

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_widget_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let repo = baserust::features::widget::PgWidgetRepo::new(pool);
        widget_repo_contract(&repo).await;
        Ok(())
    }

    /// 隔离契约的 PG 入口 —— 证明租户墙在真库上也立着,不只在内存里。
    /// 尤其钉 `widgets_tenant_name_unique_alive`:同名不同租户在**真的部分唯一索引**下不撞。
    #[sqlx::test(migrations = false)]
    async fn pg_isolates_tenants(pool: sqlx::PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let repo = baserust::features::widget::PgWidgetRepo::new(pool);
        tenant_isolation_contract(&repo).await;
        Ok(())
    }
}

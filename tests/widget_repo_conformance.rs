//! WidgetRepo 契约一致性:**同一批断言对 InMemoryWidgetRepo 与 PgWidgetRepo 各跑一遍**,
//! 钉死两实现的行为 parity —— 软删过滤 / 排序 / keyset / offset / with_total / 幂等 / 审计字段透传 / **租户隔离**。
//! "内存绿不保证 PG 绿"的漂移,全靠这一套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`cargo test --features pg-conformance`(DATABASE_URL 连 app_owner 建库迁移、仓储走运行时账号 app;用 `just test-pg`)。

use baserust::features::widget::{WidgetRepo, WidgetSortField};
use baserust::kernel::app_error::AppError;
use baserust::kernel::pagination::{PageInfo, PageParams};
use baserust::kernel::sort_order::SortOrder;
use baserust::kernel::tenant_id::TenantId;
use uuid::Uuid;

/// 契约唯一真相源。内存与 PG 都调它 —— 加实现/加断言只改这一处。
/// 只断言顺序·相对关系(updated_at >= created_at)·可见性,绝不断言绝对时间戳
/// (PG `now()` ≠ memory `now_utc()`,断绝对值必假漂移)。
/// 每个契约用自己的新租户:数据互不干扰,顺带证明「别的租户的行不进本租户的列表 / total」。
fn fresh_tenant() -> TenantId {
    TenantId::try_new(Uuid::now_v7()).unwrap()
}

fn offset_all() -> PageParams {
    PageParams::Offset {
        page: 1,
        size: 100,
        with_total: true,
    }
}

/// **租户隔离契约**(spec §4.4 / §4.9):每个方法只在传入的租户里读写。内存实现靠这个参数过滤(唯一防线),
/// PG 实现靠 `tenant_id = $1` + RLS(运行时账号跑,RLS 真生效)。两边同一份断言。
async fn tenant_isolation(repo: &dyn WidgetRepo) {
    let tenant_a = fresh_tenant();
    let tenant_b = fresh_tenant();
    let widget_a = repo
        .create(tenant_a, "shared".into(), Some("ua".into()))
        .await
        .unwrap();

    // ── 名字唯一只在租户内:别的租户可以同名;同租户重名仍 Conflict ──
    let widget_b = repo
        .create(tenant_b, "shared".into(), Some("ub".into()))
        .await
        .expect("别的租户里同名应可建");
    assert!(matches!(
        repo.create(tenant_b, "shared".into(), None).await,
        Err(AppError::Conflict(_))
    ));

    // ── 按 id 取 / 改 / 删别的租户的行 → NotFound(不泄露存在),原行不动 ──
    assert!(matches!(
        repo.get(tenant_b, widget_a.id).await,
        Err(AppError::NotFound)
    ));
    assert!(matches!(
        repo.update(tenant_b, widget_a.id, "pwned".into(), None)
            .await,
        Err(AppError::NotFound)
    ));
    assert!(matches!(
        repo.soft_delete(tenant_b, widget_a.id, None).await,
        Err(AppError::NotFound)
    ));
    let still = repo.get(tenant_a, widget_a.id).await.unwrap();
    assert_eq!(still.name, "shared");
    assert_eq!(
        still.updated_by.as_deref(),
        Some("ua"),
        "别的租户的写不该碰到它"
    );

    // ── 改名撞名也只看本租户:B 里有 only-b,A 的行改叫 only-b 不冲突 ──
    repo.create(tenant_b, "only-b".into(), None).await.unwrap();
    assert_eq!(
        repo.update(tenant_a, widget_a.id, "only-b".into(), None)
            .await
            .expect("别的租户的名字不算撞名")
            .name,
        "only-b"
    );

    // ── 列表 / total 只含本租户(offset 与 cursor 都是)──
    let page_a = repo
        .list(
            tenant_a,
            &offset_all(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        page_a.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![widget_a.id]
    );
    assert!(matches!(
        page_a.page_info,
        PageInfo::Offset { total: Some(1), .. }
    ));
    let page_b = repo
        .list(
            tenant_b,
            &offset_all(),
            None,
            WidgetSortField::Name,
            SortOrder::Asc,
        )
        .await
        .unwrap();
    assert_eq!(
        page_b
            .items
            .iter()
            .map(|w| w.name.as_str())
            .collect::<Vec<_>>(),
        vec!["only-b", "shared"]
    );
    assert!(page_b.items.iter().all(|w| w.id != widget_a.id));
    let cursor_page = repo
        .list(
            tenant_a,
            &PageParams::Cursor {
                after: None,
                limit: 10,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        cursor_page.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![widget_a.id]
    );
    // owner 过滤叠在租户之上:B 里 ub 建的那行,在 A 里按 ub 过滤也是空
    let by_ub = repo
        .list(
            tenant_a,
            &offset_all(),
            Some("ub"),
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(by_ub.items.is_empty());

    // ── cursor 锚点是别的租户的行 → BadRequest(不是本租户发出的 cursor,同伪造)──
    assert!(matches!(
        repo.list(
            tenant_a,
            &PageParams::Cursor {
                after: Some(widget_b.id),
                limit: 2
            },
            None,
            WidgetSortField::Name,
            SortOrder::Asc,
        )
        .await,
        Err(AppError::BadRequest(_))
    ));

    // ── 父子事务:tag 跟父行同租户;别的租户读不到 tag;同名父行在别的租户照样能建 ──
    let tagged = repo
        .create_with_tags(tenant_a, "tagged".into(), vec!["x".into()], None)
        .await
        .unwrap();
    assert_eq!(
        repo.tags_of(tenant_a, tagged.id).await.unwrap(),
        vec!["x".to_owned()]
    );
    assert!(repo.tags_of(tenant_b, tagged.id).await.unwrap().is_empty());
    repo.create_with_tags(tenant_b, "tagged".into(), vec!["x".into()], None)
        .await
        .expect("别的租户里同名父行 + 同 label 应可建");
}

async fn widget_repo_contract(repo: &dyn WidgetRepo, tenant: TenantId) {
    // ── create:审计字段透传(created_by = updated_by = by)──
    let alpha = repo
        .create(tenant, "alpha".into(), Some("tester".into()))
        .await
        .unwrap();
    assert_eq!(alpha.created_by.as_deref(), Some("tester"));
    assert_eq!(alpha.updated_by.as_deref(), Some("tester"));

    // ── get 回环 + 不存在 → NotFound ──
    assert_eq!(repo.get(tenant, alpha.id).await.unwrap().name, "alpha");
    assert!(matches!(
        repo.get(tenant, Uuid::now_v7()).await,
        Err(AppError::NotFound)
    ));

    // 再造两行(uuid v7 单调递增:a.id < b.id < c.id)
    let bravo = repo.create(tenant, "bravo".into(), None).await.unwrap();
    let charlie = repo.create(tenant, "charlie".into(), None).await.unwrap();

    // ── offset:ORDER BY id DESC,with_total 计存活数 ──
    let first_page = repo
        .list(
            tenant,
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
        first_page.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![charlie.id, bravo.id]
    );
    assert!(matches!(
        first_page.page_info,
        PageInfo::Offset { total: Some(3), .. }
    ));
    let second_page = repo
        .list(
            tenant,
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
        second_page.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![alpha.id]
    );

    // ── cursor keyset:首页 has_more,next_after 作锚点续翻 ──
    let cursor1 = repo
        .list(
            tenant,
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
        cursor1.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![charlie.id, bravo.id]
    );
    let next = match cursor1.page_info {
        PageInfo::Cursor {
            has_more,
            next_after,
            ..
        } => {
            assert!(has_more);
            next_after.unwrap()
        }
        _ => panic!("应是 cursor 模式"),
    };
    let cursor2 = repo
        .list(
            tenant,
            &PageParams::Cursor {
                after: Some(next),
                limit: 2,
            },
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        cursor2.items.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![alpha.id]
    );
    assert!(matches!(
        cursor2.page_info,
        PageInfo::Cursor {
            has_more: false,
            ..
        }
    ));

    // ── ownership 过滤:owner=Some 只列该 created_by 的行,total 也按 owner 算(memory↔PG parity)──
    let mine = repo
        .list(
            tenant,
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
        vec![alpha.id]
    );
    assert!(matches!(
        mine.page_info,
        PageInfo::Offset { total: Some(1), .. }
    ));

    // ── update:改名 + updated_by + updated_at 推进;软删行不可改 ──
    let updated = repo
        .update(tenant, alpha.id, "alpha2".into(), Some("editor".into()))
        .await
        .unwrap();
    assert_eq!(updated.name, "alpha2");
    assert_eq!(updated.updated_by.as_deref(), Some("editor"));
    assert!(updated.updated_at >= updated.created_at); // 触发器 / now_utc() 都须满足

    // ── soft_delete 幂等 + 软删后不可见 ──
    repo.soft_delete(tenant, alpha.id, None).await.unwrap();
    assert!(matches!(
        repo.get(tenant, alpha.id).await,
        Err(AppError::NotFound)
    ));
    assert!(matches!(
        repo.soft_delete(tenant, alpha.id, None).await,
        Err(AppError::NotFound)
    )); // 二次删幂等
    assert!(matches!(
        repo.update(tenant, alpha.id, "x".into(), None).await,
        Err(AppError::NotFound)
    )); // 改软删行
    let after = repo
        .list(
            tenant,
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
    assert!(after.items.iter().all(|w| w.id != alpha.id)); // list 不含软删行
    assert!(matches!(
        after.page_info,
        PageInfo::Offset { total: Some(2), .. }
    ));

    // ── name 存活行内唯一 → DB 约束违例下钻成 Conflict(409),memory↔PG parity ──
    // 此刻存活:b(bravo)、c(charlie);a(alpha2)已软删。
    assert!(
        matches!(
            repo.create(tenant, "bravo".into(), None).await,
            Err(AppError::Conflict(_))
        ),
        "重名 create 应 Conflict"
    );
    assert!(
        matches!(
            repo.update(tenant, charlie.id, "bravo".into(), None).await,
            Err(AppError::Conflict(_))
        ),
        "改名撞已有存活名应 Conflict"
    );
    // a 此前叫 alpha2 且已软删 → 同名可被新行复用(部分唯一索引 WHERE deleted_at IS NULL)。
    repo.create(tenant, "alpha2".into(), None)
        .await
        .expect("软删行的名字应可复用");

    // NotFound 先于 Conflict:对已软删的 a 改成**存活名**(bravo)→ NotFound,不因撞名变 Conflict。
    // (PG 靠 WHERE deleted_at IS NULL 不命中软删行;memory 须先判存活再判唯一 —— 此用例钉死该顺序。)
    assert!(
        matches!(
            repo.update(tenant, alpha.id, "bravo".into(), None).await,
            Err(AppError::NotFound)
        ),
        "软删行 + 撞存活名应 NotFound(先判存活,再判唯一)"
    );
    // self-rename no-op:改成自己当前的名 → Ok 且名不变(唯一检查须排己 r.id != id,不误判 Conflict)。
    let same = repo
        .update(tenant, charlie.id, "charlie".into(), None)
        .await
        .expect("改成自己当前的名应 Ok(no-op rename)");
    assert_eq!(same.name, "charlie");

    // ── 父子双表事务:全有或全无(单条语句演示不出的东西)──
    // 成功:一笔里建 widget(父)+ 2 个 tag(子),回读 tag(label 升序)。
    let tagged = repo
        .create_with_tags(
            tenant,
            "tx-ok".into(),
            vec!["red".into(), "blue".into()],
            Some("u".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        repo.tags_of(tenant, tagged.id).await.unwrap(),
        vec!["blue".to_owned(), "red".to_owned()]
    );
    assert_eq!(repo.get(tenant, tagged.id).await.unwrap().name, "tx-ok");

    // **原子性**:批内重复 label → 子表 (widget_id,label) 唯一违例 → 整笔回滚,**widget 父行也不该存在**。
    // PG:父先插、子失败 → ROLLBACK 撤掉父;memory:先校验后落盘 → 父根本没插。两者外部都是"全有或全无"。
    let before = repo
        .list(
            tenant,
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
            tenant,
            "tx-rollback".into(),
            vec!["dup".into(), "dup".into()],
            None
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    let after = repo
        .list(
            tenant,
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
    repo.create(tenant, "Banana".into(), None).await.unwrap();
    repo.create(tenant, "apple".into(), None).await.unwrap();
    let by_name = repo
        .list(
            tenant,
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
    let banana_index = names.iter().position(|n| *n == "Banana").unwrap();
    let apple_index = names.iter().position(|n| *n == "apple").unwrap();
    assert!(
        banana_index < apple_index,
        "name 排序必须字节序('B'=66 < 'a'=97 → Banana 在 apple 前),实际: {names:?}"
    );

    // ── cursor keyset 按 **name**(非 id 键的样例):(name, id) 复合 keyset ──
    // 此刻 name 字节序与创建序(id 序)完全不同 —— 实现若偷偷按 id 翻,下面的拼接必然对不上。
    // 期望序取自 offset 同 sort(它的 collation 口径刚在上面钉过)。
    let expected: Vec<String> = repo
        .list(
            tenant,
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
        .unwrap()
        .items
        .into_iter()
        .map(|w| w.name)
        .collect();
    assert!(expected.len() >= 5, "样本太少,测不出 keyset 翻页");

    // 逐页拼接必须**逐位**等于 offset 全量。上限保护:漏掉严格不等会翻不完(否则死循环挂 CI)。
    let mut got: Vec<String> = Vec::new();
    let mut after: Option<Uuid> = None;
    let mut done = false;
    for _ in 0..expected.len() + 2 {
        let page = repo
            .list(
                tenant,
                &PageParams::Cursor { after, limit: 2 },
                None,
                WidgetSortField::Name,
                SortOrder::Asc,
            )
            .await
            .unwrap();
        got.extend(page.items.iter().map(|w| w.name.clone()));
        match page.page_info {
            PageInfo::Cursor {
                next_after: Some(anchor),
                ..
            } => after = Some(anchor),
            PageInfo::Cursor { .. } => {
                done = true;
                break;
            }
            _ => panic!("应是 cursor 模式"),
        }
    }
    assert!(
        done,
        "cursor 翻页未在有限页内结束(keyset 谓词可能漏了严格不等)"
    );
    assert_eq!(
        got, expected,
        "cursor 按 name 翻页拼接须等于 offset 全量同序"
    );

    // 方向跟随 `order`(不是恒 desc):desc 首条 = name 最大者。
    let desc1 = repo
        .list(
            tenant,
            &PageParams::Cursor {
                after: None,
                limit: 1,
            },
            None,
            WidgetSortField::Name,
            SortOrder::Desc,
        )
        .await
        .unwrap();
    assert_eq!(desc1.items[0].name, *expected.last().unwrap());

    // 锚点行不存在(伪造 / 别的表的 cursor)→ BadRequest,与 decode 失败同口径。
    // **仅非 id 键如此**:`CreatedAt` 复用 v7 id 直接比较,不读锚点,伪造 cursor 只会翻到空页。
    assert!(
        matches!(
            repo.list(
                tenant,
                &PageParams::Cursor {
                    after: Some(Uuid::now_v7()),
                    limit: 2
                },
                None,
                WidgetSortField::Name,
                SortOrder::Asc,
            )
            .await,
            Err(AppError::BadRequest(_))
        ),
        "锚点不存在的 cursor 应 400"
    );

    // 锚点行在翻页途中被**软删**:后续页仍要翻得下去(锚点查询不过滤软删,软删行还在表里)。
    let first = repo
        .list(
            tenant,
            &PageParams::Cursor {
                after: None,
                limit: 1,
            },
            None,
            WidgetSortField::Name,
            SortOrder::Asc,
        )
        .await
        .unwrap();
    let anchor_cursor = match first.page_info {
        PageInfo::Cursor {
            next_after: Some(anchor),
            ..
        } => anchor,
        _ => panic!("首页之后应还有下一页"),
    };
    repo.soft_delete(tenant, first.items[0].id, None)
        .await
        .unwrap();
    let next = repo
        .list(
            tenant,
            &PageParams::Cursor {
                after: Some(anchor_cursor),
                limit: 1,
            },
            None,
            WidgetSortField::Name,
            SortOrder::Asc,
        )
        .await
        .unwrap();
    assert_eq!(
        next.items[0].name, expected[1],
        "锚点被软删后仍应从它之后继续翻"
    );
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_widget_contract() {
    use baserust::features::widget::InMemoryWidgetRepo;
    widget_repo_contract(&InMemoryWidgetRepo::new(), fresh_tenant()).await;
}

#[tokio::test]
async fn memory_tenant_isolation() {
    use baserust::features::widget::InMemoryWidgetRepo;
    tenant_isolation(&InMemoryWidgetRepo::new()).await;
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 app_owner + 跑着的 pg;仓储走运行时账号)──
// support 提到顶层声明:#[path] 基目录是 tests/,正确指向 tests/support/mod.rs
// (放进 mod pg 内会被推成 tests/pg/support/mod.rs)。
#[cfg(feature = "pg-conformance")]
#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{fresh_tenant, support, tenant_isolation, widget_repo_contract};
    use baserust::features::widget::{PgWidgetRepo, WidgetRepo};
    use baserust::infra::pg;
    use sqlx::{AssertSqlSafe, PgPool};
    use uuid::Uuid;

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_widget_contract(pool: PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        // 仓储走运行时账号(非 owner):生产形状,RLS 对它生效。
        let runtime_pool = support::runtime_pool(&pool)
            .await
            .expect("运行时账号连临时库");
        let repo = PgWidgetRepo::new(runtime_pool.clone());
        widget_repo_contract(&repo, fresh_tenant()).await;
        runtime_pool.close().await;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_tenant_isolation(pool: PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let runtime_pool = support::runtime_pool(&pool)
            .await
            .expect("运行时账号连临时库");
        tenant_isolation(&PgWidgetRepo::new(runtime_pool.clone())).await;
        runtime_pool.close().await;
        Ok(())
    }

    /// RLS 兜底(不经仓储,直接 SQL 打运行时账号):不设 `app.tenant_id` → 读不到任何行、写不进任何行;
    /// 设了 A 也写不进 B 的行(WITH CHECK)、读不到 B 的行(USING)。仓储漏写条件时就靠这层。
    #[sqlx::test(migrations = false)]
    async fn pg_rls_without_tenant_sees_and_writes_nothing(pool: PgPool) -> sqlx::Result<()> {
        support::bootstrap_app_schema(&pool)
            .await
            .expect("bootstrap app schema + 跑 migrations/app");
        let runtime_pool = support::runtime_pool(&pool)
            .await
            .expect("运行时账号连临时库");
        let repo = PgWidgetRepo::new(runtime_pool.clone());
        let (tenant_a, tenant_b) = (fresh_tenant(), fresh_tenant());
        let widget_a = repo
            .create_with_tags(tenant_a, "a".into(), vec!["l".into()], None)
            .await
            .unwrap();
        repo.create(tenant_b, "b".into(), None).await.unwrap();

        // 1) 不设租户:两张表都 0 行(行确实在:owner 账号能看到)
        for table in ["widgets", "widget_tags"] {
            let row_count: i64 =
                sqlx::query_scalar(AssertSqlSafe(format!("select count(*) from {table}")))
                    .fetch_one(&runtime_pool)
                    .await?;
            assert_eq!(row_count, 0, "{table}:不设 app.tenant_id 应 0 行");
        }
        let owner_sees: i64 = sqlx::query_scalar("select count(*) from widgets")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            owner_sees, 2,
            "owner 账号(BYPASSRLS)看得到全部,证明上面的 0 是 RLS 挡的"
        );

        // 2) 不设租户写:RLS 拒(42501)
        let error = sqlx::query("insert into widgets (tenant_id, id, name) values ($1, $2, 'x')")
            .bind(tenant_a.as_uuid())
            .bind(Uuid::now_v7())
            .execute(&runtime_pool)
            .await
            .expect_err("不设租户不该写得进");
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501"),
            "{error}"
        );

        // 3) 设了 A:看不到 B,写 B 的行被 WITH CHECK 拒;改 / 删 B 的行命中 0 行
        let mut transaction = pg::tenant_transaction(&runtime_pool, tenant_a).await?;
        let seen: Vec<Uuid> = sqlx::query_scalar("select id from widgets")
            .fetch_all(&mut *transaction)
            .await?;
        assert_eq!(seen, vec![widget_a.id]);
        let hit = sqlx::query("update widgets set name = 'pwned' where tenant_id = $1")
            .bind(tenant_b.as_uuid())
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        assert_eq!(hit, 0, "A 的事务里改不到 B 的行");
        let error = sqlx::query("insert into widgets (tenant_id, id, name) values ($1, $2, 'x')")
            .bind(tenant_b.as_uuid())
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await
            .expect_err("A 的事务里不该写得进 B 的行");
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501"),
            "{error}"
        );
        drop(transaction);

        // 4) nil 租户:CHECK 拒(owner 账号绕过 RLS 也拒)
        let error = sqlx::query("insert into widgets (tenant_id, id, name) values ($1, $2, 'nil')")
            .bind(Uuid::nil())
            .bind(Uuid::now_v7())
            .execute(&pool)
            .await
            .expect_err("nil 租户不该写得进");
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23514"),
            "{error}"
        );
        runtime_pool.close().await;
        Ok(())
    }
}

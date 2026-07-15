//! SearchIndexRepo 契约一致性:**同一批断言对 InMemorySearchIndexRepo 与 PgSearchIndexRepo 各跑一遍**,
//! 钉死两实现的行为 parity —— 守卫 upsert(旧 seq 跳过 / 新 seq 应用)、disjoint 列(idm vs profile
//! 各自水位、互不覆盖)、partial row(某一源先到)、`rebuild_upsert` 无守卫全量覆写。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`cargo test --features pg-conformance --test search_repo_conformance`(`just test-pg` 挂了本
//! 文件)。**本测试连 search role**(非 `#[sqlx::test]` 默认的 app role/`DATABASE_URL`)——见下 pg 模块;
//! `admin_user_index` 表在 search 库里跨测试运行共享(无每测试隔离的临时库),故每次调用契约都用全新
//! `Uuid::now_v7()` 造用户,避免运行间撞行。

use baserust::features::search::{AdminUserIndexRow, IndexQuery, IndexSort, SearchIndexRepo};
use baserust::infra::pagination::PageParams;
use baserust::infra::sort::SortOrder;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 契约唯一真相源。内存与 PG 都调它 —— 加实现/加断言只改这一处。
async fn search_index_contract(repo: &dyn SearchIndexRepo) {
    let u = Uuid::now_v7();
    let t0 = OffsetDateTime::now_utc();

    // ── 1. created 建行 ──
    repo.apply_user_created(u, "alice", Some("a@x"), false, &["user".to_owned()], t0, 5)
        .await
        .unwrap();
    let row = repo.get(u).await.unwrap().expect("created 后应可读");
    assert_eq!(row.username.as_deref(), Some("alice"));
    assert_eq!(row.roles, vec!["user".to_owned()]);
    assert!(!row.deleted);
    assert_eq!(row.idm_seq, Some(5));

    // ── 2. 守卫:旧 seq(3 < 5)被跳过,username 仍 alice ──
    repo.apply_user_updated(u, "alice2", None, false, 3)
        .await
        .unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("alice"), "旧 seq 应被跳过");
    assert_eq!(row.idm_seq, Some(5));

    // 新 seq(8 > 5)应用
    repo.apply_user_updated(u, "alice2", None, false, 8)
        .await
        .unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("alice2"));
    assert_eq!(row.idm_seq, Some(8));

    // ── 3. 列不相交:profile 写只动 display_name/profile_seq,idm 列(username)不变 ──
    repo.apply_profile_updated(u, Some("Alice Disp"), 2)
        .await
        .unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("Alice Disp"));
    assert_eq!(row.profile_seq, Some(2));
    assert_eq!(
        row.username.as_deref(),
        Some("alice2"),
        "profile 写不该动 idm 列"
    );

    // ── 4. partial row:新 user_id(v)只经 profile 事件建行,idm 列留空/默认 ──
    let v = Uuid::now_v7();
    repo.apply_profile_updated(v, Some("Bob"), 1).await.unwrap();
    let row_v = repo.get(v).await.unwrap().expect("partial row 应可读");
    assert_eq!(row_v.display_name.as_deref(), Some("Bob"));
    assert_eq!(row_v.username, None);
    assert!(!row_v.deleted);
    assert_eq!(row_v.idm_seq, None);

    // ── 4b. idm_seq IS NULL 首次落地分支:v 是 profile-first 的 partial row(idm_seq 仍 NULL),
    // 现在补第一个 idm 事件 —— 守卫应放行(NULL 视作最低水位),且不擦掉已有 profile 列 ──
    repo.apply_user_created(v, "bob", None, false, &["user".to_owned()], t0, 7)
        .await
        .unwrap();
    let row_v = repo.get(v).await.unwrap().unwrap();
    assert_eq!(
        row_v.display_name.as_deref(),
        Some("Bob"),
        "idm 首次落地不该擦掉已有 profile 列"
    );
    assert_eq!(row_v.username.as_deref(), Some("bob"));
    assert_eq!(row_v.roles, vec!["user".to_owned()]);
    assert_eq!(row_v.idm_seq, Some(7));

    // ── 5. roles_set 守卫(9 > 8)+ deleted ──
    repo.apply_roles_set(u, &["admin".to_owned()], 9)
        .await
        .unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert_eq!(row.roles, vec!["admin".to_owned()]);
    assert_eq!(row.idm_seq, Some(9));

    repo.apply_user_deleted(u, 10).await.unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert!(row.deleted);
    assert_eq!(row.idm_seq, Some(10));

    // ── 6. rebuild_upsert:无守卫全量覆写(不比较 seq,不管当前水位高低)──
    repo.rebuild_upsert(AdminUserIndexRow {
        user_id: u,
        username: Some("reb".to_owned()),
        email: Some("reb@x".to_owned()),
        email_verified: true,
        display_name: Some("Rebuilt".to_owned()),
        roles: vec!["reb".to_owned()],
        created_at: Some(t0),
        deleted: false,
        idm_seq: Some(100),
        profile_seq: Some(100),
    })
    .await
    .unwrap();
    let row = repo.get(u).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("reb"));
    assert_eq!(row.email.as_deref(), Some("reb@x"));
    assert!(row.email_verified);
    assert_eq!(row.display_name.as_deref(), Some("Rebuilt"));
    assert_eq!(row.roles, vec!["reb".to_owned()]);
    assert!(
        !row.deleted,
        "rebuild 快照本身 deleted=false,应覆写掉之前的 true"
    );
    assert_eq!(row.idm_seq, Some(100));
    assert_eq!(row.profile_seq, Some(100));
}

/// `mark_deleted_except` 契约(rebuild 的**反向收敛**:源里已删/丢了 `user.deleted` 的残留行)。
/// 三条断言:快照外的扫成 deleted、快照内的不动、水位比快照新的不动(并发投影进来的新用户)。
///
/// **本契约按设计会扫到表里其余行**(端口语义就是"不在这份快照里的都算已删")—— PG 侧因此必须与
/// 其他契约**串行**跑,见 pg 模块的锁;内存侧各自 `new()` 一份,天然隔离。
async fn search_index_sweep_contract(repo: &dyn SearchIndexRepo) {
    let keep = Uuid::now_v7();
    let ghost = Uuid::now_v7();
    let newer = Uuid::now_v7();
    let row = |id: Uuid, seq: i64| AdminUserIndexRow {
        user_id: id,
        username: Some("sweep".to_owned()),
        email: None,
        email_verified: false,
        display_name: None,
        roles: vec![],
        created_at: None,
        deleted: false,
        idm_seq: Some(seq),
        profile_seq: None,
    };
    for (id, seq) in [(keep, 5i64), (ghost, 5), (newer, 9)] {
        repo.rebuild_upsert(row(id, seq)).await.unwrap();
    }

    // 快照 = [keep],水位 5:ghost(不在快照、seq<=5)该扫;newer(seq 9 > 5)不该动。
    let swept = repo.mark_deleted_except(&[keep], 5).await.unwrap();
    assert!(swept >= 1, "快照外的 ghost 应被扫到");
    assert!(
        !repo.get(keep).await.unwrap().unwrap().deleted,
        "快照内的行不动"
    );
    let ghost_row = repo.get(ghost).await.unwrap().unwrap();
    assert!(ghost_row.deleted, "快照外的行应扫成 deleted");
    assert_eq!(ghost_row.idm_seq, Some(5), "扫删水位设为 p_idm");
    assert!(
        !repo.get(newer).await.unwrap().unwrap().deleted,
        "水位比快照新的行不动(rebuild 期间并发投影进来的新用户)"
    );

    // 幂等:已 deleted 的不再计数(重跑 rebuild 不该反复"扫到"同一批)。
    let again = repo.mark_deleted_except(&[keep], 5).await.unwrap();
    assert_eq!(again, 0, "已扫过的行不重复计数");
}

/// `SearchIndexRepo::query` 契约(P4 读路径):filter(q 跨 username/display_name、roles_any/none、
/// created 区间)+ 排序(选定键、None 落最后)+ 分页(offset 带 total、cursor keyset)—— 且半行
/// (username 未落地)/ 软删行永不出现在任何结果里。同 `search_index_contract`,memory 与 pg 共跑
/// 一套断言。**`admin_user_index` 是跨测试运行共享的表**(无临时库隔离),所以每个搜索词/角色名都
/// 嵌一段本轮独有的 tag(取自本轮 fresh v7 uuid)——不然历史行会掺进"只回 N 条"这类断言里。
async fn search_index_query_contract(repo: &dyn SearchIndexRepo) {
    let t0 = OffsetDateTime::now_utc();

    let alice = Uuid::now_v7();
    let bob = Uuid::now_v7();
    let carol = Uuid::now_v7();
    let partial = Uuid::now_v7();
    let deleted = Uuid::now_v7();

    let tag = alice.simple().to_string(); // 32 位 hex,本轮独有
    let alice_username = format!("alice-{tag}");
    let alice_display = format!("Alice Wonder {tag}");
    let bob_username = format!("bobkeyword-{tag}");
    let bob_display = format!("Bob Builder {tag}");
    let carol_username = format!("carol-{tag}");
    let role_user = format!("user-{tag}");
    let role_admin = format!("admin-{tag}");

    repo.apply_user_created(
        alice,
        &alice_username,
        Some("a@x"),
        false,
        std::slice::from_ref(&role_user),
        t0,
        1,
    )
    .await
    .unwrap();
    repo.apply_profile_updated(alice, Some(&alice_display), 1)
        .await
        .unwrap();

    repo.apply_user_created(
        bob,
        &bob_username,
        Some("b@x"),
        false,
        std::slice::from_ref(&role_admin),
        t0 + Duration::days(1),
        1,
    )
    .await
    .unwrap();
    repo.apply_profile_updated(bob, Some(&bob_display), 1)
        .await
        .unwrap();

    repo.apply_user_created(
        carol,
        &carol_username,
        Some("c@x"),
        false,
        std::slice::from_ref(&role_user),
        t0 + Duration::days(2),
        1,
    )
    .await
    .unwrap();
    // carol 不 apply_profile_updated —— display_name 留 None,验证 NULLS LAST。

    // partial row:只经 profile 事件落地,username 永远 None —— 任何 query 都不该看到它。
    repo.apply_profile_updated(partial, Some(&format!("Partial Wonder {tag}")), 1)
        .await
        .unwrap();

    // deleted row:先建后删 —— 任何 query 都不该看到它。
    repo.apply_user_created(
        deleted,
        &format!("deleted-{tag}"),
        Some("d@x"),
        false,
        std::slice::from_ref(&role_user),
        t0,
        1,
    )
    .await
    .unwrap();
    repo.apply_user_deleted(deleted, 2).await.unwrap();

    let big_page = PageParams::Offset {
        page: 1,
        size: 50,
        with_total: true,
    };

    // ── 半行/软删永不出现:本轮全量(q=tag 圈定本轮候选)应恰好是 alice/bob/carol 三条 ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &big_page,
        )
        .await
        .unwrap();
    let mut ids: Vec<Uuid> = res.rows.iter().map(|r| r.user_id).collect();
    ids.sort();
    let mut expected = vec![alice, bob, carol];
    expected.sort();
    assert_eq!(
        ids, expected,
        "半行(partial)与软删行不该出现在 query 结果里"
    );
    assert_eq!(res.total, Some(3));

    // ── q 只命中 display_name(alice:"wonder <tag>" 不在任何本轮 username 里出现) ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(format!("wonder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice]
    );
    assert_eq!(res.total, Some(1));

    // ── q 只命中 username(bob:整个 username 串不出现在任何 display_name 里) ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(bob_username.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "q 应能命中 username"
    );

    // ── q 只命中 display_name(bob:"builder <tag>" 不在任何 username 里出现) ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(format!("builder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "q 应能命中 display_name"
    );

    // ── username 过滤:独立于 q,只认 username 子串(bob 的 username 含 "bobkeyword-<tag>",不在
    // 任何本轮 display_name 里出现)。这是 P4 曾经的回归本体——投影读链只认 q,plain `username`
    // 过滤被静默丢弃;此断言钉死 username 单独过滤生效。
    let res = repo
        .query(
            &IndexQuery {
                username: Some(bob_username.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "username 过滤应只认 username 子串,忽略 display_name"
    );
    assert_eq!(res.total, Some(1));

    // ── username ∧ q:两者 AND 组合,不是各自独立的 OR ──
    // username 命中 alice(alice_username),q("wonder <tag>")也命中 alice(display_name)——两者都
    // 命中同一行,应返回 alice。
    let res = repo
        .query(
            &IndexQuery {
                username: Some(alice_username.clone()),
                q: Some(format!("wonder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice],
        "username 与 q 都命中同一行时应返回该行"
    );

    // username 命中 alice,q("builder <tag>")只命中 bob(display_name)——AND 之下两者都不该出现:
    // alice 命中 username 但不命中 q,bob 命中 q 但不命中 username。
    let res = repo
        .query(
            &IndexQuery {
                username: Some(alice_username.clone()),
                q: Some(format!("builder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert!(
        res.rows.is_empty(),
        "username 与 q 是 AND 关系:只命中其一的行(alice 命中 username 不命中 q,bob 命中 q 不命中 \
         username)都不该出现"
    );

    // ── roles_any:本轮独有的 role_admin 只在 bob 身上 ──
    let res = repo
        .query(
            &IndexQuery {
                roles_any: vec![role_admin.clone()],
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── roles_none:本轮候选(q=tag)里排除 role_user 的只剩 bob ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                roles_none: vec![role_user.clone()],
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── created 区间:本轮候选里只有 bob(t0+1d)落在 [t0+12h, t0+36h] ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                created_from: Some(t0 + Duration::hours(12)),
                created_to: Some(t0 + Duration::hours(36)),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── 排序:DisplayName Asc —— alice < bob(字节序),carol 的 None 落最后(NULLS LAST) ──
    let res = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::DisplayName,
            SortOrder::Asc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice, bob, carol],
        "display_name 字节序升序,None(carol)落最后"
    );

    // ── 分页:offset(按 created_at asc,size=2 分两页,total 正确) ──
    let page1 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Offset {
                page: 1,
                size: 2,
                with_total: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page1.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice, bob]
    );
    assert_eq!(page1.total, Some(3));

    let page2 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Offset {
                page: 2,
                size: 2,
                with_total: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page2.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![carol]
    );
    assert_eq!(page2.total, Some(3));

    // ── 分页:cursor(keyset 恒按 user_id,忽略 sort;方向随 order;两页拼起来 = 本轮三条) ──
    let cursor1 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(cursor1.rows.len(), 2);
    assert_eq!(cursor1.total, None);
    let after = cursor1.next_after.expect("还有下一页,next_after 应为 Some");

    let cursor2 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Cursor {
                after: Some(after),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(cursor2.rows.len(), 1);
    assert!(cursor2.next_after.is_none(), "读完了,不该再有下一页");

    let mut cursor_ids: Vec<Uuid> = cursor1
        .rows
        .iter()
        .chain(cursor2.rows.iter())
        .map(|r| r.user_id)
        .collect();
    cursor_ids.sort();
    assert_eq!(cursor_ids, expected);

    // ── 分页:cursor,order = Desc(newest-first keyset;方向必须跟 order 走,不能悄悄扣死升序,
    // 这是本轮修的缺陷本体 —— 之前两个后端都硬编码 user_id ASC,忽略 order) ──
    let desc1 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &PageParams::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(desc1.rows.len(), 2);
    assert_eq!(desc1.total, None);
    assert!(
        desc1.rows[0].user_id > desc1.rows[1].user_id,
        "cursor + order=Desc 应按 user_id 降序返回(newest first)"
    );
    let desc_after = desc1.next_after.expect("还有下一页,next_after 应为 Some");

    let desc2 = repo
        .query(
            &IndexQuery {
                q: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &PageParams::Cursor {
                after: Some(desc_after),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(desc2.rows.len(), 1);
    assert!(desc2.next_after.is_none(), "读完了,不该再有下一页");

    let desc_walk: Vec<Uuid> = desc1
        .rows
        .iter()
        .chain(desc2.rows.iter())
        .map(|r| r.user_id)
        .collect();
    assert!(
        desc_walk.windows(2).all(|w| w[0] > w[1]),
        "两页拼起来应整体严格降序(跨页边界也不能倒挂)"
    );
    let mut desc_ids = desc_walk.clone();
    desc_ids.sort();
    assert_eq!(desc_ids, expected, "两页拼起来应覆盖本轮三条,无重无漏");

    // ── literal LIKE 元字符(`%`)转义:q 里的字面 `%` 应逐字匹配,不当 SQL 通配符 ──
    // decoy 的 display_name 在 "50" 与 tag 之间恰好插 0 个字符——若转义失效,`%` 被当"零或多个
    // 任意字符"的通配符,decoy 也会被 percent 这条 query 误配;转义生效则只有 percent 命中。
    let percent = Uuid::now_v7();
    let percent_decoy = Uuid::now_v7();
    let percent_display = format!("50%{tag}");
    let percent_decoy_display = format!("50{tag}");
    repo.apply_user_created(
        percent,
        &format!("pct-{tag}"),
        Some("pct@x"),
        false,
        std::slice::from_ref(&role_user),
        t0,
        1,
    )
    .await
    .unwrap();
    repo.apply_profile_updated(percent, Some(&percent_display), 1)
        .await
        .unwrap();
    repo.apply_user_created(
        percent_decoy,
        &format!("pctdecoy-{tag}"),
        Some("pctd@x"),
        false,
        std::slice::from_ref(&role_user),
        t0,
        1,
    )
    .await
    .unwrap();
    repo.apply_profile_updated(percent_decoy, Some(&percent_decoy_display), 1)
        .await
        .unwrap();

    let res = repo
        .query(
            &IndexQuery {
                q: Some(percent_display.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![percent],
        "q 里的字面 `%` 应转义后逐字匹配,不该把 decoy(50 与 tag 之间无字符)当通配符命中"
    );

    // 反向:换一个不含 `%` 的字面串(decoy 自己的内容)去查,percent 不该出现——证明上面那条
    // 命中不是"啥都匹配"的退化结果。
    let res = repo
        .query(
            &IndexQuery {
                q: Some(percent_decoy_display.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        res.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![percent_decoy],
        "不含 `%` 的字面查询不该命中 percent(证明上一条不是退化的全匹配)"
    );
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_search_index_contract() {
    use baserust::features::search::InMemorySearchIndexRepo;
    search_index_contract(&InMemorySearchIndexRepo::new()).await;
}

#[tokio::test]
async fn memory_satisfies_search_index_query_contract() {
    use baserust::features::search::InMemorySearchIndexRepo;
    search_index_query_contract(&InMemorySearchIndexRepo::new()).await;
}

#[tokio::test]
async fn memory_satisfies_search_index_sweep_contract() {
    use baserust::features::search::InMemorySearchIndexRepo;
    search_index_sweep_contract(&InMemorySearchIndexRepo::new()).await;
}

// ── 入口 2:PG(需 --features pg-conformance + search role 跑着的 pg)──
// **不用 `#[sqlx::test]`**:它建临时库并用 `DATABASE_URL`(`just test-pg` 里连的是 app role),
// 而 admin_user_index 在 search schema、须以 search role 连接 —— 显式建池,读 SEARCH_DATABASE_URL
// (缺省回退本地 compose 的 search role)。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{search_index_contract, search_index_query_contract, search_index_sweep_contract};
    use baserust::features::search::PgSearchIndexRepo;

    /// PG 侧契约**串行跑**。`admin_user_index` 是跨测试共享的真表(无临时库隔离,见文件头),
    /// 而 sweep 契约按端口语义会扫掉"快照外的所有行" —— 与 query 契约并行就会把它的行
    /// (`idm_seq=1`、以及 profile-only 的 `idm_seq is null` 那行)扫成 deleted,断言随机变红。
    /// 内存侧各自 `new()` 一份,不需要这把锁。
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn connect() -> sqlx::PgPool {
        let url = std::env::var("SEARCH_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://search:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let pool = sqlx::PgPool::connect(&url).await.expect(
            "连 search role 失败(先 `just up` + `just migrate-search` + `just pg-test-grant`)",
        );
        sqlx::migrate!("migrations/search")
            .run(&pool)
            .await
            .expect("跑 migrations/search 失败(幂等,应可重复跑)");
        pool
    }

    #[tokio::test]
    async fn pg_satisfies_search_index_contract() {
        let _serial = LOCK.lock().await;
        let repo = PgSearchIndexRepo::new(connect().await);
        search_index_contract(&repo).await;
    }

    #[tokio::test]
    async fn pg_satisfies_search_index_query_contract() {
        let _serial = LOCK.lock().await;
        let repo = PgSearchIndexRepo::new(connect().await);
        search_index_query_contract(&repo).await;
    }

    #[tokio::test]
    async fn pg_satisfies_search_index_sweep_contract() {
        let _serial = LOCK.lock().await;
        let repo = PgSearchIndexRepo::new(connect().await);
        search_index_sweep_contract(&repo).await;
    }
}

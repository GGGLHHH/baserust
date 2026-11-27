//! SearchIndexRepo 契约一致性:**同一批断言对 InMemorySearchIndexRepo 与 PgSearchIndexRepo 各跑一遍**,
//! 钉死两实现的行为 parity —— 守卫 upsert(旧 seq 跳过 / 新 seq 应用)、disjoint 列(idm / profile / 成员
//! 各自水位、互不覆盖)、partial row(某一源先到)、`rebuild_*` 无守卫全量覆写,以及多租户:成员索引按租户隔离、
//! `profile.updated` / `user.*` 刷新该用户在所有租户里的行。
//!
//! 契约拿两个仓储:`repo` 写(PG = search 的 **system 池**,BYPASSRLS,同投影器)、`reader` 读(PG = **运行时池**,
//! 每次读在租户事务里 —— RLS 真的生效)。内存实现两者是同一个对象。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`cargo test --features pg-conformance --test search_repo_conformance`(`just test-pg` 挂了本
//! 文件)。**本测试连 search role**(非 `#[sqlx::test]` 默认的 app role/`DATABASE_URL`)——见下 pg 模块;
//! `admin_user_index` 表在 search 库里跨测试运行共享(无每测试隔离的临时库),故每次调用契约都用全新
//! `Uuid::now_v7()` 造用户,避免运行间撞行。

use baserust::features::search::{
    AccountCreated, AccountIndexRow, AccountUpdated, AdminUserIndexRow, IndexQuery, IndexSort,
    SearchIndexRepo,
};
use baserust::kernel::pagination::PageParams;
use baserust::kernel::sort_order::SortOrder;
use baserust::kernel::tenant_id::TenantId;
use std::slice;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 本轮独有的租户(v7,非 nil)。PG 上表跨运行共享,用新租户圈住本轮的行。
fn fresh_tenant() -> TenantId {
    TenantId::try_new(Uuid::now_v7()).expect("v7 非 nil")
}

/// 造一个「某租户里的成员」:账号事件(平台角色留空)+ 成员事件(带租户角色 `role`)。
async fn seed(
    repo: &dyn SearchIndexRepo,
    tenant: TenantId,
    id: Uuid,
    username: &str,
    email: Option<&str>,
    role: &str,
    created_at: OffsetDateTime,
) {
    repo.apply_user_created(
        AccountCreated {
            user_id: id,
            username,
            email,
            email_verified: false,
            roles: &[],
            created_at,
        },
        1,
    )
    .await
    .unwrap();
    repo.apply_member_added(tenant, id, "active", &[role.to_owned()], 2)
        .await
        .unwrap();
}

/// 本租户里按 q 查到的 user_id(大页,不翻页)。
async fn ids_in(reader: &dyn SearchIndexRepo, tenant: TenantId, search_text: &str) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(search_text.to_owned()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
        )
        .await
        .unwrap()
        .rows
        .into_iter()
        .map(|r| r.user_id)
        .collect();
    ids.sort();
    ids
}

/// 成员索引按租户隔离(spec §4.4 / §4.5):同一账号在两个租户各一行,各自的租户角色 / 状态互不影响;
/// 查一个租户只看得到它自己的成员;移出 / 租户删除后不再出现;成员事件有自己的水位(旧事件不回滚、不复活)。
async fn member_index_scoped_by_tenant(repo: &dyn SearchIndexRepo, reader: &dyn SearchIndexRepo) {
    let now = OffsetDateTime::now_utc();
    let tenant_a = fresh_tenant();
    let tenant_b = fresh_tenant();
    let empty = fresh_tenant();
    let first_user = Uuid::now_v7();
    let second_user = Uuid::now_v7();
    let tag = first_user.simple().to_string();
    let first_username = format!("scoped-u-{tag}");
    let second_username = format!("scoped-w-{tag}");

    // u 是 a、b 两个租户的成员(角色不同);w 只在 a。
    repo.apply_user_created(
        AccountCreated {
            user_id: first_user,
            username: &first_username,
            email: None,
            email_verified: false,
            roles: &["superadmin".to_owned()],
            created_at: now,
        },
        10,
    )
    .await
    .unwrap();
    repo.apply_user_created(
        AccountCreated {
            user_id: second_user,
            username: &second_username,
            email: None,
            email_verified: false,
            roles: &[],
            created_at: now,
        },
        11,
    )
    .await
    .unwrap();
    repo.apply_member_added(tenant_a, first_user, "active", &["admin".to_owned()], 12)
        .await
        .unwrap();
    repo.apply_member_added(tenant_b, first_user, "active", &["user".to_owned()], 13)
        .await
        .unwrap();
    repo.apply_member_added(tenant_a, second_user, "active", &["user".to_owned()], 14)
        .await
        .unwrap();

    let mut both = vec![first_user, second_user];
    both.sort();
    assert_eq!(
        ids_in(reader, tenant_a, &tag).await,
        both,
        "a 有 u、w 两个成员"
    );
    assert_eq!(
        ids_in(reader, tenant_b, &tag).await,
        vec![first_user],
        "b 只有 u"
    );
    assert!(
        ids_in(reader, empty, &tag).await.is_empty(),
        "没有成员的租户什么都看不到(别的租户的行不串过来)"
    );

    // 成员行的账号列抄自账号目录;roles 是**租户角色**(平台角色 superadmin 不进成员行)。
    let member_a = reader
        .get_member(tenant_a, first_user)
        .await
        .unwrap()
        .expect("a 里有 u 的行");
    assert_eq!(member_a.tenant_id, tenant_a);
    assert_eq!(member_a.username.as_deref(), Some(first_username.as_str()));
    assert_eq!(member_a.roles, vec!["admin".to_owned()]);
    assert_eq!(member_a.status.as_deref(), Some("active"));
    assert_eq!(
        member_a.idm_sequence,
        Some(10),
        "账号列连同账号水位一起抄过来"
    );
    assert_eq!(member_a.member_sequence, Some(12));
    let member_b = reader
        .get_member(tenant_b, first_user)
        .await
        .unwrap()
        .expect("b 里有 u 的行");
    assert_eq!(
        member_b.roles,
        vec!["user".to_owned()],
        "两个租户的租户角色互不影响"
    );
    assert!(reader
        .get_member(tenant_b, second_user)
        .await
        .unwrap()
        .is_none());

    // 租户角色 / 状态:守卫(旧 seq 跳过)+ 只动本租户那一行。
    repo.apply_member_roles_set(tenant_a, first_user, &["user".to_owned()], 15)
        .await
        .unwrap();
    repo.apply_member_roles_set(tenant_a, first_user, &["stale".to_owned()], 12)
        .await
        .unwrap();
    let member_a = reader
        .get_member(tenant_a, first_user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        member_a.roles,
        vec!["user".to_owned()],
        "旧 seq 的角色事件应被跳过"
    );
    assert_eq!(member_a.member_sequence, Some(15));
    repo.apply_member_updated(tenant_a, first_user, "inactive", 16)
        .await
        .unwrap();
    let member_a = reader
        .get_member(tenant_a, first_user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member_a.status.as_deref(), Some("inactive"));
    assert_eq!(member_a.roles, vec!["user".to_owned()], "状态事件不动角色");
    let member_b = reader
        .get_member(tenant_b, first_user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        member_b.status.as_deref(),
        Some("active"),
        "别的租户的行不受影响"
    );
    assert_eq!(member_b.roles, vec!["user".to_owned()]);
    // 角色过滤按租户角色:a 里 u 现在是 user,不再是 admin。
    let admins = reader
        .query(
            tenant_a,
            &IndexQuery {
                query: Some(tag.clone()),
                roles_any: vec!["admin".to_owned()],
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Offset {
                page: 1,
                size: 50,
                with_total: true,
            },
        )
        .await
        .unwrap();
    assert!(admins.rows.is_empty(), "roles 过滤看的是租户角色");

    // 移出:b 里查不到 u;旧的 member_added(13 < 17)重投不把人加回来;新的加入(18)才算。
    repo.apply_member_removed(tenant_b, first_user, 17)
        .await
        .unwrap();
    assert!(
        ids_in(reader, tenant_b, &tag).await.is_empty(),
        "移出后不在成员列表里"
    );
    let member_b = reader
        .get_member(tenant_b, first_user)
        .await
        .unwrap()
        .expect("墓碑行仍在");
    assert!(member_b.removed);
    repo.apply_member_added(tenant_b, first_user, "active", &["user".to_owned()], 13)
        .await
        .unwrap();
    assert!(
        ids_in(reader, tenant_b, &tag).await.is_empty(),
        "旧 seq 的 member_added 重投不能复活已移出的成员"
    );
    repo.apply_member_added(tenant_b, first_user, "active", &["admin".to_owned()], 18)
        .await
        .unwrap();
    assert_eq!(
        ids_in(reader, tenant_b, &tag).await,
        vec![first_user],
        "重新加入后又出现"
    );
    let member_b = reader
        .get_member(tenant_b, first_user)
        .await
        .unwrap()
        .unwrap();
    assert!(!member_b.removed);
    assert_eq!(member_b.roles, vec!["admin".to_owned()]);
    assert_eq!(
        ids_in(reader, tenant_a, &tag).await,
        both,
        "b 的变化不影响 a"
    );

    // 租户删除:a 的全部成员行不再出现;b 不受影响。
    repo.apply_tenant_deleted(tenant_a, 19).await.unwrap();
    assert!(
        ids_in(reader, tenant_a, &tag).await.is_empty(),
        "租户删除后成员列表为空"
    );
    assert_eq!(ids_in(reader, tenant_b, &tag).await, vec![first_user]);

    // rebuild_member:无守卫全量覆写一条成员行(水位再低也照写)。
    let mut row = AdminUserIndexRow::new(tenant_a, second_user);
    row.username = Some(second_username.clone());
    row.roles = vec!["rebuilt".to_owned()];
    row.status = Some("active".to_owned());
    // PG 时间戳是微秒精度:截到微秒再比整行。
    row.created_at = Some(now.replace_microsecond(now.microsecond()).unwrap());
    row.idm_sequence = Some(1);
    row.profile_sequence = Some(1);
    row.member_sequence = Some(1);
    repo.rebuild_member(row.clone()).await.unwrap();
    assert_eq!(
        reader.get_member(tenant_a, second_user).await.unwrap(),
        Some(row)
    );
    assert_eq!(ids_in(reader, tenant_a, &tag).await, vec![second_user]);
}

/// 资料全局一份(spec §6.3):`profile.updated` 刷新该用户在**所有租户**里的成员行;`user.updated` /
/// `user.deleted` 同理。资料先于成员关系到达时,加入租户的那一刻从账号目录把显示名抄进成员行。
async fn profile_update_refreshes_all_tenant_rows(
    repo: &dyn SearchIndexRepo,
    reader: &dyn SearchIndexRepo,
) {
    let now = OffsetDateTime::now_utc();
    let tenant_a = fresh_tenant();
    let tenant_b = fresh_tenant();
    let user = Uuid::now_v7();
    let tag = user.simple().to_string();

    repo.apply_user_created(
        AccountCreated {
            user_id: user,
            username: &format!("prof-{tag}"),
            email: None,
            email_verified: false,
            roles: &[],
            created_at: now,
        },
        20,
    )
    .await
    .unwrap();
    repo.apply_member_added(tenant_a, user, "active", &[], 21)
        .await
        .unwrap();
    repo.apply_member_added(tenant_b, user, "active", &[], 22)
        .await
        .unwrap();

    let display_name = format!("Shown {tag}");
    repo.apply_profile_updated(user, Some(&display_name), 5)
        .await
        .unwrap();
    for tenant in [tenant_a, tenant_b] {
        let row = reader.get_member(tenant, user).await.unwrap().unwrap();
        assert_eq!(
            row.display_name.as_deref(),
            Some(display_name.as_str()),
            "每个租户的行都刷新"
        );
        assert_eq!(row.profile_sequence, Some(5));
        assert!(row.member_sequence.is_some(), "资料事件不动成员列");
        assert_eq!(
            ids_in(reader, tenant, &format!("shown {tag}")).await,
            vec![user],
            "按新显示名搜得到"
        );
    }
    // 资料水位守卫:旧事件不回滚任何一行。
    repo.apply_profile_updated(user, Some("old"), 4)
        .await
        .unwrap();
    for tenant in [tenant_a, tenant_b] {
        let row = reader.get_member(tenant, user).await.unwrap().unwrap();
        assert_eq!(row.display_name.as_deref(), Some(display_name.as_str()));
    }

    // user.updated 同样改所有行;user.deleted 让所有租户都查不到。
    let renamed = format!("renamed-{tag}");
    repo.apply_user_updated(
        AccountUpdated {
            user_id: user,
            username: &renamed,
            email: Some("r@x"),
            email_verified: true,
        },
        23,
    )
    .await
    .unwrap();
    for tenant in [tenant_a, tenant_b] {
        let row = reader.get_member(tenant, user).await.unwrap().unwrap();
        assert_eq!(row.username.as_deref(), Some(renamed.as_str()));
        assert_eq!(row.email.as_deref(), Some("r@x"));
        assert_eq!(row.idm_sequence, Some(23));
    }
    repo.apply_user_deleted(user, 24).await.unwrap();
    for tenant in [tenant_a, tenant_b] {
        assert!(
            ids_in(reader, tenant, &tag).await.is_empty(),
            "已删账号在任何租户都不出现"
        );
    }

    // 资料先到、成员关系后到:加入时把账号目录里的显示名抄进成员行。
    let early_user = Uuid::now_v7();
    let version_tag = early_user.simple().to_string();
    repo.apply_profile_updated(early_user, Some(&format!("Early {version_tag}")), 7)
        .await
        .unwrap();
    repo.apply_user_created(
        AccountCreated {
            user_id: early_user,
            username: &format!("early-{version_tag}"),
            email: None,
            email_verified: false,
            roles: &[],
            created_at: now,
        },
        30,
    )
    .await
    .unwrap();
    repo.apply_member_added(tenant_a, early_user, "active", &[], 31)
        .await
        .unwrap();
    let row = reader
        .get_member(tenant_a, early_user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.display_name.as_deref(),
        Some(format!("Early {version_tag}").as_str())
    );
    assert_eq!(row.profile_sequence, Some(7));
    assert_eq!(
        ids_in(reader, tenant_a, &version_tag).await,
        vec![early_user]
    );
}

/// 平台账号列表(`query_accounts`,账号目录,全局):不属于任何租户的账号也在;roles 是平台角色(租户角色
/// 不参与过滤);半行 / 已删账号不出现;q 跨 username / display_name;分页同 `query`。
async fn accounts_list_is_global(repo: &dyn SearchIndexRepo, reader: &dyn SearchIndexRepo) {
    let now = OffsetDateTime::now_utc();
    let lonely = Uuid::now_v7(); // 不属于任何租户
    let member = Uuid::now_v7(); // 某租户的成员
    let gone = Uuid::now_v7();
    let half = Uuid::now_v7();
    let tag = lonely.simple().to_string();
    let platform_role = format!("plat-{tag}");
    let tenant_role = format!("tnt-{tag}");

    repo.apply_user_created(
        AccountCreated {
            user_id: lonely,
            username: &format!("lonely-{tag}"),
            email: None,
            email_verified: false,
            roles: slice::from_ref(&platform_role),
            created_at: now,
        },
        1,
    )
    .await
    .unwrap();
    repo.apply_user_created(
        AccountCreated {
            user_id: member,
            username: &format!("member-{tag}"),
            email: None,
            email_verified: false,
            roles: &[],
            created_at: now + Duration::days(1),
        },
        1,
    )
    .await
    .unwrap();
    repo.apply_member_added(
        fresh_tenant(),
        member,
        "active",
        slice::from_ref(&tenant_role),
        2,
    )
    .await
    .unwrap();
    repo.apply_profile_updated(member, Some(&format!("Shown {tag}")), 1)
        .await
        .unwrap();
    repo.apply_user_created(
        AccountCreated {
            user_id: gone,
            username: &format!("gone-{tag}"),
            email: None,
            email_verified: false,
            roles: &[],
            created_at: now,
        },
        1,
    )
    .await
    .unwrap();
    repo.apply_user_deleted(gone, 2).await.unwrap();
    repo.apply_profile_updated(half, Some(&format!("Half {tag}")), 1)
        .await
        .unwrap();

    let page = PageParams::Offset {
        page: 1,
        size: 50,
        with_total: true,
    };
    let text_query = |text: &str| IndexQuery {
        query: Some(text.to_owned()),
        ..Default::default()
    };
    let result = reader
        .query_accounts(
            &text_query(&tag),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![lonely, member],
        "全部存活账号(含不属于任何租户的),半行 / 已删不出现"
    );
    assert_eq!(result.total, Some(2));
    assert_eq!(
        result.rows[0].roles,
        vec![platform_role.clone()],
        "roles 是平台角色"
    );

    // q 命中 display_name(资料全局一份)。
    let result = reader
        .query_accounts(
            &text_query(&format!("shown {tag}")),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![member]
    );

    // 角色过滤看平台角色:租户角色不算。
    let by_role = |roles: Vec<String>| IndexQuery {
        query: Some(tag.clone()),
        roles_any: roles,
        ..Default::default()
    };
    let result = reader
        .query_accounts(
            &by_role(vec![platform_role.clone()]),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![lonely]
    );
    let result = reader
        .query_accounts(
            &by_role(vec![tenant_role.clone()]),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert!(
        result.rows.is_empty(),
        "租户角色不参与平台账号列表的角色过滤"
    );

    // 排序 display_name(None 落最后)+ cursor 分页。
    let result = reader
        .query_accounts(
            &text_query(&tag),
            IndexSort::DisplayName,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![member, lonely]
    );
    let first = reader
        .query_accounts(
            &text_query(&tag),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Cursor {
                after: None,
                limit: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        first.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![lonely]
    );
    let second = reader
        .query_accounts(
            &text_query(&tag),
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &PageParams::Cursor {
                after: first.next_after,
                limit: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        second.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![member]
    );
    assert!(second.next_after.is_none());
}

/// 账号目录(`account_index`)契约:守卫 / 列不相交 / partial row / rebuild 覆写。内存与 PG 都调它。
async fn search_index_contract(repo: &dyn SearchIndexRepo) {
    let alice = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();

    // ── 1. created 建行 ──
    repo.apply_user_created(
        AccountCreated {
            user_id: alice,
            username: "alice",
            email: Some("a@x"),
            email_verified: false,
            roles: &["user".to_owned()],
            created_at: now,
        },
        5,
    )
    .await
    .unwrap();
    let row = repo
        .get_account(alice)
        .await
        .unwrap()
        .expect("created 后应可读");
    assert_eq!(row.username.as_deref(), Some("alice"));
    assert_eq!(row.roles, vec!["user".to_owned()]);
    assert!(!row.deleted);
    assert_eq!(row.idm_sequence, Some(5));

    // ── 2. 守卫:旧 seq(3 < 5)被跳过,username 仍 alice ──
    repo.apply_user_updated(
        AccountUpdated {
            user_id: alice,
            username: "alice2",
            email: None,
            email_verified: false,
        },
        3,
    )
    .await
    .unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("alice"), "旧 seq 应被跳过");
    assert_eq!(row.idm_sequence, Some(5));

    // 新 seq(8 > 5)应用
    repo.apply_user_updated(
        AccountUpdated {
            user_id: alice,
            username: "alice2",
            email: None,
            email_verified: false,
        },
        8,
    )
    .await
    .unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("alice2"));
    assert_eq!(row.idm_sequence, Some(8));

    // ── 3. 列不相交:profile 写只动 display_name/profile_seq,idm 列(username)不变 ──
    repo.apply_profile_updated(alice, Some("Alice Disp"), 2)
        .await
        .unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("Alice Disp"));
    assert_eq!(row.profile_sequence, Some(2));
    assert_eq!(
        row.username.as_deref(),
        Some("alice2"),
        "profile 写不该动 idm 列"
    );

    // ── 4. partial row:新 user_id(v)只经 profile 事件建行,idm 列留空/默认 ──
    let bob = Uuid::now_v7();
    repo.apply_profile_updated(bob, Some("Bob"), 1)
        .await
        .unwrap();
    let bob_row = repo
        .get_account(bob)
        .await
        .unwrap()
        .expect("partial row 应可读");
    assert_eq!(bob_row.display_name.as_deref(), Some("Bob"));
    assert_eq!(bob_row.username, None);
    assert!(!bob_row.deleted);
    assert_eq!(bob_row.idm_sequence, None);

    // ── 4b. idm_seq IS NULL 首次落地分支:v 是 profile-first 的 partial row(idm_seq 仍 NULL),
    // 现在补第一个 idm 事件 —— 守卫应放行(NULL 视作最低水位),且不擦掉已有 profile 列 ──
    repo.apply_user_created(
        AccountCreated {
            user_id: bob,
            username: "bob",
            email: None,
            email_verified: false,
            roles: &["user".to_owned()],
            created_at: now,
        },
        7,
    )
    .await
    .unwrap();
    let bob_row = repo.get_account(bob).await.unwrap().unwrap();
    assert_eq!(
        bob_row.display_name.as_deref(),
        Some("Bob"),
        "idm 首次落地不该擦掉已有 profile 列"
    );
    assert_eq!(bob_row.username.as_deref(), Some("bob"));
    assert_eq!(bob_row.roles, vec!["user".to_owned()]);
    assert_eq!(bob_row.idm_sequence, Some(7));

    // ── 5. roles_set 守卫(9 > 8)+ deleted ──
    repo.apply_roles_set(alice, &["admin".to_owned()], 9)
        .await
        .unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert_eq!(row.roles, vec!["admin".to_owned()]);
    assert_eq!(row.idm_sequence, Some(9));

    repo.apply_user_deleted(alice, 10).await.unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert!(row.deleted);
    assert_eq!(row.idm_sequence, Some(10));

    // ── 6. rebuild_upsert:无守卫全量覆写(不比较 seq,不管当前水位高低)──
    repo.rebuild_account(AccountIndexRow {
        user_id: alice,
        username: Some("reb".to_owned()),
        email: Some("reb@x".to_owned()),
        email_verified: true,
        display_name: Some("Rebuilt".to_owned()),
        roles: vec!["reb".to_owned()],
        created_at: Some(now),
        deleted: false,
        idm_sequence: Some(100),
        profile_sequence: Some(100),
    })
    .await
    .unwrap();
    let row = repo.get_account(alice).await.unwrap().unwrap();
    assert_eq!(row.username.as_deref(), Some("reb"));
    assert_eq!(row.email.as_deref(), Some("reb@x"));
    assert!(row.email_verified);
    assert_eq!(row.display_name.as_deref(), Some("Rebuilt"));
    assert_eq!(row.roles, vec!["reb".to_owned()]);
    assert!(
        !row.deleted,
        "rebuild 快照本身 deleted=false,应覆写掉之前的 true"
    );
    assert_eq!(row.idm_sequence, Some(100));
    assert_eq!(row.profile_sequence, Some(100));
}

/// `SearchIndexRepo::query` 契约(P4 读路径):filter(q 跨 username/display_name、roles_any/none、
/// created 区间)+ 排序(选定键、None 落最后)+ 分页(offset 带 total、cursor keyset)—— 且半行
/// (username 未落地)/ 软删行永不出现在任何结果里。同 `search_index_contract`,memory 与 pg 共跑
/// 一套断言。**`admin_user_index` 是跨测试运行共享的表**(无临时库隔离),所以每个搜索词/角色名都
/// 嵌一段本轮独有的 tag(取自本轮 fresh v7 uuid)——不然历史行会掺进"只回 N 条"这类断言里。
async fn search_index_query_contract(repo: &dyn SearchIndexRepo, reader: &dyn SearchIndexRepo) {
    let now = OffsetDateTime::now_utc();
    // 本轮独有的租户:成员索引按租户查,别的租户(含历史运行留下的行)天然不掺进来。
    let tenant = fresh_tenant();

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

    seed(
        repo,
        tenant,
        alice,
        &alice_username,
        Some("a@x"),
        &role_user,
        now,
    )
    .await;
    repo.apply_profile_updated(alice, Some(&alice_display), 1)
        .await
        .unwrap();

    seed(
        repo,
        tenant,
        bob,
        &bob_username,
        Some("b@x"),
        &role_admin,
        now + Duration::days(1),
    )
    .await;
    repo.apply_profile_updated(bob, Some(&bob_display), 1)
        .await
        .unwrap();

    seed(
        repo,
        tenant,
        carol,
        &carol_username,
        Some("c@x"),
        &role_user,
        now + Duration::days(2),
    )
    .await;
    // carol 不 apply_profile_updated —— display_name 留 None,验证 NULLS LAST。

    // partial row:只经 profile 事件落地,username 永远 None —— 任何 query 都不该看到它。
    repo.apply_profile_updated(partial, Some(&format!("Partial Wonder {tag}")), 1)
        .await
        .unwrap();
    repo.apply_member_added(tenant, partial, "active", &[], 2)
        .await
        .unwrap();

    // deleted row:先建后删 —— 任何 query 都不该看到它。
    seed(
        repo,
        tenant,
        deleted,
        &format!("deleted-{tag}"),
        Some("d@x"),
        &role_user,
        now,
    )
    .await;
    repo.apply_user_deleted(deleted, 2).await.unwrap();

    let big_page = PageParams::Offset {
        page: 1,
        size: 50,
        with_total: true,
    };

    // ── 半行/软删永不出现:本轮全量(q=tag 圈定本轮候选)应恰好是 alice/bob/carol 三条 ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Asc,
            &big_page,
        )
        .await
        .unwrap();
    let mut ids: Vec<Uuid> = result.rows.iter().map(|r| r.user_id).collect();
    ids.sort();
    let mut expected = vec![alice, bob, carol];
    expected.sort();
    assert_eq!(
        ids, expected,
        "半行(partial)与软删行不该出现在 query 结果里"
    );
    assert_eq!(result.total, Some(3));

    // ── q 只命中 display_name(alice:"wonder <tag>" 不在任何本轮 username 里出现) ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(format!("wonder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice]
    );
    assert_eq!(result.total, Some(1));

    // ── q 只命中 username(bob:整个 username 串不出现在任何 display_name 里) ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(bob_username.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "q 应能命中 username"
    );

    // ── q 只命中 display_name(bob:"builder <tag>" 不在任何 username 里出现) ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(format!("builder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "q 应能命中 display_name"
    );

    // ── username 过滤:独立于 q,只认 username 子串(bob 的 username 含 "bobkeyword-<tag>",不在
    // 任何本轮 display_name 里出现)。这是 P4 曾经的回归本体——投影读链只认 q,plain `username`
    // 过滤被静默丢弃;此断言钉死 username 单独过滤生效。
    let result = reader
        .query(
            tenant,
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
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob],
        "username 过滤应只认 username 子串,忽略 display_name"
    );
    assert_eq!(result.total, Some(1));

    // ── username ∧ q:两者 AND 组合,不是各自独立的 OR ──
    // username 命中 alice(alice_username),q("wonder <tag>")也命中 alice(display_name)——两者都
    // 命中同一行,应返回 alice。
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                username: Some(alice_username.clone()),
                query: Some(format!("wonder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice],
        "username 与 q 都命中同一行时应返回该行"
    );

    // username 命中 alice,q("builder <tag>")只命中 bob(display_name)——AND 之下两者都不该出现:
    // alice 命中 username 但不命中 q,bob 命中 q 但不命中 username。
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                username: Some(alice_username.clone()),
                query: Some(format!("builder {tag}")),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert!(
        result.rows.is_empty(),
        "username 与 q 是 AND 关系:只命中其一的行(alice 命中 username 不命中 q,bob 命中 q 不命中 \
         username)都不该出现"
    );

    // ── roles_any:本轮独有的 role_admin 只在 bob 身上 ──
    let result = reader
        .query(
            tenant,
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
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── roles_none:本轮候选(q=tag)里排除 role_user 的只剩 bob ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── created 区间:本轮候选里只有 bob(t0+1d)落在 [t0+12h, t0+36h] ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
                created_from: Some(now + Duration::hours(12)),
                created_to: Some(now + Duration::hours(36)),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![bob]
    );

    // ── 排序:DisplayName Asc —— alice < bob(字节序),carol 的 None 落最后(NULLS LAST) ──
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
                ..Default::default()
            },
            IndexSort::DisplayName,
            SortOrder::Asc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice, bob, carol],
        "display_name 字节序升序,None(carol)落最后"
    );

    // ── 分页:offset(按 created_at asc,size=2 分两页,total 正确) ──
    let page1 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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

    let page2 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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
    let cursor1 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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

    let cursor2 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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
    let desc1 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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

    let desc2 = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(tag.clone()),
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
    seed(
        repo,
        tenant,
        percent,
        &format!("pct-{tag}"),
        Some("pct@x"),
        &role_user,
        now,
    )
    .await;
    repo.apply_profile_updated(percent, Some(&percent_display), 1)
        .await
        .unwrap();
    seed(
        repo,
        tenant,
        percent_decoy,
        &format!("pctdecoy-{tag}"),
        Some("pctd@x"),
        &role_user,
        now,
    )
    .await;
    repo.apply_profile_updated(percent_decoy, Some(&percent_decoy_display), 1)
        .await
        .unwrap();

    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(percent_display.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![percent],
        "q 里的字面 `%` 应转义后逐字匹配,不该把 decoy(50 与 tag 之间无字符)当通配符命中"
    );

    // 反向:换一个不含 `%` 的字面串(decoy 自己的内容)去查,percent 不该出现——证明上面那条
    // 命中不是"啥都匹配"的退化结果。
    let result = reader
        .query(
            tenant,
            &IndexQuery {
                query: Some(percent_decoy_display.clone()),
                ..Default::default()
            },
            IndexSort::CreatedAt,
            SortOrder::Desc,
            &big_page,
        )
        .await
        .unwrap();
    assert_eq!(
        result.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
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
    let repo = InMemorySearchIndexRepo::new();
    search_index_query_contract(&repo, &repo).await;
}

#[tokio::test]
async fn memory_accounts_list_is_global() {
    use baserust::features::search::InMemorySearchIndexRepo;
    let repo = InMemorySearchIndexRepo::new();
    accounts_list_is_global(&repo, &repo).await;
}

#[tokio::test]
async fn memory_member_index_scoped_by_tenant() {
    use baserust::features::search::InMemorySearchIndexRepo;
    let repo = InMemorySearchIndexRepo::new();
    member_index_scoped_by_tenant(&repo, &repo).await;
}

#[tokio::test]
async fn memory_profile_update_refreshes_all_tenant_rows() {
    use baserust::features::search::InMemorySearchIndexRepo;
    let repo = InMemorySearchIndexRepo::new();
    profile_update_refreshes_all_tenant_rows(&repo, &repo).await;
}

// ── 入口 2:PG(需 --features pg-conformance + search 的三个账号)──
// **不用 `#[sqlx::test]`**:它建临时库并用 `DATABASE_URL`(`just test-pg` 里连的是 app_owner),
// 而索引表在 search schema、须以 search 的账号连接 —— 显式建池:SEARCH_OWNER_DATABASE_URL 迁移、
// SEARCH_SYSTEM_DATABASE_URL(system 账号,BYPASSRLS)写 —— 和投影器一样;SEARCH_DATABASE_URL(运行时账号,
// 受 RLS 约束)读 —— 和请求路径一样。缺省回退本地 compose 的 search_owner / search_system / search。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::{
        accounts_list_is_global, member_index_scoped_by_tenant,
        profile_update_refreshes_all_tenant_rows, search_index_contract,
        search_index_query_contract,
    };
    use baserust::features::search::PgSearchIndexRepo;
    use sqlx::PgPool;
    use std::env;
    use uuid::Uuid;

    fn url(var: &str, user: &str) -> String {
        env::var(var).unwrap_or_else(|_| {
            format!("postgres://{user}:pwd@localhost:5821/baserust?sslmode=disable")
        })
    }

    /// 迁移(owner,幂等)后返回 (system 池, 运行时池)。
    async fn connect() -> (PgPool, PgPool) {
        let owner = PgPool::connect(&url("SEARCH_OWNER_DATABASE_URL", "search_owner"))
            .await
            .expect(
                "连 search_owner 失败(先 `just up` + `just db-ensure-roles` + `just migrate-search`)",
            );
        sqlx::migrate!("migrations/search")
            .run(&owner)
            .await
            .expect("跑 migrations/search 失败(幂等,应可重复跑)");
        owner.close().await;
        let system = PgPool::connect(&url("SEARCH_SYSTEM_DATABASE_URL", "search_system"))
            .await
            .expect("连 search_system 失败(先 `just db-ensure-roles`)");
        let runtime = PgPool::connect(&url("SEARCH_DATABASE_URL", "search"))
            .await
            .expect("连 search 运行时账号失败(先 `just up` + `just db-ensure-roles`)");
        (system, runtime)
    }

    #[tokio::test]
    async fn pg_satisfies_search_index_contract() {
        let (system, _) = connect().await;
        search_index_contract(&PgSearchIndexRepo::new(system)).await;
    }

    #[tokio::test]
    async fn pg_satisfies_search_index_query_contract() {
        let (system, runtime) = connect().await;
        search_index_query_contract(
            &PgSearchIndexRepo::new(system),
            &PgSearchIndexRepo::new(runtime),
        )
        .await;
    }

    /// 平台账号列表:system 写、**运行时账号**读(账号目录不开 RLS,运行时账号只有 SELECT)。
    #[tokio::test]
    async fn pg_accounts_list_is_global() {
        let (system, runtime) = connect().await;
        accounts_list_is_global(
            &PgSearchIndexRepo::new(system),
            &PgSearchIndexRepo::new(runtime),
        )
        .await;
    }

    /// 运行时账号写不了账号目录(只 system 写;迁移 0003 收回了 DML)。
    #[tokio::test]
    async fn pg_runtime_role_cannot_write_account_index() {
        let (_, runtime) = connect().await;
        let result = sqlx::query("insert into account_index (user_id) values ($1)")
            .bind(Uuid::now_v7())
            .execute(&runtime)
            .await;
        assert!(result.is_err(), "运行时账号不该能写 account_index");
    }

    #[tokio::test]
    async fn pg_member_index_scoped_by_tenant() {
        let (system, runtime) = connect().await;
        member_index_scoped_by_tenant(
            &PgSearchIndexRepo::new(system),
            &PgSearchIndexRepo::new(runtime),
        )
        .await;
    }

    #[tokio::test]
    async fn pg_profile_update_refreshes_all_tenant_rows() {
        let (system, runtime) = connect().await;
        profile_update_refreshes_all_tenant_rows(
            &PgSearchIndexRepo::new(system),
            &PgSearchIndexRepo::new(runtime),
        )
        .await;
    }

    /// RLS 真的生效:运行时账号不设 `app.tenant_id` 直接查成员索引 → 0 行(哪怕表里有行);
    /// 写也写不进(WITH CHECK)。system 账号(BYPASSRLS)看得到。
    #[tokio::test]
    async fn pg_runtime_role_sees_no_member_rows_without_tenant() {
        let (system, runtime) = connect().await;
        let repo = PgSearchIndexRepo::new(system.clone());
        let tenant = super::fresh_tenant();
        let user_id = Uuid::now_v7();
        use baserust::features::search::SearchIndexRepo;
        repo.apply_member_added(tenant, user_id, "active", &[], 1)
            .await
            .unwrap();
        let seen_by_system: i64 =
            sqlx::query_scalar("select count(*) from admin_user_index where tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(&system)
                .await
                .unwrap();
        assert_eq!(seen_by_system, 1);
        let seen_by_runtime: i64 =
            sqlx::query_scalar("select count(*) from admin_user_index where tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(&runtime)
                .await
                .unwrap();
        assert_eq!(seen_by_runtime, 0, "运行时账号不设租户 → RLS 过滤成 0 行");
        let insert =
            sqlx::query("insert into admin_user_index (tenant_id, user_id) values ($1, $2)")
                .bind(tenant.as_uuid())
                .bind(Uuid::now_v7())
                .execute(&runtime)
                .await;
        assert!(insert.is_err(), "运行时账号不设租户写不进(WITH CHECK)");
    }
}

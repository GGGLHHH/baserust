//! `search::rebuild` 的跨模块集成测试:idm 内存用户 / 租户 / 成员 + profile 内存仓储 + 组合根适配器
//! `ProfileDisplayNames` 一起装配(零 DB)。放在 tests/ 而非 rebuild.rs 的单测里 —— search 核心不许
//! 依赖别的业务模块与组合根(见 `tests/architecture.rs`),装配多模块是集成测试的事。

use idm::{MemberKey, NewRole, NewTenant, NewUser};
use std::sync::Arc;

use baserust::app::adapters::ProfileDisplayNames;
use baserust::features::profile::{InMemoryProfileRepo, ProfileFields, ProfileRepo};
use baserust::features::search::rebuild::PAGE_LIMIT;
use baserust::features::search::{
    rebuild, IdmSources, InMemorySearchIndexRepo, IndexQuery, IndexSort, RebuildCounts,
    SearchIndexRepo, Watermarks,
};
use baserust::kernel::pagination::PageParams;
use baserust::kernel::sort_order::SortOrder;
use baserust::kernel::tenant_id::TenantId;
use idm::{
    InMemoryMemberRepo, InMemoryRoleRepo, InMemoryTenantRepo, InMemoryUserRepo, MemberRepo,
    RoleRepo, RoleScope, TenantRepo, UserRepo,
};

/// 内存 idm 三件套(租户 / 成员仓储与用户仓储共享存储,成员外键校验看同一批用户和租户)。
struct Idm {
    users: InMemoryUserRepo,
    tenants: InMemoryTenantRepo,
    members: InMemoryMemberRepo,
}

impl Default for Idm {
    fn default() -> Self {
        Self::new()
    }
}

impl Idm {
    fn new() -> Self {
        let users = InMemoryUserRepo::new();
        let tenants = InMemoryTenantRepo::new_shared_with(&users);
        let members = InMemoryMemberRepo::new_shared_with(&users);
        Self {
            users,
            tenants,
            members,
        }
    }

    fn sources(&self) -> IdmSources<'_> {
        IdmSources {
            users: &self.users,
            tenants: &self.tenants,
            members: &self.members,
        }
    }
}

#[tokio::test]
async fn backfills_all_alive_users_with_profile_enrichment_and_watermarks() {
    let idm = Idm::new();
    let users = &idm.users;
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    // 两个存活用户;u1 建了 profile(display_name),u2 没有 → 应回填为 None。
    let alice = users
        .create(
            NewUser {
                username: "alice",
                email: Some("alice@x"),
                password_hash: "hash",
            },
            None,
        )
        .await
        .unwrap();
    let bob = users
        .create(
            NewUser {
                username: "bob",
                email: Some("bob@x"),
                password_hash: "hash",
            },
            None,
        )
        .await
        .unwrap();
    profiles
        .upsert(
            alice.id,
            ProfileFields {
                display_name: Some("Alice Disp".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    let written = rebuild(
        idm.sources(),
        &ProfileDisplayNames::new(profiles),
        &index,
        Watermarks { idm: 100, app: 200 },
    )
    .await
    .unwrap();
    assert_eq!(
        written,
        RebuildCounts {
            accounts: 2,
            members: 0
        }
    );

    let row1 = index
        .get_account(alice.id)
        .await
        .unwrap()
        .expect("u1 应已回填");
    assert_eq!(row1.username.as_deref(), Some("alice"));
    assert!(row1.roles.is_empty(), "{:?}", row1.roles);
    assert_eq!(row1.display_name.as_deref(), Some("Alice Disp"));
    assert_eq!(row1.idm_sequence, Some(100));
    assert_eq!(row1.profile_sequence, Some(200));
    assert!(!row1.deleted);

    let row2 = index
        .get_account(bob.id)
        .await
        .unwrap()
        .expect("u2 应已回填");
    assert_eq!(row2.username.as_deref(), Some("bob"));
    assert_eq!(row2.display_name, None, "无 profile 的用户应回填 None");
    assert_eq!(row2.idm_sequence, Some(100));
    assert_eq!(row2.profile_sequence, Some(200));
}

/// **翻页必须收全**:超过一页时,keyset 要把每一页都走到,`alive` 才完整 —— 漏掉任何一个
/// 存活用户,后面的 sweep 就会把它扫成 deleted(回填反而删活人)。这里跨 `PAGE_LIMIT` 边界,
/// 钉住循环的终止条件(`next_after.is_none()`,不是"页不满就停")。
#[tokio::test]
async fn multi_page_backfill_keeps_every_alive_user() {
    let idm = Idm::new();
    let users = &idm.users;
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    let user_count = PAGE_LIMIT as usize + 3; // 跨页:一整页 + 零头
    let mut ids = Vec::with_capacity(user_count);
    for i in 0..user_count {
        ids.push(
            users
                .create(
                    NewUser {
                        username: &format!("u{i}"),
                        email: None,
                        password_hash: "hash",
                    },
                    None,
                )
                .await
                .unwrap()
                .id,
        );
    }

    let written = rebuild(
        idm.sources(),
        &ProfileDisplayNames::new(profiles),
        &index,
        Watermarks { idm: 100, app: 200 },
    )
    .await
    .unwrap();
    assert_eq!(
        written.accounts, user_count,
        "每一页的用户都该回填(翻页漏人 = 后面被扫成已删)"
    );
    for id in ids {
        let row = index
            .get_account(id)
            .await
            .unwrap()
            .expect("每个存活用户都该有索引行");
        assert!(!row.deleted, "存活用户不该被 sweep 扫掉");
    }
}

#[tokio::test]
async fn no_alive_users_backfills_zero() {
    let idm = Idm::new();
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    let written = rebuild(
        idm.sources(),
        &ProfileDisplayNames::new(profiles),
        &index,
        Watermarks { idm: 1, app: 1 },
    )
    .await
    .unwrap();
    assert_eq!(
        written,
        RebuildCounts {
            accounts: 0,
            members: 0
        }
    );
}

/// 多租户:成员索引按 idm 的成员关系回填,**一个成员关系一行** —— 同一账号在两个租户各一行,
/// 角色是各自的租户角色,显示名来自全局资料;已删账号的成员关系不回填。
#[tokio::test]
async fn rebuild_fills_one_member_row_per_membership() {
    let idm = Idm::new();
    let roles = InMemoryRoleRepo::new_shared_with(&idm.users);
    let admin = roles
        .upsert(
            NewRole {
                name: "admin",
                display_name: "Admin",
                scope: RoleScope::Tenant,
            },
            None,
        )
        .await
        .unwrap();
    let user_role = roles
        .upsert(
            NewRole {
                name: "user",
                display_name: "User",
                scope: RoleScope::Tenant,
            },
            None,
        )
        .await
        .unwrap();
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    let tenant_a = idm
        .tenants
        .create(
            NewTenant {
                slug: "ta",
                name: "Tenant A",
            },
            None,
        )
        .await
        .unwrap();
    let tenant_b = idm
        .tenants
        .create(
            NewTenant {
                slug: "tb",
                name: "Tenant B",
            },
            None,
        )
        .await
        .unwrap();
    let alice = idm
        .users
        .create(
            NewUser {
                username: "alice",
                email: None,
                password_hash: "hash",
            },
            None,
        )
        .await
        .unwrap();
    let bob = idm
        .users
        .create(
            NewUser {
                username: "bob",
                email: None,
                password_hash: "hash",
            },
            None,
        )
        .await
        .unwrap();
    let gone = idm
        .users
        .create(
            NewUser {
                username: "gone",
                email: None,
                password_hash: "hash",
            },
            None,
        )
        .await
        .unwrap();
    idm.members
        .add(
            MemberKey {
                tenant_id: tenant_a.id,
                user_id: alice.id,
            },
            &[admin],
            None,
        )
        .await
        .unwrap();
    idm.members
        .add(
            MemberKey {
                tenant_id: tenant_b.id,
                user_id: alice.id,
            },
            &[user_role],
            None,
        )
        .await
        .unwrap();
    idm.members
        .add(
            MemberKey {
                tenant_id: tenant_a.id,
                user_id: bob.id,
            },
            &[user_role],
            None,
        )
        .await
        .unwrap();
    idm.members
        .add(
            MemberKey {
                tenant_id: tenant_a.id,
                user_id: gone.id,
            },
            &[],
            None,
        )
        .await
        .unwrap();
    idm.users.soft_delete(gone.id, None).await.unwrap();
    profiles
        .upsert(
            alice.id,
            ProfileFields {
                display_name: Some("Alice Disp".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    let counts = rebuild(
        idm.sources(),
        &ProfileDisplayNames::new(profiles),
        &index,
        Watermarks { idm: 100, app: 200 },
    )
    .await
    .unwrap();
    assert_eq!(
        counts,
        RebuildCounts {
            accounts: 2,
            members: 3
        },
        "存活账号 2 个;成员关系 4 条,其中 gone 的账号已删不回填"
    );

    let tenant_a_id = TenantId::try_new(tenant_a.id).unwrap();
    let tenant_b_id = TenantId::try_new(tenant_b.id).unwrap();
    let alice_a = index
        .get_member(tenant_a_id, alice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice_a.username.as_deref(), Some("alice"));
    assert_eq!(alice_a.roles, vec!["admin".to_owned()]);
    assert_eq!(alice_a.status.as_deref(), Some("active"));
    assert_eq!(
        alice_a.display_name.as_deref(),
        Some("Alice Disp"),
        "显示名来自全局资料"
    );
    assert_eq!(alice_a.idm_sequence, Some(100));
    assert_eq!(alice_a.member_sequence, Some(100));
    assert_eq!(alice_a.profile_sequence, Some(200));
    let alice_b = index
        .get_member(tenant_b_id, alice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        alice_b.roles,
        vec!["user".to_owned()],
        "各租户的租户角色各自独立"
    );
    assert!(index
        .get_member(tenant_b_id, bob.id)
        .await
        .unwrap()
        .is_none());
    assert!(index
        .get_member(tenant_a_id, gone.id)
        .await
        .unwrap()
        .is_none());

    let page = PageParams::Offset {
        page: 1,
        size: 10,
        with_total: true,
    };
    let in_a = index
        .query(
            tenant_a_id,
            &IndexQuery::default(),
            IndexSort::Username,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        in_a.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice.id, bob.id]
    );
    let in_b = index
        .query(
            tenant_b_id,
            &IndexQuery::default(),
            IndexSort::Username,
            SortOrder::Asc,
            &page,
        )
        .await
        .unwrap();
    assert_eq!(
        in_b.rows.iter().map(|r| r.user_id).collect::<Vec<_>>(),
        vec![alice.id]
    );
}

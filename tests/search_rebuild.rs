//! `search::rebuild` 的跨模块集成测试:idm 内存用户 + profile 内存仓储 + 组合根适配器
//! `ProfileDisplayNames` 一起装配(零 DB)。放在 tests/ 而非 rebuild.rs 的单测里 —— search 核心不许
//! 依赖别的业务模块与组合根(见 `tests/architecture.rs`),装配多模块是集成测试的事。

use std::sync::Arc;

use baserust::app::adapters::ProfileDisplayNames;
use baserust::features::profile::{InMemoryProfileRepo, ProfileFields, ProfileRepo};
use baserust::features::search::rebuild::PAGE_LIMIT;
use baserust::features::search::{rebuild, InMemorySearchIndexRepo, SearchIndexRepo};
use idm::{InMemoryUserRepo, UserRepo};

#[tokio::test]
async fn backfills_all_alive_users_with_profile_enrichment_and_watermarks() {
    let users = InMemoryUserRepo::new();
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    // 两个存活用户;u1 建了 profile(display_name),u2 没有 → 应回填为 None。
    let u1 = users
        .create("alice", Some("alice@x"), "hash", None)
        .await
        .unwrap();
    let u2 = users
        .create("bob", Some("bob@x"), "hash", None)
        .await
        .unwrap();
    profiles
        .upsert(
            u1.id,
            ProfileFields {
                display_name: Some("Alice Disp".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    let written = rebuild(
        &users,
        &ProfileDisplayNames::new(profiles),
        &index,
        100,
        200,
    )
    .await
    .unwrap();
    assert_eq!(written, 2);

    let row1 = index.get(u1.id).await.unwrap().expect("u1 应已回填");
    assert_eq!(row1.username.as_deref(), Some("alice"));
    assert_eq!(row1.roles, Vec::<String>::new());
    assert_eq!(row1.display_name.as_deref(), Some("Alice Disp"));
    assert_eq!(row1.idm_seq, Some(100));
    assert_eq!(row1.profile_seq, Some(200));
    assert!(!row1.deleted);

    let row2 = index.get(u2.id).await.unwrap().expect("u2 应已回填");
    assert_eq!(row2.username.as_deref(), Some("bob"));
    assert_eq!(row2.display_name, None, "无 profile 的用户应回填 None");
    assert_eq!(row2.idm_seq, Some(100));
    assert_eq!(row2.profile_seq, Some(200));
}

/// **翻页必须收全**:超过一页时,keyset 要把每一页都走到,`alive` 才完整 —— 漏掉任何一个
/// 存活用户,后面的 sweep 就会把它扫成 deleted(回填反而删活人)。这里跨 `PAGE_LIMIT` 边界,
/// 钉住循环的终止条件(`next_after.is_none()`,不是"页不满就停")。
#[tokio::test]
async fn multi_page_backfill_keeps_every_alive_user() {
    let users = InMemoryUserRepo::new();
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    let n = PAGE_LIMIT as usize + 3; // 跨页:一整页 + 零头
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        ids.push(
            users
                .create(&format!("u{i}"), None, "hash", None)
                .await
                .unwrap()
                .id,
        );
    }

    let written = rebuild(
        &users,
        &ProfileDisplayNames::new(profiles),
        &index,
        100,
        200,
    )
    .await
    .unwrap();
    assert_eq!(
        written, n,
        "每一页的用户都该回填(翻页漏人 = 后面被扫成已删)"
    );
    for id in ids {
        let row = index
            .get(id)
            .await
            .unwrap()
            .expect("每个存活用户都该有索引行");
        assert!(!row.deleted, "存活用户不该被 sweep 扫掉");
    }
}

#[tokio::test]
async fn no_alive_users_backfills_zero() {
    let users = InMemoryUserRepo::new();
    let profiles = Arc::new(InMemoryProfileRepo::new());
    let index = InMemorySearchIndexRepo::new();

    let written = rebuild(&users, &ProfileDisplayNames::new(profiles), &index, 1, 1)
        .await
        .unwrap();
    assert_eq!(written, 0);
}

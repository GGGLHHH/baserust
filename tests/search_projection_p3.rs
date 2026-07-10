//! Spec 2 · P3 capstone e2e —— 真用户写 → projector 把 idm/profile 两源事件投影进
//! **一张** `search.admin_user_index` 行 → 行按 username + display_name 双源收敛。
//!
//! 门 **双 feature**(`pg-conformance` + `nats-conformance`):不开就编译成空文件,
//! `just check`/`just test`/`just lint` 全不受影响。跑它:`just test-search`
//! (需全栈:先 `just up` 起 pg + nats + `just migrate-search`,`.env` 配好 pg + NATS_URL)。
//!
//! **关键设置**:`.env` 不设 `SEARCH_DB_HOST` → 默认无投影 backend。本测试在 `Config::load` **前**
//! 显式设 `SEARCH_DB_*`(默认端口是 5432,PG 实际在 5821,必须覆盖 host+port)才装得出 projector。
//!
//! **独立 durable**:dev server(若在跑)用固定 durable `admin_user_projector`;JetStream 同名
//! durable 竞争投递(每条只给一个消费者)。故本测试**不** spawn `bg.projector`,自建一个
//! 唯一 durable(`proj_test_<uniq>`)的 projector,与 dev server 不抢。同时 spawn `bg.relays`
//! (它们把 idm/app outbox 的事件发布到流,projector 才有得消费)。
#![cfg(all(feature = "pg-conformance", feature = "nats-conformance"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use baserust::app::adapters::ProfileDisplayNames;
use baserust::app::state::{connect_for_schema, Schema};
use baserust::app::{AppState, Mount};
use baserust::features::profile::{PgProfileRepo, PutProfileRequest};
use baserust::features::search::projector::Projector;
use baserust::features::search::{rebuild, AdminUserIndexRow, PgSearchIndexRepo, SearchIndexRepo};
use baserust::features::users::{ListUsersFilter, UserSortField};
use baserust::infra::audit::AuditContext;
use baserust::infra::config::Config;
use baserust::infra::pagination::PageParams;
use idm::{PgUserRepo, RegisterInput};

/// 轮询 `index_repo.get(user_id)` 直到 `pred(&row)` 为真或超时;超时 → `None`。
async fn poll_row(
    index: &Arc<dyn SearchIndexRepo>,
    user_id: Uuid,
    budget: Duration,
    pred: impl Fn(&AdminUserIndexRow) -> bool,
) -> Option<AdminUserIndexRow> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Some(row) = index.get(user_id).await.expect("get 投影行不应报错") {
            if pred(&row) {
                return Some(row);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn user_write_converges_into_projection_row() -> anyhow::Result<()> {
    // 1. **先设 SEARCH_DB_*(Config::load 前)** 再载 .env —— dotenvy 默认不覆盖已设 env,
    //    .env 无 SEARCH_DB_* → 我们设的值存活。默认端口 5432,PG 在 5821,host+port 都要覆盖。
    std::env::set_var("SEARCH_DB_HOST", "localhost");
    std::env::set_var("SEARCH_DB_PORT", "5821");
    std::env::set_var("SEARCH_DB_USER", "search");
    std::env::set_var("SEARCH_DB_PASSWORD", "pwd");
    std::env::set_var("SEARCH_DB_DATABASE", "baserust");
    dotenvy::from_path(".env").ok();
    let config = Config::load()?;
    assert!(
        config.search_database_url().is_some(),
        "缺 SEARCH backend:测试应已设 SEARCH_DB_HOST"
    );
    assert!(
        config.nats_url.is_some(),
        "缺 NATS_URL:先 `just up` 起 nats 并确保 .env 配好"
    );
    assert!(
        config.idm_database_url().is_some() && config.app_database_url().is_some(),
        "缺 pg 配置(APP_DB_HOST/IDM_DB_HOST):先 `just up` 并确保 .env 配好"
    );

    // 2. 起三个 schema 的池 + 幂等迁移(sqlx 追已应用版本,只补未应用的)。必须先于 AppState::new
    //    —— seed/mock 写会 emit 到 outbox,表不在会炸启动。
    let idm_pool = connect_for_schema(&config, Schema::Idm)
        .await?
        .expect("idm pool");
    let app_pool = connect_for_schema(&config, Schema::App)
        .await?
        .expect("app pool");
    let search_pool = connect_for_schema(&config, Schema::Search)
        .await?
        .expect("search pool(已断言 search_database_url Some)");
    sqlx::migrate!("migrations/idm").run(&idm_pool).await?;
    sqlx::migrate!("migrations/app").run(&app_pool).await?;
    sqlx::migrate!("migrations/search")
        .run(&search_pool)
        .await?;

    // 3. 起真 app(pg+nats,Both)→ 断言 projector 已装出(Task 4 接线证据)。
    let (state, bg) = AppState::new(&config, Mount::Both).await?;
    assert!(
        bg.projector.is_some(),
        "pg+nats+search 下应装出 projector(Task 4)"
    );

    // 4. 本测试自建 projector,用唯一 durable(不 spawn bg.projector,避与 dev server 固定 durable 抢)。
    let uniq_suffix = Uuid::now_v7().simple().to_string();
    let index_repo: Arc<dyn SearchIndexRepo> =
        Arc::new(PgSearchIndexRepo::new(search_pool.clone()));
    let projector = Projector::connect(
        config.nats_url.as_deref().unwrap(),
        index_repo.clone(),
        &format!("proj_test_{uniq_suffix}"),
    )
    .await?;

    // 5. 一个 watch 通道统管关停:spawn relays(发布事件)+ 测试 projector(消费投影)。
    let (tx, rx) = tokio::sync::watch::channel(false);
    for r in bg.relays {
        tokio::spawn(r.run(rx.clone()));
    }
    tokio::spawn(projector.run(rx.clone()));

    // 6. 经真 service 驱动写:register(→ user.created,roles [])+ profile put(→ profile.updated)。
    //    唯一名贯穿两源,收敛判据 = 同一行同时有本轮的 username(idm 源)与 display_name(profile 源)。
    let uniq = format!("p3-{uniq_suffix}");
    let disp = format!("Disp {uniq}");
    let outcome = state
        .auth
        .register(
            RegisterInput {
                username: uniq.clone(),
                email: None,
                password: "password123".into(),
            },
            Some("p3-e2e".into()),
        )
        .await?;
    let user_id = outcome.user.id;
    state
        .profiles
        .put(
            user_id,
            PutProfileRequest {
                display_name: Some(disp.clone()),
                phone: None,
                avatar_content_id: None,
            },
            &AuditContext::system(),
        )
        .await?;

    // 7. 轮询收敛(≤25s):两源都投进同一行 —— username(idm)+ display_name(profile)。
    let row = poll_row(&index_repo, user_id, Duration::from_secs(25), |row| {
        row.username.as_deref() == Some(uniq.as_str())
            && row.display_name.as_deref() == Some(disp.as_str())
    })
    .await
    .unwrap_or_else(|| {
        panic!("25s 内投影行未收敛(username={uniq} + display_name={disp} 应双源投进同一行)")
    });
    assert_eq!(
        row.roles,
        Vec::<String>::new(),
        "register 天然无角色 → roles 应为空"
    );
    assert!(!row.deleted, "存活用户 deleted 应为 false");
    assert!(row.idm_seq.is_some(), "idm 源已投 → idm_seq 应非空");
    assert!(
        row.profile_seq.is_some(),
        "profile 源已投 → profile_seq 应非空"
    );

    // 7b. P4 落点:投影已收敛 → 经真接线的 `state.user_admin.list()` q 搜索命中(username 侧 +
    //     display_name 侧跨字段搜索均经投影生效),且有 backend 时 `sort_by=display_name` 不再 422。
    let list_page = |page: u64| PageParams::Offset {
        page,
        size: 20,
        with_total: true,
    };

    // display_name 侧:取 disp 独有的前缀子串("Disp p3-" + 4 位 hex,uniq 里不含 "Disp"),
    // 只可能经投影的 display_name 列命中,证 P4 的"display_name 可搜"这一核心落点。
    let disp_substr = &disp[..12];
    let filter_by_disp = ListUsersFilter {
        q: Some(disp_substr.to_string()),
        ..Default::default()
    };
    let page = state.user_admin.list(&filter_by_disp, list_page(1)).await?;
    assert!(
        page.items.iter().any(|u| u.id == user_id),
        "q={disp_substr}(display_name 独有子串)应命中 user_id={user_id},实际 items={:?}",
        page.items.iter().map(|u| u.id).collect::<Vec<_>>()
    );

    // username 侧:q=完整 uniq(username 本身)应命中。
    let filter_by_uniq = ListUsersFilter {
        q: Some(uniq.clone()),
        ..Default::default()
    };
    let page = state.user_admin.list(&filter_by_uniq, list_page(1)).await?;
    assert!(
        page.items.iter().any(|u| u.id == user_id),
        "q={uniq}(username)应命中 user_id={user_id},实际 items={:?}",
        page.items.iter().map(|u| u.id).collect::<Vec<_>>()
    );

    // 有 search 后端时 sort_by=display_name 不应 422(回退路才 422;此处走投影路)。
    let filter_sort_display_name = ListUsersFilter {
        sort_by: UserSortField::DisplayName,
        ..Default::default()
    };
    state
        .user_admin
        .list(&filter_sort_display_name, list_page(1))
        .await
        .expect("有 search 后端时 sort_by=display_name 不应 422");

    // 8. 删用户 → 轮询直到 deleted 翻 true(user.deleted 事件投影)。
    state
        .user_admin
        .delete(user_id, Some("p3-e2e".into()))
        .await?;
    let deleted_row = poll_row(&index_repo, user_id, Duration::from_secs(25), |row| {
        row.deleted
    })
    .await
    .expect("25s 内 user.deleted 未把行 deleted 翻 true");
    assert!(deleted_row.deleted);

    // 9. 重建实测(真 PG):建第二个用户 U2(不删)→ 读 outbox 水位 → rebuild 从当前状态回填 →
    //    断言 U2 行命中,且 idm_seq = 快照水位。connect_for_schema 已按 role 设 search_path,
    //    `outbox` 分别解析到 idm.outbox / app.outbox。
    let u2_uniq = format!("p3-rebuild-{uniq_suffix}");
    let u2 = state
        .auth
        .register(
            RegisterInput {
                username: u2_uniq.clone(),
                email: None,
                password: "password123".into(),
            },
            Some("p3-e2e".into()),
        )
        .await?;
    let u2_id = u2.user.id;
    let p_idm: i64 = sqlx::query_scalar("select coalesce(max(id),0) from outbox")
        .fetch_one(&idm_pool)
        .await?;
    let p_app: i64 = sqlx::query_scalar("select coalesce(max(id),0) from outbox")
        .fetch_one(&app_pool)
        .await?;
    rebuild(
        &PgUserRepo::new(idm_pool.clone()),
        &ProfileDisplayNames::new(Arc::new(PgProfileRepo::new(app_pool.clone()))),
        &*index_repo,
        p_idm,
        p_app,
    )
    .await?;
    let u2_row = index_repo
        .get(u2_id)
        .await?
        .expect("rebuild 后 U2 行应命中");
    assert_eq!(u2_row.username.as_deref(), Some(u2_uniq.as_str()));
    assert_eq!(
        u2_row.idm_seq,
        Some(p_idm),
        "rebuild 应把 idm_seq 设为快照水位"
    );

    // 10. 收尾:停后台任务 + best-effort 删 U2(reruns 干净)。
    let _ = tx.send(true);
    let _ = state.user_admin.delete(u2_id, Some("p3-e2e".into())).await;

    Ok(())
}

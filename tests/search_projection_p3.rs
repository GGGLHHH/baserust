//! Spec 2 · P3 capstone e2e —— 真用户写 → relay 发事件 → projector(**system 池**)把 idm 账号 / idm 成员 /
//! profile 三源事件投影进账号目录 `search.account_index` 与租户成员索引 `search.admin_user_index`(成员行经
//! system 池 / RLS 读回)→ 请求路径的平台账号列表(`user_admin.list`,**运行时池**读账号目录)搜得到。多租户(Task 8)另验:
//! 不属于任何租户的账号也在平台账号列表里、
//! 同一账号在两个租户各一行、`profile.updated` 刷新两行、认证审计事件记下租户、老 durable 的过滤主题被补上
//! `tenant.*`、rebuild_search 按成员关系回填。
//!
//! 门 **双 feature**(`pg-conformance` + `nats-conformance`):不开就编译成空文件,
//! `just check`/`just test`/`just lint` 全不受影响。跑它:`just test-search`
//! (需全栈:先 `just up` 起 pg + nats + `just migrate-search`,`.env` 配好 pg + NATS_URL)。
//!
//! **关键设置**:`.env` 不设 `SEARCH_DB_HOST` → 默认无投影 backend。本测试在 `Config::load` **前**
//! 补上 `SEARCH_DB_*`(只补没设的:环境里已给的 host / port 优先,方便指向别的测试库)才装得出 projector。
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
use baserust::app::state::{connect_for_schema, connect_system_for_schema, Schema};
use baserust::app::{AppState, Mount};
use baserust::features::auth::adapters::emit::{emit_auth_event, success_data};
use baserust::features::auth_audit::adapters::projector::AuthEventProjector;
use baserust::features::auth_audit::{
    AuthChannel, AuthEventQuery, AuthEventRepo, AuthEventType, PgAuthEventRepo,
};
use baserust::features::profile::{PgProfileRepo, PutProfile};
use baserust::features::search::projector::Projector;
use baserust::features::search::{
    rebuild, AdminUserIndexRow, IdmSources, PgSearchIndexRepo, SearchIndexRepo,
};
use baserust::features::users::model::CreateUser;
use baserust::features::users::{ListUsers, UserSortField};
use baserust::infra::client_context::ClientContext;
use baserust::infra::config::Config;
use baserust::kernel::audit::AuditContext;
use baserust::kernel::pagination::PageParams;
use baserust::kernel::tenant::{TenantId, DEFAULT_TENANT_ID};
use idm::{MemberRepo, PgMemberRepo, PgTenantRepo, PgUserRepo, RegisterInput, TenantRepo};

/// 轮询 `index_repo.get_member(tenant, user_id)` 直到 `pred(&row)` 为真或超时;超时 → `None`。
async fn poll_member(
    index: &Arc<dyn SearchIndexRepo>,
    tenant: TenantId,
    user_id: Uuid,
    budget: Duration,
    pred: impl Fn(&AdminUserIndexRow) -> bool,
) -> Option<AdminUserIndexRow> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Some(row) = index
            .get_member(tenant, user_id)
            .await
            .expect("get_member 投影行不应报错")
        {
            if pred(&row) {
                return Some(row);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

/// 只在环境里没设时才设(环境优先:`SEARCH_DB_PORT=15821` 之类指向测试库)。
fn set_default_env(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, value);
    }
}

/// 迁移要用 owner 账号(spec §4.4:运行时账号只有 DML,建不了表):同一个库,账号换成
/// `<SCHEMA>_DB_OWNER_USER`(缺省 = 运行时账号名 + `_owner`)/ `<SCHEMA>_DB_OWNER_PASSWORD`(缺省 pwd)。
async fn owner_pool(
    runtime: &sqlx::PgPool,
    prefix: &str,
    runtime_user: &str,
) -> anyhow::Result<sqlx::PgPool> {
    let user = std::env::var(format!("{prefix}_DB_OWNER_USER"))
        .unwrap_or_else(|_| format!("{runtime_user}_owner"));
    let password =
        std::env::var(format!("{prefix}_DB_OWNER_PASSWORD")).unwrap_or_else(|_| "pwd".into());
    let opts = runtime
        .connect_options()
        .as_ref()
        .clone()
        .username(&user)
        .password(&password);
    Ok(sqlx::PgPool::connect_with(opts).await?)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_and_projectors_work_with_rls_on() -> anyhow::Result<()> {
    // 1. **先补 SEARCH_DB_*(Config::load 前)** 再载 .env —— dotenvy 默认不覆盖已设 env,
    //    .env 无 SEARCH_DB_* → 我们设的值存活。默认端口 5432,本地 compose 的 PG 在 5821。
    set_default_env("SEARCH_DB_HOST", "localhost");
    set_default_env("SEARCH_DB_PORT", "5821");
    set_default_env("SEARCH_DB_USER", "search");
    set_default_env("SEARCH_DB_PASSWORD", "pwd");
    set_default_env("SEARCH_DB_DATABASE", "baserust");
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
    sqlx::migrate!("migrations/app")
        .run(&owner_pool(&app_pool, "APP", &config.app_db_user).await?)
        .await?;
    sqlx::migrate!("migrations/search")
        .run(&owner_pool(&search_pool, "SEARCH", &config.search_db_user).await?)
        .await?;

    // 3. 起真 app(pg+nats,Both)→ 断言 projector 已装出(Task 4 接线证据)。
    let (state, bg) = AppState::new(&config, Mount::Both).await?;
    assert!(
        bg.projector.is_some(),
        "pg+nats+search 下应装出 projector(Task 4)"
    );

    assert!(
        bg.auth_projector.is_some(),
        "pg+nats+search 下应装出 auth_event projector"
    );

    // 4. 本测试自建 projector,用唯一 durable(不 spawn bg.projector,避与 dev server 固定 durable 抢)。
    //    写侧用 search 的 **system 池**(BYPASSRLS,同组合根);读侧 `state.user_admin` 走运行时池 + 租户事务。
    //    **老 durable 升级**:先按多租户之前的过滤主题(只有 user.> / app.>)建好 durable,再 connect ——
    //    connect 应把 tenant.> 补进过滤主题,否则成员事件永远到不了投影器。
    let uniq_suffix = Uuid::now_v7().simple().to_string();
    let durable = format!("proj_test_{uniq_suffix}");
    let nats_url = config.nats_url.clone().unwrap();
    let js = async_nats::jetstream::new(async_nats::connect(&nats_url).await?);
    let stream = js.get_stream("USER_SEARCH_EVENTS").await?;
    stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            durable_name: Some(durable.clone()),
            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            filter_subjects: vec!["events.idm.user.>".to_owned(), "events.app.>".to_owned()],
            ..Default::default()
        })
        .await?;
    let search_system = connect_system_for_schema(&config, Schema::Search)
        .await?
        .expect("search system 池");
    let index_repo: Arc<dyn SearchIndexRepo> =
        Arc::new(PgSearchIndexRepo::new(search_system.clone()));
    let projector = Projector::connect(&nats_url, index_repo.clone(), &durable).await?;
    let mut info = stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&durable)
        .await
        .map_err(|e| anyhow::anyhow!("get_consumer: {e}"))?;
    let filters = info
        .info()
        .await
        .map_err(|e| anyhow::anyhow!("consumer info: {e}"))?
        .config
        .filter_subjects
        .clone();
    assert!(
        filters.iter().any(|s| s == "events.idm.tenant.>"),
        "老 durable 的过滤主题应补上 tenant.>,实际 {filters:?}"
    );

    // auth_event 投影器同理自建唯一 durable(写 auth_event 用 system 池)。
    let auth_repo: Arc<dyn AuthEventRepo> = Arc::new(PgAuthEventRepo::new(search_system.clone()));
    let auth_projector = AuthEventProjector::connect(
        &nats_url,
        auth_repo.clone(),
        &format!("auth_test_{uniq_suffix}"),
        None,
    )
    .await?;

    // 5. 一个 watch 通道统管关停:spawn relays(发布事件)+ 测试 projector(消费投影)。
    let (tx, rx) = tokio::sync::watch::channel(false);
    for r in bg.relays {
        tokio::spawn(r.run(rx.clone()));
    }
    tokio::spawn(projector.run(rx.clone()));
    tokio::spawn(auth_projector.run(rx.clone()));

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
            PutProfile {
                display_name: Some(disp.clone()),
                phone: None,
                avatar_content_id: None,
            },
            &AuditContext::system(),
        )
        .await?;

    // 7. 轮询收敛(≤25s):注册自动加入默认租户(角色 user)→ 默认租户的成员行同时有 username(idm 账号)、
    //    租户角色(idm 成员)、display_name(profile)三源。
    let row = poll_member(
        &index_repo,
        DEFAULT_TENANT_ID,
        user_id,
        Duration::from_secs(25),
        |row| {
            row.username.as_deref() == Some(uniq.as_str())
                && row.display_name.as_deref() == Some(disp.as_str())
                && row.member_seq.is_some()
        },
    )
    .await
    .unwrap_or_else(|| {
        panic!("25s 内默认租户的成员行未收敛(username={uniq} + display_name={disp} + 成员事件)")
    });
    assert_eq!(
        row.roles,
        vec!["user".to_owned()],
        "注册加入默认租户 → 租户角色 user"
    );
    assert_eq!(row.status.as_deref(), Some("active"));
    assert!(!row.deleted && !row.removed);
    assert!(row.idm_seq.is_some(), "idm 源已投 → idm_seq 应非空");
    assert!(
        row.profile_seq.is_some(),
        "profile 源已投 → profile_seq 应非空"
    );
    let account = index_repo
        .get_account(user_id)
        .await?
        .expect("账号目录也有这一行");
    assert_eq!(account.username.as_deref(), Some(uniq.as_str()));
    assert_eq!(account.roles, Vec::<String>::new(), "register 无平台角色");

    // 7a. 第二个租户:把同一账号加进去(idm 成员仓储 → tenant.member_added)→ 第二个租户里也有一行;
    //     再改资料 → 两个租户的行都刷新(资料全局一份)。
    let tenants = PgTenantRepo::new(idm_pool.clone());
    let members = PgMemberRepo::new(idm_pool.clone());
    let second = tenants
        .create(
            &format!("p3-{}", &uniq_suffix[..12]),
            "P3 second",
            Some("p3-e2e".into()),
        )
        .await?;
    let second_id = TenantId::new(second.id)?;
    members
        .add(second.id, user_id, &[], Some("p3-e2e".into()))
        .await?;
    poll_member(
        &index_repo,
        second_id,
        user_id,
        Duration::from_secs(25),
        |row| {
            row.username.as_deref() == Some(uniq.as_str())
                && row.display_name.as_deref() == Some(disp.as_str())
        },
    )
    .await
    .expect("25s 内第二个租户的成员行未出现(账号列应从账号目录抄)");
    let disp2 = format!("Disp2 {uniq}");
    state
        .profiles
        .put(
            user_id,
            PutProfile {
                display_name: Some(disp2.clone()),
                phone: None,
                avatar_content_id: None,
            },
            &AuditContext::system(),
        )
        .await?;
    for t in [DEFAULT_TENANT_ID, second_id] {
        poll_member(&index_repo, t, user_id, Duration::from_secs(25), |row| {
            row.display_name.as_deref() == Some(disp2.as_str())
        })
        .await
        .unwrap_or_else(|| panic!("25s 内租户 {t} 的成员行显示名未刷新"));
    }
    let disp = disp2;

    // 7a'. 认证审计记租户:发一条切换租户事件(handler 同款组装)→ relay → auth_event 投影器 → 行上有 tenant_id。
    emit_auth_event(
        &state.idm_outbox,
        AuthEventType::TenantSwitched,
        user_id,
        success_data(
            &ClientContext::default(),
            AuthChannel::Public,
            user_id,
            None,
            Some(&uniq),
            Some(second.id),
        ),
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(25);
    let switched = loop {
        let page = auth_repo
            .list(
                &AuthEventQuery {
                    user_id: Some(user_id),
                    event_type: Some(AuthEventType::TenantSwitched),
                    ..Default::default()
                },
                PageParams::Offset {
                    page: 1,
                    size: 10,
                    with_total: false,
                },
            )
            .await?;
        if let Some(row) = page.items.into_iter().next() {
            break row;
        }
        assert!(
            Instant::now() < deadline,
            "25s 内 auth.tenant_switched 未落 auth_event"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(
        switched.tenant_id,
        Some(second.id),
        "auth_event 记下切换后的租户"
    );

    // 7b. P4 落点:投影已收敛 → 经真接线的 `state.user_admin.list()`(平台账号列表,读全局账号目录)q 搜索命中
    //     (username 侧 + display_name 侧跨字段搜索均经投影生效),且有 backend 时 `sort_by=display_name` 不再 422。
    //     这条读走的是**运行时池**(NOBYPASSRLS,对账号目录只有 SELECT)。
    let list_page = |page: u64| PageParams::Offset {
        page,
        size: 20,
        with_total: true,
    };

    // display_name 侧:取 disp 独有的前缀子串("Disp p3-" + 4 位 hex,uniq 里不含 "Disp"),
    // 只可能经投影的 display_name 列命中,证 P4 的"display_name 可搜"这一核心落点。
    let disp_substr = &disp[..12];
    let filter_by_disp = ListUsers {
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
    let filter_by_uniq = ListUsers {
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
    let filter_sort_display_name = ListUsers {
        sort_by: UserSortField::DisplayName,
        ..Default::default()
    };
    state
        .user_admin
        .list(&filter_sort_display_name, list_page(1))
        .await
        .expect("有 search 后端时 sort_by=display_name 不应 422");

    // 7c. 平台账号列表(全局账号目录,不分租户):平台管理员新建、**不属于任何租户**的账号投影进账号目录后,
    //     `/users` 列表(运行时池读 account_index)搜得到它;它在任何租户里都没有成员行。
    let lonely_name = format!("p3-lonely-{uniq_suffix}");
    let lonely = state
        .user_admin
        .create(
            CreateUser {
                username: lonely_name.clone(),
                email: None,
                password: "password123".into(),
                roles: vec![],
            },
            Some("p3-e2e".into()),
        )
        .await?;
    let filter_lonely = ListUsers {
        q: Some(lonely_name.clone()),
        ..Default::default()
    };
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let page = state.user_admin.list(&filter_lonely, list_page(1)).await?;
        if page.items.iter().any(|u| u.id == lonely.id) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "25s 内不属于任何租户的新账号没出现在平台账号列表里"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        index_repo
            .get_member(DEFAULT_TENANT_ID, lonely.id)
            .await?
            .is_none(),
        "平台管理员建的账号不自动进任何租户"
    );

    // 8. 删用户 → 轮询直到两个租户的成员行 deleted 都翻 true(user.deleted 事件投影到该用户所有行)。
    state
        .user_admin
        .delete(user_id, Some("p3-e2e".into()))
        .await?;
    for t in [DEFAULT_TENANT_ID, second_id] {
        let deleted_row = poll_member(&index_repo, t, user_id, Duration::from_secs(25), |row| {
            row.deleted
        })
        .await
        .unwrap_or_else(|| panic!("25s 内 user.deleted 未把租户 {t} 的行 deleted 翻 true"));
        assert!(deleted_row.deleted);
    }

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
    let users = PgUserRepo::new(idm_pool.clone());
    let counts = rebuild(
        IdmSources {
            users: &users,
            tenants: &tenants,
            members: &members,
        },
        &ProfileDisplayNames::new(Arc::new(PgProfileRepo::new(app_pool.clone()))),
        &*index_repo,
        p_idm,
        p_app,
    )
    .await?;
    assert!(counts.accounts >= 1 && counts.members >= 1, "{counts:?}");
    let u2_row = index_repo
        .get_account(u2_id)
        .await?
        .expect("rebuild 后 U2 账号行应命中");
    assert_eq!(u2_row.username.as_deref(), Some(u2_uniq.as_str()));
    assert_eq!(
        u2_row.idm_seq,
        Some(p_idm),
        "rebuild 应把 idm_seq 设为快照水位"
    );
    let u2_member = index_repo
        .get_member(DEFAULT_TENANT_ID, u2_id)
        .await?
        .expect("rebuild 后 U2 在默认租户的成员行应命中(一个成员关系一行)");
    assert_eq!(u2_member.username.as_deref(), Some(u2_uniq.as_str()));
    assert_eq!(u2_member.roles, vec!["user".to_owned()]);
    assert_eq!(u2_member.member_seq, Some(p_idm));

    // 10. 收尾:停后台任务 + best-effort 删 U2 / 第二个租户 / 测试 durable(reruns 干净)。
    let _ = tx.send(true);
    let _ = state.user_admin.delete(u2_id, Some("p3-e2e".into())).await;
    let _ = tenants.soft_delete(second.id, Some("p3-e2e".into())).await;
    let _ = stream.delete_consumer(&durable).await;
    let _ = stream
        .delete_consumer(&format!("auth_test_{uniq_suffix}"))
        .await;

    Ok(())
}

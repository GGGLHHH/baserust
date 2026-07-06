//! Spec 2 · P1 capstone e2e —— 真用户写 → 真事件落 JetStream 流。
//!
//! 门 **双 feature**(`pg-conformance` + `nats-conformance`):不开就编译成空文件,
//! `just check`/`just test`/`just test-pg`/`just test-nats` 全不受影响。跑它:`just test-durable`
//! (需全栈:先 `just up` 起 pg + nats,`.env` 配好 `*_DB_HOST`/`NATS_URL`)。
//!
//! 链路:.env→Config → 保证 outbox 表在 → 起真 app(Both,pg+nats)→ 装 relay(Task 8)→
//! 先建 `DeliverPolicy::New` consumer(只收本轮之后的消息,免疫流里历史)→ 起 relay →
//! 经真 service 写(register + profile put,emit 在 repo 层)→ 断言两条领域事件落流、event_id 互异。
//!
//! **偏离 brief 两处(均被真实代码逼出,详见 task-9-report.md)**:
//! 1. 建用户走公有的 `idm::AuthService::register`(→ `users.create` emit `user.created`),
//!    因 `users::CreateUserRequest` 是私有 DTO,集成测试(外部 crate)够不着。语义等价:同样
//!    emit `events.idm.user.created`、payload 含 `username`,且 register 天然无角色(免 seed 角色)。
//! 2. idm 的 outbox 迁移(0003)已按 content-crate 先例从 rust-idm 拷进本仓 `migrations/idm/`,
//!    故用 `sqlx::migrate!("migrations/idm")` 幂等应用它;app 侧用 `migrations/app`(含 0004)。
#![cfg(all(feature = "pg-conformance", feature = "nats-conformance"))]

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use uuid::Uuid;

use baserust::app::state::{connect_for_schema, Schema};
use baserust::app::{AppState, Mount};
use baserust::features::profile::PutProfileRequest;
use baserust::infra::audit::AuditContext;
use baserust::infra::config::Config;
use idm::RegisterInput;

#[tokio::test(flavor = "multi_thread")]
async fn user_write_lands_as_durable_event() -> anyhow::Result<()> {
    // 1. config from .env → 满 pg+nats(内存模式跑不了本测试)。
    dotenvy::from_path(".env").ok();
    let config = Config::load()?;
    assert!(
        config.nats_url.is_some(),
        "缺 NATS_URL:先 `just up` 起 nats 并确保 .env 配好"
    );
    assert!(
        config.idm_database_url().is_some() && config.app_database_url().is_some(),
        "缺 pg 配置(APP_DB_HOST/IDM_DB_HOST):先 `just up` 并确保 .env 配好"
    );

    // 2. 保证 outbox 表存在(幂等:sqlx 追踪已应用版本,只补未应用的)。
    //    idm outbox 在本仓 migrations/idm/0003,app outbox 在本仓 migrations/app/0004。
    //    必须先于 AppState::new —— seed/mock 写会 emit 到 outbox,表不在会炸启动。
    let idm_pool = connect_for_schema(&config, Schema::Idm)
        .await?
        .expect("idm pool(idm_database_url 已断言 Some)");
    let app_pool = connect_for_schema(&config, Schema::App)
        .await?
        .expect("app pool(app_database_url 已断言 Some)");
    sqlx::migrate!("migrations/idm").run(&idm_pool).await?;
    sqlx::migrate!("migrations/app").run(&app_pool).await?;

    // 3. 起真 app:pg 仓储 + JetStreamPublisher + 装 outbox relay(Task 8 接线)。
    let (state, bg) = AppState::new(&config, Mount::Both).await?;
    assert!(
        !bg.relays.is_empty(),
        "pg+nats 下应装出 outbox relay(证明 Task 8 按进程接了线)"
    );

    // 4. **先建 consumer 再写**:临时 ephemeral pull consumer + DeliverPolicy::New —— 只投递
    //    consumer 建好之后发布的消息,天然免疫流里上一轮/历史堆积,精确框住本轮事件。
    //    空 filter = 覆盖流内全 subject(events.idm.> + events.app.>)。
    let client = async_nats::connect(config.nats_url.clone().unwrap()).await?;
    let js = async_nats::jetstream::new(client);
    let stream = js.get_stream("USER_SEARCH_EVENTS").await?;
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
            ..Default::default()
        })
        .await?;

    // 5. 起 relay 后台循环(poll 每 1s;shutdown 经 watch 通道)。
    let (tx, rx) = tokio::sync::watch::channel(false);
    for r in bg.relays {
        tokio::spawn(r.run(rx.clone()));
    }

    // 6. 经真 service 驱动写(emit 在 repo 层,无需 HTTP/鉴权)。用 v7 uuid 造每轮唯一名。
    let uniq = format!("dep1-{}", Uuid::now_v7().simple());
    let disp = format!("Name {uniq}");
    // register → users.create → 事务内 emit user.created 到 idm.outbox(payload 含 username)。
    let outcome = state
        .auth
        .register(
            RegisterInput {
                username: uniq.clone(),
                email: None,
                password: "password123".into(),
            },
            Some("durable-e2e".into()),
        )
        .await?;
    let user_id = outcome.user.id;
    // profile put → upsert → 事务内 emit profile.updated 到 app.outbox(payload 含 display_name)。
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

    // 7. 轮询 consumer 收两条事件(relay 每 1s poll,给 20s 预算)。按本轮唯一 username/display_name
    //    过滤,seed/mock/其他事件不干扰。**对同时在跑的 dev-server relay 也稳**:Nats-Msg-Id 去重
    //    折叠重复发布,唯一 username/display_name 消歧本轮事件。
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut idm_event_id: Option<String> = None;
    let mut app_event_id: Option<String> = None;
    while Instant::now() < deadline && (idm_event_id.is_none() || app_event_id.is_none()) {
        let mut batch = consumer
            .fetch()
            .max_messages(128)
            .expires(Duration::from_secs(2))
            .messages()
            .await?;
        while let Some(msg) = batch.next().await {
            let msg = msg.map_err(|e| anyhow::anyhow!("consumer fetch: {e}"))?;
            // envelope(Task 5):{event_id, schema, type, aggregate_id, seq, data};data 是原 payload。
            let env: serde_json::Value =
                serde_json::from_slice(msg.payload.as_ref()).unwrap_or(serde_json::Value::Null);
            match msg.subject.as_str() {
                "events.idm.user.created"
                    if env["data"]["username"].as_str() == Some(uniq.as_str()) =>
                {
                    idm_event_id = env["event_id"].as_str().map(str::to_owned);
                }
                "events.app.profile.updated"
                    if env["data"]["display_name"].as_str() == Some(disp.as_str()) =>
                {
                    app_event_id = env["event_id"].as_str().map(str::to_owned);
                }
                _ => {}
            }
            let _ = msg.ack().await;
        }
    }

    // 8. 收尾:停 relay + best-effort 删本轮用户(reruns 干净;删会 emit user.deleted,无害)。
    let _ = tx.send(true);
    let _ = state
        .user_admin
        .delete(user_id, Some("durable-e2e".into()))
        .await;

    // 9. 断言:两条事件都落了,且 event_id 互异(idm-<n> vs app-<m>)。
    let idm_id =
        idm_event_id.expect("events.idm.user.created(data.username==uniq)应在 stream 落地");
    let app_id =
        app_event_id.expect("events.app.profile.updated(data.display_name==disp)应在 stream 落地");
    assert_ne!(idm_id, app_id, "两条事件的 event_id 应互异");

    Ok(())
}

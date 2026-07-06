//! JetStream 发布端冒烟测试 —— 需要跑着的 NATS(`just up` 起的 compose 服务含 nats)。
//! 门 `nats-conformance` feature(同 `event_bus_conformance` 的 NATS 入口),`just check`/`just test`
//! (不开 feature)不编译本文件;`just test-nats` 连它一起跑。
#![cfg(feature = "nats-conformance")]

use baserust::infra::jetstream::JetStreamPublisher;
use uuid::Uuid;

fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:2224".to_owned())
}

/// connect 是幂等的(`get_or_create_stream`):同一进程/repeat run 连两次都不该报错。
#[tokio::test]
async fn connect_is_idempotent() {
    let url = nats_url();
    JetStreamPublisher::connect(&url)
        .await
        .expect("首次 connect 应成功(需要跑着的 NATS,先 just up)");
    JetStreamPublisher::connect(&url)
        .await
        .expect("重复 connect 应幂等成功(get_or_create_stream 不应因流已存在报错)");
}

/// publish 落地可回读:发一条唯一 payload 的事件到 idm 子 subject,用临时 pull consumer 读回,
/// 断言拿到的正是刚发的这条(payload + Nats-Msg-Id 都对得上)。用唯一 id 而非绝对计数,
/// 兼容本测试被反复跑(流是持久化的,历史消息会攒着)。
#[tokio::test]
async fn publish_lands_and_is_readable_back() {
    let publisher = JetStreamPublisher::connect(&nats_url())
        .await
        .expect("需要跑着的 NATS(先 just up)");

    let event_id = format!("smoke-{}", Uuid::new_v4());
    let payload = format!("payload-{event_id}");

    publisher
        .publish("events.idm.user.created", &event_id, payload.as_bytes())
        .await
        .expect("publish 应成功并拿到 server ack");

    // 直连裸 client 建临时 consumer 读回,不复用 JetStreamPublisher 的内部状态(黑盒验证)。
    let client = async_nats::connect(nats_url())
        .await
        .expect("裸 client 连接应成功");
    let js = async_nats::jetstream::new(client);
    let stream = js
        .get_stream("USER_SEARCH_EVENTS")
        .await
        .expect("流应已被 JetStreamPublisher::connect 建好");
    // 用 `LastPerSubject` 而非 `All`+`fetch(50)`:流会持久化累积历史消息(max_age 7 天,
    // 重启不清空),固定拉最老 50 条早晚会把刚发的这条挤出窗口外 —— 不可重复跑。
    // `LastPerSubject` 配上这里的单一 `filter_subject` 只会投递该 subject 上最新一条,
    // 不管流里已经攒了多少历史消息,天然可重复跑。
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject,
            filter_subject: "events.idm.user.created".to_owned(),
            ..Default::default()
        })
        .await
        .expect("建临时 pull consumer 应成功");

    let mut messages = consumer
        .fetch()
        .max_messages(1)
        .expires(std::time::Duration::from_secs(5))
        .messages()
        .await
        .expect("fetch 一批消息应成功");
    use futures_util::StreamExt;
    let msg = messages
        .next()
        .await
        .expect("LastPerSubject 应能投递该 subject 上最新一条")
        .expect("消息应可读");
    assert_eq!(
        msg.payload.as_ref(),
        payload.as_bytes(),
        "读回的应是刚发布的这条(唯一 payload 保证是本次跑的消息)"
    );
    let msg_id = msg
        .headers
        .as_ref()
        .and_then(|h| h.get("Nats-Msg-Id"))
        .map(|v| v.to_string());
    assert_eq!(msg_id.as_deref(), Some(event_id.as_str()));
    msg.ack().await.expect("ack 应成功");
}

/// dedup:同一 `event_id` 发两次,`duplicate_window` 内 server 只落一次 —— 用两次都拿到的
/// `PublishAck.sequence` 相同 + 第二次 ack 带 `duplicate: true` 来验证。
/// `JetStreamPublisher::publish()` 本身只报成功/失败、不掏 `PublishAck` 细节,所以这里跟
/// `publish_lands_and_is_readable_back` 一样直连裸 client/context 发布,拿到原始 ack 断言,
/// 不然"两次都 Ok"这个断言就算 server 端完全没去重也永远成立,测不出真去重。
///
/// subject 故意用跟 `publish_lands_and_is_readable_back` 不同的
/// `events.idm.user.dedup-smoke`(仍匹配流的 `events.idm.>` 前缀,落同一个流):cargo test
/// 默认并发跑各测试函数,若共用 `events.idm.user.created`,这条测试的发布会跟那条测试的
/// `DeliverPolicy::LastPerSubject` 读回抢"该 subject 最新一条",两个测试互相污染导致偶发失败。
/// 去重本身只认 stream 内的 `Nats-Msg-Id`,跟 subject 取什么值无关,换个专属 subject 零成本消除竞态。
#[tokio::test]
async fn duplicate_event_id_is_deduped() {
    // connect 一次确保流已建好(裸 client 发布不会自动建流)。
    JetStreamPublisher::connect(&nats_url())
        .await
        .expect("需要跑着的 NATS(先 just up)");

    let client = async_nats::connect(nats_url())
        .await
        .expect("裸 client 连接应成功");
    let context = async_nats::jetstream::new(client);

    let event_id = format!("smoke-dedup-{}", Uuid::new_v4());
    let payload = b"dedup-payload";

    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", event_id.as_str());
    let ack1 = context
        .publish_with_headers(
            "events.idm.user.dedup-smoke",
            headers.clone(),
            payload.to_vec().into(),
        )
        .await
        .expect("首次 publish 应成功发出")
        .await
        .expect("首次 publish 应拿到 server ack");
    let ack2 = context
        .publish_with_headers(
            "events.idm.user.dedup-smoke",
            headers,
            payload.to_vec().into(),
        )
        .await
        .expect("重复 publish 应成功发出")
        .await
        .expect("重复 publish(同 event_id)应仍拿到 server ack(去重,不是错误)");

    assert!(
        ack2.duplicate,
        "重复 Nats-Msg-Id 的第二次 ack 应标记 duplicate=true"
    );
    assert_eq!(
        ack1.sequence, ack2.sequence,
        "去重命中时不应落新消息,第二次 ack 的 sequence 应复用第一次的"
    );
}

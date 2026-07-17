//! EventBus 契约:**一份契约,memory 与 PG 双实现各跑一遍**(镜像 widget_repo_conformance,防漂移)。
//! PG 入口:`cargo test --features pg-conformance --test event_bus_conformance`(用 `just test-pg`)。

use std::time::Duration;

use baserust::features::widget::{EventBus, MemoryEventBus, WidgetEvent};
use tokio::time::timeout;
use uuid::Uuid;

/// 5s 内必须收到一条事件,且是 `Deleted{expected}`(契约用 Deleted:payload 最小,断言只看 id)。
async fn expect_deleted(
    sub: &mut Box<dyn baserust::features::widget::EventSubscription>,
    expected: Uuid,
) {
    let got = timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("5s 内应收到事件")
        .expect("总线不应关闭");
    match got {
        WidgetEvent::Deleted { id, .. } => assert_eq!(id, expected),
        other => panic!("期待 Deleted,得到 {other:?}"),
    }
}

/// 契约本体:订阅后发布必达 / 多订阅各收一份 / 订阅前发布的收不到(无回放)。
/// 连接预算:PG 侧每条订阅占 1 连接 + publish 临时 1 条;`#[sqlx::test]` pool 上限 5 ——
/// 本契约恰好 4 订阅,再加订阅会让 PG 入口卡在 acquire(内存侧照常绿)。加用例前先算这笔账。
async fn event_bus_contract(bus: &dyn EventBus) {
    // 1. 订阅后发布 → 收到
    let mut sub = bus.subscribe().await.expect("订阅应成功");
    let id1 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted {
        id: id1,
        tenant_id: uuid::Uuid::from_u128(0xACE),
        created_by: None,
    })
    .await;
    expect_deleted(&mut sub, id1).await;

    // 2. 两个订阅各收一份(广播,非竞争消费)
    let mut a = bus.subscribe().await.unwrap();
    let mut b = bus.subscribe().await.unwrap();
    let id2 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted {
        id: id2,
        tenant_id: uuid::Uuid::from_u128(0xACE),
        created_by: None,
    })
    .await;
    expect_deleted(&mut a, id2).await;
    expect_deleted(&mut b, id2).await;

    // 3. 无回放:晚订阅者收不到旧事件 —— 新订阅后发 id3,第一条即 id3(而非 id1/id2)
    let mut late = bus.subscribe().await.unwrap();
    let id3 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted {
        id: id3,
        tenant_id: uuid::Uuid::from_u128(0xACE),
        created_by: None,
    })
    .await;
    expect_deleted(&mut late, id3).await;
}

#[tokio::test]
async fn memory_satisfies_event_bus_contract() {
    event_bus_contract(&MemoryEventBus::new()).await;
}

/// Lagged 不断流(memory 专属:pg 无掉队概念,不进共享契约):
/// 容量 64,灌 200 条不读 → 订阅者掉队;之后 recv 应跳过丢失的返回后段事件,而非 None/挂死。
#[tokio::test]
async fn memory_lagged_subscriber_skips_and_continues() {
    let bus = MemoryEventBus::new();
    let mut sub = bus.subscribe().await.unwrap();
    let last = Uuid::now_v7();
    for _ in 0..199 {
        bus.publish(WidgetEvent::Deleted {
            id: Uuid::now_v7(),
            tenant_id: uuid::Uuid::from_u128(0xACE),
            created_by: None,
        })
        .await;
    }
    bus.publish(WidgetEvent::Deleted {
        id: last,
        tenant_id: uuid::Uuid::from_u128(0xACE),
        created_by: None,
    })
    .await;
    // 前 136 条被挤掉;能一路读到最后一条 = 掉队后仍在流上
    let mut got_last = false;
    for _ in 0..64 {
        match timeout(Duration::from_secs(5), sub.recv()).await.unwrap() {
            Some(WidgetEvent::Deleted { id, .. }) if id == last => {
                got_last = true;
                break;
            }
            Some(_) => continue,
            None => panic!("掉队不应关闭流"),
        }
    }
    assert!(got_last, "应能读到掉队后仍保留的最后一条");
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 app role + 跑着的 pg)──
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::*;
    use baserust::features::widget::PgEventBus;

    /// pg_notify 不碰任何表 → 免迁移;`#[sqlx::test]` 的临时库即可。
    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_event_bus_contract(pool: sqlx::PgPool) {
        event_bus_contract(&PgEventBus::new(pool)).await;
    }
}

// ── 入口 3:NATS(需 --features nats-conformance + 跑着的 nats,`just up` 含;用 `just test-nats`)──
#[cfg(feature = "nats-conformance")]
mod nats {
    use super::*;
    use baserust::features::widget::NatsEventBus;

    /// core NATS 契约同一份;`NATS_URL` 可覆盖(默认本地 compose 的主机端口 2224)。
    #[tokio::test]
    async fn nats_satisfies_event_bus_contract() {
        let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:2224".to_owned());
        let bus = NatsEventBus::connect(&url)
            .await
            .expect("需要跑着的 NATS(先 just up)");
        event_bus_contract(&bus).await;
    }
}

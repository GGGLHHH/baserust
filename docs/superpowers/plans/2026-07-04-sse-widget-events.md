# SSE widget 事件流实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给脚手架加 SSE 范式:widget 变更事件经可拔插 EventBus(memory / PG LISTEN-NOTIFY)推给已鉴权浏览器。

**Architecture:** `features/widget/events.rs` 定义 `WidgetEvent` + 窄端口 `EventBus`/`EventSubscription`(端口归消费方,同 `WidgetRepo` 范式),双实现按 `APP_DB_HOST` 在组合根二选一。`WidgetService` 写成功后 fire-and-forget publish;`GET /widgets/events` 三轴鉴权后把订阅适配成 `Sse` 流。

**Tech Stack:** axum 0.8 SSE · tokio broadcast · sqlx PgListener/pg_notify · futures-util(unfold)· utoipa。

**Spec:** `docs/superpowers/specs/2026-07-04-sse-design.md`

## Global Constraints

- 每个 Task 结束必须过 `just check && just test && just lint`(clippy `-D warnings` 零警告)。
- 统一错误契约:原始错误只进日志;publish 失败绝不让写操作失败。
- 无回放、best-effort:两实现一致;`ponytail:` 注释钉天花板(单实例 / NOTIFY 8000B)。
- 注释风格:中文、讲"为什么",对齐仓库现有密度。
- 与 spec 的一处已知偏差:`create_with_tags` 是 repo 层范式、无 service/route 调用方 → **不发事件**(事件发布点在 service 层)。

---

### Task 1: 事件类型 + 端口 + MemoryEventBus + 契约测试(memory 侧)

**Files:**
- Create: `src/features/widget/events.rs`
- Create: `tests/event_bus_conformance.rs`
- Modify: `src/features/widget/mod.rs`(挂 mod + re-export)
- Modify: `src/features/widget/types.rs:11`(`Widget` 加 `Deserialize`)

**Interfaces:**
- Produces: `WidgetEvent`(enum,`Created{widget}/Updated{widget}/Deleted{id}`,`fn name(&self) -> &'static str`)、`trait EventBus { async fn publish(&self, event: WidgetEvent); async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError>; }`、`trait EventSubscription { async fn recv(&mut self) -> Option<WidgetEvent>; }`、`MemoryEventBus::new()`。后续所有 Task 依赖这些签名。

- [ ] **Step 1: 写契约测试(先失败)**

`tests/event_bus_conformance.rs` 全文:

```rust
//! EventBus 契约:**一份契约,memory 与 PG 双实现各跑一遍**(镜像 widget_repo_conformance,防漂移)。
//! PG 入口:`cargo test --features pg-conformance --test event_bus_conformance`(用 `just test-pg`)。

use std::time::Duration;

use tokio::time::timeout;
use uuid::Uuid;
use xchangeai::features::widget::{EventBus, MemoryEventBus, WidgetEvent};

/// 5s 内必须收到一条事件,且是 `Deleted{expected}`(契约用 Deleted:payload 最小,断言只看 id)。
async fn expect_deleted(sub: &mut Box<dyn xchangeai::features::widget::EventSubscription>, expected: Uuid) {
    let got = timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("5s 内应收到事件")
        .expect("总线不应关闭");
    match got {
        WidgetEvent::Deleted { id } => assert_eq!(id, expected),
        other => panic!("期待 Deleted,得到 {other:?}"),
    }
}

/// 契约本体:订阅后发布必达 / 多订阅各收一份 / 订阅前发布的收不到(无回放)。
async fn event_bus_contract(bus: &dyn EventBus) {
    // 1. 订阅后发布 → 收到
    let mut sub = bus.subscribe().await.expect("订阅应成功");
    let id1 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted { id: id1 }).await;
    expect_deleted(&mut sub, id1).await;

    // 2. 两个订阅各收一份(广播,非竞争消费)
    let mut a = bus.subscribe().await.unwrap();
    let mut b = bus.subscribe().await.unwrap();
    let id2 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted { id: id2 }).await;
    expect_deleted(&mut a, id2).await;
    expect_deleted(&mut b, id2).await;

    // 3. 无回放:晚订阅者收不到旧事件 —— 新订阅后发 id3,第一条即 id3(而非 id1/id2)
    let mut late = bus.subscribe().await.unwrap();
    let id3 = Uuid::now_v7();
    bus.publish(WidgetEvent::Deleted { id: id3 }).await;
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
        bus.publish(WidgetEvent::Deleted { id: Uuid::now_v7() }).await;
    }
    bus.publish(WidgetEvent::Deleted { id: last }).await;
    // 前 136 条被挤掉;能一路读到最后一条 = 掉队后仍在流上
    let mut got_last = false;
    for _ in 0..64 {
        match timeout(Duration::from_secs(5), sub.recv()).await.unwrap() {
            Some(WidgetEvent::Deleted { id }) if id == last => {
                got_last = true;
                break;
            }
            Some(_) => continue,
            None => panic!("掉队不应关闭流"),
        }
    }
    assert!(got_last, "应能读到掉队后仍保留的最后一条");
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test --test event_bus_conformance 2>&1 | tail -5`
Expected: 编译错 `unresolved import ... EventBus`(模块还不存在)。

- [ ] **Step 3: `Widget` 加 `Deserialize`**

`src/features/widget/types.rs:11`,原:

```rust
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
```

改为(PgEventBus 要从 NOTIFY payload 反序列化事件,`rfc3339` serde 模块本就双向):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
```

同文件顶部 `use serde::{Deserialize, Serialize};`(原来只 import 了什么就补齐)。

- [ ] **Step 4: 写 `src/features/widget/events.rs`**

```rust
//! widget 变更事件 + **可拔插事件总线端口**(SSE 范式的发布/订阅侧)。
//!
//! 生态没有标准 EventBus 抽象(只有 channel 原语与各家 broker 客户端),正解即本 repo 范式:
//! **端口归消费方、自定义窄 trait、双实现可拔插**(同 `WidgetRepo`/`UserDirectory`)。
//! 端口 typed 到 `WidgetEvent`(窄接口):别的模块要事件,照抄这套自己定义,不做通用总线。
//!
//! 契约(两实现一致,`event_bus_conformance` 钉住):
//! - **fire-and-forget**:publish 失败只落日志,绝不让写操作失败;
//! - **best-effort、无回放**:订阅只收订阅之后的事件,断线丢事件(要回放 = 事件表 + 游标,另一个范式);
//! - 慢消费者掉队(Lagged)跳过继续,不断流。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use super::types::Widget;
use crate::infra::error::AppError;

/// widget 变更事件。SSE 帧的 event name = serde tag(created/updated/deleted)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetEvent {
    Created { widget: Widget },
    Updated { widget: Widget },
    Deleted { id: Uuid },
}

impl WidgetEvent {
    /// SSE event name。与 serde tag 手动保持一致(仅 3 个变体,不值得运行期序列化再解析)。
    pub fn name(&self) -> &'static str {
        match self {
            WidgetEvent::Created { .. } => "created",
            WidgetEvent::Updated { .. } => "updated",
            WidgetEvent::Deleted { .. } => "deleted",
        }
    }
}

/// 事件总线端口。发布方(service)与订阅方(SSE handler)都在 widget 模块 —— 端口归消费方。
#[async_trait]
pub trait EventBus: Send + Sync {
    /// fire-and-forget:失败只落日志(warn),**绝不让写操作失败**。
    async fn publish(&self, event: WidgetEvent);
    /// 新订阅,从订阅时刻起收事件(无回放)。
    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError>;
}

/// 一条订阅。`None` = 总线关闭(SSE 流随之正常结束,浏览器 EventSource 自动重连)。
#[async_trait]
pub trait EventSubscription: Send {
    async fn recv(&mut self) -> Option<WidgetEvent>;
}

// ── 内存实现:tokio broadcast(零依赖默认,单进程测试/开发用)──

/// ponytail: 单实例 —— 多实例各见各的写;跨实例扇出用 PgEventBus。
pub struct MemoryEventBus {
    tx: broadcast::Sender<WidgetEvent>,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        // 64:突发缓冲。慢消费者超出即 Lagged(跳过),不是背压 —— SSE 场景丢旧事件可接受。
        Self {
            tx: broadcast::channel(64).0,
        }
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for MemoryEventBus {
    async fn publish(&self, event: WidgetEvent) {
        // 无订阅者时 send 返 Err —— 合法状态(没人在看),刻意忽略。
        let _ = self.tx.send(event);
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        Ok(Box::new(MemorySubscription(self.tx.subscribe())))
    }
}

struct MemorySubscription(broadcast::Receiver<WidgetEvent>);

#[async_trait]
impl EventSubscription for MemorySubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.recv().await {
                Ok(e) => return Some(e),
                // 掉队:跳过丢失的继续收,不断流(契约)。
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "事件订阅者掉队,跳过");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}
```

(PgEventBus 在 Task 2 加进同文件;`use sqlx::postgres::PgListener;` 到 Task 2 再加,否则 unused import 挂 lint。)

- [ ] **Step 5: 挂进 `src/features/widget/mod.rs`**

在 `mod port;` 前加一行 `mod events;`;re-export 块加:

```rust
pub use events::{EventBus, EventSubscription, MemoryEventBus, WidgetEvent};
```

- [ ] **Step 6: 跑测试确认过**

Run: `cargo test --test event_bus_conformance 2>&1 | tail -3`
Expected: `memory_satisfies_event_bus_contract ... ok`。

- [ ] **Step 7: 全量门禁 + commit**

Run: `just check && just test && just lint`
Expected: 全绿。

```bash
git add src/features/widget/events.rs src/features/widget/mod.rs src/features/widget/types.rs tests/event_bus_conformance.rs
git commit -m "feat(widget): EventBus 端口 + 内存实现 + 契约测试(SSE 范式第一步)"
```

---

### Task 2: PgEventBus(LISTEN/NOTIFY)+ PG 侧契约

**Files:**
- Modify: `src/features/widget/events.rs`(追加 PgEventBus)
- Modify: `src/features/widget/mod.rs`(re-export 加 `PgEventBus`)
- Modify: `tests/event_bus_conformance.rs`(追加 pg 入口)
- Modify: `justfile:43`(test-pg 加 `--test event_bus_conformance`)

**Interfaces:**
- Consumes: Task 1 的 `EventBus`/`EventSubscription`/`WidgetEvent`、`event_bus_contract`。
- Produces: `PgEventBus::new(pool: sqlx::PgPool)`。

- [ ] **Step 1: 契约测试加 PG 入口(先失败)**

`tests/event_bus_conformance.rs` 末尾追加:

```rust
// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 app role + 跑着的 pg)──
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::*;
    use xchangeai::features::widget::PgEventBus;

    /// pg_notify 不碰任何表 → 免迁移;`#[sqlx::test]` 的临时库即可。
    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_event_bus_contract(pool: sqlx::PgPool) {
        event_bus_contract(&PgEventBus::new(pool)).await;
    }
}
```

Run: `cargo check --features pg-conformance --all-targets 2>&1 | tail -3`
Expected: 编译错 `unresolved import ... PgEventBus`。

- [ ] **Step 2: `events.rs` 追加 PgEventBus**

文件顶部 use 区加 `use sqlx::postgres::PgListener;`,末尾追加:

```rust
// ── PG 实现:pg_notify / LISTEN(多实例扇出;NOTIFY 在事务内 → commit 才投递,回滚不发幽灵事件)──

const CHANNEL: &str = "widget_events";

pub struct PgEventBus {
    pool: sqlx::PgPool,
}

impl PgEventBus {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EventBus for PgEventBus {
    async fn publish(&self, event: WidgetEvent) {
        // ponytail: NOTIFY payload 上限 8000 字节(widget 事件几百字节,富余);超限升级路径 = 只发 id、订阅方回查。
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "widget 事件序列化失败,丢弃");
                return;
            }
        };
        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(&payload)
            .execute(&self.pool)
            .await
        {
            // fire-and-forget 契约:失败只落日志,绝不上抛影响写操作。
            tracing::warn!(error = %e, "widget 事件发布失败(NOTIFY)");
        }
    }

    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError> {
        let mut listener = PgListener::connect_with(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        listener
            .listen(CHANNEL)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(Box::new(PgSubscription(listener)))
    }
}

struct PgSubscription(PgListener);

#[async_trait]
impl EventSubscription for PgSubscription {
    async fn recv(&mut self) -> Option<WidgetEvent> {
        loop {
            match self.0.recv().await {
                // 坏 payload(未来版本混发/人为 NOTIFY):跳过,不断流。
                Ok(n) => match serde_json::from_str(n.payload()) {
                    Ok(e) => return Some(e),
                    Err(e) => tracing::warn!(error = %e, "widget 事件 payload 非法,跳过"),
                },
                // PgListener 自带断线重连;到这说明不可恢复 → 结束流(客户端 EventSource 自动重连)。
                Err(e) => {
                    tracing::warn!(error = %e, "PgListener 断开,事件流结束");
                    return None;
                }
            }
        }
    }
}
```

`mod.rs` re-export 行改为:

```rust
pub use events::{EventBus, EventSubscription, MemoryEventBus, PgEventBus, WidgetEvent};
```

- [ ] **Step 3: justfile test-pg 加新契约**

`justfile:43` 原:

```
    DATABASE_URL="{{app_db_url}}" cargo test --features pg-conformance --test widget_repo_conformance --test policy_repo_test -- --nocapture
```

改为:

```
    DATABASE_URL="{{app_db_url}}" cargo test --features pg-conformance --test widget_repo_conformance --test policy_repo_test --test event_bus_conformance -- --nocapture
```

- [ ] **Step 4: 编译两种 feature 口径 + 跑 PG 契约(pg 在跑才行;没跑至少过编译)**

Run: `cargo check --all-targets && cargo check --features pg-conformance --all-targets`
Expected: 双绿。
Run(pg 在跑时): `docker compose up -d pg && just test-pg 2>&1 | tail -5`
Expected: `pg_satisfies_event_bus_contract ... ok`。

- [ ] **Step 5: 门禁 + commit**

Run: `just check && just test && just lint`

```bash
git add src/features/widget/events.rs src/features/widget/mod.rs tests/event_bus_conformance.rs justfile
git commit -m "feat(widget): PgEventBus(pg_notify/LISTEN)+ PG 契约入口"
```

---

### Task 3: WidgetService 发布事件 + 组合根装配

**Files:**
- Modify: `src/features/widget/service.rs`(字段 + 三处 publish + 测试 fixture + 新单测)
- Modify: `src/app/state.rs`(AppState 字段 `widget_events` + 装配 + 注入 service)
- Modify: `tests/widget_api.rs:29-33`、`tests/content_api.rs:44-46`、`tests/auth_api.rs:23-25`、`tests/rate_limit_test.rs:20-22,92-94`(AppState 字面量补字段;bus **共享一个**)

**Interfaces:**
- Consumes: `EventBus`/`MemoryEventBus`/`PgEventBus`/`WidgetEvent`(Task 1/2)。
- Produces: `WidgetService::new(repo, users, events: Arc<dyn EventBus>)`(**签名变更**);`AppState.widget_events: Arc<dyn EventBus>`(Task 4 的 SSE handler 订阅用)。

- [ ] **Step 1: 写 service 单测(先失败)**

`src/features/widget/service.rs` tests 模块追加:

```rust
/// create 成功后发布 Created 事件;订阅方收到的 widget 与返回值一致。
#[tokio::test]
async fn create_publishes_created_event() {
    use crate::features::widget::{EventBus, MemoryEventBus, WidgetEvent};
    let bus = Arc::new(MemoryEventBus::new());
    let svc = WidgetService::new(
        Arc::new(InMemoryWidgetRepo::new()),
        Arc::new(StaticUserDirectory::empty()),
        bus.clone(),
    );
    let mut sub = bus.subscribe().await.unwrap();
    let w = svc
        .create(CreateWidget { name: "evt".into() }, &ctx())
        .await
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
        .await
        .expect("1s 内应收到事件")
        .expect("总线不应关闭");
    match got {
        WidgetEvent::Created { widget } => assert_eq!(widget.id, w.id),
        other => panic!("期待 Created,得到 {other:?}"),
    }
}
```

Run: `cargo test -p xchangeai --lib widget::service 2>&1 | tail -3`
Expected: 编译错(`new` 还是两参)。

- [ ] **Step 2: service 加字段 + publish**

`service.rs` 头部 import 加:

```rust
use super::events::{EventBus, WidgetEvent};
```

struct 与 new:

```rust
pub struct WidgetService {
    repo: Arc<dyn WidgetRepo>,
    users: Arc<dyn UserDirectory>,
    /// 变更事件总线(SSE 范式)。fire-and-forget:publish 失败绝不影响写。
    events: Arc<dyn EventBus>,
}

impl WidgetService {
    pub fn new(
        repo: Arc<dyn WidgetRepo>,
        users: Arc<dyn UserDirectory>,
        events: Arc<dyn EventBus>,
    ) -> Self {
        Self { repo, users, events }
    }
```

三个写方法成功路径发事件(`create` 为例,`update` 同理发 `Updated { widget: w.clone() }`):

```rust
    pub async fn create(
        &self,
        input: CreateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        input.validate()?;
        let w = self.repo.create(input.name, ctx.audit_id()).await?;
        self.events
            .publish(WidgetEvent::Created { widget: w.clone() })
            .await;
        Ok(w)
    }
```

```rust
    pub async fn update(
        &self,
        id: Uuid,
        input: UpdateWidget,
        ctx: &AuditContext,
    ) -> Result<Widget, AppError> {
        input.validate()?;
        let w = self.repo.update(id, input.name, ctx.audit_id()).await?;
        self.events
            .publish(WidgetEvent::Updated { widget: w.clone() })
            .await;
        Ok(w)
    }
```

```rust
    pub async fn delete(&self, id: Uuid, ctx: &AuditContext) -> Result<(), AppError> {
        self.repo.soft_delete(id, ctx.audit_id()).await?;
        self.events.publish(WidgetEvent::Deleted { id }).await;
        Ok(())
    }
```

tests 模块两个既有 fixture 补第三参:`new_svc()` 与 `list_enriched_attaches_user_and_degrades_dirty` 里的 `WidgetService::new(repo, dir)` 都加 `Arc::new(MemoryEventBus::new())`(import 就用 Step 1 的 use)。

- [ ] **Step 3: 组合根装配**

`src/app/state.rs`:import 行加 `EventBus, MemoryEventBus, PgEventBus`(并入现有 `crate::features::widget::{...}`);`AppState` struct 加字段:

```rust
    /// widget 变更事件总线(SSE 订阅端点用;service 持同一实例发布)。
    pub widget_events: Arc<dyn EventBus>,
```

`AppState::new` 里 `widget_repo` 选择之后加装配(同款 presence 开关):

```rust
        // 事件总线(SSE 范式):同 repo 的可拔插开关 —— 有 app pool → PG(多实例扇出),无 → 内存(单实例)。
        let widget_events: Arc<dyn EventBus> = match &app_pool {
            Some(pool) => Arc::new(PgEventBus::new(pool.clone())),
            None => Arc::new(MemoryEventBus::new()),
        };
```

`Ok(Self { ... })` 里:

```rust
            widgets: WidgetService::new(widget_repo, user_directory, widget_events.clone()),
            widget_events,
```

- [ ] **Step 4: 四个测试文件的 AppState 字面量补字段**

每处模式相同 —— **service 与 state 字段必须共享同一个 bus**(否则 Task 4 的 SSE 集成测试订阅不到 service 发的事件)。以 `tests/widget_api.rs` 为例:

```rust
    let bus: Arc<dyn xchangeai::features::widget::EventBus> =
        Arc::new(xchangeai::features::widget::MemoryEventBus::new());
    let state = AppState {
        widgets: WidgetService::new(
            Arc::new(InMemoryWidgetRepo::new()),
            Arc::new(xchangeai::features::widget::StaticUserDirectory::empty()),
            bus.clone(),
        ),
        widget_events: bus,
        // ...其余字段不动
    };
```

同样改 `tests/content_api.rs:44`、`tests/auth_api.rs:23`、`tests/rate_limit_test.rs:20` 与 `:92`。

- [ ] **Step 5: 跑测试确认过 + 门禁 + commit**

Run: `cargo test create_publishes_created_event 2>&1 | tail -3` → PASS
Run: `just check && just test && just lint` → 全绿

```bash
git add src/features/widget/service.rs src/app/state.rs tests/widget_api.rs tests/content_api.rs tests/auth_api.rs tests/rate_limit_test.rs
git commit -m "feat(widget): service 写成功后发布变更事件(fire-and-forget)"
```

---

### Task 4: SSE 端点 + 鉴权 + OpenAPI + 集成测试

**Files:**
- Modify: `Cargo.toml`(加 `futures-util`)
- Modify: `src/features/widget/routes.rs`(handler `widget_events`)
- Modify: `src/features/widget/mod.rs`(挂路由)
- Modify: `src/infra/op_perms.rs`(表加 `widget_events`)
- Modify: `tests/widget_api.rs`(3 个集成测试)

**Interfaces:**
- Consumes: `AppState.widget_events.subscribe()`、`WidgetEvent::name()`、三轴套件(`CurrentUser`/`TokenScope`/`require_scoped`)。
- Produces: `GET /api/v1/widgets/events`(operationId = `widget_events`)。

- [ ] **Step 1: 写集成测试(先失败)**

`tests/widget_api.rs` 追加(文件已有 `AppTokens`/`Perm`/`Uuid` import;`futures_util` Step 2 加依赖后可用):

```rust
/// SSE:开流 → create → 第一帧就是 created 事件(keep-alive 15s 远大于测试窗口,不会先到)。
#[tokio::test]
async fn sse_stream_receives_created_event() {
    use futures_util::StreamExt;
    let (app, admin) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/widgets/events")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body().into_data_stream();

    // handler 返回时订阅已建立 → 此刻 create 必被本流看到
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/v1/widgets")
                .header("authorization", format!("Bearer {admin}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"sse-demo"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
        .await
        .expect("5s 内应收到 SSE 帧")
        .expect("流不应结束")
        .unwrap();
    let text = String::from_utf8(frame.to_vec()).unwrap();
    assert!(text.contains("event: created"), "应是 created 帧: {text}");
    assert!(text.contains(r#""name":"sse-demo""#), "应含 widget JSON: {text}");
}

/// 未认证 → 401(EventSource 只能靠 cookie/无 header,这里用无凭据模拟)。
#[tokio::test]
async fn sse_requires_auth() {
    let (app, _admin) = test_app();
    let resp = app
        .oneshot(
            Request::get("/api/v1/widgets/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 降权令牌(scope 只有 write,无 read)→ 403:scope 只收窄不放大。
#[tokio::test]
async fn sse_requires_read_scope() {
    let (app, _admin) = test_app();
    let tokens = AppTokens::new("test-secret"); // 与 test_app 同 secret,验签才过
    let scoped = tokens
        .mint_scoped(
            Uuid::nil(),
            "admin",
            vec!["admin".to_owned()],
            vec![Perm::WidgetWrite],
            900,
        )
        .unwrap();
    let resp = app
        .oneshot(
            Request::get("/api/v1/widgets/events")
                .header("authorization", format!("Bearer {scoped}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

Run: `cargo test --test widget_api sse 2>&1 | tail -3`
Expected: 编译错(`futures_util` 未知 / 端点 404 —— 先见编译错)。

- [ ] **Step 2: 加依赖**

`Cargo.toml` `base64 = "0.22"` 附近加:

```toml
# SSE:把 EventSubscription::recv 适配成 axum Sse 要的 Stream(unfold)。已是传递依赖,提直接零额外编译。
futures-util = { version = "0.3", default-features = false, features = ["std"] }
```

- [ ] **Step 3: handler(`src/features/widget/routes.rs` 追加)**

文件头部 import 补:

```rust
use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;

use super::events::WidgetEvent;
```

末尾追加 handler:

```rust
/// 订阅 widget 变更事件流(SSE)。需登录 + `widgets:read` —— 与列表同权:能看列表就能看变更。
/// EventSource 不能自定义 header,凭据靠 httponly cookie(Bearer 兜底给 curl/测试)。
/// best-effort 无回放:断线期间的事件丢失,EventSource 自动重连拿新订阅。
#[utoipa::path(
    get,
    path = "/widgets/events",
    tag = "widgets",
    responses(
        (status = 200, description = "SSE 事件流;每帧 event = type(created/updated/deleted),data = WidgetEvent JSON", content_type = "text/event-stream", body = WidgetEvent),
        (status = 401, description = "未认证", body = ErrorBody),
        (status = 403, description = "无 widgets:read 权限", body = ErrorBody)
    )
)]
pub async fn widget_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    state
        .policy
        .require_scoped(&user.0, &scope.0, Perm::WidgetRead)?;
    let sub = state.widget_events.subscribe().await?;
    // recv() → SSE 帧;None(总线关)→ 流结束。json_data 对我们的类型不会失败,失败即结束流(ok()?)。
    let stream = futures_util::stream::unfold(sub, |mut sub| async move {
        let event = sub.recv().await?;
        let frame = Event::default().event(event.name()).json_data(&event).ok()?;
        Some((Ok::<_, Infallible>(frame), sub))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
```

(routes.rs 现有 import 若已含 `ErrorBody`/`Perm`/`CurrentUser`/`TokenScope`/`State`/`AppState` 则不重复加;缺啥补啥。)

- [ ] **Step 4: 挂路由 + op_perms**

`src/features/widget/mod.rs` `router()` 加:

```rust
        .routes(routes!(routes::widget_events))
```

`src/infra/op_perms.rs` widget 组(`admin_list_widgets` 条目后)加:

```rust
    OpAuthz {
        operation_id: "widget_events",
        perm: Some(Perm::WidgetRead),
    },
```

(不加的话 `every_operation_classified` fail-closed 测试会红 —— 这正是范式在自证。)

- [ ] **Step 5: 跑测试 + 门禁 + commit**

Run: `cargo test --test widget_api sse 2>&1 | tail -5` → 3 个 PASS
Run: `just check && just test && just lint` → 全绿(openapi 契约测试顺带验 scope 注入)

```bash
git add Cargo.toml Cargo.lock src/features/widget/routes.rs src/features/widget/mod.rs src/infra/op_perms.rs tests/widget_api.rs
git commit -m "feat(widget): SSE 事件流端点(三轴鉴权 + OpenAPI)"
```

---

### Task 5: 部署注释 + README + 端到端验证

**Files:**
- Modify: `nginx.conf`(`location /api/` 块)
- Modify: `README.md`(端点表)

- [ ] **Step 1: nginx**

`nginx.conf` `location /api/ {` 块内加:

```nginx
            # SSE(/api/v1/widgets/events):关缓冲事件才实时透传;长连接读超时拉长。
            # 对普通 JSON 响应无感(响应小,缓冲本就一次刷完)。
            proxy_buffering off;
            proxy_read_timeout 1h;
```

- [ ] **Step 2: README 端点表加一行**

`| GET | /api/v1/widgets/{id} | ...` 行后加:

```markdown
| GET | `/api/v1/widgets/events` | SSE 变更事件流(created/updated/deleted;需登录 + `widgets:read`) |
```

- [ ] **Step 3: 端到端手验(dev 进程在跑时)**

```bash
# 终端 1:登录拿 cookie 并挂流
curl -s -c /tmp/sse.jar -X POST localhost:8137/api/v1/auth/login -H 'content-type: application/json' -d '{"identifier":"admin","password":"pwd"}' > /dev/null
curl -N -b /tmp/sse.jar localhost:8137/api/v1/widgets/events &
# 终端 2:触发
curl -s -b /tmp/sse.jar -X POST localhost:8137/api/v1/widgets -H 'content-type: application/json' -d '{"name":"live"}'
```

Expected: 终端 1 打出 `event: created` + data JSON。

- [ ] **Step 4: 门禁 + commit**

Run: `just check && just test && just lint`

```bash
git add nginx.conf README.md
git commit -m "docs: SSE 端点(README + nginx 反代注意事项)"
```

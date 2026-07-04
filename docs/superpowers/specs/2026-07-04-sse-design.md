# SSE 范式设计 — widget 变更事件流(可拔插 EventBus)

日期:2026-07-04 · 状态:待实现

## 目标

给脚手架加 **SSE(Server-Sent Events)范式**:演示"服务端事件怎么发布、怎么过鉴权推给浏览器"。
纯 demo 场景 —— **widget 变更广播**(create/update/delete),业务价值为零,范式价值:

1. 可拔插 **EventBus 端口**(memory + PG LISTEN/NOTIFY 双实现,镜像 repo 范式);
2. **SSE + 鉴权**:EventSource 不能自定义 header,httponly cookie 是唯一正解(正好是本 repo 认证形态);
3. 事件与写操作的关系:fire-and-forget,发布失败绝不影响写。

## 非目标(YAGNI,注释钉住)

- Last-Event-ID 回放 / 事件持久化:两实现都 best-effort,断线丢事件。要回放 = 事件表 + 游标,另一个范式。
- 通用事件路由/过滤(per-user 通知流):端口 typed 到 `WidgetEvent`,窄接口;别的模块要事件,照抄这套自己定义。
- 外部 broker(NATS/Kafka/Redis):生态无标准 EventBus trait,自定义窄端口即惯例。多机房/高吞吐时再换 broker 实现同一 trait。

## 架构

生态调研结论:Rust **没有标准 EventBus 抽象** —— 只有进程内 channel 原语(`tokio::sync::broadcast` 等)
和各家 broker 客户端。正解 = 本 repo 既有范式:**端口归消费方,自定义窄 trait,双实现可拔插**
(同 `WidgetRepo` / `UserDirectory` / `ObjectStore`)。

```
WidgetService(写成功)──publish──▶ EventBus(trait)◀──subscribe── SSE handler(GET /widgets/events)
                                    ├─ MemoryEventBus:tokio::sync::broadcast(单实例)
                                    └─ PgEventBus:pg_notify / PgListener(多实例扇出)
```

装配开关同 repo:`APP_DB_HOST` 有 → `PgEventBus`(复用 app pool),无 → `MemoryEventBus`。组合根 `AppState::new` 注入。

## 组件

### 1. 事件 + 端口(`src/features/widget/events.rs`,新文件)

```rust
/// widget 变更事件。SSE 帧的 event name = serde tag(created/updated/deleted)。
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetEvent {
    Created { widget: Widget },
    Updated { widget: Widget },
    Deleted { id: Uuid },
}

/// 事件总线端口(归 widget:发布方 service、订阅方 routes 都在本模块)。
#[async_trait]
pub trait EventBus: Send + Sync {
    /// fire-and-forget:失败只落日志(tracing::warn),**绝不让写操作失败**。
    async fn publish(&self, event: WidgetEvent);
    /// 新订阅,从订阅时刻起收事件(无回放)。
    async fn subscribe(&self) -> Result<Box<dyn EventSubscription>, AppError>;
}

/// 一条订阅。`None` = 总线关闭(SSE 流随之结束)。
/// 实现内部吞掉"慢消费者掉队"(broadcast Lagged):跳过丢失的、继续收,不断流。
#[async_trait]
pub trait EventSubscription: Send {
    async fn recv(&mut self) -> Option<WidgetEvent>;
}
```

### 2. MemoryEventBus(与端口同在 `events.rs`,量小不拆目录;双实现 + 端口一文件收口)

- 包 `tokio::sync::broadcast::Sender<WidgetEvent>`(capacity 64)。
- `publish` = `send`,无订阅者返 Err —— 刻意忽略(合法状态)。
- `recv` 循环:`Ok(e)` → `Some(e)`;`Lagged(_)` → `continue`(吞掉);`Closed` → `None`。
- 天花板:单实例;多实例各见各的写。`ponytail:` 注释指向 PgEventBus。

### 3. PgEventBus

- `publish` = `SELECT pg_notify('widget_events', $1)`,`$1` = `serde_json::to_string(&event)`。
  失败(连接断等)→ `tracing::warn`,不上抛。
- `subscribe` = `sqlx::postgres::PgListener::connect_with(pool)` + `listen("widget_events")`;
  `recv` 循环:拿 notification → `serde_json::from_str`(坏 payload → warn + 跳过)。
- **多实例扇出白送**。事务性投递(回滚不发幽灵事件)**不在本实现内**:publish 用独立连接 autocommit,正确性来自"写成功后才 publish";要事务性需在写事务同一连接上 NOTIFY。
- 天花板:NOTIFY payload 上限 8000 字节(widget 事件几百字节,富余)。超限升级路径:payload 只放 id,订阅方回查。`ponytail:` 注释钉住。

### 3b. NatsEventBus(2026-07-04 后补,用户决策:NATS 为多实例**默认**后端)

- **选择链(IoC,组合根装配)**:`NATS_URL` 设了 → NATS;否则有 app pool → PG(LISTEN/NOTIFY,
  "已有 PG 不加组件"的退路);都没有 → 内存(单实例最终 fallback)。三实现同一 `EventBus` 端口。
- core NATS(非 JetStream):契约不变 —— best-effort、无回放;subject `widget.events`。
- 启动 fail-fast 连接,之后 Client 自动重连(断线窗口丢事件,同契约);compose 加 `nats` 服务 + healthcheck。
- 脚手架连无鉴权 NATS;跨信任域配 token/nkey + TLS(ponytail 注释钉住)。
- 契约测试入口 3:`--features nats-conformance`(`just test-nats`)。

### 4. 发布点(`WidgetService`)

- 加字段 `events: Arc<dyn EventBus>`;`new` 签名加一参(组合根 + 测试同步改,测试给 MemoryEventBus)。
- `create` / `update` / `delete` 成功路径末尾 `self.events.publish(...).await`。
- ~~`create_with_tags` 也发 `Created`~~ 实现偏差(计划已批准):它是 repo 层范式、无 service 调用方 → 不发事件。

### 5. SSE 端点(`widget/routes.rs` + `widget/mod.rs` 挂载)

- `GET /api/v1/widgets/events`,三轴镜像:`CurrentUser`(401)+ `require_scoped(WidgetRead)`(403)。
- handler:`bus.subscribe()` → 用 `futures_util::stream::unfold` 把 `recv()` 适配成 `Stream<Item = Result<Event, Infallible>>` → `Sse::new(stream).keep_alive(KeepAlive::new().interval(15s))`。
- SSE 帧:`Event::default().event(<tag>).json_data(&event)`;event name 从 serde tag 取(实现时用一个 `fn name(&self) -> &'static str` 或直接 match,别运行期序列化再解析)。
- 依赖:`futures-util` 由传递依赖提为直接依赖(仅 `stream::unfold`,零额外编译)。

### 6. 装配 + 文档 + 部署

- `app/state.rs`:按 `app_pool` 有无选 PgEventBus / MemoryEventBus,注入 `WidgetService::new`。
- `infra/op_perms.rs`:`widget_events → Perm::WidgetRead`(fail-closed 测试逼着补)。
- OpenAPI:`#[utoipa::path]` 响应标 `content_type = "text/event-stream"`,描述写明事件形状 = `WidgetEvent` schema。
- `nginx.conf`:`/api/` location 加注释 + `proxy_buffering off;`(SSE 经反代必须;一并 `proxy_read_timeout` 拉长注释说明)。
- `README.md` 端点表加一行。

## 错误处理

- publish 失败:warn 日志,写操作照常返回(fire-and-forget 契约)。
- 订阅 Lagged:实现内部跳过,流不断。
- PgListener 断连:sqlx PgListener 自动重连;重连窗口内的事件丢失(best-effort 契约,文档写明)。
- 总线关闭(Sender drop / listener 不可恢复):`recv` 返 `None` → SSE 流正常结束,浏览器 EventSource 自动重连 → 新订阅。

## 测试

1. **契约测试**(`tests/event_bus_conformance.rs`,镜像 `widget_repo_conformance`):
   一份契约函数吃 `&dyn EventBus` —— publish 后 recv 到、两个订阅各收一份、订阅前发布的收不到(无回放)。
   memory 直跑;pg 走 `#[sqlx::test]`(`test-pg` 口径)。
2. **集成测试**(`tests/widget_api.rs` 加用例):登录 → 开流 → create widget → 断言收到 `event: created` 帧
   (`tokio::time::timeout` 包住防挂死);未认证 → 401;缺 read scope 的降权令牌 → 403。
3. **service 单测**:publish 不阻塞写(零订阅者时 create 仍 Ok)。

## 改动面

新文件 `events.rs`(~120 行含双实现)+ conformance 测试(~80 行);service ~15 行;routes ~45 行;
state ~10 行;op_perms/openapi/nginx/README 各 1-3 行。新直接依赖:`futures-util`(已在树里)。

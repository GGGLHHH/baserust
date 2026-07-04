---
name: eventbus
description: Use when a module needs to publish/subscribe domain events or push realtime updates to the browser (SSE / event stream / EventBus / NATS / LISTEN-NOTIFY), or when deciding where event infrastructure crosses the pluggable-port boundary.
---

# EventBus(领域事件 + SSE 实时推送,可拔插三后端)

非显然的**判断**,先钉住;机制:**照抄 `widget/events.rs` + `widget_events` handler**(`features/widget/`)——活样板(端口 + memory/PG/NATS 三实现 + SSE 适配)。

## 端口归消费方,typed 事件 —— 不做通用总线

每个要事件的模块**自己声明** `XxxEvent` 枚举 + 自己的 `EventBus`/`EventSubscription` trait(`features/<mod>/events.rs`),三实现照抄改常量(channel `<mod>_events` / subject `<mod>.events`,**各模块必须不同**,撞名=串台)。

**禁止**:`EventBus<T>` 泛型进 `infra/`、跨模块 import 别人的 bus/事件。字面重复是**刻意的**——事件形状、降级策略、序列化演进以后必然分叉,横切抽象比重复贵。天花板:第 3 个模块也要事件时,再评估共享 NATS client(外面 connect 一次、各模块 `new(client.clone())`);在那之前每模块自连,2 条连接不值得抽。

## 选择链(IoC,组合根装配)

`NATS_URL` → NATS(多实例默认)→ 有 app pool → PG LISTEN/NOTIFY(不加组件的退路)→ 内存(单实例兜底)。装配照抄 `state.rs` 的 `widget_events` 段;PG 分支**复用既有 pool**,不另开。

## 发布纪律(fire-and-forget)

publish 在 **service 层、repo 写成功之后**(`repo.xxx().await?` 的下一行),签名返回 `()` ——失败只 `tracing::warn!`,**绝不**让写操作失败/回滚。不进事务(PG NOTIFY 走独立连接 autocommit;一致性来自"写成功才发"的顺序纪律,见 `transactions` skill 的边界)。事件=已提交状态的 UI 提示,不是业务状态。

## 契约:best-effort、无回放

断线丢事件是契约不是 bug。前端必须**先 GET 全量再叠 SSE 增量**;要回放=事件表+游标(另一个范式,别混进来)。

## SSE 端点三轴 + 权限对齐

镜像 `widget_events` handler:`CurrentUser`(401)+ `require_scoped(<Mod>Read)`(403)。**权限对齐 list 端点,不发明订阅专属权限**(能看列表就能订变更)。`op_perms.rs` 加一条(漏了 fail-closed 测试拦红)。默认广播无行级过滤;要"只看自己的"→ handler 每帧 `data_access`/`allows_created_by` 判定,不过就 `continue` 跳帧(见 `authorization` skill),**别**在 bus 层分频道。

## 测试接线(最易漏)

1. service 单测:写成功后订阅方收到对应事件(照 `create_publishes_created_event`)。
2. 契约测试:镜像 `tests/event_bus_conformance.rs`(一份契约,memory 直跑,PG/NATS 各 feature 入口)。
3. **justfile:`test-pg` 与 `test-nats` 的 `--test` 清单必须加新契约文件**——不加,PG/NATS 口径的契约永不执行、静默漂移。
4. API 集成:开流→写→断言帧;无凭据 401;缺 read scope 降权令牌 403。

## Red flags

- `EventBus<T>` / `infra/eventbus.rs` / import 别的模块的事件 → 消费方自己声明,照抄样板
- publish 在 repo 里 / 事务里 / 返回 `Result` 上抛 → service 层写成功后,fire-and-forget
- 订阅走 service 转发一层皮 → handler 直接 `state.<mod>_events.subscribe()`
- channel/subject 抄样板忘改名 → 跨模块串台
- 新契约文件没进 justfile `--test` 清单 → PG/NATS 契约静默不跑
- 发明 `xxx:subscribe` 权限 → 对齐 list 的 read 权限

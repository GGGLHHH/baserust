---
name: observability
description: Use when adding or changing monitoring in baserust - the admin 系统监控 page data (request / DB / background-job / SSE stats in src/infra/monitor), /metrics counters, tracing spans or log fields - or when a new Postgres repo method, background job, SSE stream or external call needs to be observable, or when deciding what a stat may be keyed by.
---

# 监控 / 可观测性

baserust 的监控是**后台里的「系统监控」页**(`/admin/monitoring`,前端 `basereact`),数据来自**进程内存**,
不依赖任何外部组件:后端 `GET /api/v1/admin/monitoring`(需 `users:admin`)现算一份报告。
**不要再引入 Grafana / Prometheus / Loki / Tempo / OTel 这类外部套件**(用户明确否决过:要的是后台里的页面)。

## 数据从哪来

| 数据 | 采集点 | 怎么加 |
|---|---|---|
| 请求量 / 4xx / 5xx / 延迟(按路由模板) | `infra::monitor::track_requests` 中间件 | 自动,新路由不用管 |
| 数据库操作耗时 | `infra::monitor::DbTimingLayer` 给 `pg.*` span 计时 | 仓储方法加 `#[tracing::instrument(name = "pg.<表>.<方法>", skip_all)]` |
| outbox / projector / SSE | `infra::telemetry` 的埋点函数(同时写 `/metrics`) | 调 `telemetry::outbox_*` / `record_projector_message` / `SseConnectionGuard` |
| 依赖健康 / 连接池 | `app::probes::Probes`(与 `/readyz` 同源) | 新依赖加进 `Probes` |
| 进程资源 | `metrics_process::collector::collect` | 自动 |

存储分两层:
- **实时(1 小时)**:`Monitor` 进程全局单例,全部是**累计值**;`app::monitoring::run_sampler` 每 15s 存一份累计快照,
  环形保留 1 小时。窗口统计 = 当前 − 最老快照,曲线 = 相邻快照之差。
- **历史 / 日志**:`OpsStore` 端口(`infra/monitor/store.rs`,PG 实现 `store_pg.rs`,表在 `migrations/ops`)。
  `run_minute_flusher` 每分钟 `take_minute` 落一行(同时累加进小时表与小时明细);`run_log_writer` 把采集队列里的日志批量写入;
  `run_retention` 每小时按保留期删(分钟 15 天 / 小时 13 个月 / 明细 30 天 / 日志 15 天,常量在 `store::Retention`)。
  延迟存成固定分桶直方图数组(`hist.rs`),任意时间段相加后都能重算分位数 —— **改桶界 = 历史数据作废**,别随手改。
- **日志采集**:`logs::LogCaptureLayer` 收 WARN / ERROR 事件(带所在 `http` span 的 request_id / 路由),`record_access` 记 5xx 与 ≥1s 的请求;
  进有界队列,满了丢弃并计数,绝不阻塞请求。字段名像 password / token / cookie 的值入库前替换为 `[REDACTED]`。
  写库失败的日志用 `target: logs::STORE_TARGET` 打,采集层跳过它(否则失败日志又进队列、循环)。
分进程部署:实时数据 app 经 `IDM_INTERNAL_URL` 拉 idm 的 `/internal/monitoring`;历史 / 日志两个进程都写同一个 ops 库,app 直接读。

## 判断

- **新 PG 仓储方法 → 必须加 `pg.*` span**(照抄 `features/widget/adapters/postgres.rs`):不加,监控页的数据库操作表里就没有它。`skip_all`:参数里有用户数据,别进日志字段。
- **统计的键只许有限小集合**:路由**模板**(`/widgets/{id}`,未匹配一律 `unmatched`)、仓储方法名、relay 来源、projector 名。**用户 id、请求路径原文、错误消息、IP 绝不能当键** —— 每个值一行,内存和页面都会被撑爆。细节进日志。
- **高频后台循环不建空 span**:每秒一轮的轮询(outbox relay)只在真有活时建 span;`telemetry::outbox_polled` 仍每轮调(页面靠它判断 relay 是否停滞)。
- **后台组件启动就登记**(`telemetry::outbox_started`、projector 的 `pending_tick` 首拍):没活干时页面上也有这一行、显示 0,而不是不见了。
- **状态类数据(占用、积压)定时采样**,别在热路径里查。
- **监控接口自己的轮询、探针不计入请求统计**(`UNTRACKED_PATHS`),否则监控页开着就成了流量主力。
- **加字段 = 改 `infra/monitor/report.rs` 的 DTO** → `just openapi-snapshot-accept` → 前端 `pnpm generate` 后在页面上用。
- **不要把敏感数据打进 WARN / ERROR 日志的正文**:字段名脱敏只认字段名,正文原样入库(保留 15 天)。要带用户输入就放进命名字段。
- `/metrics`(`METRICS_ENABLED`)是给外部抓取的 Prometheus 文本接口,名字常量在 `telemetry.rs`;改名算破坏性变更。

## Red flags

- 统计键里出现 id / 路径原文 / 错误文本 → 改成闭集,细节进日志
- 新 PG 仓储方法没有 `tracing::instrument(name = "pg.…")` → 监控页缺这段耗时
- 在每秒的循环里无条件建 span → 日志被空轮询淹没
- 想加 OTel / Grafana / Prometheus 服务 → 先问用户;现在的约定是监控页 + 进程内数据

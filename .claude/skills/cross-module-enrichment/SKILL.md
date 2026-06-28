---
name: cross-module-enrichment
description: Use when one module's list or response must display a field owned by another module or schema (order list showing customer name, widget list showing creator username), especially under physical schema/role or service isolation where a cross-schema JOIN is impossible or forbidden.
---

# Cross-Module Enrichment

读时按需把另一个模块/schema 的展示字段拼到本模块列表上 —— 不 JOIN、不 N+1、两个 feature 彼此零认知。

## When to use

- 本模块列表要显示别模块的字段(creator username、customer name、author avatar)
- 两边在不同 schema(role 的 search_path 隔离)或不同服务,物理上 JOIN 不通
- 富化字段是展示型、要**最新值**、不需要按它排序/过滤/深分页

**NOT** when:需要按对端字段排序/搜索/深分页(→ 反规范化快照 或 CQRS 投影换可排序);或本就同 schema 可安全 JOIN。

## The one decision that matters: 端口归属

老手都知道别 JOIN、别 N+1。**唯一反直觉、最容易做错的是:接口归谁定义、适配器放哪。** 三种做法,只有第三种不随消费者增多而腐化:

| 做法 | 编译依赖 | 腐化点 |
|---|---|---|
| ❌ 提供方发布公共契约,消费方依赖它 | consumer → provider | provider 要预测所有消费者的需求 |
| ❌ 消费方定义端口,提供方实现它 | provider → consumer | provider 依赖每个消费者的端口,多消费者依赖膨胀 |
| ✅ 消费方定义端口,**组合根**写适配器 | 两 feature 互不 import | provider/consumer 彼此零认知,耦合集中在组合根一处 |

**铁律:端口归消费方(它最小地声明"我要什么")、适配器归组合根(唯一同时认识两边的地方)、provider 与 consumer 彼此 import 一次都不出现。** `widget/port.rs` + `app/adapters/` 连起来读就是 ports-and-adapters 本身。

## Recipe

1. **provider 加批量读原语**:`find_by_ids(&[Uuid]) -> Vec<T>`(`WHERE id = ANY/IN ...`,过滤软删,空集短路)。一次查,不是每行一次。
2. **consumer 定义窄端口 + 瘦 DTO**:`trait Directory { async fn batch_by_ids(&[Uuid]) -> HashMap<Uuid, Brief> }`。`Brief` 只含展示字段,不是 provider 实体全貌。端口/DTO 都用 consumer 的语汇,**不 import provider**。
3. **组合根写适配器**:provider 的 repo → consumer 的端口,薄翻译(map + 转调 + 错误翻译),**无业务判断**。按拓扑选实现(进程内复用 repo / 分进程走 HTTP),同一端口换实现。
4. **富化在 consumer 的 service**:list 后收集 **distinct** id → parse 过滤脏值('system'/NULL/非 UUID)→ **一次** batch → 内存 zip 成**独立 view DTO**。领域/repo/FromRow **保持纯净**,绝不掺富化字段、绝不 JOIN。
5. **降级,分两类**:单个 id 查不到 = 数据缺失 = 该字段 `None`(主行照常返回,不 500、不丢行,可 warn 对账);整个 batch 报错 = 系统故障 = 向上传 error 走统一错误契约。"customer 不存在"和"crm 挂了"是两回事。

## Common mistakes

- **把适配器塞进某个 feature** → features 互相 import。适配器归组合根,两边对彼此无知。
- **端口暴露 provider 实体/错误** → 用 consumer 语汇 + 瘦 Brief,错误在边界翻译。
- **领域/repo 掺富化字段** → 独立 view DTO,repo 纯净。
- **缺失就 500 或填 `"(unknown)"`** → `None`,展示交前端。
- **每行查一次** → distinct id 一次 batch。

## baserust 锚点

provider 原语 `UserRepo::find_by_ids`;consumer 窄端口 `src/features/widget/port.rs` 的 `UserDirectory` + `UserBrief`;组合根适配器 `src/app/adapters/` 的 `InProcessUserDirectory`;富化 `WidgetService::list_enriched`;投影 `Page::map_items`(`Page<Widget>→Page<WidgetView>`);跨 schema 连接走 `connect_for_schema`(同 memory `cross-schema-access` 原则:禁 join、走对方 repo、标识引用非 FK)。装配按 `Mount` 在 `AppState::new` 注入,与按 `*_DB_HOST` 选 Pg/Memory repo 是同一个 seam。

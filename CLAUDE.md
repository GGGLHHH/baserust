# AGENTS.md — baserust

Go→Rust 后端**脚手架**:提供可复用的**范式**(不是业务逻辑)。新业务照范式加、别另起炉灶。

- 人看的运行/部署/端点/栈 → `README.md`
- **怎么干活 → 本文 + `.claude/skills/`**

## 在这干活的铁律

1. **做有 skill 的事,先读对应 skill**(`.claude/skills/`),别凭感觉:
   - 加新业务模块 → **`adding-a-feature`**(wiring checklist + gotchas + API 约定)
   - 列表/响应要带别模块的字段(跨模块 / 跨 schema 富化) → **`cross-module-enrichment`**(端口归消费方 / 组合根适配 / 禁 join / 批量防 N+1 / 降级)
   - 端点要 role/权限/scope 鉴权 → **`authorization`**(判断:perm-not-role / 403 vs 404 / read:all 是 mode 非闸 / doc 由 op_perms 注入不手敲 security)
   - 多步原子写(事务)→ **`transactions`**(原子单元=一个 trait 方法 / Tx 不进签名 / memory 先校验后改 / 跨 repo 不组合一个 tx)
   - 模块要发领域事件 / 实时推送(SSE / EventBus / NATS)→ **`eventbus`**(端口归消费方不做泛型总线 / service 写成功后 fire-and-forget / 行级过滤在 handler 逐帧 / justfile 契约接线最易漏)
   - `ToSchema` 字段只有有限已知取值(status/type/channel/outcome/reason code)→ **`closed-enums`**(闭集枚举而非裸 String,防前端类型漂移 / 无 catch-all 除非多写者版本偏斜 / 读模型强类型、写模型可留 String / 前端 import 生成 union,不手写平行 union)
2. **照着 `widget` 改**:它是六边形分层的活样板(核心 `model` / `ports` / `service` + `adapters/{http,memory,postgres,bus}`),也是跨模块富化的样板。
3. **每个改动过 `just check && just test && just lint`**(clippy 是 `-D warnings`,零警告)。`just test` 含黑盒 HTTP 验收(`tests/http_*.rs`)、OpenAPI 快照、架构规则。
   - **加 / 改接口**:在对应 `tests/http_<模块>.rs` 写黑盒测试并在文件头 `//! covers: METHOD /path` 登记(`http_coverage` 守卫:规范里每个接口都得有);接口形状有意变了 → `just openapi-snapshot-accept` 更新快照,diff 随代码一起提交评审。
4. **提交需许可**:未经明确同意不要 commit。

## 固定架构(稳定骨架,改动要慎重)

- **六边形(端口与适配器),依赖只向内指**:
  - **核心** = 独立 crate **`baserust-core`(`crates/core`)**:`kernel/`(共享内核:`AppError` / 分页 `PageParams`·`Page` / `SortOrder` / 审计 `Actor`·`AuditContext` / 权限 `Perm`·`Policy`)+ `features/<m>/` 的 `model.rs`(领域模型 + garde 校验)、`ports.rs`(trait 端口)、`service.rs`(用例)、`events.rs`、`memory.rs`(内存适配器:默认实现 + 核心单测的假适配器)。**依赖规则由编译器保证**:核心 crate 的 `Cargo.toml` 里没有 axum / tower / utoipa / sqlx / sea-query / NATS / S3 / JWT;`tests/architecture.rs` 再守依赖清单不许加回这些、核心模块之间不许直接互相 import(协作走端口)、主 crate 不许再长出核心代码。
  - **主 crate** 的 `src/features/<m>/mod.rs` 整体重新导出核心(`crate::features::<m>::model` 等路径不变),本模块只放 `adapters/`。
  - **适配器** = `features/<m>/adapters/`:`http/{dto,routes,mod}.rs`(线格式 DTO + `ToSchema` + handler,与领域模型互转)、`memory.rs` / `postgres.rs`(仓储实现,PG 行结构 `FromRow` 只在这)、`bus.rs` / `projector.rs` 等。HTTP 侧都在 `src/infra/http/`:handler 返回 `Result<_, ApiError>`(包一层核心 `AppError`,service 的错误经 `?` 自动转;映射在 `HttpErrorExt`)、审计提取器 `Audit(ctx): Audit`、分页查询参数解析与 cursor 编码、核心闭集枚举的 schema(`closed_enum_to_schema!(XSchema => X, …)` 生成标记类型,DTO 字段 `#[schema(value_type = XSchema)]`)。这些包装都是孤儿规则所需:核心类型在别的 crate,不能直接给它们实现 axum / utoipa 的 trait。`SortOrder` → sea-query 在 `infra/pg.rs`。
  - **HTTP DTO 与领域模型分开**:DTO 保持原 Rust 类型名 → OpenAPI schema 名与生成的前端类型不变;领域模型可以自由演进。
  - **可拔插仓储**:service 持 `Arc<dyn Repo>` 端口;内存实现是默认(零 DB 跑测试、也是核心单测的假适配器),PG 实现按 `*_DB_HOST` 启动时二选一。
  - **核心业务 = 一次同步调用 + 一个本地事务**;事件只做请求外副作用(先进程内,需要可靠投递再 outbox + MQ,消费端幂等)。
- **composition root = `src/app/`**:唯一耦合所有模块处 —— `router.rs`(Mount 枚举 + 中间件栈)、`runtime.rs`(`run`)、`state.rs`(`AppState::new` 装配 + `connect_for_schema`)、`adapters/`(跨模块适配器)。**业务模块彼此零 import**,胶水只在这。
- **多进程拓扑**:开发单体 `Both`(一个进程挂全);生产 app / idm 分进程 + nginx 按 `/api/v1/{public,frontend,admin}/auth/` 三前缀分流。`Mount` 枚举驱动挂哪些模块 + 连哪个库。
- **跨 schema 隔离**:app / idm 各自 role 的 search_path 物理隔离。**禁跨 schema join**;跨模块只读走 `connect_for_schema(对方)` + 对方 repo;引用用标识(字符串)非 FK。
- **统一不泄露错误契约**:所有出错(含 panic / timeout)→ `ErrorBody` JSON `{code,error}`,原始细节只进日志。
- **config 零环境变量静默启动**:全字段有默认,不设任何 env 也能跑(内存模式)。
- **认证**:httponly cookie + Bearer 兜底;app 进程只 decode JWT(roles 在 claim 里),不查 idm 库。

## API 约定

RESTful。写操作用 **PUT 全量替换、禁 PATCH**(更新 DTO 别为"部分更新"把字段全 `Option`)。动词:`GET` / `POST`(→201) / `PUT`(全量更新) / `DELETE`(→204);path 用复数资源名,`/api/v1` 由 nest 加、别重复。细则见 `adding-a-feature` skill。

## 目录地图

| 路径 | 是什么 | 稳定度 |
|---|---|---|
| `src/app/` | composition root:装配 / 路由 / 启动 / 跨模块适配器 | 稳定 |
| `crates/core/` | **核心 crate `baserust-core`**:`kernel/`(error / pagination / sort / audit / authz)+ `features/<m>/`(model / ports / service / events / memory) | 稳定(kernel)/ 易变(features) |
| `src/infra/` | 适配器侧横切:config / **http**(错误→HTTP、提取器、分页查询、审计提取器、闭集 schema)/ authz(TokenScope 提取器 + 登录中间件)/ openapi / op_perms / pg / outbox / jetstream / objectstore | 稳定 |
| `src/features/<name>/` | 业务模块的适配器:`mod.rs`(重新导出核心)+ `adapters/`(http / postgres / bus / projector …;auth、content 只有 HTTP 边界,核心在 idm / content 领域库) | **易变,细节看代码** |
| `src/bin/` | `idm`(分进程入口)、`seed` | 稳定 |
| `migrations/{app,idm}/` · `tests/` | 各 schema 独立 role;`http_*` 黑盒 HTTP 验收(真实端口 + reqwest,不认识 web 框架,换底座只改 `http_support::serve`)+ `*_api`(axum oneshot)+ `*_conformance` 内存↔PG 对拍 + `openapi_snapshot` + `architecture` | — |

> 业务模块(`src/features/*`)变化快,本文**不记其细节** —— 要看就读代码 / 测试。文档只钉上面这些稳定骨架。

## 命令

全集见 `justfile`。常用:`just dev`(单进程起) · `just test`(全量,`--workspace`) · `just test-http`(只跑黑盒) · `just test-pg`(PG conformance) · `just lint` · `just openapi-snapshot-accept` · `just seed`。

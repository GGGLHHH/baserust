# AGENTS.md — baserust

Go→Rust 后端**脚手架**:提供可复用的**范式**(不是业务逻辑)。新业务照范式加、别另起炉灶。

- 人看的运行/部署/端点/栈 → `README.md`
- **怎么干活 → 本文 + `.claude/skills/`**

## 在这干活的铁律

1. **做有 skill 的事,先读对应 skill**(`.claude/skills/`),别凭感觉:
   - 加新业务模块 → **`adding-a-feature`**(wiring checklist + gotchas + API 约定)
   - 列表/响应要带别模块的字段(跨模块 / 跨 schema 富化) → **`cross-module-enrichment`**(端口归消费方 / 组合根适配 / 禁 join / 批量防 N+1 / 降级)
   - 端点要 role/权限/scope 鉴权 → **`authorization`**(判断:perm-not-role / 403 vs 404 / read:all 是 mode 非闸 / doc 由 operation_permissions 注入不手敲 security)
   - 多步原子写(事务)→ **`transactions`**(原子单元=一个 trait 方法 / Tx 不进签名 / memory 先校验后改 / 跨 repo 不组合一个 tx)
   - 模块要发领域事件 / 实时推送(SSE / EventBus / NATS)→ **`eventbus`**(端口归消费方不做泛型总线 / service 写成功后 fire-and-forget / 行级过滤在 handler 逐帧 / justfile 契约接线最易漏)
   - 改后台「系统监控」页的数据、加 span / 日志字段,新 PG 仓储方法、后台任务要可观测 → **`observability`**(PG 方法必加 `pg.*` span / 统计键只许闭集 / 空轮询不建 span / 不引入外部监控套件)
   - `ToSchema` 字段只有有限已知取值(status/type/channel/outcome/reason code)→ **`closed-enums`**(闭集枚举而非裸 String,防前端类型漂移 / 无 catch-all 除非多写者版本偏斜 / 读模型强类型、写模型可留 String / 前端 import 生成 union,不手写平行 union)
2. **照着 `widget` 改**:它是六边形分层的活样板(核心 `model` / `ports` / `widget_service` / `in_memory_widget_repo` + `adapters/{http,pg_widget_repo,bus}`),也是跨模块富化的样板。
3. **每个改动过 `just check && just test && just lint`**(clippy 是 `-D warnings`,零警告)。`just test` 含黑盒 HTTP 验收(`tests/http_*.rs`)、OpenAPI 快照、架构规则。
   - **加 / 改接口**:在对应 `tests/http_<模块>.rs` 写黑盒测试并在文件头 `//! covers: METHOD /path` 登记(`http_coverage` 守卫:规范里每个接口都得有);接口形状有意变了 → `just openapi-snapshot-accept` 更新快照,diff 随代码一起提交评审。
4. **提交需许可**:未经明确同意不要 commit。

## 固定架构(稳定骨架,改动要慎重)

- **六边形(端口与适配器),依赖只向内指**:
  - **核心** = 独立 crate **`baserust-core`(`crates/core`)**:`kernel/`(共享内核:`AppError` / 分页 `PageParams`·`Page` / `SortOrder` / 审计 `Actor`·`AuditContext` / 权限 `Permission`·`Policy`)+ `features/<m>/` 的 `model.rs`(领域模型 + garde 校验)、`ports.rs`(trait 端口)、`<m>_service.rs`(用例)、`<m>_event.rs`、`in_memory_<m>_repo.rs` 等(内存适配器:默认实现 + 核心单测的假适配器;文件按主要条目命名,见下文「代码风格」)。**依赖规则由编译器保证**:核心 crate 的 `Cargo.toml` 里没有 axum / tower / utoipa / sqlx / sea-query / NATS / S3 / JWT;`tests/architecture.rs` 再守依赖清单不许加回这些、核心模块之间不许直接互相 import(协作走端口)、主 crate 不许再长出核心代码。
  - **主 crate** 的 `src/features/<m>/mod.rs` 按名重新导出核心(`crate::features::<m>::model` 等路径不变,不用 glob),本模块只放 `adapters/`。
  - **适配器** = `features/<m>/adapters/`:`http/{dto,routes,mod}.rs`(线格式 DTO + `ToSchema` + handler,与领域模型互转)、`pg_<m>_repo.rs`(PG 仓储实现,PG 行结构 `FromRow` 只在这;内存实现在核心 crate,`adapters` 按名重新导出)、`bus.rs` / `projector.rs` 等。HTTP 侧都在 `src/infra/http/`:handler 返回 `Result<_, ApiError>`(包一层核心 `AppError`,service 的错误经 `?` 自动转;映射在 `HttpErrorExt`)、审计提取器 `Audit(ctx): Audit`、分页查询参数解析与 cursor 编码、核心闭集枚举的 schema(`closed_enum_to_schema!(XSchema => X, …)` 生成标记类型,DTO 字段 `#[schema(value_type = XSchema)]`)。这些包装都是孤儿规则所需:核心类型在别的 crate,不能直接给它们实现 axum / utoipa 的 trait。`SortOrder` → sea-query 在 `infra/pg.rs`。
  - **HTTP DTO 与领域模型分开**:DTO 保持原 Rust 类型名 → OpenAPI schema 名与生成的前端类型不变;领域模型可以自由演进。
  - **可拔插仓储**:service 持 `Arc<dyn Repo>` 端口;内存实现是默认(零 DB 跑测试、也是核心单测的假适配器),PG 实现按 `*_DB_HOST` 启动时二选一。
  - **核心业务 = 一次同步调用 + 一个本地事务**;事件只做请求外副作用(先进程内,需要可靠投递再 outbox + MQ,消费端幂等)。
- **composition root = `src/app/`**:唯一耦合所有模块处 —— `router.rs`(Mount 枚举 + 中间件栈)、`runtime.rs`(`run`)、`app_state.rs`(`AppState::try_new` 装配 + `connect_for_schema` + 库服务的类型别名 `AppAuthService` / `AppContentService`)、`adapters/`(跨模块适配器)。**业务模块彼此零 import**,胶水只在这。
- **多进程拓扑**:开发单体 `Both`(一个进程挂全);生产 app / idm 分进程 + nginx 按 `/api/v1/{public,frontend,admin}/auth/` 与 `/api/v1/admin/platform/`(平台组织管理)两类前缀分流到 idm,其余到 app(`nginx.conf` 与 stack 的 `deploy/nginx.conf` 由 stack 的 `scripts/check-nginx-drift.sh` 对齐)。`Mount` 枚举驱动挂哪些模块 + 连哪个库。
- **多租户(单机共享实例,组织 = 租户)**:账号全局一份(idm),组织 / 成员关系 / 租户角色也在 idm;token 的 `roles` = 平台角色、`tenant_id` = 当前组织(平台上下文缺省)、`tenant_roles` = 当前组织角色。没有「关闭多租户」开关,单租户项目就是只有默认组织 `DEFAULT_TENANT_ID`(`…0001`)。
  - **租户只从 token 来**:handler 用 `CurrentTenant` 提取器(缺 → 403 `tenant_required`,绝不落默认组织),不收请求里的 `tenant_id`;核心用 `kernel::tenant_id::TenantId`(nil 构造即报错)。跨组织的资源 id → **404**。
  - **每张业务表**带 `tenant_id` + `CHECK <> nil` + `ENABLE`/`FORCE ROW LEVEL SECURITY` + `tenant_isolation` 策略;PG 仓储每个方法用 `infra::pg::tenant_transaction`(事务级 `set_config('app.tenant_id', …, true)`,**禁会话级 SET**)且 SQL 再写 `tenant_id = $1`。全局表(字典、账号目录、outbox、迁移台账…)登记在 `tests/rls_audit.rs` 的 `GLOBAL_TABLES`;`rls_audit`(`just test-pg`)守「每张表要么隔离、要么在白名单」+ 运行时账号非 owner、无 BYPASSRLS。
  - **PG 账号三分**(app / content / search):`<schema>_owner` 跑迁移、拥有表;`<schema>` 运行时只有 DML、受 RLS;`<schema>_system` BYPASSRLS,只给后台任务 / 投影器 / 平台级读的单独连接池(`AppState` 的 `*_system_pool`)。建库 `scripts/initdb/10-tenancy-roles.sh`(幂等,老库 `just db-ensure-roles` 在迁移**之前**跑)。idm、ops 不拆。
  - **权限有作用域**:`Permission::scope()` / `RoleName::scope()` 穷尽 match,平台级权限只由平台角色给、租户级只由当前组织角色给(细节 → `authorization` skill)。
  - **角色 4 级**(2026-11-26):平台角色 `superadmin`(只有一个,只由 seed 声明,任何接口都授不出 / 撤不掉)、`platform_admin`(平台管理员);组织角色 `admin` / `user`。superadmin 独占 `ops:read`(监控)/ `audit:read`(登录日志)/ `platform:roles`(任命平台管理员、管持平台角色的账号);平台管理员 = 其余平台级权限。**防接管**:对持平台角色的账号做账号管理写操作、在组织里改角色 / 移出,要 `platform:roles`(`Policy::require_platform_role_authority`,目标角色用未过滤原始名)。
  - **领域事件带 `tenant_id`**,总线全实例广播,SSE handler 逐帧过滤当前组织;outbox 信封带 `tenant_id`(全局事件为 null)。content 的个人内容(头像)= `ContentScope::Personal`,不属于任何组织。
  - 新模块的租户清单(TenantId 入参 / tenant_transaction / RLS 迁移 / 跨租户黑盒测试 / rls_audit)→ `adding-a-feature` skill。
- **跨 schema 隔离**:app / idm 各自 role 的 search_path 物理隔离。**禁跨 schema join**;跨模块只读走 `connect_for_schema(对方)` + 对方 repo;引用用标识(字符串)非 FK。
- **统一不泄露错误契约**:所有出错(含 panic / timeout)→ `ErrorBody` JSON `{code,error}`,原始细节只进日志。
- **config 零环境变量静默启动**:全字段有默认,不设任何 env 也能跑(内存模式)。
- **认证**:httponly cookie + Bearer 兜底;app 进程只 decode JWT(roles 在 claim 里),不查 idm 库。
- **监控**:后台「系统监控」页(`/api/v1/admin/monitoring` 实时 + `/history` + `/logs`,需 `ops:read`,superadmin 独占)。实时数据在进程内存(`src/infra/monitor/`,15s 一个快照、留 1 小时);每分钟落盘到 **`ops` schema**(`OPS_DB_HOST`;分钟级 15 天 / 小时级 13 个月 / 明细 30 天),WARN 及以上日志 + 5xx + 慢请求经采集层进 `ops.log_record`(15 天、入库前脱敏);前端错误经 `POST /api/v1/public/client-errors`(`app/client_errors.rs`,免登录、进程内限流)直接写同一张表,service = `web`。不配 ops 库 = 内存里最近 24 小时。分进程时 app 经 `IDM_INTERNAL_URL` 汇总 idm 实时数据(`app/monitoring.rs`)。埋点函数在 `src/infra/telemetry.rs`(同时写给外部抓取用的 `/metrics`);`/readyz` 逐项检查依赖(`app/probes.rs`)。不引入外部监控套件。

## API 约定

RESTful。写操作用 **PUT 全量替换、禁 PATCH**(更新 DTO 别为"部分更新"把字段全 `Option`)。动词:`GET` / `POST`(→201) / `PUT`(全量更新) / `DELETE`(→204);path 用复数资源名,`/api/v1` 由 nest 加、别重复。细则见 `adding-a-feature` skill。

## 目录地图

| 路径 | 是什么 | 稳定度 |
|---|---|---|
| `src/app/` | composition root:装配 / 路由 / 启动 / 跨模块适配器 | 稳定 |
| `crates/core/` | **核心 crate `baserust-core`**:`kernel/`(app_error / pagination / sort_order / audit / authorization / tenant_id)+ `features/<m>/`(model / ports / `<m>_service` / 事件 / 内存适配器) | 稳定(kernel)/ 易变(features) |
| `src/infra/` | 适配器侧横切:config / **http**(错误→HTTP、提取器、分页查询、审计提取器、闭集 schema)/ authorization(TokenScope 提取器 + 登录中间件)/ openapi / operation_permissions / pg / outbox / jet_stream_publisher / s3_object_store | 稳定 |
| `src/features/<name>/` | 业务模块的适配器:`mod.rs`(重新导出核心)+ `adapters/`(http / `pg_<m>_repo` / bus / projector …;auth、content 只有 HTTP 边界,核心在 idm / content 领域库) | **易变,细节看代码** |
| `src/bin/` | `idm`(分进程入口)、`seed` | 稳定 |
| `migrations/{app,idm,content,search,ops}/` · `tests/` | 各 schema 独立 role;`http_*` 黑盒 HTTP 验收(真实端口 + reqwest,不认识 web 框架,换底座只改 `http_support::serve`)+ `*_api`(axum oneshot)+ `*_conformance` 内存↔PG 对拍 + `openapi_snapshot` + `architecture` | — |

> 业务模块(`src/features/*`)变化快,本文**不记其细节** —— 要看就读代码 / 测试。文档只钉上面这些稳定骨架。

## 命令

全集见 `justfile`。常用:`just dev`(单进程起) · `just test`(全量,`--workspace`) · `just test-http`(只跑黑盒) · `just test-pg`(PG conformance) · `just lint` · `just fmt` · `just openapi-snapshot-accept` · `just seed`。

`just lint` / `just fmt` 除了稳定版工具链还要 nightly 的 rustfmt(只用它的格式化,不用 nightly 编译):
`rustup toolchain install nightly --profile minimal --component rustfmt`。

## 代码风格

遵循 [Google Rust 风格指南](https://google.github.io/styleguide/rustguide.html)。

**工具守的**(过了 `just lint` 就算数):

- 格式:`rustfmt.toml`(`max_width = 100`)+ nightly rustfmt 的三项 `imports_granularity=Module,hex_literal_case=Lower,format_macro_matchers=true`(取值在 justfile 的 `google_fmt`,CI 里同一串);
- lint:`Cargo.toml` 的 `[workspace.lints]`(`unsafe_code = "forbid"`、`absolute_paths`、`must_use_candidate`、`missing_panics_doc`、`redundant_clone` 等)+ `clippy.toml` 的阈值(路径最多两段、测试里允许 unwrap / expect);
- 各 crate 根的 `#![warn(clippy::unwrap_used)]`:产品代码不许 `unwrap`,测试里的 panic 就是断言。

**要人守的**(评审时看):

- 不用 glob 导入(测试模块的 `use super::*` 除外);一条 `use` 只从一个模块导入;
- 命名不缩写(`accumulator` 不是 `acc`,`severity` 不是 `sev`);
- `.parse()` / `.into()` / 复杂迭代链的结果在变量声明上标类型,不用 turbofish;
- 公开 API 用 enum 不用 bool 参数(如 `monitoring::MetricsEndpoint`、`monitor::ProjectorOutcome`);会 panic 的写 `# Panics`;
- 依赖库(idm / content)里 `#[non_exhaustive]` 的类型:结构体用库给的构造函数建(`AuthUser::new(..).in_tenant(..)`、`UploadContentInput::new(..)` 后再改可选字段),不写结构体字面量;`match` 它们的枚举时已知变体逐个列出,通配分支只兜库以后新加的变体,并在注释里写明依据(「Don't omit patterns on `non_exhaustive` enums when matching」);
- 构造函数按「Naming initialization functions」命名:不会失败的叫 `new()`,有多个时叫 `new_with_xxx()`(如 `AuditContext::new_with_user`、`Page::new_with_offset`、`ProfileView::new_with_profile`);返回 `Result` 的叫 `try_new` / `try_new_with_xxx`;值到值的转换叫 `from_xxx()` 并配同语义的 `From` 实现(如 `infra::http::pagination::Page::from_core` + `From<CorePage<U>>`)。可失败的值转换实现 `TryFrom` / `FromStr`,不另写 `parse` 之类的自定义方法;
- 公开签名收借用的数据用 `&T` / `&[T]` / `&str` / `Option<&T>`,不收 `&Arc<T>` / `&Vec<T>` / `&String` / `&Option<T>`;多字段返回值、多个同类型位置参数用具名结构体(`TimeRange`、`PermissionCheck`、`OffsetPosition`、`AccountCreated`、`OutboundEvent`、`LogOrigin`、`Watermarks`、`DurableConsumer` 等;idm 的 `MemberKey` / `NewUser` / `NewRole` / `NewTenant` / `RoleGrant` 同理);
- 文件 / 叶子模块按主要条目命名(`WidgetService` → `widget_service.rs`),一个文件一个主要条目;
- 锁中毒绝不读里面的数据:本项目的统一策略写在 `infra::monitor::lock_or_reset` 上。

**符合指南条款的例外情形**(每条都落在指南的明文例外 / 适用范围里,依据附原文;别「顺手修掉」):

- **`Arc<dyn Port>` 注入端口** —— 两条条款都不构成违反:
  - 「Generics versus `dyn Trait`」原文 *"In libraries, prefer accepting generics … over `dyn Trait`"* 只约束库;按「Apply API design rules in context」,
    baserust(含 `baserust-core`)是 *"Application code — Intended for use in a single application"*,不是库。另外仓储 / 总线要在启动时按配置(`*_DB_HOST` / `NATS_URL`)
    二选一,运行期多态本来就要 `dyn`。
  - 「Avoid `Rc` and `Arc`」的例外 *"Use `Rc` and `Arc` when the alternative ownership and borrowing structure would be unreasonably complex to write,
    understand, or maintain."* 成立:axum 的 `State<AppState>` 要求 `Clone + 'static`,每个请求 / SSE 流 / `tokio::spawn` 的后台任务都要拿到 `'static` 的端口;同一个实例被
    多个用例和后台任务共享(如资料仓储同时给 `ProfileService` 与 `InProcessProfileDirectory`、widget 事件总线同时给用例和 SSE handler)。改成借用就得给 `AppState`
    带生命周期,与 axum / tokio 的 `'static` 要求冲突。依据也写在 `AppState` 的文档注释上。idm / content 的服务是泛型的(`AuthService<U, S, R, M>` /
    `ContentService<C, O, S>`),这里统一填 `Arc<dyn …>` 起别名 `AppAuthService` / `AppContentService`;`AuthService` 不 `Clone`,`AppState.auth` 持 `Arc<AppAuthService>`。
- **按层命名的叶子模块** —— 「Name source files and leaf modules after the primary user-defined item」:有主要条目的文件都已按条目命名(`widget_service.rs`、
  `in_memory_widget_repo.rs`、`pg_widget_repo.rs`、`app_state.rs` …,一个文件一个主要条目)。剩下的按层 / 按用途命名的文件都是多个同级条目、没有单一主要条目,
  落在原文 *"Leaf modules that are not primarily about any particular abstraction can be named as desired."*:`model.rs` / `ports.rs`(多个类型 / 端口)、
  `http/{dto,routes}.rs`(多个 DTO / handler)、`bus.rs`(PG / NATS 两个总线 + 共用线格式)、`token.rs`(签发 + 验签 + 共用 claim)、`emit.rs`、`rebuild.rs`、
  `store.rs` / `report.rs` / `logs.rs`(监控的多个类型)、`seed.rs` / `router.rs` / `runtime.rs` / `monitoring.rs` 等。以函数为主的模块同理(条款说的是 abstraction)。
- **`features/*/mod.rs` 按名重新导出核心** —— 不再用 glob:「Don't use glob imports」只允许 *"`pub use submodule::*` for non-leaf modules"*,被导出的是另一个
  crate(`baserust-core`)的模块,不是本模块的子模块,不在例外里。现在是 `pub use baserust_core::features::<m>::{model, ports, …, XxxService, …};`,
  `crate::features::<m>::model` 等路径不变;核心新加公开条目要在这里补一行。
- **不加 `#[non_exhaustive]`** —— 条款不适用:「Apply `#[non_exhaustive]` to publicly-exposed enums / public structs with public fields」的适用条件是
  *"If an enum is part of a public API used by other teams"* / *"Structs with public fields that are part of a public API used by other teams"*;baserust 是单一应用,
  没有跨团队的下游调用方。穷尽 match 反而让新增变体在编译期暴露所有该改的地方。
- **`CatchPanicLayer`** —— 「Don't call `panic::catch_unwind`」的例外 *"It is acceptable as a defense in depth mechanism as long as it is never relied upon for any
  properties. A codebase that is already attempting to avoid panics may choose to wrap critical entry points with a `catch_unwind` recovery mechanism just in case a
  panic slips through."* 成立:① 不依赖它保证任何性质 —— 没有它,panic 的请求只是断连,同样不泄露细节;事务原子性、鉴权、租户隔离都不经过它;它只把断连变成
  不泄露细节的 500 JSON;② 已在尽量避免 panic:两个 crate 根 `#![warn(clippy::unwrap_used)]` + `clippy -D warnings`,必须 panic 的地方用 `expect("不变量")` 并按
  `missing_panics_doc` 写 `# Panics`,锁中毒统一走 `lock_or_reset` 不 panic;③ 本项目用默认 `panic=unwind`(`Cargo.toml` 没有设 `panic = "abort"`)。依据也写在
  `app/router.rs` 挂它的地方。
- **保留的缩写**(「Avoid abbreviations」的例外 *"Common abbreviations found in Wikipedia"* / *"Abbreviations that are unlikely to be confusing to people outside of your
  project"*):HTTP、API、DB、PG / `Pg`(PostgreSQL)、SSE、JWT、PEM、IdM(`idm`)、DTO、KPI、IP、TTL、S3、NATS、CPU、RSS、URL、UUID、CORS、ACK、p50 / p95 / p99、
  `ms`(毫秒的 SI 符号)、`min` / `max`、`len`(标准库惯例)、repo、config、stats、info、docs;`Ext` 后缀是指南「Naming extension traits」自己规定的;`ops` 是
  数据库 schema 名(`OPS_DB_HOST`);`sslmode` 是 libpq 的参数名。其余公开项一律全称(`Permission`、`Histogram`、`OperationAuthorization`、`timestamp`、`query`、
  `*_seconds`、`*_sequence` …)。
- **保留的单字母名**(同属「Avoid abbreviations」的例外 *"Abbreviations that are unlikely to be confusing to people outside of your project"*):局部变量 / 参数 / 模式绑定一律全称
  (`server`、`client`、`response`、`event`、`error` …),只留这几类:单行的极短闭包参数(`.map(|row| …)` 也行,但 `.filter(|p| p.scope() == …)`、`.map_err(|e| …)` 这种一眼
  看懂的不强改;闭包体跨多行就用全称)、整数下标 `i` / `j`、`fmt(&self, f: &mut Formatter)` 的 `f`(标准库惯例)、宏元变量、泛型参数 `T` / `U` 与生命周期 `'a`。
  channel 两端的私有字段 `tx` / `rx` 与 `ctx`、`env` 按维基百科常见缩写保留。日志字段名(`tracing` 的 key)与线上名同理不随变量改名。
- **线上名字不随 Rust 改名**:JSON 字段 / 查询参数 / 环境变量用 `#[serde(rename = "…")]` 保持原名(`q`、`t`、`ts`、`*_secs`、`open_fds`、`bind_addr`、`app_env` …),
  闭集 schema 名用 `closed_enum_to_schema!(Marker => Enum as "旧名", …)`(`Permission` 的 schema 仍叫 `Perm`);handler / DTO 的文档注释会进 OpenAPI 描述
  和前端生成的类型注释,改它要走 `just openapi-snapshot-accept` 评审,并在 basereact 重新生成 `src/generated/api-types.d.ts`。
- **handler 返回的元组**(`(StatusCode, CookieJar, Json<…>)` 等 axum 响应组合)——「Prefer named fields over tuples」的例外 *"In very local contexts where there is
  unlikely to be any confusion"*:它们只交给 `IntoResponse` 消费,从不按 `.0` / `.1` 取值;测试文件里的私有辅助函数同理。公开 API 的多字段返回值都已是具名结构体。

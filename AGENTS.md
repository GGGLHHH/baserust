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
2. **照着 `widget` 改**:它是分层范式的活样板(`routes → service → repo(trait) → types`),也是跨模块富化的样板。
3. **每个改动过 `just check && just test && just lint`**(clippy 是 `-D warnings`,零警告)。
4. **提交需许可**:未经明确同意不要 commit。

## 固定架构(稳定骨架,改动要慎重)

- **薄分层 + 可拔插仓储**:service 持 `Arc<dyn Repo>` 端口;内存实现是默认(零 DB 跑测试),PG 实现按 `*_DB_HOST` 启动时二选一。**解耦 repo、不解耦 sqlx**(解耦只跟着"会变的边界"走)。
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
| `src/infra/` | 横切:config / error / audit / **authz**(RBAC+scope)/ pagination / openapi / extract | 稳定 |
| `src/features/<name>/` | 业务模块(auth 认证 HTTP 边界、widget 示例 + 富化样板) | **易变,细节看代码** |
| `src/bin/` | `idm`(分进程入口)、`seed` | 稳定 |
| `migrations/{app,idm}/` · `tests/` | 各 schema 独立 role;`*_api` 黑盒 + `*_conformance` 内存↔PG 对拍 | — |

> 业务模块(`src/features/*`)变化快,本文**不记其细节** —— 要看就读代码 / 测试。文档只钉上面这些稳定骨架。

## 命令

全集见 `justfile`。常用:`just dev`(单进程起) · `just test`(全量) · `just test-pg`(PG conformance) · `just lint` · `just seed`。

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **baserust** (1321 symbols, 2823 relationships, 110 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "master"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/baserust/context` | Codebase overview, check index freshness |
| `gitnexus://repo/baserust/clusters` | All functional areas |
| `gitnexus://repo/baserust/processes` | All execution flows |
| `gitnexus://repo/baserust/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->

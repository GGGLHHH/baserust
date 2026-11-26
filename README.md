# baserust (Rust 后端脚手架)

Go → Rust 迁移的基础脚手架:只含**生产级地基 + 代码范式**,无业务逻辑。
crate 名 `baserust`;示例域 `features/widget/` 是范式样板,加真实业务照抄它。

## 拿脚手架

新项目照这份起,不要 git history:

```bash
npx degit GGGLHHH/baserust my-app    # 只拉当前快照,无 .git;进去再 git init
```

## 跑起来

```bash
cp .env.example .env    # 可选;不配也能跑(走内存)
just run                # 或 cargo run
```

默认监听 `.env` 的 `BIND_ADDR`(缺省 `0.0.0.0:8080`),widget 仓储走**内存**、无需数据库。
设 `APP_DB_HOST`(连本地 compose pg)即切 Postgres —— **触发开关是 `APP_DB_HOST`,不是单一 DATABASE_URL**(连接按 role 分字段 `APP_DB_*`,见 `.env.example`)。

接 Postgres 的完整本地流程:

```bash
docker compose up -d pg     # 起库(role/schema 由 initdb 建好)
just migrate-app            # 跑迁移(显式,不在 app 启动时跑)
just dev                    # .env 默认 APP_DB_HOST=localhost → 连 pg
```

## 端点

`/api/v1` 下分三组——`/public` 免登录、`/frontend` 需登录、`/admin` 需后台准入(当前租户的 `admin:login` 或任一平台级权限;组级闸 + 端点内细粒度双层)。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 存活探针 |
| POST | `/api/v1/public/auth/register` | 注册(token 写 httponly cookie) |
| POST | `/api/v1/public/auth/login` | 登录(401 同码同文案防枚举) |
| POST | `/api/v1/public/auth/refresh` | 刷新会话(读 refresh cookie) |
| POST | `/api/v1/public/auth/logout` | 登出,清 cookie(幂等) |
| GET | `/api/v1/frontend/widgets/stats` | 当前租户计数(仅登录样板) |
| GET | `/api/v1/frontend/widgets` | 列表,**双模式分页**(offset `?page=&size=` / cursor `?cursor=&size=`) |
| POST | `/api/v1/frontend/widgets` | 创建 |
| GET/PUT/DELETE | `/api/v1/frontend/widgets/{id}` | 取 / 改名 / 软删除 |
| GET | `/api/v1/frontend/widgets/my-count` | 我创建的 widget 数(仅登录样板) |
| GET | `/api/v1/frontend/widgets/purge-preview` | 删除预检(多权限 **AND** 样板:`widgets:read`+`widgets:delete`) |
| GET | `/api/v1/frontend/widgets/overview` | 概览(多权限 **OR** 样板:`widgets:read` 或 `members:admin`,两支都是租户级) |
| GET | `/api/v1/frontend/widgets/events` | SSE 变更事件流(created/updated/deleted;需登录 + `widgets:read`) |
| POST | `/api/v1/frontend/contents/upload` | 一次性上传(multipart/form-data):建 content + object 行、推字节、同步元数据 |
| GET | `/api/v1/frontend/contents` | 列当前用户的内容(单租户) |
| POST | `/api/v1/frontend/contents` | 建内容(仅 content 行,status=created) |
| GET | `/api/v1/frontend/contents/{id}` | 取内容 |
| PUT | `/api/v1/frontend/contents/{id}` | 全量更新内容可编辑字段 |
| DELETE | `/api/v1/frontend/contents/{id}` | 软删内容 |
| GET | `/api/v1/frontend/contents/{id}/preview` | inline 预览;presign 后端 307 跳签名 URL,内存后端代理字节 |
| GET | `/api/v1/frontend/contents/{id}/download` | 下载内容主对象字节(presign 后端 307 跳转) |
| POST | `/api/v1/frontend/contents/upload-url` | 两步上传①:建账+签直传凭证(`upload_url=null` 回退一步上传) |
| POST | `/api/v1/frontend/contents/{id}/confirm-upload` | 两步上传③:核对落桶→销账(幂等;未传 409) |
| GET | `/api/v1/frontend/contents/{id}/objects` | 列某内容的对象 |
| GET | `/api/v1/frontend/contents/{id}/metadata` | 取内容元数据 |
| PUT | `/api/v1/frontend/contents/{id}/metadata` | 全量替换内容元数据(PUT,upsert) |
| GET | `/api/v1/frontend/permissions/me` | 当前令牌的角色 + 有效权限(role ∩ scope,排序;仅登录) |
| GET | `/api/v1/frontend/profiles/me` | 请求者自己的资料(仅登录零 perm;未建 → 200 空资料) |
| PUT | `/api/v1/frontend/profiles/me` | 全量替换 upsert 自己的资料(仅登录零 perm,不要当前租户;201 建/200 替) |
| POST | `/api/v1/frontend/profiles/me/avatar` | 传自己的头像(multipart,栅格图):存成个人内容(不属于任何租户)并绑定 |
| GET | `/api/v1/frontend/profiles/{user_id}` | 按 id 读任意用户资料(`profiles:read`,平台级;资料全局一份) |
| PUT | `/api/v1/frontend/profiles/{user_id}` | 按 id 全量替换资料(`profiles:write`,平台级);`profiles:write:all` 可改任何人 |
| GET | `/api/v1/frontend/profiles/{user_id}/avatar` | 某用户的头像(仅登录;个人内容,跨租户可见) |
| GET/PUT/DELETE | `/api/v1/frontend/auth/me` | 当前用户:查 / 改资料 / 注销(注销需密码) |
| POST | `/api/v1/frontend/auth/me/password` | 改密(撤销所有会话) |
| POST | `/api/v1/frontend/auth/logout-all` | 撤销所有会话 |
| POST | `/api/v1/admin/auth/login` | 后台登录:验密后进最近用过的、有 `admin:login` 的租户;都没有而有平台级权限 → 平台上下文;否则 403 不发 token(一个租户都没加入 → `tenant_required`,否则 `forbidden`) |
| GET | `/api/v1/admin/auth/me` | 当前管理员(组闸:后台准入) |
| GET | `/api/v1/admin/widgets` | 后台 widget 列表(当前租户;租户级 `widgets:read`,有 `read:all` 看本租户全部、否则只看自己的) |
| GET | `/docs` | Scalar API 文档 UI |
| GET | `/api-docs/openapi.{json,yaml}` | OpenAPI 规范 |

## 加一个业务模块

有项目级 skill **`adding-a-feature`**(加业务时会自动 invoke)。手动概要:核心放 `crates/core/src/features/<name>/`、适配器放 `src/features/<name>/adapters/`,照抄 `widget` 的结构

```
crates/core/src/features/<name>/          核心(独立 crate,依赖里没有任何 web / 数据库 / 消息框架)
  model.rs · ports.rs · service.rs        领域模型 / 端口 trait / 用例
  memory.rs                               内存适配器(默认实现 + 核心单测的假适配器)
src/features/<name>/
  mod.rs                                  重新导出核心
  adapters/http/{dto,routes,mod}.rs       HTTP 适配器:线格式 DTO ↔ 领域模型、handler、router
  adapters/postgres.rs                    仓储实现(PG 行结构只在这)
```

然后 **4 处装配**:`features/mod.rs`(`pub mod`)、`app/state.rs`(AppState 加字段 + 装配)、`app/router.rs`(路由 merge 进 `/api/v1`)、`infra/openapi.rs`(tags)。基础设施(分页 / 审计 / 软删除 / 错误契约 / 提取器)全部复用,只写业务特有部分。

## 架构

```
src/
  main.rs · lib.rs        入口(瘦) / 库根(解锁 tests/)
  app/                    装配层:state(AppState) · router(build_router)
  infra/                  适配器侧横切:config · http(错误→HTTP / 提取器 / 分页查询)· openapi · pg · outbox …
  health.rs               探针
  features/widget/        业务模块的适配器(adapters/);核心在 crates/core
crates/core/              核心 crate baserust-core:kernel(error · pagination · sort · audit · authz)+ 各模块 model/ports/service/memory
```

范式要点:

- **六边形(端口与适配器)**:核心是独立 crate `crates/core`,依赖里没有任何 web / 数据库 / 消息框架,由编译器保证依赖只向内;适配器在主 crate 的 `adapters/` 与 `infra/`;`tests/architecture.rs` 守核心依赖清单与模块边界
- **可拔插实现**:`Arc<dyn Repo>` 端口,启动按 `APP_DB_HOST` 注入内存或 Postgres 实现
- **统一不泄露错误契约**:核心 `AppError` → HTTP 适配器 `IntoResponse`,原始细节只进日志、响应只给 `{code,error}`
- **role/schema 隔离**:每个 schema 一个 pg role(role 的 search_path 指向同名 schema),代码/迁移零 schema 前缀
- **多租户账号拆分**:app / content / search 各三个账号 —— `<schema>_owner` 跑迁移、拥有表;`<schema>` 运行时只有 DML、非 owner、受 RLS 约束(`infra::pg::tenant_tx` 设事务级 `app.tenant_id`);`<schema>_system` BYPASSRLS,给后台任务的单独连接池。建库脚本 `scripts/initdb/10-tenancy-roles.sh`(幂等,老库 `just db-ensure-roles` 升级);`tests/rls_audit.rs` 守「每张表要么租户隔离、要么在全局表白名单」
- **search 读模型(多租户)**:`account_index` 账号目录(全局)+ `admin_user_index` 租户成员索引(主键 `(tenant_id, user_id)`,RLS),投影器与保留期任务用 `search_system` 池写(账号目录运行时账号只读);后台「用户」列表 = 平台账号列表(全部账号,读账号目录,运行时池),租户成员列表读成员索引(运行时池 + 租户事务)。**从多租户之前的版本升级**:search 迁移 0003 建出的成员索引是空的,迁移后跑一次 `rebuild_search`(本地 `cargo run --bin rebuild_search`;容器镜像里同名二进制,覆盖 entrypoint 运行,环境变量同 app 进程;baserust-stack 的 deploy.sh 发现索引为空会自动跑)
- **从多租户之前的版本升级(本机)**:`just db-ensure-roles`(拆账号,**在迁移之前**)→ `just migrate` → `cargo run --bin rebuild_search`。旧数据全部归默认组织;app 启动(和 `seed`)时会把资料引用的旧头像转成个人内容,用 content 的 system 账号改表(UPDATE 权限由 `10-tenancy-roles.sh` 授)。生产步骤见 baserust-stack 的 `scripts/prod/README.md`「从多租户之前的版本升级」
- **基础实体**:审计字段(created_by/at · updated_by/at)+ 软删除(`deleted_at`,`base_select` 收口);`updated_at` 由 DB 触发器维护
- **审计上下文**:`AuditContext`(未认证 → Anonymous → created_by NULL;已认证 → 取鉴权中间件 `auth::authenticate` 塞的 `idm::AuthUser` 作 created_by)
- **认证**:httponly cookie + Bearer 兜底;JWT 用 Ed25519 非对称:idm 私钥签发、app 公钥验签(`keys/` dev 对仅开发,prod `just gen-keys`)
- **分页**:offset(跳页+total)/ cursor(keyset on uuid v7)双模式

## 监控

后台「系统监控」页(前端 `/admin/monitoring`,需 `ops:read`,superadmin 独占),两个标签页:

- **概览**:依赖健康、请求量 / 错误率 / 延迟(按接口)、数据库操作耗时、连接池、outbox / projector、SSE、进程内存与 CPU。趋势可切 1 小时(进程内实时,15 秒一点)/ 24 小时 / 7 天 / 30 天 / 90 天 / 1 年;点曲线上的点跳到那段时间的日志。
- **日志**:WARN 及以上的日志 + 失败请求(5xx)+ 慢请求(≥1 秒)+ 前端错误,按时间段 / 级别 / 服务(app / idm / 前端)/ 关键字 / 请求 ID 筛选。敏感字段(密码、token、cookie…)入库前脱敏。
- **前端错误**:浏览器里的未捕获异常、Promise 拒绝、页面渲染出错由前端(生产构建)经 `POST /api/v1/public/client-errors` 上报(免登录;每 IP 每分钟 30 条、全站每分钟 600 条,超出静默丢弃;页面地址去掉 query),见 `src/app/client_errors.rs`。

历史与日志存在 `ops` schema(`OPS_DB_HOST`,compose 已配),分层保留:分钟级 15 天、小时级 13 个月、接口与数据库明细 30 天、日志 15 天,过期由进程内的任务每小时清理。不配 ops 库也能用:只留内存里最近 24 小时、重启清空。老的 pg 卷先 `just db-ensure-roles` 补建 role,再 `just migrate-ops`。接口:`GET /api/v1/admin/monitoring`(实时)、`/history`、`/logs`;分进程部署时 app 经 `IDM_INTERNAL_URL` 汇总 idm 的实时数据,历史和日志两个进程都写同一个 ops 库。外部抓取另有 `/metrics`(`METRICS_ENABLED=true`)。

## 部署

生产是单机 docker compose。一键部署(前端 + 后端 + nginx 打成离线部署包,服务器上执行一条命令)在总仓库 **baserust-stack** 的 `scripts/prod/`;本仓库提供它复用的生产 compose、环境变量模板和建库脚本,见 [scripts/prod/README.md](scripts/prod/README.md)。

## 测试

```bash
just test          # 默认:零 DB,单测 + API 集成 + 黑盒 HTTP 验收 + OpenAPI 快照 + 内存侧仓储 conformance
just test-http     # 只跑黑盒 HTTP 验收(tests/http_*.rs:真实端口 + reqwest,换 web 框架时原样当验收标准)
just pg-test-grant # 一次性:给 app_owner(sqlx::test 建库 / 迁移的账号)授 CREATEDB + CREATE ON DATABASE
just test-pg       # repo conformance 打真 PG(sqlx::test 临时库以 app_owner 迁移、仓储走运行时账号 app;再加 RLS 审计)
just test-all      # 内存 + PG
```

防漂移:`widget_repo_contract` 一份契约,内存实现和 PG 实现各跑一遍,任一方在软删过滤/分页/幂等/审计上偏离立刻被抓。

## 命令

```
just run / dev / watch / check / test / test-pg / test-all
just migrate-app / migrate-idm / migrate-add <schema> <name>
just lint / fmt / fix / clean
```

## 栈

axum 0.8 · sea-query 1.0 + sqlx 0.9 · utoipa 5(+ Scalar) · async-nats(事件总线) · figment · tracing · garde · thiserror/anyhow · tokio · time · base64。版本见 `Cargo.toml`。

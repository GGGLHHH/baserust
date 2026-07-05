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

`/api/v1` 下分三组——`/public` 免登录、`/frontend` 需登录、`/admin` 需 `users:admin`(组级闸 + 端点内细粒度双层)。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 存活探针 |
| POST | `/api/v1/public/auth/register` | 注册(token 写 httponly cookie) |
| POST | `/api/v1/public/auth/login` | 登录(401 同码同文案防枚举) |
| POST | `/api/v1/public/auth/refresh` | 刷新会话(读 refresh cookie) |
| POST | `/api/v1/public/auth/logout` | 登出,清 cookie(幂等) |
| GET | `/api/v1/public/widgets/stats` | 公开计数(免登录样板) |
| GET | `/api/v1/frontend/widgets` | 列表,**双模式分页**(offset `?page=&size=` / cursor `?cursor=&size=`) |
| POST | `/api/v1/frontend/widgets` | 创建 |
| GET/PUT/DELETE | `/api/v1/frontend/widgets/{id}` | 取 / 改名 / 软删除 |
| GET | `/api/v1/frontend/widgets/my-count` | 我创建的 widget 数(仅登录样板) |
| GET | `/api/v1/frontend/widgets/purge-preview` | 删除预检(多权限 **AND** 样板:`widgets:read`+`widgets:delete`) |
| GET | `/api/v1/frontend/widgets/overview` | 概览(多权限 **OR** 样板:`widgets:read` 或 `users:admin`) |
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
| GET | `/api/v1/frontend/profiles/me` | 请求者自己的资料(仅登录零 perm;未建 404 引导建资料) |
| GET | `/api/v1/frontend/profiles/{user_id}` | 读任意用户资料(`avatar_url` 富化为相对 preview 路径) |
| PUT | `/api/v1/frontend/profiles/{user_id}` | 全量替换 upsert 自己的资料(201 建/200 替);`profiles:write:all` 可改任何人 |
| GET/PUT/DELETE | `/api/v1/frontend/auth/me` | 当前用户:查 / 改资料 / 注销(注销需密码) |
| POST | `/api/v1/frontend/auth/me/password` | 改密(撤销所有会话) |
| POST | `/api/v1/frontend/auth/logout-all` | 撤销所有会话 |
| POST | `/api/v1/admin/auth/login` | 后台登录:验密后需 `users:admin`,否则 403 不发 token |
| GET | `/api/v1/admin/auth/me` | 当前管理员(组闸 `users:admin`) |
| GET | `/api/v1/admin/widgets` | 管理端全量 widget 列表(原 `/widgets/admin/all`) |
| GET | `/docs` | Scalar API 文档 UI |
| GET | `/api-docs/openapi.{json,yaml}` | OpenAPI 规范 |

## 加一个业务模块

有项目级 skill **`adding-a-feature`**(加业务时会自动 invoke)。手动概要:在 `src/features/<name>/` 照抄 `widget/` 的结构

```
features/<name>/
  types.rs · service.rs · routes.rs
  repo/ → mod.rs(trait + Iden) · memory.rs · postgres.rs
```

然后 **4 处装配**:`features/mod.rs`(`pub mod`)、`app/state.rs`(AppState 加字段 + 装配)、`app/router.rs`(路由 merge 进 `/api/v1`)、`infra/openapi.rs`(tags)。基础设施(分页 / 审计 / 软删除 / 错误契约 / 提取器)全部复用,只写业务特有部分。

## 架构

```
src/
  main.rs · lib.rs        入口(瘦) / 库根(解锁 tests/)
  app/                    装配层:state(AppState) · router(build_router)
  infra/                  框架管线 + 共享:config · error · extract · openapi · audit · pagination
  health.rs               探针
  features/widget/        业务模块层(vertical slice,薄分层 routes→service→repo→types)
```

范式要点:

- **薄分层** routes → service → repo(trait)→ types
- **可拔插实现**:`Arc<dyn Repo>` 端口,启动按 `APP_DB_HOST` 注入内存或 Postgres 实现
- **统一不泄露错误契约**:`AppError` → `IntoResponse`,原始细节只进日志、响应只给 `{code,error}`
- **role/schema 隔离**:每个 schema 一个 pg role(role 的 search_path 指向同名 schema),代码/迁移零 schema 前缀
- **基础实体**:审计字段(created_by/at · updated_by/at)+ 软删除(`deleted_at`,`base_select` 收口);`updated_at` 由 DB 触发器维护
- **审计上下文**:`AuditContext`(未认证 → Anonymous → created_by NULL;已认证 → 取鉴权中间件 `auth::authenticate` 塞的 `idm::AuthUser` 作 created_by)
- **认证**:httponly cookie + Bearer 兜底;JWT 用 Ed25519 非对称:idm 私钥签发、app 公钥验签(`keys/` dev 对仅开发,prod `just gen-keys`)
- **分页**:offset(跳页+total)/ cursor(keyset on uuid v7)双模式

## 测试

```bash
just test          # 默认:零 DB,单测 + API 集成 + 内存侧仓储 conformance
just pg-test-grant # 一次性:给 app role 授 CREATEDB + CREATE ON DATABASE
just test-pg       # repo conformance 打真 PG(sqlx::test 临时库,与内存同一份契约防漂移)
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

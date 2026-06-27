# xchangeai (Rust 脚手架)

Go → Rust 迁移的基础脚手架:只含地基 + 代码范式,**无业务逻辑**。
示例域 `widget/` 是范式样板,加真实业务时照抄它。

## 跑起来

```bash
cp .env.example .env   # 可选
just run               # 或 cargo run
```

默认监听 `:8080`,widget 仓储走**内存**(无需数据库)。设 `DATABASE_URL` 即切 Postgres。

端点:

- `GET  /health`
- `GET  /widgets` · `POST /widgets`
- `GET  /api-docs/openapi.json` · `GET /api-docs/openapi.yaml`

## 加一个业务模块

照抄 `src/widget/` 的 5 个文件:

| 文件 | 职责 |
|---|---|
| `types.rs` | DTO(`Serialize`/`Deserialize`/`ToSchema`/`Validate`) |
| `repo.rs` | `Repo` trait + 实现(内存 / Postgres) |
| `service.rs` | 业务逻辑 + 校验(handler 保持薄) |
| `routes.rs` | handler(`#[utoipa::path]` 标注) |
| `mod.rs` | 导出 + `pub fn router()` |

然后两处接线:`main.rs` 的 `build_router` 加 `.merge(你的模块::router())`,`state.rs` 的 `AppState` 加一个 service 字段并在 `new` 里装配。

## 架构范式

- **分层**:routes → service → repo(trait)。
- **依赖注入**:`AppState` + axum `State` 提取器,不用 DI 框架。
- **可拔插实现**:`Arc<dyn Trait>` 端口,启动时按配置注入内存或 DB 实现(镜像 Go 的 `AUTH_BACKEND=memory|db`)。
- **统一错误**:`AppError` 枚举 + `IntoResponse`,handler 用 `?` 传播。
- **声明式 OpenAPI**:`#[utoipa::path]` + `routes!()` 自动汇总规范;`to_yaml()` 生成 YAML。

## 命令

`just run` / `check` / `test` / `lint` / `fmt`。

## 栈

axum · utoipa/utoipa-axum · sqlx · figment · tracing · thiserror/anyhow · tokio。版本见 `Cargo.toml`。

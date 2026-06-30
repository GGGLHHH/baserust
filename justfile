# 开发命令(替代 Makefile)。用法:`just <目标>`。

# 读 .env,让 PG_PORT / APP_DB_* 等与 docker-compose 用同一份配置(否则 just 默认不读 .env)。
set dotenv-load := true

# 起服务(默认内存仓储;设 DATABASE_URL 切 Postgres)
run:
    cargo run

# 热更新:改任意 .rs 自动重编译并重启服务(watchexec 已装,-r 杀旧起新)
dev:
    watchexec -r -e rs -- cargo run

# 编译/clippy 实时反馈面板(改代码即时看红线,不跑服务;面板内按 c/l/t 切 check/clippy/test)
watch:
    bacon clippy

# 快速编译检查
check:
    cargo check --all-targets

# 测试(默认:零 DB,含内存侧仓储一致性 conformance)
test:
    cargo test

# ───── 仓储一致性测试(同一契约对内存/PG 各跑一遍,防 drift)─────
# 一次性:给测试集群 app role 授权(只动本地 dev pg,不碰 prod):
#   CREATEDB —— #[sqlx::test] 建临时库;CREATE ON DATABASE —— 在 base 库建 _sqlx_test 元数据 schema。
# 没装本机 psql 可改:docker compose exec -T pg psql -U <super> -d <db> -c "<同样的 SQL>"
pg-test-grant:
    psql "postgres://{{env_var_or_default('POSTGRES_USER','xchangeai')}}:{{env_var_or_default('POSTGRES_PASSWORD','xchangeai')}}@{{pg_host}}:{{pg_port}}/{{pg_db}}" -c "alter role {{env_var_or_default('APP_DB_USER','app')}} createdb; grant create on database {{pg_db}} to {{env_var_or_default('APP_DB_USER','app')}}; alter role {{env_var_or_default('IDM_DB_USER','idm')}} createdb; grant create on database {{pg_db}} to {{env_var_or_default('IDM_DB_USER','idm')}};"

# PG conformance(连 app role,search_path=app 由 role 配置继承;先起 pg)。
# 授权前置 pg-test-grant 自动跑(幂等:ALTER ROLE CREATEDB / GRANT 重复执行均 no-op)。
test-pg: pg-test-grant
    DATABASE_URL="{{app_db_url}}" cargo test --features pg-conformance --test widget_repo_conformance --test policy_repo_test -- --nocapture

# 全量:内存层(单测/api/内存 conformance) + app schema 的 PG conformance
# (idm 仓储 conformance 随 idm 抽成独立 rust-idm crate 后已迁出本仓)
test-all: test test-pg

# ───── 数据库迁移(sqlx-cli,类似 goose;显式执行,不在 app 启动时跑)─────
# 每个 schema 用同名 role 连接(role 的 search_path = 同名 schema),各自独立 _sqlx_migrations,
# 互不冲突。完整串可用 APP_DATABASE_URL/IDM_DATABASE_URL 覆盖,或只覆盖密码 APP_DB_PASSWORD 等。
# pg 的 host/port/db 也从 env 读(和 compose 同一套:PG_PORT 等),默认连本地 compose pg。
pg_host := env_var_or_default("PG_HOST", "localhost")
pg_port := env_var_or_default("PG_PORT", "5821")
pg_db := env_var_or_default("POSTGRES_DB", "xchangeai")
app_db_url := env_var_or_default("APP_DATABASE_URL", "postgres://" + env_var_or_default("APP_DB_USER", "app") + ":" + env_var_or_default("APP_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
idm_db_url := env_var_or_default("IDM_DATABASE_URL", "postgres://" + env_var_or_default("IDM_DB_USER", "idm") + ":" + env_var_or_default("IDM_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")

# 所有 schema 迁移(聚合,像 Go Makefile 的 migrate 总目标)
migrate: migrate-app migrate-idm

# ── app schema(role app)──
migrate-app:
    sqlx migrate run --source migrations/app --database-url "{{app_db_url}}"
migrate-app-revert:
    sqlx migrate revert --source migrations/app --database-url "{{app_db_url}}"
migrate-app-info:
    sqlx migrate info --source migrations/app --database-url "{{app_db_url}}"

# ── idm schema(role idm)──
migrate-idm:
    sqlx migrate run --source migrations/idm --database-url "{{idm_db_url}}"
migrate-idm-revert:
    sqlx migrate revert --source migrations/idm --database-url "{{idm_db_url}}"
migrate-idm-info:
    sqlx migrate info --source migrations/idm --database-url "{{idm_db_url}}"

# 新建某 schema 的可回滚迁移(内部参数化,创建用):just migrate-add app create_widgets
migrate-add schema name:
    sqlx migrate add -r --source migrations/{{schema}} {{name}}

# seed 默认数据:idm(role/账号/授予)+ app authz(permissions / role_permissions)。幂等,可重复跑。
# 先 `just migrate`(建两 schema 的表)。idm 连 idm role、app 连 app role。
seed:
    IDM_DATABASE_URL="{{idm_db_url}}" APP_DATABASE_URL="{{app_db_url}}" cargo run --bin seed

# lint:格式检查 + clippy(警告即失败)
lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings

# 自动格式化
fmt:
    cargo fmt --all

# 自动修复(类似 eslint --fix):clippy 机器可应用的建议自动改 + 格式化。一键修掉能自动修的。
# --allow-dirty/--allow-staged:clippy --fix 默认要求 git 干净,开发时工作区常有改动,放开。
fix:
    cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features
    cargo fmt --all

# 清理热更新累积的编译缓存(自己的 codegen 产物 + 增量),保留依赖缓存 → 下次只重编自己、秒级
clean:
    cargo clean -p xchangeai
    rm -rf target/debug/incremental

# 导出 OpenAPI 规范(服务需在跑)
openapi-json:
    curl -s http://localhost:8137/api-docs/openapi.json

openapi-yaml:
    curl -s http://localhost:8137/api-docs/openapi.yaml

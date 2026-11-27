# 开发命令(替代 Makefile)。用法:`just <目标>`。

# 读 .env,让 PG_PORT / APP_DB_* 等与 docker-compose 用同一份配置(否则 just 默认不读 .env)。
set dotenv-load := true

# 起服务(默认内存仓储;设 DATABASE_URL 切 Postgres)
run:
    cargo run

# 热更新:改任意 .rs 自动重编译并重启服务(watchexec 已装,-r 杀旧起新)
dev:
    watchexec -r -e rs -- cargo run

# 起本地依赖栈(除 app/idm:这俩留给 `just dev` / `just run` 在本机进程跑)。
# nginx 也不起 —— 它反代的就是 app/idm 容器、且 depends_on 它们 healthy,本机跑模式下用不上。
# 含:pg + migrate(建表后退出)+ minio + minio-init(建桶后退出)+ dbhub。停栈:`docker compose down`。
# 透传额外 flag:改了迁移/代码后 `just up --build` 重建镜像(migrate 跑的就是这镜像,确保用最新)。
up *flags:
    docker compose up -d {{flags}} pg migrate minio minio-init nats dbhub

# 编译/clippy 实时反馈面板(改代码即时看红线,不跑服务;bacon 默认键位:面板内按 c 切 clippy、t 切 test、d 开文档)
watch:
    bacon clippy

# 快速编译检查
check:
    cargo check --workspace --all-targets

# 测试(默认:零 DB,含内存侧仓储一致性 conformance)
test:
    cargo test --workspace

# ───── 仓储一致性测试(同一契约对内存/PG 各跑一遍,防 drift)─────
# 一次性:给测试集群授权(只动本地 dev pg,不碰 prod):
#   CREATEDB —— #[sqlx::test] 建临时库;CREATE ON DATABASE —— 在 base 库建 _sqlx_test 元数据 schema。
#   app_owner 是 baserust 里跑 #[sqlx::test] 的账号(临时库里以 owner 跑迁移,仓储再用运行时账号 app 连);
#   _sqlx_test 已被别的账号建过(老库里是 app)时,再给 app_owner 授它的权限。
#   运行时账号 app 拆分后不再跑 #[sqlx::test](仓储连 sqlx::test 建好的临时库),不授 CREATEDB;
#   idm / content / search 的授权留给 rust-idm / rust-content 自己的 PG 测试用。
# 没装本机 psql 可改:docker compose exec -T pg psql -U <super> -d <db> -c "<同样的 SQL>"
pg-test-grant:
    psql "postgres://{{env_var_or_default('POSTGRES_USER','baserust')}}:{{env_var_or_default('POSTGRES_PASSWORD','baserust')}}@{{pg_host}}:{{pg_port}}/{{pg_db}}" -c "alter role {{app_owner_user}} createdb; grant create on database {{pg_db}} to {{app_owner_user}}; do \$\$ begin if exists (select 1 from pg_namespace where nspname = '_sqlx_test') then grant usage, create on schema _sqlx_test to {{app_owner_user}}; grant all on all tables in schema _sqlx_test to {{app_owner_user}}; grant all on all sequences in schema _sqlx_test to {{app_owner_user}}; end if; end \$\$; alter role {{env_var_or_default('IDM_DB_USER','idm')}} createdb; grant create on database {{pg_db}} to {{env_var_or_default('IDM_DB_USER','idm')}}; alter role {{env_var_or_default('CONTENT_DB_USER','content')}} createdb; grant create on database {{pg_db}} to {{env_var_or_default('CONTENT_DB_USER','content')}}; alter role {{env_var_or_default('SEARCH_DB_USER','search')}} createdb; grant create on database {{pg_db}} to {{env_var_or_default('SEARCH_DB_USER','search')}};"

# PG conformance(先起 pg 并 just migrate)。账号拆分之后(spec §4.4):
#   DATABASE_URL = app_owner —— #[sqlx::test] 用它建临时库、跑迁移(tests/support);
#   仓储走运行时账号 APP_DB_USER / APP_DB_PASSWORD(非 owner,RLS 真的生效);
#   SEARCH_OWNER_DATABASE_URL 跑 search 迁移;search 契约写走 SEARCH_SYSTEM_DATABASE_URL(system,同投影器)、
#   读走 SEARCH_DATABASE_URL(运行时,RLS 生效);auth_event(平台级)走 system;
#   rls_audit 以 *_OWNER_DATABASE_URL 迁移三个 schema,再用 APP_DATABASE_URL(运行时)查系统目录、试 tenant_transaction。
# 授权前置 pg-test-grant 自动跑(幂等:ALTER ROLE CREATEDB / GRANT 重复执行均 no-op)。
test-pg: pg-test-grant
    DATABASE_URL="{{app_owner_db_url}}" APP_DATABASE_URL="{{app_db_url}}" APP_OWNER_DATABASE_URL="{{app_owner_db_url}}" CONTENT_OWNER_DATABASE_URL="{{content_owner_db_url}}" SEARCH_DATABASE_URL="{{search_db_url}}" SEARCH_SYSTEM_DATABASE_URL="{{search_system_db_url}}" SEARCH_OWNER_DATABASE_URL="{{search_owner_db_url}}" OPS_DATABASE_URL="{{ops_db_url}}" cargo test --features pg-conformance --test widget_repo_conformance --test policy_repo_test --test event_bus_conformance --test profile_repo_conformance --test search_repo_conformance --test auth_event_repo_conformance --test ops_store_conformance --test rls_audit --test avatar_repair_pg -- --nocapture

# NATS conformance(事件总线契约打真 NATS;先 `just up` 起 nats)+ JetStream 发布端冒烟
test-nats:
    NATS_URL="nats://localhost:{{env_var_or_default('NATS_PORT','2224')}}" cargo test --features nats-conformance --test event_bus_conformance --test jetstream_smoke -- --nocapture

# 黑盒 HTTP 验收(tests/http_*.rs):真实端口 + reqwest,测试体不认识 web 框架。也包含在 `just test` 里;单独跑用这个。
test-http:
    cargo test --test 'http_*'

# OpenAPI 快照:接口有意变更后接受新快照(装了 cargo-insta 也可用 `cargo insta review` 逐处审)
openapi-snapshot-accept:
    INSTA_UPDATE=always cargo test --test openapi_snapshot

# 全量:内存层(单测/api/内存 conformance) + app schema 的 PG conformance + NATS 契约
# (idm 仓储 conformance 随 idm 抽成独立 rust-idm crate 后已迁出本仓)
test-all: test test-pg test-nats

# P1 durable-events 端到端(真用户写 → 真事件落 JetStream 流)。需**全栈**:先 `just up` 起 pg + nats,
# `.env` 配好 pg + NATS_URL(测试自读 .env)。双 feature 门,单线程串跑。**刻意不进 test-all**:
# 重 e2e、要整套依赖,留作独立 opt-in gate。
test-durable:
    cargo test --features pg-conformance,nats-conformance --test durable_events_p1 -- --nocapture --test-threads=1

# search 投影 e2e(pg+nats;先 just up + just migrate-search)
test-search: pg-test-grant
    SEARCH_DATABASE_URL="{{search_db_url}}" SEARCH_OWNER_DATABASE_URL="{{search_owner_db_url}}" NATS_URL="nats://localhost:{{env_var_or_default('NATS_PORT','2224')}}" cargo test --features pg-conformance,nats-conformance --test search_projection_p3 -- --nocapture --test-threads=1

# ───── 数据库迁移(sqlx-cli,类似 goose;显式执行,不在 app 启动时跑)─────
# 每个 schema 各自独立 _sqlx_migrations,互不冲突;连接账号的 search_path = 该 schema。
# app / content / search 拆了账号(spec §4.4):迁移用 **<schema>_owner**(拥有表),
# 运行时账号 <schema> 只有 DML —— 所以下面这三个 schema 的迁移串是 *_owner_db_url。idm / ops 不拆。
# 完整串可用 APP_OWNER_DATABASE_URL / APP_DATABASE_URL(运行时)等覆盖,或只覆盖账号密码
# APP_DB_OWNER_USER / APP_DB_OWNER_PASSWORD 等(owner 账号名缺省 = 运行时账号名 + _owner)。
# pg 的 host/port/db 也从 env 读(和 compose 同一套:PG_PORT 等),默认连本地 compose pg。
pg_host := env_var_or_default("PG_HOST", "localhost")
pg_port := env_var_or_default("PG_PORT", "5821")
pg_db := env_var_or_default("POSTGRES_DB", "baserust")
app_db_url := env_var_or_default("APP_DATABASE_URL", "postgres://" + env_var_or_default("APP_DB_USER", "app") + ":" + env_var_or_default("APP_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
idm_db_url := env_var_or_default("IDM_DATABASE_URL", "postgres://" + env_var_or_default("IDM_DB_USER", "idm") + ":" + env_var_or_default("IDM_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
content_db_url := env_var_or_default("CONTENT_DATABASE_URL", "postgres://" + env_var_or_default("CONTENT_DB_USER", "content") + ":" + env_var_or_default("CONTENT_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
search_db_url := env_var_or_default("SEARCH_DATABASE_URL", "postgres://" + env_var_or_default("SEARCH_DB_USER", "search") + ":" + env_var_or_default("SEARCH_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
app_owner_user := env_var_or_default("APP_DB_OWNER_USER", env_var_or_default("APP_DB_USER", "app") + "_owner")
content_owner_user := env_var_or_default("CONTENT_DB_OWNER_USER", env_var_or_default("CONTENT_DB_USER", "content") + "_owner")
search_owner_user := env_var_or_default("SEARCH_DB_OWNER_USER", env_var_or_default("SEARCH_DB_USER", "search") + "_owner")
app_owner_db_url := env_var_or_default("APP_OWNER_DATABASE_URL", "postgres://" + app_owner_user + ":" + env_var_or_default("APP_DB_OWNER_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
content_owner_db_url := env_var_or_default("CONTENT_OWNER_DATABASE_URL", "postgres://" + content_owner_user + ":" + env_var_or_default("CONTENT_DB_OWNER_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
search_system_db_url := env_var_or_default("SEARCH_SYSTEM_DATABASE_URL", "postgres://" + env_var_or_default("SEARCH_DB_SYSTEM_USER", env_var_or_default("SEARCH_DB_USER", "search") + "_system") + ":" + env_var_or_default("SEARCH_DB_SYSTEM_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
search_owner_db_url := env_var_or_default("SEARCH_OWNER_DATABASE_URL", "postgres://" + search_owner_user + ":" + env_var_or_default("SEARCH_DB_OWNER_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")
ops_db_url := env_var_or_default("OPS_DATABASE_URL", "postgres://" + env_var_or_default("OPS_DB_USER", "ops") + ":" + env_var_or_default("OPS_DB_PASSWORD", "pwd") + "@" + pg_host + ":" + pg_port + "/" + pg_db + "?sslmode=disable")

# 10-tenancy-roles.sh 要的 owner / system 账号与密码(缺省同 docker-compose.yml)
tenancy_role_env := "-e APP_DB_OWNER_USER=" + app_owner_user + " -e APP_DB_OWNER_PASSWORD=" + env_var_or_default("APP_DB_OWNER_PASSWORD", "pwd") + " -e APP_DB_SYSTEM_USER=" + env_var_or_default("APP_DB_SYSTEM_USER", env_var_or_default("APP_DB_USER", "app") + "_system") + " -e APP_DB_SYSTEM_PASSWORD=" + env_var_or_default("APP_DB_SYSTEM_PASSWORD", "pwd") + " -e CONTENT_DB_OWNER_USER=" + content_owner_user + " -e CONTENT_DB_OWNER_PASSWORD=" + env_var_or_default("CONTENT_DB_OWNER_PASSWORD", "pwd") + " -e CONTENT_DB_SYSTEM_USER=" + env_var_or_default("CONTENT_DB_SYSTEM_USER", env_var_or_default("CONTENT_DB_USER", "content") + "_system") + " -e CONTENT_DB_SYSTEM_PASSWORD=" + env_var_or_default("CONTENT_DB_SYSTEM_PASSWORD", "pwd") + " -e SEARCH_DB_OWNER_USER=" + search_owner_user + " -e SEARCH_DB_OWNER_PASSWORD=" + env_var_or_default("SEARCH_DB_OWNER_PASSWORD", "pwd") + " -e SEARCH_DB_SYSTEM_USER=" + env_var_or_default("SEARCH_DB_SYSTEM_USER", env_var_or_default("SEARCH_DB_USER", "search") + "_system") + " -e SEARCH_DB_SYSTEM_PASSWORD=" + env_var_or_default("SEARCH_DB_SYSTEM_PASSWORD", "pwd")

# 所有 schema 迁移(聚合,像 Go Makefile 的 migrate 总目标)
migrate: migrate-app migrate-idm migrate-content migrate-search migrate-ops

# ── app schema(迁移用 app_owner;运行时 app、后台 app_system)──
migrate-app:
    sqlx migrate run --source migrations/app --database-url "{{app_owner_db_url}}"
migrate-app-revert:
    sqlx migrate revert --source migrations/app --database-url "{{app_owner_db_url}}"
migrate-app-info:
    sqlx migrate info --source migrations/app --database-url "{{app_owner_db_url}}"

# ── idm schema(role idm)──
migrate-idm:
    sqlx migrate run --source migrations/idm --database-url "{{idm_db_url}}"
migrate-idm-revert:
    sqlx migrate revert --source migrations/idm --database-url "{{idm_db_url}}"
migrate-idm-info:
    sqlx migrate info --source migrations/idm --database-url "{{idm_db_url}}"

# ── content schema(迁移用 content_owner)── 表来自 rust-content crate 的 migrations(拷进 migrations/content)
migrate-content:
    sqlx migrate run --source migrations/content --database-url "{{content_owner_db_url}}"
migrate-content-revert:
    sqlx migrate revert --source migrations/content --database-url "{{content_owner_db_url}}"
migrate-content-info:
    sqlx migrate info --source migrations/content --database-url "{{content_owner_db_url}}"

# ── search schema(迁移用 search_owner)── CQRS 读模型:account_index + admin_user_index(租户成员索引)、auth_event(projector 写,list 读)
migrate-search:
    sqlx migrate run --source migrations/search --database-url "{{search_owner_db_url}}"
migrate-search-revert:
    sqlx migrate revert --source migrations/search --database-url "{{search_owner_db_url}}"
migrate-search-info:
    sqlx migrate info --source migrations/search --database-url "{{search_owner_db_url}}"

# ── ops schema(role ops)── 后台监控的历史指标与日志
migrate-ops:
    sqlx migrate run --source migrations/ops --database-url "{{ops_db_url}}"
migrate-ops-revert:
    sqlx migrate revert --source migrations/ops --database-url "{{ops_db_url}}"
migrate-ops-info:
    sqlx migrate info --source migrations/ops --database-url "{{ops_db_url}}"

# initdb 只在空卷首次启动时跑,后加的 schema / 账号靠这个补;可重复执行,之后再 just migrate。
# 00 补 role + schema;10 做多租户的账号拆分(owner / 运行时 / system,表转给 owner、运行时账号只留 DML)。
# owner / system 的账号密码从这里显式传进去 —— 老的 pg 容器建的时候还没有这几个环境变量。
# 给已有的 pg 卷补齐各 schema 的 role + schema,并拆分 owner / 运行时 / system 账号
db-ensure-roles:
    docker compose exec -T pg bash -s < scripts/initdb/00-roles-schemas.sh
    docker compose exec -T {{tenancy_role_env}} pg bash -s < scripts/initdb/10-tenancy-roles.sh

# 新建某 schema 的可回滚迁移(内部参数化,创建用):just migrate-add app create_widgets
migrate-add schema name:
    sqlx migrate add -r --source migrations/{{schema}} {{name}}

# seed 默认数据:idm(role/账号/授予)+ app authz(permissions / role_permissions)+ 旧头像修复(content system 账号)。幂等,可重复跑。
# 先 `just migrate`(建两 schema 的表)。idm 连 idm role、app 连 app role。
# seed bin 与 app 进程同一套 Config 字段(IDM_DB_*/APP_DB_*),此处只补齐 host/port/db 指向 compose pg。
seed:
    IDM_DB_HOST="{{pg_host}}" IDM_DB_PORT="{{pg_port}}" IDM_DB_DATABASE="{{pg_db}}" APP_DB_HOST="{{pg_host}}" APP_DB_PORT="{{pg_port}}" APP_DB_DATABASE="{{pg_db}}" CONTENT_DB_HOST="{{pg_host}}" CONTENT_DB_PORT="{{pg_port}}" CONTENT_DB_DATABASE="{{pg_db}}" cargo run --bin seed

# prod seed:读外部账号文件(默认 seed.prod.toml,.gitignore 已挡,含真密码),不碰仓库里的 pwd 默认。
# 先 `cp seed.prod.toml.example seed.prod.toml` 填强密码。DB 指向经 IDM_DB_*/APP_DB_* env 或此处覆盖。
seed-prod file="seed.prod.toml":
    @test -f "{{file}}" || (echo "缺 {{file}}:先 cp seed.prod.toml.example {{file}} 并填真密码" && exit 1)
    SEED_FILE="{{file}}" cargo run --bin seed

# 生成生产 JWT 密钥对(Ed25519)。dev 对已入库(keys/),这个目标给 prod 造新对。
gen-keys out="./keys/prod-ed25519":
    openssl genpkey -algorithm ed25519 -out {{out}}.pem
    openssl pkey -in {{out}}.pem -pubout -out {{out}}.pub.pem
    @echo "idm 进程: JWT_PRIVATE_KEY_FILE={{out}}.pem + JWT_PUBLIC_KEY_FILE={{out}}.pub.pem"
    @echo "app 进程: 只设 JWT_PUBLIC_KEY_FILE={{out}}.pub.pem"

# lint:格式检查 + clippy(警告即失败)
lint:
    cargo fmt --all -- --check
    cargo +nightly fmt --all -- --check --config {{google_fmt}}
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# 自动格式化
fmt:
    cargo fmt --all
    cargo +nightly fmt --all -- --config {{google_fmt}}

# Google Rust 风格指南要求、但只有 nightly rustfmt 支持的三项(稳定版只有 rustfmt.toml 里的 max_width)
google_fmt := "imports_granularity=Module,hex_literal_case=Lower,format_macro_matchers=true"

# 自动修复(类似 eslint --fix):clippy 机器可应用的建议自动改 + 格式化。一键修掉能自动修的。
# --allow-dirty/--allow-staged:clippy --fix 默认要求 git 干净,开发时工作区常有改动,放开。
fix:
    cargo clippy --fix --allow-dirty --allow-staged --workspace --all-targets --all-features
    cargo fmt --all

# 清理热更新累积的编译缓存(自己的 codegen 产物 + 增量),保留依赖缓存 → 下次只重编自己、秒级
clean:
    cargo clean -p baserust
    rm -rf target/debug/incremental

# 导出 OpenAPI 规范(服务需在跑)
openapi-json:
    curl -s http://localhost:8137/api-docs/openapi.json

openapi-yaml:
    curl -s http://localhost:8137/api-docs/openapi.yaml

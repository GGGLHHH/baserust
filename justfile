# 开发命令(替代 Makefile)。用法:`just <目标>`。

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

# 测试
test:
    cargo test

# lint:格式检查 + clippy(警告即失败)
lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings

# 自动格式化
fmt:
    cargo fmt --all

# 导出 OpenAPI 规范(服务需在跑)
openapi-json:
    curl -s http://localhost:8137/api-docs/openapi.json

openapi-yaml:
    curl -s http://localhost:8137/api-docs/openapi.yaml

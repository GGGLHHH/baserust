# syntax=docker/dockerfile:1

# ---- builder:编译 release 二进制 ----
FROM rust:1.94-bookworm AS builder
WORKDIR /app

# 先用 manifest + 占位 main 缓存依赖层:Cargo.toml/lock 不变时,改源码不重编依赖。
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

# 再拷真实源码编译(sqlx 用运行时 query_as,build 不需要 DATABASE_URL / 在线 DB)
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- migrate:专门执行数据库迁移的镜像(sqlx-cli + migrations,跑完即退出)----
# 放在 runtime 之前,使 runtime 仍是 Dockerfile 的默认(最后)stage。
FROM rust:1.94-bookworm AS migrate
RUN cargo install sqlx-cli --version ^0.8 --no-default-features --features rustls,postgres
WORKDIR /app
COPY migrations ./migrations
COPY scripts/migrate-all.sh ./migrate-all.sh
# 入口脚本按 schema 遍历:每个 schema 用对应 role 迁移(空 schema 跳过)。role 名/密码由环境注入。
# 回滚/查看用本地 `just migrate-app-revert` 等;容器内要单跑可覆盖 entrypoint 调 sqlx。
ENTRYPOINT ["sh", "./migrate-all.sh"]

# ---- runtime:精简镜像,只放二进制 ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 app
COPY --from=builder /app/target/release/xchangeai /usr/local/bin/xchangeai
USER app

# 容器内不写文件日志:不设 LOG_FILE → 只输出 stdout,由 docker/k8s 收集。
ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info,xchangeai=info
EXPOSE 8080
ENTRYPOINT ["xchangeai"]

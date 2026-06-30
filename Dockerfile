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

# 再拷真实源码编译(sqlx 用运行时 query_as,build 不需要 DATABASE_URL / 在线 DB)。
# seed.toml / mock.toml:进程内 seed/mock 用 include_str! 编译期嵌入,故 build 上下文需有它们(否则编译失败)。
COPY src ./src
COPY seed.toml ./seed.toml
COPY mock.toml ./mock.toml
RUN touch src/main.rs && cargo build --release

# ---- sqlx:仅用来产出 sqlx-cli 二进制(构建期 stage,不进任何运行镜像)----
FROM rust:1.94-bookworm AS sqlx
RUN cargo install sqlx-cli --version ^0.8 --no-default-features --features rustls,postgres

# ---- migrate:精简迁移镜像 = slim + sqlx 二进制 + migrations(跑完即退出)----
# 运行期只需 sqlx 二进制,不需 Rust 工具链 → 从 ~1.6G(整套 rust 镜像 + 编译缓存)降到 ~90MB。
# ca-certificates:prod 连托管 PG 走 TLS 时要(本地 sslmode=disable 用不上,但留着不亏)。
# 放在 runtime 之前,使 runtime 仍是 Dockerfile 的默认(最后)stage。
FROM debian:bookworm-slim AS migrate
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=sqlx /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx
COPY migrations ./migrations
COPY scripts/migrate-all.sh ./migrate-all.sh
# 入口脚本按 schema 遍历:每个 schema 用对应 role 迁移(空 schema 跳过)。role 名/密码由环境注入。
# 回滚/查看用本地 `just migrate-app-revert` 等;容器内要单跑可覆盖 entrypoint 调 sqlx。
ENTRYPOINT ["sh", "./migrate-all.sh"]

# ---- runtime:精简镜像,只放二进制 ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 app
# 两个进程二进制:xchangeai(app,默认 ENTRYPOINT)+ idm(分进程,compose 里 override entrypoint)。
COPY --from=builder /app/target/release/xchangeai /usr/local/bin/xchangeai
COPY --from=builder /app/target/release/idm /usr/local/bin/idm
USER app

# 容器内不写文件日志:不设 LOG_FILE → 只输出 stdout,由 docker/k8s 收集。
ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info,xchangeai=info
EXPOSE 8080
ENTRYPOINT ["xchangeai"]

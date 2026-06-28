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

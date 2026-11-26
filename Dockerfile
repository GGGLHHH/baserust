# (不写 syntax 指令:那会强制去 Docker Hub 拉 dockerfile frontend,离线/受限网络下 build 直接挂;
#  本文件没用 cache-mount/heredoc 等扩展特性,buildkit 内置 frontend 足够。)

# ---- git 依赖的本地源码(可选)----
# 默认是空 stage:cargo 按 Cargo.toml 去 GitHub 拉 idm / content。
# baserust-stack 的 scripts/prod/build.sh 用 --build-context idm-src=<目录> / content-src=<目录> 换成
# 本地子模块的源码(提交号与 Cargo.lock 一致,它会先核对),构建时就不用连 GitHub。
FROM scratch AS idm-src
FROM scratch AS content-src

# ---- builder:编译 release 二进制 ----
FROM rust:1.94-bookworm AS builder
WORKDIR /app
# 可选:crates.io 镜像(BUILD_MIRROR=cn 时由 baserust-stack 的 scripts/prod/build.sh 传入;不传 = 官方源)。
ARG CARGO_MIRROR=
RUN if [ -n "$CARGO_MIRROR" ]; then \
      printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' "$CARGO_MIRROR" > "$CARGO_HOME/config.toml"; \
    fi

# 给了本地源码就用 [patch] 把 git 依赖指过去(没给 = 目录为空,不写 patch)。
COPY --from=idm-src / /deps/idm/
COPY --from=content-src / /deps/content/
RUN if [ -f /deps/idm/Cargo.toml ]; then \
      printf '\n[patch."https://github.com/GGGLHHH/rust-idm"]\nidm = { path = "/deps/idm" }\n' >> "$CARGO_HOME/config.toml"; \
    fi \
 && if [ -f /deps/content/Cargo.toml ]; then \
      printf '\n[patch."https://github.com/GGGLHHH/rust-content"]\ncontent = { path = "/deps/content" }\n' >> "$CARGO_HOME/config.toml"; \
    fi

# 先用 manifest + 占位源码缓存依赖层:Cargo.toml/lock 不变时,改源码不重编依赖。
# 工作区两个 crate(主 crate + crates/core 核心)的 manifest 都要先到位,占位 main / lib 各一个。
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml ./crates/core/Cargo.toml
RUN mkdir -p src crates/core/src \
 && echo 'fn main() {}' > src/main.rs \
 && touch crates/core/src/lib.rs \
 && cargo build --release \
 && rm -rf src crates/core/src

# 再拷真实源码编译(sqlx 用运行时 query_as,build 不需要 DATABASE_URL / 在线 DB)。
# seed.toml / mock.toml:进程内 seed/mock 用 include_str! 编译期嵌入,故 build 上下文需有它们(否则编译失败)。
COPY crates/core/src ./crates/core/src
COPY src ./src
COPY seed.toml ./seed.toml
COPY mock.toml ./mock.toml
# keys/:config.rs 用 include_str! 编译期嵌入 dev 密钥对(零配置启动的默认 JWT 钥),故 build 上下文需有它们。
# 只嵌入 dev 对(prod 钥永不入库、运行期经 JWT_*_KEY_FILE 挂卷);.dockerignore 别把 keys/ 整个排掉。
COPY keys ./keys
RUN touch src/main.rs crates/core/src/lib.rs && cargo build --release

# ---- sqlx:仅用来产出 sqlx-cli 二进制(构建期 stage,不进任何运行镜像)----
FROM rust:1.94-bookworm AS sqlx
# 可选:crates.io 镜像(BUILD_MIRROR=cn 时由 baserust-stack 的 scripts/prod/build.sh 传入;不传 = 官方源)。
ARG CARGO_MIRROR=
RUN if [ -n "$CARGO_MIRROR" ]; then \
      printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' "$CARGO_MIRROR" > "$CARGO_HOME/config.toml"; \
    fi
RUN cargo install sqlx-cli --version ^0.8 --no-default-features --features rustls,postgres

# ---- migrate:精简迁移镜像 = slim + sqlx 二进制 + migrations(跑完即退出)----
# 运行期只需 sqlx 二进制,不需 Rust 工具链 → 从 ~1.6G(整套 rust 镜像 + 编译缓存)降到 ~90MB。
# ca-certificates:prod 连托管 PG 走 TLS 时要(本地 sslmode=disable 用不上,但留着不亏)。
# 放在 runtime 之前,使 runtime 仍是 Dockerfile 的默认(最后)stage。
FROM debian:bookworm-slim AS migrate
# 可选:Debian 镜像(如 http://mirrors.aliyun.com;不传 = 官方源)。
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then sed -i "s|http://deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi
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
# 可选:Debian 镜像(如 http://mirrors.aliyun.com;不传 = 官方源)。
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then sed -i "s|http://deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 app
# 两个进程二进制:baserust(app,默认 ENTRYPOINT)+ idm(分进程,compose 里 override entrypoint)。
COPY --from=builder /app/target/release/baserust /usr/local/bin/baserust
COPY --from=builder /app/target/release/idm /usr/local/bin/idm
# 运维工具:search 读模型全量回填(多租户升级后成员索引是空的,要跑一次;投影漂移时也用它)。
# 用法:同一镜像覆盖 entrypoint,环境变量与 app 进程相同(要 idm / app / search 三个库)。
COPY --from=builder /app/target/release/rebuild_search /usr/local/bin/rebuild_search
USER app

# 容器内不写文件日志:不设 LOG_FILE → 只输出 stdout,由 docker/k8s 收集。
ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info,baserust=info
EXPOSE 8080
ENTRYPOINT ["baserust"]

# Auth 审计日志 Phase 1 — baserust 改动 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 baserust 落地认证审计日志:idm 进程的 auth handler 把全生命周期事件写进 `idm.outbox`,新 `auth_event` projector 投影成 search-schema 读模型,admin 端点可查;统一 90 天保留。

**Architecture:** 复用现成 CQRS 链(idm.outbox → relay → JetStream `events.idm.auth.*` → projector → 读模型 → keyset 查询)。发射在 idm 进程 auth handler 层(天然有 ip/ua/channel),经 idm crate 新增的 `OutboxRepo::emit` 写 `idm.outbox`。读模型 `auth_event` 落 **search schema**,与 `admin_user_index` 同进程(`needs_idm`)。**Phase 1 用普通表 + DELETE 保留,不上分区**(见下方决策)。

**Tech Stack:** Rust · axum 0.8 · sqlx 0.9 · sea-query · async-nats(JetStream)· utoipa · uuid v7 · time · 依赖 rust-idm ≥ v0.5.0(配套计划 `2026-07-08-auth-audit-phase1-idm.md` 产出)。

## Global Constraints

- **前置依赖**:本计划开始前,`2026-07-08-auth-audit-phase1-idm.md` 的 Task 1–4 必须完成(提供 `OutboxRepo::emit`、`IdmError::InvalidCredentials`/`CredentialFailure`、`AuthOutcome.session_id`、`logout -> Option<Uuid>`)。联调期把 `baserust/Cargo.toml` 的 `idm` 依赖临时改 `idm = { path = "../rust-idm" }`,全链跑通后再 pin `tag = "v0.5.0"`。
- **进程约束**:auth handler 跑在 idm 进程(`Mount::Idm`,`needs_idm`),只连 idm/search schema,**写不了 app.outbox** → 审计事件一律写 `idm.outbox`。
- **决策(Phase 1)**:`auth_event` 用**普通表 + 90 天 DELETE 保留**,不上分区(分区是规模优化,自动化最重最易错;表前向兼容,后续可转)。事件只来自 idm → 去重键 `event_seq` 单列,不设 `event_source`。
- **防枚举**:login/admin_login 失败仍统一返 401(`AppError::Unauthorized`);失败原因只进审计事件,绝不进响应体。
- **可信代理 IP**:不信 `X-Forwarded-For` 最左(可伪造);按"信任 N 层代理(配置,默认 1)"从右数解析;`forwarded_chain` 存 XFF 全文。
- **GitNexus(项目规矩)**:编辑任何 symbol 前先 `impact({target, direction:"upstream"})`,HIGH/CRITICAL 先警示;提交前 `detect_changes()`。
- **提交纪律**:未获用户明确许可**不得** commit / push。
- **富化留桩**:geo/asn/device 列 Phase 1 恒 null(Phase 2 填);`prev_session_id` 恒 null(Phase 3)。
- 命令一律在 `/Users/ggg/private/baserust` 下跑。UI/vendored `src/components/ui/*` 与本计划无关(纯后端)。

---

### Task 1: 依赖 pin idm + `From<IdmError>` 补 `InvalidCredentials` 臂

**Files:**
- Modify: `/Users/ggg/private/baserust/Cargo.toml:12`(idm 依赖联调改 path,最终 pin v0.5.0)
- Modify: `/Users/ggg/private/baserust/src/infra/error.rs:144-153`(`From<idm::IdmError>` 加臂)
- Test: `/Users/ggg/private/baserust/src/infra/error.rs`(新增 `#[cfg(test)] mod tests` 或加入现有)

**Interfaces:**
- Consumes(from idm plan):`idm::IdmError::InvalidCredentials(idm::CredentialFailure)`。
- Produces:`AppError::from(idm::IdmError::InvalidCredentials(_))` → `AppError::Unauthorized`(HTTP 401 不变)。

- [ ] **Step 1: 写失败测试**（`src/infra/error.rs` 末尾）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn invalid_credentials_maps_to_401() {
        let e = AppError::from(idm::IdmError::InvalidCredentials(
            idm::CredentialFailure::BadPassword,
        ));
        assert!(matches!(e, AppError::Unauthorized));
        assert_eq!(e.status_code(), StatusCode::UNAUTHORIZED);
    }
}
```

- [ ] **Step 2: 联调切 idm path 依赖**（`Cargo.toml:12`)

```toml
idm = { path = "../rust-idm" }
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cargo test -p baserust --lib infra::error::tests::invalid_credentials_maps_to_401`
Expected: 编译失败 —— `no variant named 'InvalidCredentials'`(说明 idm 已升级、缺 From 臂;若报 `no variant` on idm 端则 idm plan 未先行)。

- [ ] **Step 4: 补 From 臂**（`src/infra/error.rs:146-152` 的 match 加一臂)

```rust
impl From<idm::IdmError> for AppError {
    fn from(e: idm::IdmError) -> Self {
        match e {
            idm::IdmError::NotFound => AppError::NotFound,
            idm::IdmError::Unauthorized => AppError::Unauthorized,
            // 失败原因只供审计(handler 发事件时读),HTTP 仍统一 401,防枚举不变。
            idm::IdmError::InvalidCredentials(_) => AppError::Unauthorized,
            idm::IdmError::Conflict(m) => AppError::Conflict(m),
            idm::IdmError::Internal(e) => AppError::Internal(e),
        }
    }
}
```

- [ ] **Step 5: 跑测试确认通过 + 全 lib 编译**

Run: `cargo test -p baserust --lib infra::error && cargo build`
Expected: PASS;`cargo build` 绿(idm path 依赖生效)。

- [ ] **Step 6: Commit**（须先取得许可)

```bash
git add Cargo.toml Cargo.lock src/infra/error.rs
git commit -m "chore(deps): idm path dep + map InvalidCredentials to 401"
```

---

### Task 2: `ClientContext` 提取器（可信代理 IP + UA + request-id）

**Files:**
- Create: `/Users/ggg/private/baserust/src/infra/client_context.rs`
- Modify: `/Users/ggg/private/baserust/src/infra/mod.rs`(挂 `pub mod client_context;`)
- Modify: `/Users/ggg/private/baserust/src/infra/config.rs`(加 `trusted_proxy_hops: usize`,默认 1)
- Test: 同文件 `#[cfg(test)] mod tests`

**Interfaces:**
- Produces:`ClientContext { ip: Option<IpAddr>, forwarded_chain: Option<String>, user_agent: Option<String>, request_id: Option<String> }`,`FromRequestParts`(`Rejection = Infallible`)。auth handler 加此参即得。
- Produces:`resolve_client_ip(xff: Option<&str>, real_ip: Option<&str>, peer: Option<IpAddr>, trusted_hops: usize) -> Option<IpAddr>`(纯函数,可单测)。

- [ ] **Step 1: 写失败测试**（`client_context.rs` 内)

```rust
#[cfg(test)]
mod tests {
    use super::resolve_client_ip;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusts_nth_from_right_not_leftmost() {
        // client 伪造最左;真实链: client_forged, real_client, nginx。信 1 跳(nginx)→ 取右数第 2 = real_client。
        let xff = "1.2.3.4, 203.0.113.9, 10.0.0.1";
        assert_eq!(
            resolve_client_ip(Some(xff), None, None, 1),
            Some(ip("203.0.113.9")),
            "信 1 层代理应取右数第 2 跳,不取伪造的最左"
        );
    }

    #[test]
    fn falls_back_to_real_ip_then_peer() {
        assert_eq!(
            resolve_client_ip(None, Some("198.51.100.7"), None, 1),
            Some(ip("198.51.100.7"))
        );
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(resolve_client_ip(None, None, Some(peer), 1), Some(peer));
        assert_eq!(resolve_client_ip(None, None, None, 1), None);
    }

    #[test]
    fn short_chain_yields_none_not_panic() {
        // 只有 1 跳但信 1 层 → 右数第 2 不存在 → None(不 panic、不误取伪造值)。
        assert_eq!(resolve_client_ip(Some("1.2.3.4"), None, None, 1), None);
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p baserust --lib infra::client_context`
Expected: 编译失败 —— `unresolved module` / `cannot find function resolve_client_ip`。

- [ ] **Step 3: 实现**（`src/infra/client_context.rs`)

```rust
//! 认证审计用的客户端上下文提取器(HTTP 边界)。IP 反伪造:不信 XFF 最左(客户端可写),
//! 按"信任 N 层反代"从右数取第 (N+1) 跳;forwarded_chain 存 XFF 全文供取证。UA/request-id 直读头。

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;

/// 认证事件的来源维度。channel(public/admin)由 handler 决定,不在此。
#[derive(Clone, Debug, Default)]
pub struct ClientContext {
    pub ip: Option<IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// 解析可信客户端 IP。`trusted_hops` = 我方信任的反代层数(nginx 等,配置)。
/// XFF 从右数第 (trusted_hops+1) 跳才是我方边界外的真实客户端;不足则 None(拒绝退回可伪造值)。
/// XFF 缺失 → X-Real-IP → peer(直连)。
pub fn resolve_client_ip(
    xff: Option<&str>,
    real_ip: Option<&str>,
    peer: Option<IpAddr>,
    trusted_hops: usize,
) -> Option<IpAddr> {
    if let Some(xff) = xff {
        let hops: Vec<&str> = xff.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        // 右数第 (trusted_hops+1) 跳:len - 1 - trusted_hops。
        if let Some(idx) = hops.len().checked_sub(trusted_hops + 1) {
            if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                return Some(ip);
            }
        }
        return None;
    }
    if let Some(r) = real_ip {
        if let Ok(ip) = r.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    peer
}

impl<S: Send + Sync> FromRequestParts<S> for ClientContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let forwarded_chain = header("x-forwarded-for").map(str::to_owned);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        // trusted_hops 由 router 经 extension 注入(见 Task 8);缺省信 1 层。
        let trusted_hops = parts.extensions.get::<TrustedHops>().map(|t| t.0).unwrap_or(1);
        let ip = resolve_client_ip(
            forwarded_chain.as_deref(),
            header("x-real-ip"),
            peer,
            trusted_hops,
        );
        Ok(Self {
            ip,
            forwarded_chain,
            user_agent: parts.headers.get(USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_owned),
            request_id: header("x-request-id").map(str::to_owned),
        })
    }
}

/// 经 router extension 注入的可信反代层数(避免提取器依赖全局 config)。
#[derive(Clone, Copy)]
pub struct TrustedHops(pub usize);
```

- [ ] **Step 4: 挂模块 + config 字段**

`src/infra/mod.rs` 加 `pub mod client_context;`。`src/infra/config.rs` 的 `Config` 加字段 `pub trusted_proxy_hops: usize`,`Default`/figment 默认 `1`（参照该文件现有字段默认写法)。

- [ ] **Step 5: 跑测试确认通过**

Run: `cargo test -p baserust --lib infra::client_context`
Expected: PASS(3 个 IP 解析用例全绿)。

- [ ] **Step 6: Commit**（须先取得许可)

```bash
git add src/infra/client_context.rs src/infra/mod.rs src/infra/config.rs
git commit -m "feat(audit): ClientContext extractor with trusted-proxy IP resolution"
```

---

### Task 3: `auth_event` 迁移（search schema,普通表 + 索引）

**Files:**
- Create(via `just migrate-add search create_auth_event`): `migrations/search/0002_create_auth_event.up.sql` + `.down.sql`

**Interfaces:**
- Produces:`auth_event` 表(search schema)。列见 spec;去重唯一键 `event_seq`;查询索引 `(user_id, occurred_at desc)`、`(ip, occurred_at desc) where ip is not null`、`(id desc)`(keyset)。

- [ ] **Step 1: 生成迁移对**

Run: `just migrate-add search create_auth_event`
Expected: 生成 `migrations/search/0002_create_auth_event.{up,down}.sql` 空文件。

- [ ] **Step 2: 写 up.sql**（`migrations/search/0002_create_auth_event.up.sql`)

```sql
-- 认证审计读模型(CQRS)。projector 从 events.idm.auth.* 投影;append-only(只 insert/select)。
-- 无 schema 前缀:靠 search role 的 search_path=search 落位(同 admin_user_index)。
-- Phase 1:普通表 + 90 天 DELETE 保留(分区是后续规模优化,表结构前向兼容)。
create table auth_event (
    id                   uuid        primary key,               -- v7,投影时生成;兼作 keyset 排序键
    event_type           text        not null,                  -- auth.login_succeeded / ...
    occurred_at          timestamptz not null,                  -- 源事件发生时刻(保留/时间过滤按它)
    channel              text        not null,                  -- public | admin
    auth_method          text        not null default 'password',
    -- 主体
    user_id              uuid,                                  -- 失败且用户不存在时 null
    identifier_attempted text,                                  -- 提交的用户名/邮箱原文(不脱敏)
    session_id           uuid,                                  -- = jti,关联 idm.sessions
    prev_session_id      uuid,                                  -- refresh 血缘(Phase 3;Phase 1 恒 null)
    actor                text,                                  -- 触发者;撤别人会话时为 admin
    -- 结果
    outcome              text        not null,                  -- success | failure
    failure_reason       text,                                  -- unknown_user / bad_password / no_admin_perm / ...
    -- 来源(原始)
    ip                   inet,
    forwarded_chain      text,
    user_agent           text,
    request_id           text,
    -- 派生(Phase 2 填;Phase 1 恒 null)
    country              text,
    city                 text,
    asn                  bigint,
    isp_org              text,
    is_datacenter        boolean,
    os                   text,
    browser              text,
    device_type          text,
    -- 溯源
    event_seq            bigint      not null,                  -- idm.outbox 行 id;auth 事件唯一来源 → 单列去重
    projected_at         timestamptz not null default (now() at time zone 'utc')
);
-- 幂等:同一 idm outbox 行重投一次 → 唯一键吸收(projector INSERT ... ON CONFLICT DO NOTHING)。
create unique index auth_event_seq_uidx on auth_event (event_seq);
-- 某用户历史(admin/用户活动);全局审计流按 ip 聚合(安全);keyset 翻页按 id v7。
create index auth_event_user_time_idx on auth_event (user_id, occurred_at desc);
create index auth_event_ip_time_idx   on auth_event (ip, occurred_at desc) where ip is not null;
create index auth_event_id_idx        on auth_event (id desc);
-- 保留:DELETE WHERE occurred_at < now()-90d 走它。
create index auth_event_occurred_idx  on auth_event (occurred_at);
```

- [ ] **Step 3: 写 down.sql**

```sql
drop table if exists auth_event;
```

- [ ] **Step 4: 本地跑迁移验证**

Run: `just migrate-search && just migrate-search-info`
Expected: `0002_create_auth_event` 状态 installed(需本地 search DB;无则跳过,靠 Task 10 集成测试的 `sqlx::migrate!` 覆盖)。

- [ ] **Step 5: Commit**（须先取得许可)

```bash
git add migrations/search/0002_create_auth_event.up.sql migrations/search/0002_create_auth_event.down.sql
git commit -m "feat(audit): auth_event read-model migration (search schema)"
```

---

### Task 4: `AuthEvent` 类型 + `AuthEventRepo`（insert + list）

**Files:**
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/mod.rs`
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/types.rs`
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/repo/mod.rs`
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/repo/postgres.rs`
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/repo/memory.rs`
- Modify: `/Users/ggg/private/baserust/src/features/mod.rs`(挂 `pub mod auth_audit;`)
- Test: `repo/memory.rs` 内 `#[cfg(test)]`

**Interfaces:**
- Produces:`NewAuthEvent`(写模型,projector 组装后传 repo)、`AuthEventRow`(读模型,`sqlx::FromRow`)、`AuthEventQuery`(过滤:user_id/event_type/outcome/time 窗)。
- Produces trait `AuthEventRepo`:
  - `insert(&self, ev: &NewAuthEvent) -> Result<(), AppError>`(ON CONFLICT (event_seq) DO NOTHING)
  - `list(&self, q: &AuthEventQuery, page: PageParams) -> Result<Page<AuthEventRow>, AppError>`(keyset by id v7 + 过滤)
  - `delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError>`(保留 job 用)

- [ ] **Step 1: 写失败测试**（`repo/memory.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::pagination::PageParams;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn ev(seq: i64, user: Option<Uuid>) -> NewAuthEvent {
        NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: "auth.login_succeeded".into(),
            occurred_at: OffsetDateTime::now_utc(),
            channel: "public".into(),
            auth_method: "password".into(),
            user_id: user,
            identifier_attempted: None,
            session_id: Some(Uuid::now_v7()),
            actor: user.map(|u| u.to_string()),
            outcome: "success".into(),
            failure_reason: None,
            ip: None,
            forwarded_chain: None,
            user_agent: None,
            request_id: None,
            event_seq: seq,
        }
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_list_filters_by_user() {
        let repo = InMemoryAuthEventRepo::new();
        let alice = Uuid::now_v7();
        repo.insert(&ev(1, Some(alice))).await.unwrap();
        repo.insert(&ev(1, Some(alice))).await.unwrap(); // 同 seq 重投 → 无第二行
        repo.insert(&ev(2, Some(Uuid::now_v7()))).await.unwrap();

        let q = AuthEventQuery { user_id: Some(alice), ..Default::default() };
        let page = repo.list(&q, PageParams::Offset { page: 1, size: 20, with_total: true }).await.unwrap();
        assert_eq!(page.items.len(), 1, "同 seq 去重 + 按 user 过滤只剩 alice 一行");
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p baserust --lib features::auth_audit`
Expected: 编译失败(模块/类型不存在)。

- [ ] **Step 3: `types.rs`**（写模型 + 读模型 + 查询过滤)

```rust
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// 写模型:projector 从 envelope 组装后交 repo 落库(Phase 1 富化列不在此,DB 默认 null)。
#[derive(Debug, Clone)]
pub struct NewAuthEvent {
    pub id: Uuid,
    pub event_type: String,
    pub occurred_at: OffsetDateTime,
    pub channel: String,
    pub auth_method: String,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub actor: Option<String>,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub event_seq: i64,
}

/// 读模型行(admin 端点返回)。
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AuthEventRow {
    pub id: Uuid,
    pub event_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub channel: String,
    pub user_id: Option<Uuid>,
    pub identifier_attempted: Option<String>,
    pub session_id: Option<Uuid>,
    pub outcome: String,
    pub failure_reason: Option<String>,
    pub ip: Option<String>, // inet → 文本回传
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// 列表过滤(admin)。空 = 不限。
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub ip: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
}
```

- [ ] **Step 4: `repo/mod.rs`**（trait + 类型再导出)

```rust
mod memory;
mod postgres;

pub use memory::InMemoryAuthEventRepo;
pub use postgres::PgAuthEventRepo;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};
use super::types::{AuthEventQuery, AuthEventRow, NewAuthEvent};

#[async_trait]
pub trait AuthEventRepo: Send + Sync {
    /// 幂等落库:同 event_seq 重投不重复(ON CONFLICT DO NOTHING)。
    async fn insert(&self, ev: &NewAuthEvent) -> Result<(), AppError>;
    /// keyset(id v7)+ 过滤列表。
    async fn list(&self, q: &AuthEventQuery, page: PageParams) -> Result<Page<AuthEventRow>, AppError>;
    /// 保留:删 occurred_at < cutoff 的行,返回删除数。
    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError>;
}
```

- [ ] **Step 5: `repo/postgres.rs`**（insert + list + delete;keyset 镜像 `search/repo/postgres.rs` 的 cursor 分支,过滤用 sea-query）

```rust
use async_trait::async_trait;
use sea_query::{Expr, Iden, Order, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::infra::error::AppError;
use crate::infra::pagination::{encode_cursor, Page, PageParams};
use crate::infra::extract::AssertSqlSafe; // 与 search repo 同一 SQL-safe 包装(确认实际路径,search postgres.rs 有 import)
use super::super::types::{AuthEventQuery, AuthEventRow, NewAuthEvent};
use super::AuthEventRepo;

#[derive(Iden)]
enum AuthEvent {
    Table,
    Id, EventType, OccurredAt, Channel, AuthMethod,
    UserId, IdentifierAttempted, SessionId, Actor,
    Outcome, FailureReason, Ip, ForwardedChain, UserAgent, RequestId, EventSeq,
}

const READ_COLS: &[AuthEvent] = &[
    AuthEvent::Id, AuthEvent::EventType, AuthEvent::OccurredAt, AuthEvent::Channel,
    AuthEvent::UserId, AuthEvent::IdentifierAttempted, AuthEvent::SessionId,
    AuthEvent::Outcome, AuthEvent::FailureReason, AuthEvent::Ip, AuthEvent::UserAgent,
];
// country/city/os/browser 由 AuthEventRow 承接,Phase 1 恒 null;读时 select 它们(见下 SELECT list)。

pub struct PgAuthEventRepo {
    pool: PgPool,
}
impl PgAuthEventRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn apply_filters(q: &mut sea_query::SelectStatement, f: &AuthEventQuery) {
    if let Some(u) = f.user_id {
        q.and_where(Expr::col(AuthEvent::UserId).eq(u));
    }
    if let Some(t) = &f.event_type {
        q.and_where(Expr::col(AuthEvent::EventType).eq(t.clone()));
    }
    if let Some(o) = &f.outcome {
        q.and_where(Expr::col(AuthEvent::Outcome).eq(o.clone()));
    }
    if let Some(ip) = &f.ip {
        q.and_where(Expr::cust_with_values(r#""ip" = $1::inet"#, [ip.clone()]));
    }
    if let Some(from) = f.from {
        q.and_where(Expr::col(AuthEvent::OccurredAt).gte(from));
    }
    if let Some(to) = f.to {
        q.and_where(Expr::col(AuthEvent::OccurredAt).lt(to));
    }
}

#[async_trait]
impl AuthEventRepo for PgAuthEventRepo {
    async fn insert(&self, ev: &NewAuthEvent) -> Result<(), AppError> {
        // 显式列 INSERT + ON CONFLICT (event_seq) DO NOTHING(幂等)。富化列不写 → DB 默认 null。
        // ip 用 ::inet cast(sea-query 无 inet 类型,用 cust)。
        let sql = r#"insert into auth_event
            (id, event_type, occurred_at, channel, auth_method, user_id, identifier_attempted,
             session_id, actor, outcome, failure_reason, ip, forwarded_chain, user_agent, request_id, event_seq)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::inet,$13,$14,$15,$16)
            on conflict (event_seq) do nothing"#;
        sqlx::query(sql)
            .bind(ev.id).bind(&ev.event_type).bind(ev.occurred_at).bind(&ev.channel)
            .bind(&ev.auth_method).bind(ev.user_id).bind(&ev.identifier_attempted)
            .bind(ev.session_id).bind(&ev.actor).bind(&ev.outcome).bind(&ev.failure_reason)
            .bind(ev.ip.map(|i| i.to_string())).bind(&ev.forwarded_chain)
            .bind(&ev.user_agent).bind(&ev.request_id).bind(ev.event_seq)
            .execute(&self.pool).await.map_err(|e| AppError::Internal(e.into()))?;
        Ok(())
    }

    async fn list(&self, f: &AuthEventQuery, page: PageParams) -> Result<Page<AuthEventRow>, AppError> {
        // SELECT list 固定(含 Phase 1 恒 null 的 country/city/os/browser),与 AuthEventRow 列序一致。
        const SEL: &str = r#"id, event_type, occurred_at, channel, user_id, identifier_attempted,
            session_id, outcome, failure_reason, host(ip) as ip, user_agent,
            country, city, os, browser from auth_event"#;
        match page {
            PageParams::Offset { page, size, with_total } => {
                let mut q = Query::select();
                q.expr(Expr::cust(SEL));
                apply_filters(&mut q, f);
                q.order_by(AuthEvent::Id, Order::Desc).limit(size).offset((page.saturating_sub(1)) * size);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows = sqlx::query_as_with::<_, AuthEventRow, _>(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool).await.map_err(|e| AppError::Internal(e.into()))?;
                let total = if with_total {
                    let mut c = Query::select();
                    c.expr(Expr::cust("count(*) from auth_event"));
                    apply_filters(&mut c, f);
                    let (csql, cvalues) = c.build_sqlx(PostgresQueryBuilder);
                    let n: i64 = sqlx::query_scalar_with::<_, i64, _>(AssertSqlSafe(csql), cvalues)
                        .fetch_one(&self.pool).await.map_err(|e| AppError::Internal(e.into()))?;
                    Some(n as u64)
                } else { None };
                Ok(Page::offset(rows, page, size, total))
            }
            PageParams::Cursor { after, limit } => {
                let mut q = Query::select();
                q.expr(Expr::cust(SEL));
                apply_filters(&mut q, f);
                if let Some(after) = after {
                    q.and_where(Expr::col(AuthEvent::Id).lt(after)); // id v7 DESC keyset
                }
                q.order_by(AuthEvent::Id, Order::Desc).limit(limit + 1);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let mut rows = sqlx::query_as_with::<_, AuthEventRow, _>(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool).await.map_err(|e| AppError::Internal(e.into()))?;
                let has_more = rows.len() as u64 > limit;
                let next = if has_more { rows.truncate(limit as usize); rows.last().map(|r| encode_cursor(r.id)) } else { None };
                Ok(Page::cursor(rows, limit, next))
            }
        }
    }

    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let r = sqlx::query("delete from auth_event where occurred_at < $1")
            .bind(cutoff).execute(&self.pool).await.map_err(|e| AppError::Internal(e.into()))?;
        Ok(r.rows_affected())
    }
}
```

> 注:`AssertSqlSafe` 的确切导入路径以 `src/features/search/repo/postgres.rs` 顶部为准(实现时对齐)。`Expr::cust(SEL)` 拼固定列名 = 零用户输入,安全。

- [ ] **Step 6: `repo/memory.rs`**（in-memory:Vec + seq 去重 + user 过滤 + keyset;供 handler/projector 单测)

```rust
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};
use super::super::types::{AuthEventQuery, AuthEventRow, NewAuthEvent};
use super::AuthEventRepo;

#[derive(Default)]
pub struct InMemoryAuthEventRepo {
    rows: Mutex<Vec<NewAuthEvent>>,
}
impl InMemoryAuthEventRepo {
    pub fn new() -> Self {
        Self { rows: Mutex::new(Vec::new()) }
    }
    /// 测试辅助:当前落库条数。
    pub fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}

fn to_row(e: &NewAuthEvent) -> AuthEventRow {
    AuthEventRow {
        id: e.id, event_type: e.event_type.clone(), occurred_at: e.occurred_at,
        channel: e.channel.clone(), user_id: e.user_id,
        identifier_attempted: e.identifier_attempted.clone(), session_id: e.session_id,
        outcome: e.outcome.clone(), failure_reason: e.failure_reason.clone(),
        ip: e.ip.map(|i| i.to_string()), user_agent: e.user_agent.clone(),
        country: None, city: None, os: None, browser: None,
    }
}

#[async_trait]
impl AuthEventRepo for InMemoryAuthEventRepo {
    async fn insert(&self, ev: &NewAuthEvent) -> Result<(), AppError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.event_seq == ev.event_seq) {
            return Ok(()); // 幂等
        }
        rows.push(ev.clone());
        Ok(())
    }

    async fn list(&self, f: &AuthEventQuery, page: PageParams) -> Result<Page<AuthEventRow>, AppError> {
        let rows = self.rows.lock().unwrap();
        let mut items: Vec<&NewAuthEvent> = rows.iter()
            .filter(|r| f.user_id.is_none_or(|u| r.user_id == Some(u)))
            .filter(|r| f.event_type.as_ref().is_none_or(|t| &r.event_type == t))
            .filter(|r| f.outcome.as_ref().is_none_or(|o| &r.outcome == o))
            .collect();
        items.sort_by(|a, b| b.id.cmp(&a.id)); // id v7 DESC
        let out: Vec<AuthEventRow> = items.iter().map(|e| to_row(e)).collect();
        match page {
            PageParams::Offset { page, size, with_total } => {
                let total = if with_total { Some(out.len() as u64) } else { None };
                let start = ((page.saturating_sub(1)) * size) as usize;
                let slice = out.into_iter().skip(start).take(size as usize).collect();
                Ok(Page::offset(slice, page, size, total))
            }
            PageParams::Cursor { limit, .. } => {
                let slice: Vec<_> = out.into_iter().take(limit as usize).collect();
                Ok(Page::cursor(slice, limit, None))
            }
        }
    }

    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| r.occurred_at >= cutoff);
        Ok((before - rows.len()) as u64)
    }
}
```

- [ ] **Step 7: `mod.rs` + 挂载**

`src/features/auth_audit/mod.rs`:
```rust
pub mod repo;
pub mod types;

pub use repo::{AuthEventRepo, InMemoryAuthEventRepo, PgAuthEventRepo};
pub use types::{AuthEventQuery, AuthEventRow, NewAuthEvent};
```
`src/features/mod.rs` 加 `pub mod auth_audit;`。

- [ ] **Step 8: 跑测试确认通过**

Run: `cargo test -p baserust --lib features::auth_audit`
Expected: PASS(`insert_is_idempotent_and_list_filters_by_user` 绿)。

- [ ] **Step 9: Commit**（须先取得许可)

```bash
git add src/features/auth_audit src/features/mod.rs
git commit -m "feat(audit): auth_event types + repo (insert/list/retention, pg+memory)"
```

---

### Task 5: `AuthEventProjector`（消费 events.idm.auth.* → repo.insert）

**Files:**
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/projector.rs`
- Modify: `/Users/ggg/private/baserust/src/features/auth_audit/mod.rs`(挂 `pub mod projector;`)
- Test: 同文件 `#[cfg(test)]`

**Interfaces:**
- Consumes:`AuthEventRepo`(Task 4)。
- Produces:`AuthEventProjector::connect(nats_url, repo, durable_name) -> anyhow::Result<Self>` + `run(shutdown)`;durable 名 `"auth_event_projector"`,只认 `auth.*`。

**镜像来源**:`src/features/search/projector.rs:1-169`(`Envelope`、`ApplyError{Poison,Transient}`、`connect`、`run` 循环逐字照抄,仅 `apply_message` 换成下方 auth 版;`pull::Config` 加 `filter_subject: Some("events.idm.auth.>".to_owned())` 只收 auth 主题)。

- [ ] **Step 1: 写失败测试**（`projector.rs`;测 `apply_message` 纯逻辑,直接喂 envelope 字节 + in-memory repo)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::auth_audit::InMemoryAuthEventRepo;
    use serde_json::json;
    use std::sync::Arc;

    fn envelope(seq: i64, ev_type: &str, data: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "event_id": format!("idm-{seq}"), "schema": "idm", "type": ev_type,
            "aggregate_id": "00000000-0000-0000-0000-000000000000", "seq": seq, "data": data,
        })).unwrap()
    }

    #[tokio::test]
    async fn projects_login_succeeded_and_is_idempotent() {
        let repo = Arc::new(InMemoryAuthEventRepo::new());
        let uid = uuid::Uuid::now_v7();
        let payload = envelope(7, "auth.login_succeeded", json!({
            "occurred_at": "2026-07-08T10:00:00Z", "channel": "public", "outcome": "success",
            "user_id": uid, "session_id": uuid::Uuid::now_v7(), "identifier_attempted": null,
            "failure_reason": null, "ip": null, "forwarded_chain": null, "user_agent": null, "request_id": null,
        }));
        AuthEventProjector::apply_message(repo.as_ref(), &payload).await.unwrap();
        AuthEventProjector::apply_message(repo.as_ref(), &payload).await.unwrap(); // 同 seq 幂等
        assert_eq!(repo.len(), 1);
    }

    #[tokio::test]
    async fn unknown_type_is_ignored_bad_payload_is_poison() {
        let repo = Arc::new(InMemoryAuthEventRepo::new());
        // 非 auth.* → 忽略(Ok)
        AuthEventProjector::apply_message(repo.as_ref(), &envelope(1, "user.created", json!({}))).await.unwrap();
        // auth.* 但 data 坏 → Poison
        let bad = envelope(2, "auth.login_succeeded", json!({"channel": 123}));
        assert!(matches!(AuthEventProjector::apply_message(repo.as_ref(), &bad).await, Err(ApplyError::Poison(_))));
        assert_eq!(repo.len(), 0);
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p baserust --lib features::auth_audit::projector`
Expected: 编译失败(类型不存在)。

- [ ] **Step 3: 实现**（照抄 search projector 骨架 + 下方 auth `apply_message`;`AuthEventData` 承接 envelope `data`)

```rust
//! auth_event 投影器:消费 JetStream events.idm.auth.*,投影成 auth_event 读模型。
//! 骨架(Envelope/ApplyError/connect/run)镜像 features::search::projector;仅 apply_message 换成 auth 版。

use std::sync::Arc;

use anyhow::Context;
use async_nats::jetstream::{self, consumer::{pull, AckPolicy}};
use futures_util::StreamExt;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::repo::AuthEventRepo;
use super::types::NewAuthEvent;
use crate::infra::jetstream::STREAM_NAME;

#[derive(Debug, Deserialize)]
struct Envelope {
    r#type: String,
    seq: i64,
    data: serde_json::Value,
}

/// envelope.data 的形状(handler 发射时组装,见 Task 7)。缺省字段 = null。
#[derive(Debug, Deserialize)]
struct AuthEventData {
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    channel: String,
    outcome: String,
    #[serde(default = "default_method")]
    auth_method: String,
    #[serde(default)] user_id: Option<Uuid>,
    #[serde(default)] identifier_attempted: Option<String>,
    #[serde(default)] session_id: Option<Uuid>,
    #[serde(default)] actor: Option<String>,
    #[serde(default)] failure_reason: Option<String>,
    #[serde(default)] ip: Option<std::net::IpAddr>,
    #[serde(default)] forwarded_chain: Option<String>,
    #[serde(default)] user_agent: Option<String>,
    #[serde(default)] request_id: Option<String>,
}
fn default_method() -> String { "password".into() }

#[derive(Debug)]
pub enum ApplyError {
    Poison(String),
    Transient(crate::infra::error::AppError),
}

pub struct AuthEventProjector {
    consumer: jetstream::consumer::Consumer<pull::Config>,
    repo: Arc<dyn AuthEventRepo>,
}

impl AuthEventProjector {
    pub async fn connect(nats_url: &str, repo: Arc<dyn AuthEventRepo>, durable_name: &str) -> anyhow::Result<Self> {
        let client = async_nats::connect(nats_url).await.with_context(|| format!("连接 NATS 失败: {nats_url}"))?;
        let js = jetstream::new(client);
        let stream = js.get_stream(STREAM_NAME).await.with_context(|| format!("获取流 {STREAM_NAME} 失败"))?;
        let consumer = stream.get_or_create_consumer(durable_name, pull::Config {
            durable_name: Some(durable_name.to_owned()),
            ack_policy: AckPolicy::Explicit,
            filter_subject: "events.idm.auth.>".to_owned(), // 只收 auth 主题
            ..Default::default()
        }).await.with_context(|| format!("建/绑 durable {durable_name} 失败"))?;
        Ok(Self { consumer, repo })
    }

    // run(): 逐字照抄 search projector.rs:119-169(Poison→ack、Transient→不 ack)。

    async fn apply_message(repo: &dyn AuthEventRepo, payload: &[u8]) -> Result<(), ApplyError> {
        let env: Envelope = serde_json::from_slice(payload)
            .map_err(|e| ApplyError::Poison(format!("envelope 反序列化: {e}")))?;
        if !env.r#type.starts_with("auth.") {
            return Ok(()); // 非 auth 事件,忽略(前向兼容)
        }
        let d: AuthEventData = serde_json::from_value(env.data)
            .map_err(|e| ApplyError::Poison(format!("{} data: {e}", env.r#type)))?;
        let new = NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: env.r#type,
            occurred_at: d.occurred_at,
            channel: d.channel,
            auth_method: d.auth_method,
            user_id: d.user_id,
            identifier_attempted: d.identifier_attempted,
            session_id: d.session_id,
            actor: d.actor,
            outcome: d.outcome,
            failure_reason: d.failure_reason,
            ip: d.ip,
            forwarded_chain: d.forwarded_chain,
            user_agent: d.user_agent,
            request_id: d.request_id,
            event_seq: env.seq,
        };
        repo.insert(&new).await.map_err(ApplyError::Transient)
    }
}
```

> `run` 方法从 `src/features/search/projector.rs:119-169` 逐字复制(只改 `Self::apply_message` 已是本类型的)。`filter_subject` 用 `events.idm.auth.>` → 本 durable 只投递 auth 主题,与 search projector(无 filter)井水不犯河水。

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p baserust --lib features::auth_audit::projector`
Expected: PASS(投影 + 幂等 + 未知忽略 + 坏 data poison)。

- [ ] **Step 5: Commit**（须先取得许可)

```bash
git add src/features/auth_audit/projector.rs src/features/auth_audit/mod.rs
git commit -m "feat(audit): auth_event projector (events.idm.auth.* -> read model)"
```

---

### Task 6: auth handler 发射事件（写 idm.outbox）

**Files:**
- Modify: `/Users/ggg/private/baserust/src/app/state.rs`(`AppState` 加 `idm_outbox: Option<Arc<dyn idm::OutboxRepo>>`;构建)
- Create: `/Users/ggg/private/baserust/src/features/auth/emit.rs`(事件组装 + emit 助手)
- Modify: `/Users/ggg/private/baserust/src/features/auth/routes.rs`(各 handler 调 emit)
- Modify: `/Users/ggg/private/baserust/src/features/auth/mod.rs`(挂 `mod emit;`)
- Test: `/Users/ggg/private/baserust/tests/auth_audit_emit.rs`(新,镜像 `tests/users_api.rs` in-memory oneshot)

**Interfaces:**
- Consumes:idm `OutboxRepo::emit`(idm plan Task 1)、`ClientContext`(Task 2)、`AuthOutcome.session_id` / `login` 失败原因 / `logout` 返回(idm plan)。
- Produces:`emit_auth_event(outbox, event_type, aggregate_id, data)`;handler 在成功/失败路径调用。**发射失败只 warn 不阻断认证响应**(fire-and-forget:审计不能拖垮登录)。

- [ ] **Step 1: 先跑 impact(项目规矩)**

Run(GitNexus):`impact({target: "login", direction: "upstream"})`、`impact({target: "AppState", direction: "upstream"})`
Expected:记录 blast radius;`AppState` 加字段大概率 HIGH(渲染/装配链)——照规矩先警示用户再改。

- [ ] **Step 2: 写失败测试**（`tests/auth_audit_emit.rs`,镜像 `tests/users_api.rs::test_app`,但 AppState 注入 `InMemoryOutboxRepo` 作 `idm_outbox`,登录后 poll 断言事件)

```rust
// 关键断言(完整 harness 照抄 users_api.rs::test_app,额外:let outbox = Arc::new(InMemoryOutboxRepo::new());
// 装进 AppState.idm_outbox = Some(outbox.clone());登录用真 in-memory idm 服务)。
#[tokio::test]
async fn login_success_emits_login_succeeded() {
    let (app, outbox, creds) = test_app_with_outbox().await; // creds = 预置用户
    let resp = app.oneshot(post_json("/api/v1/public/auth/login", &creds)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = outbox.poll_unpublished(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "auth.login_succeeded");
}

#[tokio::test]
async fn login_bad_password_emits_login_failed_with_reason() {
    let (app, outbox, mut creds) = test_app_with_outbox().await;
    creds.password = "wrong".into();
    let resp = app.oneshot(post_json("/api/v1/public/auth/login", &creds)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "失败仍统一 401(防枚举)");

    let rows = outbox.poll_unpublished(10).await.unwrap();
    assert_eq!(rows[0].event_type, "auth.login_failed");
    assert_eq!(rows[0].payload["failure_reason"], "bad_password");
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cargo test -p baserust --test auth_audit_emit`
Expected: 编译/断言失败(handler 未发射、AppState 无 idm_outbox)。

- [ ] **Step 4: `AppState` 加字段 + 构建**（`src/app/state.rs`)

- struct 加(`state.rs:55-78` 内):
```rust
    /// idm.outbox 写句柄(仅 needs_idm 进程 Some):auth handler 发审计事件用。
    pub idm_outbox: Option<Arc<dyn idm::OutboxRepo>>,
```
- 构建:在 `state.rs:345`(`db_pool: app_pool.or(idm_pool)` **移动 idm_pool 之前**)加:
```rust
        let idm_outbox: Option<Arc<dyn idm::OutboxRepo>> = idm_pool
            .as_ref()
            .map(|p| Arc::new(idm::PgOutboxRepo::new(p.clone())) as Arc<dyn idm::OutboxRepo>);
```
- `Self { ... }` 里加 `idm_outbox,`。测试装配(`tests/*`、`state.rs` 内 Both 装配、`router.rs` 的 api_spec 若构造 AppState)同步补字段。

- [ ] **Step 5: `emit.rs` 助手**

```rust
//! auth 审计事件的组装 + 发射。发射失败绝不阻断认证(fire-and-forget,warn 落日志)。
use std::sync::Arc;

use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infra::client_context::ClientContext;

/// 把事件写进 idm.outbox。`outbox` 为 None(非 idm 进程/测试未装)时静默跳过。
pub async fn emit_auth_event(
    outbox: &Option<Arc<dyn idm::OutboxRepo>>,
    event_type: &str,
    aggregate_id: Uuid,
    data: Value,
) {
    let Some(outbox) = outbox else { return };
    if let Err(e) = outbox.emit(event_type, aggregate_id, data).await {
        tracing::warn!(error = %e, event_type, "auth 审计事件发射失败(不阻断认证)");
    }
}

/// 成功类事件 payload。
pub fn success_data(
    ctx: &ClientContext,
    channel: &str,
    user_id: Uuid,
    session_id: Option<Uuid>,
) -> Value {
    json!({
        "occurred_at": OffsetDateTime::now_utc(),
        "channel": channel, "outcome": "success",
        "user_id": user_id, "session_id": session_id,
        "ip": ctx.ip, "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent, "request_id": ctx.request_id,
    })
}

/// 失败类事件 payload(aggregate_id 用 nil 哨兵,真实线索在 identifier/reason)。
pub fn failure_data(
    ctx: &ClientContext,
    channel: &str,
    identifier: Option<&str>,
    reason: &str,
) -> Value {
    json!({
        "occurred_at": OffsetDateTime::now_utc(),
        "channel": channel, "outcome": "failure",
        "identifier_attempted": identifier, "failure_reason": reason,
        "ip": ctx.ip, "forwarded_chain": ctx.forwarded_chain,
        "user_agent": ctx.user_agent, "request_id": ctx.request_id,
    })
}
```

- [ ] **Step 6: handler 发射**（`src/features/auth/routes.rs`;`login` 全貌,其余同法)

`login`(替换 `routes.rs:102-111`,加 `ctx: ClientContext` 参 + 匹配失败原因):
```rust
pub async fn login(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    req.validate()?;
    let identifier = req.identifier.clone();
    match state.auth.login(req.into()).await {
        Ok(outcome) => {
            emit_auth_event(&state.idm_outbox, "auth.login_succeeded", outcome.user.id,
                success_data(&ctx, "public", outcome.user.id, Some(outcome.session_id))).await;
            let jar = set_auth_cookies(jar, &outcome, state.cookie_secure);
            Ok((jar, Json(outcome.user.into())))
        }
        Err(e) => {
            let reason = match &e {
                AppError::Unauthorized => match idm_reason(&e) { Some(r) => r, None => "bad_password" },
                _ => return Err(e),
            };
            // 注:实际拿 reason 需在 From 转换前读 idm 错误;见下方说明改用直接匹配 idm::IdmError。
            emit_auth_event(&state.idm_outbox, "auth.login_failed", Uuid::nil(),
                failure_data(&ctx, "public", Some(&identifier), reason)).await;
            Err(e)
        }
    }
}
```

> **实现要点(避免上面 `idm_reason` 占位)**:`state.auth.login()` 返回 `Result<_, idm::IdmError>`。在把它 `?`/`From` 成 `AppError` **之前**先 match `idm::IdmError::InvalidCredentials(cf)` 取 `cf`(`CredentialFailure::UnknownUser => "unknown_user"`,`BadPassword => "bad_password"`),发事件后再 `Err(AppError::from(idm_err))`。即 handler 直接持 `idm::IdmError` 分支,不经早期 `?`。login 体重构为:`let idm_err = match state.auth.login(...).await { Ok(o)=>{...return Ok},Err(e)=>e };` 然后 `let reason = match &idm_err { idm::IdmError::InvalidCredentials(CredentialFailure::UnknownUser)=>"unknown_user", idm::IdmError::InvalidCredentials(CredentialFailure::BadPassword)=>"bad_password", _=>return Err(idm_err.into()) };` 发 `auth.login_failed` 后 `Err(idm_err.into())`。

其余 handler 发射点(同法,列全以防漏):
- `register`(routes.rs:82) 成功 → `auth.registered`(user_id + session_id)。
- `admin_login`(routes.rs:244):idm login 成功但无 `admin:login` → 撤会话后发 `auth.admin_access_denied`(channel=admin,failure_reason="no_admin_perm",user_id=outcome.user.id);成功过闸 → `auth.login_succeeded`(channel=admin);login 本身失败 → `auth.login_failed`(channel=admin,同 login 的 reason 匹配)。
- `refresh`(routes.rs:131) 成功 → `auth.refreshed`(user_id + 新 session_id)。
- `logout`(routes.rs:150):`state.auth.logout()` 返回 `Some(session_id)` → `auth.logged_out`(带 session_id);None 不发。
- `logout_all`(routes.rs:167) 成功 → `auth.logout_all`(user_id=user.0.id)。
- `change_password`(routes.rs:225) 成功 → `auth.password_changed`。
- `delete_me`(routes.rs:200) 成功 → `auth.account_deleted`。

`me`/`update_me`/`get_me` 不发(非认证生命周期事件)。

`src/features/auth/mod.rs` 加 `mod emit;` 并在 routes 用 `use super::emit::{emit_auth_event, success_data, failure_data};`。

- [ ] **Step 7: 跑测试确认通过 + detect_changes(项目规矩)**

Run: `cargo test -p baserust --test auth_audit_emit && cargo test -p baserust --lib`
GitNexus: `detect_changes({scope: "compare", base_ref: "master"})` —— 确认只动 auth 发射链 + AppState,无意外 symbol。
Expected: PASS;detect_changes 无越界。

- [ ] **Step 8: Commit**（须先取得许可)

```bash
git add src/app/state.rs src/features/auth
git commit -m "feat(audit): auth handlers emit lifecycle events to idm.outbox"
```

---

### Task 7: 装配 projector + 保留 job（runtime 接线）

**Files:**
- Modify: `/Users/ggg/private/baserust/src/app/state.rs`(`build_auth_event_projector` + `BackgroundTasks` 加字段 + build search-pool clone for read repo;保留 job 句柄)
- Modify: `/Users/ggg/private/baserust/src/app/runtime.rs`(spawn projector + 保留 job)
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/retention.rs`(90 天 DELETE 循环)

**Interfaces:**
- Consumes:`AuthEventProjector`、`PgAuthEventRepo`、`connect_for_schema(Schema::Search)`。
- Produces:`BackgroundTasks.auth_projector: Option<AuthEventProjector>` + `auth_retention: Option<AuthRetentionJob>`;runtime 各 spawn 一条。

- [ ] **Step 1: 保留 job**（`src/features/auth_audit/retention.rs`)

```rust
//! auth_event 90 天保留:周期 DELETE occurred_at < now()-90d。审计 append-only,靠删旧控量。
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use super::repo::AuthEventRepo;

const RETENTION_DAYS: i64 = 90;

pub struct AuthRetentionJob {
    repo: Arc<dyn AuthEventRepo>,
    interval: Duration,
}
impl AuthRetentionJob {
    pub fn new(repo: Arc<dyn AuthEventRepo>) -> Self {
        Self { repo, interval: Duration::from_secs(6 * 3600) } // 每 6h 扫一次
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() { break; }
            let cutoff = OffsetDateTime::now_utc() - time::Duration::days(RETENTION_DAYS);
            match self.repo.delete_older_than(cutoff).await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "auth_event 保留:删除过期行"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "auth_event 保留删除失败,下轮重试"),
            }
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
                changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { break; } }
            }
        }
    }
}
```

- [ ] **Step 2: `build_auth_event_projector` + 保留 job 构建**（`src/app/state.rs`,镜像 `build_projector` `state.rs:409-424`)

```rust
async fn build_auth_event_projector(
    config: &Config,
    needs_idm: bool,
    search_pool: Option<&PgPool>,
) -> anyhow::Result<Option<AuthEventProjector>> {
    let (Some(nats_url), Some(pool)) = (config.nats_url.as_deref().filter(|_| needs_idm), search_pool) else {
        return Ok(None);
    };
    let repo: Arc<dyn AuthEventRepo> = Arc::new(PgAuthEventRepo::new(pool.clone()));
    Ok(Some(AuthEventProjector::connect(nats_url, repo, "auth_event_projector").await?))
}
```
`BackgroundTasks`(`state.rs:80-85`)加:
```rust
    pub auth_projector: Option<AuthEventProjector>,
    pub auth_retention: Option<AuthRetentionJob>,
```
`AppState::new` 尾部构建(注意 `search_pool` 在 `build_projector` 后仍可 `.as_ref()`;保留 job 需自己的 repo,`search_pool.clone()`):
```rust
        let auth_projector = build_auth_event_projector(config, needs_idm, search_pool.as_ref()).await?;
        let auth_retention = search_pool.as_ref().filter(|_| needs_idm).map(|p| {
            AuthRetentionJob::new(Arc::new(PgAuthEventRepo::new(p.clone())) as Arc<dyn AuthEventRepo>)
        });
```
`BackgroundTasks { relays, projector, auth_projector, auth_retention }`。

- [ ] **Step 3: runtime spawn**（`src/app/runtime.rs:54-62` 区)

```rust
    if let Some(p) = bg.auth_projector {
        tokio::spawn(p.run(shutdown_rx.clone()));
    }
    if let Some(j) = bg.auth_retention {
        tokio::spawn(j.run(shutdown_rx.clone()));
    }
```

- [ ] **Step 4: 编译 + 全 lib 测试**

Run: `cargo build && cargo test -p baserust --lib`
Expected: PASS。

- [ ] **Step 5: Commit**（须先取得许可)

```bash
git add src/app/state.rs src/app/runtime.rs src/features/auth_audit/retention.rs src/features/auth_audit/mod.rs
git commit -m "feat(audit): wire auth_event projector + 90d retention job"
```

---

### Task 8: admin 查询端点

**Files:**
- Create: `/Users/ggg/private/baserust/src/features/auth_audit/routes.rs`(两个 handler + query DTO)
- Modify: `/Users/ggg/private/baserust/src/features/auth_audit/mod.rs`(`pub mod routes;` + `pub fn admin_router()`)
- Modify: `/Users/ggg/private/baserust/src/app/state.rs`(`AppState` 加 `auth_events: Option<Arc<dyn AuthEventRepo>>` 读句柄)
- Modify: `/Users/ggg/private/baserust/src/app/router.rs:78-80` + `:183-188`(两处 merge `auth_audit::admin_router()`)
- Modify: `/Users/ggg/private/baserust/src/infra/op_perms.rs`(两行:`list_user_auth_events` / `list_auth_events` → `UsersAdmin`)
- Test: `/Users/ggg/private/baserust/tests/auth_audit_api.rs`(镜像 `users_api.rs::authz_matrix`)

**Interfaces:**
- Consumes:`AuthEventRepo`(读句柄)、`require_scoped(Perm::UsersAdmin)`、`PageQuery`。
- Produces:`GET /admin/users/{id}/auth-events`(`list_user_auth_events`)、`GET /admin/auth-events`(`list_auth_events`)。

- [ ] **Step 1: 写失败测试**（`tests/auth_audit_api.rs`,镜像 users_api authz 矩阵)

```rust
#[tokio::test]
async fn auth_events_authz_matrix() {
    let (app, superadmin, admin) = test_app().await; // 同 users_api::test_app,AppState.auth_events = Some(in-mem)
    // 无 token → 组闸 401
    let r = app.clone().oneshot(Request::get("/api/v1/admin/auth-events").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // admin 有 admin:login 无 users:admin → 403
    let r = app.clone().oneshot(get("/api/v1/admin/auth-events", &admin)).await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // superadmin → 200
    let r = app.oneshot(get("/api/v1/admin/auth-events", &superadmin)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p baserust --test auth_audit_api`
Expected: 404/编译失败(端点不存在)。

- [ ] **Step 3: `AppState` 读句柄 + 构建**（`state.rs`;同 Task 7 的 `search_pool.clone()` 再建一个 `PgAuthEventRepo` 作读句柄;`Mount::App` 无 search → None)

```rust
    pub auth_events: Option<Arc<dyn AuthEventRepo>>,
```
构建(needs_idm + search_pool):`Some(Arc::new(PgAuthEventRepo::new(search_pool_clone)))`;`Self{..}` 补字段;测试装配注入 in-memory。

- [ ] **Step 4: `routes.rs`**（镜像 `users/routes.rs::list_users` 的守卫 + 分页)

```rust
use axum::extract::{Path, Query, State};
use uuid::Uuid;

use crate::app::state::AppState;
use crate::features::auth_audit::{AuthEventQuery, AuthEventRow};
use crate::infra::audit::CurrentUser;
use crate::infra::authz::{Perm, TokenScope};
use crate::infra::error::AppError;
use crate::infra::extract::Json;
use crate::infra::pagination::{Page, PageQuery};

#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct AuthEventFilter {
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub ip: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<time::OffsetDateTime>,
}

#[utoipa::path(get, path = "/users/{id}/auth-events", tag = "users",
    params(PageQuery, AuthEventFilter),
    responses((status = 200, body = Page<AuthEventRow>), (status = 401), (status = 403)))]
pub async fn list_user_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
    Query(filter): Query<AuthEventFilter>,
) -> Result<Json<Page<AuthEventRow>>, AppError> {
    state.policy.require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let repo = state.auth_events.as_ref().ok_or(AppError::NotFound)?;
    let q = AuthEventQuery {
        user_id: Some(id),
        event_type: filter.event_type, outcome: filter.outcome, ip: filter.ip,
        from: filter.from, to: filter.to,
    };
    Ok(Json(repo.list(&q, page.resolve()?).await?))
}

#[utoipa::path(get, path = "/auth-events", tag = "users",
    params(PageQuery, AuthEventFilter),
    responses((status = 200, body = Page<AuthEventRow>), (status = 401), (status = 403)))]
pub async fn list_auth_events(
    State(state): State<AppState>,
    user: CurrentUser,
    scope: TokenScope,
    Query(page): Query<PageQuery>,
    Query(filter): Query<AuthEventFilter>,
) -> Result<Json<Page<AuthEventRow>>, AppError> {
    state.policy.require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;
    let repo = state.auth_events.as_ref().ok_or(AppError::NotFound)?;
    let q = AuthEventQuery {
        user_id: None,
        event_type: filter.event_type, outcome: filter.outcome, ip: filter.ip,
        from: filter.from, to: filter.to,
    };
    Ok(Json(repo.list(&q, page.resolve()?).await?))
}
```

`mod.rs` 加:
```rust
pub mod routes;
use crate::app::state::AppState;
use utoipa_axum::{router::OpenApiRouter, routes};
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_user_auth_events))
        .routes(routes!(routes::list_auth_events))
}
```

- [ ] **Step 5: router 两处 merge + op_perms 两行**

`router.rs:78-80`(`if needs_idm` 内 admin 组)加 `.merge(auth_audit::admin_router())`;`router.rs:183-188`(api_spec)同样加。顶部 `use crate::features::auth_audit;`。
`op_perms.rs` 的 `OP_PERMS` 加两条:
```rust
    OpAuthz { operation_id: "list_user_auth_events", perm: PermReq::All(&[Perm::UsersAdmin]) },
    OpAuthz { operation_id: "list_auth_events", perm: PermReq::All(&[Perm::UsersAdmin]) },
```

- [ ] **Step 6: 跑测试确认通过 + openapi 授权测试**

Run: `cargo test -p baserust --test auth_audit_api && cargo test -p baserust --test openapi_authz_test`
Expected: PASS(authz 矩阵 + openapi 每端点有 perm 行,不 fail-closed)。

- [ ] **Step 7: Commit**（须先取得许可)

```bash
git add src/features/auth_audit src/app/state.rs src/app/router.rs src/infra/op_perms.rs
git commit -m "feat(audit): admin auth-events query endpoints"
```

---

### Task 9: PG 集成 + 保留 e2e（真库 + NATS 全链）

**Files:**
- Create: `/Users/ggg/private/baserust/tests/auth_audit_p1.rs`(镜像 `tests/search_projection_p3.rs`)
- Modify: `/Users/ggg/private/baserust/justfile`(加 `test-authevent` 目标,镜像 `test-search`)

**Interfaces:**
- Consumes:整条 Phase 1 链(handler emit → relay → JetStream → projector → auth_event → 端点/查询)。

- [ ] **Step 1: 写集成测试**（镜像 `search_projection_p3.rs:15-116` 的装配:env → Config::load → connect_for_schema + inline `sqlx::migrate!("migrations/search")` → `AppState::new(Both)` → spawn `bg.relays` + `bg.auth_projector` → 驱动 `state.auth.login(...)`... 但 login 发射在 handler 层,集成测试要走 HTTP,故用 `build_router` + oneshot 打 `/api/v1/public/auth/login`,再 `poll` 直查 `auth_event` 表)

```rust
#![cfg(all(feature = "pg-conformance", feature = "nats-conformance"))]
// 装配同 search_projection_p3(env + 三 schema pool + inline migrate + AppState::new(Both) + spawn relays)。
// 额外 spawn bg.auth_projector。用 build_router 起 app,oneshot 登录,poll auth_event 直到出现 login_succeeded。

#[tokio::test(flavor = "multi_thread")]
async fn login_flows_into_auth_event_and_retention_drops_old() -> anyhow::Result<()> {
    // ... 装配(照抄 search_projection_p3 76-116)+ 预置用户(state.auth.register)...
    // 1) oneshot POST /api/v1/public/auth/login → 200
    // 2) poll: select count(*) from auth_event where event_type='auth.login_succeeded' and user_id=$1 > 0(budget 25s)
    // 3) 保留:手插一行 occurred_at = now()-91d → PgAuthEventRepo::delete_older_than(now()-90d) → 该行没了,新行还在
    Ok(())
}
```

> 完整 body 照 `search_projection_p3.rs` 的 `poll_row` + 装配逐段填(env 变量名同 `SEARCH_DB_*`;登录走 HTTP 而非直调 service,因发射在 handler)。

- [ ] **Step 2: justfile 目标**

```makefile
test-authevent:
    NATS_URL="nats://localhost:4222" cargo test --features pg-conformance,nats-conformance --test auth_audit_p1 -- --nocapture --test-threads=1
```

- [ ] **Step 3: 本地跑(需 PG + NATS)**

Run: `just test-authevent`
Expected: PASS(登录事件落表 + 保留删旧留新)。无本地 PG/NATS 环境则标注跳过,交 CI。

- [ ] **Step 4: Commit**（须先取得许可)

```bash
git add tests/auth_audit_p1.rs justfile
git commit -m "test(audit): auth_event e2e (login -> projection) + retention"
```

---

### Task 10: 切正式 tag + 收尾

- [ ] **Step 1: idm 切 tag**:确认配套 idm 计划已 push `v0.5.0`;把 `baserust/Cargo.toml:12` 从 `path = "../rust-idm"` 改回 `idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.5.0" }`。

- [ ] **Step 2: 全量验证**

Run: `cargo build && cargo test -p baserust --lib && cargo clippy --all-targets -- -D warnings && cargo fmt -- --check`
Expected: 全绿。

- [ ] **Step 3: detect_changes 全量核对**（项目规矩)

GitNexus: `detect_changes({scope: "compare", base_ref: "master"})` —— 确认改动面 = auth 发射链 + auth_audit 模块 + 装配 + 迁移,无越界 symbol。

- [ ] **Step 4: Commit**（须先取得许可)

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): pin idm v0.5.0"
```

---

## Self-Review

- **Spec 覆盖**:发射模型(Task 6)、idm.outbox 复用(Task 6 + idm plan)、projector(Task 5)、auth_event 表(Task 3)、保留(Task 7)、admin 端点(Task 8)、ClientContext/可信代理(Task 2)、幂等 ON CONFLICT(Task 4/5)、集成+保留 e2e(Task 9)—— 对齐 spec「改动面(Phase 1)· baserust 仓」全部条目。Phase 2(富化)/Phase 3(血缘、frontend、按会话撤销)明确不在本计划。
- **决策偏离 spec 并已在 Global Constraints 标注**:普通表 + DELETE(非分区);`event_seq` 单列去重(无 event_source);`ClientContext` 独立提取器;复用 `Perm::UsersAdmin`。
- **类型一致**:`AuthEventRepo`(insert/list/delete_older_than)、`NewAuthEvent`/`AuthEventRow`/`AuthEventQuery`、`AuthEventProjector::{connect,apply_message,run}`、`ClientContext`/`resolve_client_ip`、`AppState.{idm_outbox,auth_events}`、`BackgroundTasks.{auth_projector,auth_retention}` 全计划自洽;消费 idm plan 的 `OutboxRepo::emit`/`InvalidCredentials`/`CredentialFailure`/`AuthOutcome.session_id`/`logout->Option<Uuid>` 已在 Global Constraints + 各 Interfaces 声明。
- **无占位**:除两处显式标注"照抄 search projector run() / search_projection_p3 装配"(有精确 file:line + 明确改点)外,均含真实代码 + 命令 + 预期。projector `run` 与集成测试装配是**逐字复制既有文件**,非占位。
- **项目规矩**:Task 6/10 含 impact/detect_changes 步;未授权不 commit(每 Commit 步标注)。

# Auth 审计日志 Phase 1 — idm crate 改动 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 `rust-idm` crate 加三处小改,让 baserust 的 auth handler 能把全生命周期认证事件写进 `idm.outbox`:暴露 outbox 写入口、`login` 回传失败原因、`AuthOutcome`/`logout` 暴露 `session_id`。

**Architecture:** 纯 Rust,**零迁移**。事件发射本身留在 baserust(handler 层,那里天然有 ip/ua/channel);idm 只补三个消费方拿不到的东西。仓库:`/Users/ggg/private/rust-idm`(独立 repo,`github.com/GGGLHHH/rust-idm`)。

**Tech Stack:** Rust · sqlx 0.9(postgres)· sea-query · async-trait · thiserror · time · uuid v7 · 测试用 in-memory repos + `FakeHasher` + `TestClock`。

## Global Constraints

- **零迁移**:不碰 `rust-idm/migrations/*`(`idm.outbox` 通用表足够;`sessions` 加列是 Phase 3)。
- **防枚举不变**:`login` 现在回传失败原因,但那**只供审计**;HTTP 401 收口由 baserust handler 负责(本 crate 零 HTTP)。
- **Breaking changes**:`AuthOutcome` 加字段、`login` 换错误变体、`logout` 换返回类型 —— 消费方只有 baserust,由其配套计划 `2026-07-08-auth-audit-phase1-app.md` 一并适配后 pin 新 tag。
- **测试范式**:单测走 `#[cfg(test)] mod tests`,in-memory repos + `FakeHasher`;`FakeHasher::hash(p) = "fake$"+p`,`verify(p, phc) = (phc == "fake$"+p)`;`register_input(u)` 的密码是 `"password123"`。
- **提交纪律**:未获用户明确许可**不得** commit / push / 打 tag(Task 5 的 git 步骤须先取得许可)。
- 命令一律在 `/Users/ggg/private/rust-idm` 下跑。

---

### Task 1: `OutboxRepo::emit` —— 暴露 outbox 写入口

**Files:**
- Modify: `/Users/ggg/private/rust-idm/src/repo/mod.rs:303-310`(`OutboxRepo` trait 加 `emit`)
- Modify: `/Users/ggg/private/rust-idm/src/repo/postgres.rs:869-907`(`PgOutboxRepo` impl 加 `emit`)
- Modify: `/Users/ggg/private/rust-idm/src/repo/memory.rs:723-746`(`InMemoryOutboxRepo` impl 加 `emit`)
- Test: `/Users/ggg/private/rust-idm/src/repo/memory.rs`(现有 `mod tests`,line 748+)

**Interfaces:**
- Produces: `OutboxRepo::emit(&self, event_type: &str, aggregate_id: Uuid, payload: serde_json::Value) -> Result<(), IdmError>` —— baserust handler 经 `Arc<dyn idm::OutboxRepo>` 调用,单条非事务 insert(auth 事件不挂 domain 写事务)。

- [ ] **Step 1: 写失败测试**(加到 `memory.rs` 的 `mod tests`,紧接 `outbox_emit_poll_mark_roundtrip` 之后)

```rust
    /// 公共 `OutboxRepo::emit`(auth 事件用):emit → poll 立即可见,FIFO 保序。
    #[tokio::test]
    async fn public_emit_appends_pollable_row() {
        let outbox = InMemoryOutboxRepo::new();
        let agg = Uuid::now_v7();
        outbox
            .emit("auth.login_succeeded", agg, json!({"user_id": agg}))
            .await
            .unwrap();

        let rows = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "auth.login_succeeded");
        assert_eq!(rows[0].aggregate_id, agg);
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p idm --lib repo::memory::tests::public_emit_appends_pollable_row`
Expected: 编译失败 —— `no method named 'emit' found for struct 'InMemoryOutboxRepo'`。

- [ ] **Step 3: trait 加 `emit`**（`src/repo/mod.rs`,`OutboxRepo` 内 `mark_published` 之后）

```rust
    /// **非事务** emit(auth 审计事件用):不挂任何 domain 写事务,单条 insert 到 outbox。
    /// 与 `emit_outbox` 助手(挂调用方 `&mut Transaction`)互补 —— 后者给"领域写 + 事件同事务"的场景,
    /// 本方法给"无领域写的纯审计事件"(登录成功/失败/登出…),由消费方(app handler)在 HTTP 边界调用。
    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), IdmError>;
```

- [ ] **Step 4: `PgOutboxRepo` impl `emit`**（`src/repo/postgres.rs`,`impl OutboxRepo for PgOutboxRepo` 内 `mark_published` 之后;复用文件内已有的 `Query`/`PostgresQueryBuilder`/`AssertSqlSafe`/`Outbox` 导入,同 `emit_outbox`)

```rust
    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError> {
        // 与内部 `emit_outbox` 同一插入形状,但走本 repo 自己的连接池(非事务、单条)。
        let (sql, values) = Query::insert()
            .into_table(Outbox::Table)
            .columns([Outbox::EventType, Outbox::AggregateId, Outbox::Payload])
            .values_panic([
                event_type.to_owned().into(),
                aggregate_id.into(),
                payload.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }
```

- [ ] **Step 5: `InMemoryOutboxRepo` impl `emit`**（`src/repo/memory.rs`,`impl OutboxRepo for InMemoryOutboxRepo` 内 `mark_published` 之后;转调已有私有 `OutboxStore::emit`）

```rust
    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), IdmError> {
        self.inner.emit(event_type, aggregate_id, payload);
        Ok(())
    }
```

- [ ] **Step 6: 跑测试确认通过 + 全 lib 测试**

Run: `cargo test -p idm --lib`
Expected: PASS(新测试 + 原有全绿)。

- [ ] **Step 7: Commit**（须先取得用户许可）

```bash
git -C /Users/ggg/private/rust-idm add src/repo/mod.rs src/repo/postgres.rs src/repo/memory.rs
git -C /Users/ggg/private/rust-idm commit -m "feat(outbox): public non-transactional OutboxRepo::emit for audit events"
```

---

### Task 2: `login` 回传失败原因（防枚举仍由消费方收口）

**Files:**
- Modify: `/Users/ggg/private/rust-idm/src/error.rs`(加 `CredentialFailure` + `IdmError::InvalidCredentials`)
- Modify: `/Users/ggg/private/rust-idm/src/lib.rs:22`(导出 `CredentialFailure`)
- Modify: `/Users/ggg/private/rust-idm/src/service.rs:123-135`(`login` 分支返回原因)
- Test: `/Users/ggg/private/rust-idm/src/service.rs`(现有 `mod tests`,line 395+)

**Interfaces:**
- Produces: `idm::CredentialFailure { UnknownUser, BadPassword }`(pub);`IdmError::InvalidCredentials(CredentialFailure)`。`login` 失败即返此变体(不再返 `Unauthorized`)。消费方 `From<IdmError> for AppError` 须把它映射成 401,并在映射前读出 reason 供审计。

- [ ] **Step 1: 写失败测试**（加到 `service.rs` 的 `mod tests`)

```rust
    #[tokio::test]
    async fn login_reports_distinct_failure_reasons() {
        use crate::error::CredentialFailure;
        use crate::input::LoginInput;

        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        .build();
        svc.register(register_input("alice"), None).await.unwrap();

        // 未知用户
        let unknown = svc
            .login(LoginInput { identifier: "ghost".into(), password: "password123".into() })
            .await
            .unwrap_err();
        assert!(
            matches!(unknown, IdmError::InvalidCredentials(CredentialFailure::UnknownUser)),
            "查无此人应为 UnknownUser"
        );

        // 密码错(alice 存在,密码非 password123)
        let bad = svc
            .login(LoginInput { identifier: "alice".into(), password: "wrong".into() })
            .await
            .unwrap_err();
        assert!(
            matches!(bad, IdmError::InvalidCredentials(CredentialFailure::BadPassword)),
            "密码不匹配应为 BadPassword"
        );
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p idm --lib service::tests::login_reports_distinct_failure_reasons`
Expected: 编译失败 —— `no variant named 'InvalidCredentials'` / `unresolved import 'crate::error::CredentialFailure'`。

- [ ] **Step 3: `error.rs` 加类型**（在 `IdmError` enum 之前加 `CredentialFailure`,并在 enum 内 `Unauthorized` 之后加变体）

```rust
/// 登录凭据失败的具体原因。**仅供审计**——HTTP 层仍统一 401(防枚举由消费方 app 收口)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// identifier 查无存活用户。
    UnknownUser,
    /// 用户存在但密码不匹配。
    BadPassword,
}
```

```rust
    /// 登录凭据无效,携带失败原因**供审计**。消费方**必须**仍统一返 401(防枚举),
    /// 原因只进审计事件、绝不进响应体。
    #[error("invalid credentials")]
    InvalidCredentials(CredentialFailure),
```

（同时更新文件头注释第 4-5 行:防枚举现由消费方保证,原因供审计——把"返回同一个 `Unauthorized`"改述为"返回携带原因的 `InvalidCredentials`,HTTP 收口由 app 统一 401"。）

- [ ] **Step 4: `lib.rs` 导出**（把 `pub use error::IdmError;` 改为)

```rust
pub use error::{CredentialFailure, IdmError};
```

- [ ] **Step 5: `login` 分支返回原因**（`service.rs:123-135`,替换两处 `Err(IdmError::Unauthorized)`;在文件顶部 use 区确认 `CredentialFailure` 可达,如需则 `use crate::error::CredentialFailure;`)

```rust
    pub async fn login(&self, input: LoginInput) -> Result<AuthOutcome, IdmError> {
        let identifier = normalize(&input.identifier);
        let Some(found) = self.inner.users.find_by_identifier(&identifier).await? else {
            return Err(IdmError::InvalidCredentials(CredentialFailure::UnknownUser));
        };
        if !self
            .verify_password(input.password, found.password_hash)
            .await?
        {
            return Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword));
        }
        self.issue_session(&found.user, None).await
    }
```

- [ ] **Step 6: 跑测试确认通过 + 全绿**

Run: `cargo test -p idm --lib`
Expected: PASS。注意 `injected_clock_drives_session_expiry` 仍断言 refresh 过期为 `IdmError::Unauthorized`——未改 refresh,保持绿。

- [ ] **Step 7: Commit**（须先取得许可）

```bash
git -C /Users/ggg/private/rust-idm add src/error.rs src/lib.rs src/service.rs
git -C /Users/ggg/private/rust-idm commit -m "feat(auth): login surfaces UnknownUser vs BadPassword for audit (HTTP 401 unchanged)"
```

---

### Task 3: `AuthOutcome` 暴露 `session_id`

**Files:**
- Modify: `/Users/ggg/private/rust-idm/src/service.rs:20-37`(`AuthOutcome` 加字段)
- Modify: `/Users/ggg/private/rust-idm/src/service.rs:272-278`(`issue_session` 组 `AuthOutcome` 填 `session_id`)
- Test: `/Users/ggg/private/rust-idm/src/service.rs`(`mod tests`)

**Interfaces:**
- Produces: `AuthOutcome.session_id: Uuid`(= 该次登录/注册/刷新新建会话的 `sessions.id`,即 JWT `jti`)。baserust handler 用它记 `login_succeeded`/`registered`/`refreshed` 事件的 `session_id`。

- [ ] **Step 1: 写失败测试**（`service.rs` 的 `mod tests`)

```rust
    #[tokio::test]
    async fn auth_outcome_exposes_rotating_session_id() {
        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        .build();

        let reg = svc.register(register_input("alice"), None).await.unwrap();
        assert!(!reg.session_id.is_nil(), "注册应带非空 session_id");

        // 刷新轮换 → 新会话,session_id 必不同。
        let refreshed = svc.refresh(&reg.refresh_token).await.unwrap();
        assert_ne!(
            reg.session_id, refreshed.session_id,
            "refresh 轮换后应是新的 session_id"
        );
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p idm --lib service::tests::auth_outcome_exposes_rotating_session_id`
Expected: 编译失败 —— `no field 'session_id' on type 'AuthOutcome'`。

- [ ] **Step 3: `AuthOutcome` 加字段**（`service.rs:20-37`,`user` 之后加）

```rust
    /// 本次登录/注册/刷新所建会话的 id(= `sessions.id` = JWT `jti`)。审计/设备管理用。
    pub session_id: Uuid,
```

- [ ] **Step 4: `issue_session` 填字段**（`service.rs:272-278`,`AuthOutcome { ... }` 里加 `session_id: session.id`)

```rust
        Ok(AuthOutcome {
            user: to_view(user, roles),
            session_id: session.id,
            access_token: access,
            refresh_token: refresh,
            access_max_age_secs: self.inner.access_ttl_secs,
            refresh_max_age_secs: self.inner.refresh_ttl_secs,
        })
```

- [ ] **Step 5: 跑测试确认通过 + 全绿**

Run: `cargo test -p idm --lib`
Expected: PASS。

- [ ] **Step 6: Commit**（须先取得许可）

```bash
git -C /Users/ggg/private/rust-idm add src/service.rs
git -C /Users/ggg/private/rust-idm commit -m "feat(auth): expose session_id on AuthOutcome"
```

---

### Task 4: `logout` 返回被撤会话 id

**Files:**
- Modify: `/Users/ggg/private/rust-idm/src/service.rs:168-179`(`logout` 返回 `Option<Uuid>`)
- Test: `/Users/ggg/private/rust-idm/src/service.rs`(`mod tests`)

**Interfaces:**
- Produces: `logout(&self, refresh_token: &str) -> Result<Option<Uuid>, IdmError>` —— `Some(session_id)` = 撤了这个会话;`None` = 无活跃会话(幂等,已登出/无效 token)。baserust handler 用返回值记 `logged_out` 的 `session_id`(None 时不发事件)。

- [ ] **Step 1: 写失败测试**（`service.rs` 的 `mod tests`)

```rust
    #[tokio::test]
    async fn logout_returns_revoked_session_id_then_none() {
        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        .build();

        let reg = svc.register(register_input("alice"), None).await.unwrap();
        let revoked = svc.logout(&reg.refresh_token).await.unwrap();
        assert_eq!(revoked, Some(reg.session_id), "登出应返回被撤会话 id");

        // 幂等:同一 token 再登出 → 无活跃会话 → None。
        assert_eq!(svc.logout(&reg.refresh_token).await.unwrap(), None);
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p idm --lib service::tests::logout_returns_revoked_session_id_then_none`
Expected: 编译失败 —— `expected 'Option<Uuid>', found '()'` / mismatched types。

- [ ] **Step 3: `logout` 改返回**（`service.rs:168-179`)

```rust
    /// 登出:撤销该 refresh 对应的会话,返回被撤会话 id。幂等(找不到活跃会话 → `None`)。
    pub async fn logout(&self, refresh_token: &str) -> Result<Option<Uuid>, IdmError> {
        let hash = token::hash_refresh(refresh_token);
        if let Some(session) = self
            .inner
            .sessions
            .find_active(&hash, self.inner.clock.now())
            .await?
        {
            self.inner.sessions.revoke(session.id).await?;
            return Ok(Some(session.id));
        }
        Ok(None)
    }
```

- [ ] **Step 4: 跑测试确认通过 + 全绿 + clippy**

Run: `cargo test -p idm --lib && cargo clippy -p idm --all-targets`
Expected: PASS,clippy 无 warning。

- [ ] **Step 5: Commit**（须先取得许可）

```bash
git -C /Users/ggg/private/rust-idm add src/service.rs
git -C /Users/ggg/private/rust-idm commit -m "feat(auth): logout returns revoked session id"
```

---

### Task 5: 版本号 + 切 tag(供 baserust pin)

**Files:**
- Modify: `/Users/ggg/private/rust-idm/Cargo.toml`(`version = "0.4.0"` → `"0.5.0"`)

**Interfaces:**
- Produces: git tag `v0.5.0`,baserust `Cargo.toml` 由配套计划改 `idm = { git = "...", tag = "v0.5.0" }` pin。

- [ ] **Step 1: 全套验证**（改动整体 sanity)

Run: `cargo test -p idm && cargo clippy -p idm --all-targets && cargo fmt -p idm -- --check`
Expected: 全 PASS(含 `tests/` 契约测试;PG 契约走 `--features pg-conformance` + 本地 PG,无 PG 环境则只跑 lib + memory 契约)。

- [ ] **Step 2: 升版本号**（`Cargo.toml` `[package]` 段)

```toml
version = "0.5.0"
```

- [ ] **Step 3: Commit + tag + push**（**须先取得用户明确许可**;push tag 是对外可见动作)

```bash
git -C /Users/ggg/private/rust-idm add Cargo.toml
git -C /Users/ggg/private/rust-idm commit -m "chore(release): v0.5.0 — auth audit hooks (emit, login reason, session_id)"
git -C /Users/ggg/private/rust-idm tag v0.5.0
git -C /Users/ggg/private/rust-idm push origin master --tags
```

- [ ] **Step 4: 交接**:通知配套计划 `2026-07-08-auth-audit-phase1-app.md` 可把 baserust 的 `idm` 依赖 pin 到 `tag = "v0.5.0"`。

---

## 联调提示(可选,避免每步 push tag)

`baserust/Cargo.toml` 注释里写明:本地联调时把 `idm = { git = ..., tag = ... }` 临时改成 `idm = { path = "../rust-idm" }`。开发期用 path 依赖跑通 baserust 侧全链,最后再切 tag、pin `v0.5.0`。这样 Task 5 的 push 可以放到两份计划都验证完之后一次做。

## Self-Review

- 覆盖:emit 口(Task1)、失败原因(Task2)、session_id(Task3)、logout 返回(Task4)、release(Task5)—— 对齐 spec「改动面(Phase 1)· rust-idm 仓」三条 + 切 tag。
- 无占位:每步含真实代码 + 精确插入点(file:line)+ 可跑命令 + 预期。
- 类型一致:`OutboxRepo::emit` 签名、`CredentialFailure`/`InvalidCredentials`、`AuthOutcome.session_id: Uuid`、`logout -> Result<Option<Uuid>, IdmError>` 在计划内自洽,消费方契约已在 Interfaces 注明供 app 计划对接。

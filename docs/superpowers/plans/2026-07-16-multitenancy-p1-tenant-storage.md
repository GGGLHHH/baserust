# 多租户 P1:租户存储层 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 idm schema 建 `tenants` / `tenant_members` / `user_active_tenant` 三张表,配一个内存 ↔ PG 双实现的 `TenantRepo`,并用 conformance 对拍钉住两者行为一致 —— **app 侧一个字不改,跑完表在那儿但没人用**。

**Architecture:** 照 `src/features/profile/repo/` 的形状(**不是 widget**)—— 本模块查询全为固定语句,直接 const SQL,不引 sea-query/Iden/COLS。表落 idm schema 是 spec §2 推导出的硬约束:铸 token 的进程(`Mount::Idm`)没有 `app_pool`。

**Tech Stack:** Rust / axum / sqlx(const SQL,非宏)/ async-trait / uuid v7 / time::OffsetDateTime

## Global Constraints

- 设计真源:`docs/superpowers/specs/2026-07-16-multitenancy-design.md`。本计划只实现其 **§3.4 的 P1**。
- 每个改动过 `just check && just test && just lint` —— clippy 是 `-D warnings`,**零警告**。
- 注释用中文,与仓库既有风格一致。
- 业务模块彼此零 import;胶水只在 `src/app/`。**P1 不碰 `src/app/`。**
- 迁移编号:idm 现有最大 **0003** → 新文件是 `0004_add_tenants`。idm 侧命名动词用 `add_*`(不是 app 的 `create_*`)。
- **提交需许可**:未经用户明确同意不要 `git commit`。本计划里的 commit 步骤请先问。

---

## 关键约束:为什么 conformance 不能抄 widget

| | widget / profile | **本计划(tenants)** |
|---|---|---|
| 表在哪个 schema | app | **idm** |
| PG 测试怎么连 | `#[sqlx::test]`(读 `DATABASE_URL` = **app role**) | ❌ 用不了 —— app role 的 `search_path=app`,物理碰不到 idm |
| 照抄哪个 | — | **`tests/search_repo_conformance.rs`**(它也在非 app schema) |
| 隔离 | 每测试一个临时库,自动 drop | **无隔离,表跨测试运行共享** |
| 因此契约必须 | — | ① 每次用全新 `Uuid::now_v7()` 造数据,避免运行间撞行<br>② **绝不断言全表 count / total** |

`tenant_members.user_id references users(id)` 是真 FK(同 schema,合法)⇒ **PG 侧契约必须先插一行 user**,内存侧不需要。故契约函数收 `user_id` 做参数,两个入口各自准备。

---

## File Structure

| 文件 | 责任 |
|---|---|
| `migrations/idm/0004_add_tenants.up.sql` | 建三张表 + 索引 + trigger |
| `migrations/idm/0004_add_tenants.down.sql` | 反序 drop(不删共用函数) |
| `src/features/tenants/mod.rs` | 模块组织 + 导出。**P1 无 router** |
| `src/features/tenants/types.rs` | `TenantStatus` / `TenantRole` 闭集枚举 + `Membership` |
| `src/features/tenants/repo/mod.rs` | `TenantRepo` trait(契约)+ 两实现装配点 |
| `src/features/tenants/repo/memory.rs` | 内存实现(默认,零 DB) |
| `src/features/tenants/repo/postgres.rs` | PG 实现(const SQL) |
| `tests/tenant_repo_conformance.rs` | 契约对拍(内存 + PG 各跑一遍) |
| `justfile:47` | **修改** —— `test-pg` 加 `--test tenant_repo_conformance` |
| `src/features/mod.rs` | **修改** —— `pub mod tenants;` |

---

### Task 1: 迁移 + 类型

**Files:**
- Create: `migrations/idm/0004_add_tenants.up.sql`
- Create: `migrations/idm/0004_add_tenants.down.sql`
- Create: `src/features/tenants/types.rs`
- Create: `src/features/tenants/mod.rs`
- Modify: `src/features/mod.rs`

**Interfaces:**
- Produces: `TenantStatus::{Active, Suspended}`、`TenantRole::{Admin, Member}`(含 `wire()` / `as_db()` / `parse_db()`)、`Membership { tenant_id, name, display_name, role }`

- [ ] **Step 1: 手建迁移文件 —— ⚠️ 不要用 `just migrate-add`**

```bash
ls migrations/idm/          # 确认当前最大编号(应为 0003)
touch migrations/idm/0004_add_tenants.up.sql migrations/idm/0004_add_tenants.down.sql
```

> ⚠️ **`just migrate-add idm add_tenants` 会生成时间戳前缀**(`20260716064856_add_tenants.up.sql`),
> 违反本仓四个 schema 目录无一例外的 4 位顺序编号约定。仓库自己的 skill 早就记了这个坑:
> `.claude/skills/adding-a-feature/SKILL.md:41` —— *"just migrate-add makes a timestamp prefix"
> → "Hand-write `000N_create_<name>s.{up,down}.sql` to keep the sequential 000N convention"*。
>
> **这不是洁癖,是地雷**:时间戳一旦被应用进 `_sqlx_migrations`,将来任何人正常建的
> `0005_xxx`(version `5`)版本号都**低于**已应用的 `20260716064856` → 撞 sqlx 的乱序守卫,
> 把下一个迁移任务直接卡死。
>
> 编号取 `ls migrations/idm/ | tail -1` 的下一个,**别硬套本文的数字**。

- [ ] **Step 2: 写 up 迁移**

写入 `migrations/idm/0004_add_tenants.up.sql`(照 `0002_add_roles.up.sql` 的风格):

```sql
-- 多租户:tenants(实体)+ tenant_members(事实)+ user_active_tenant(状态)。
-- **为什么落 idm 而非 app**:铸 token 的进程(Mount::Idm)没有 app_pool(src/app/state.rs:106),
-- 而「每租户一套角色」要求铸币时就知道是哪个租户 → membership 必须铸币进程够得着。
-- 详见 docs/superpowers/specs/2026-07-16-multitenancy-design.md §2.1。
-- set_updated_at_utc() 已由 0001 在 idm schema 建好,本迁移**同 schema 直接复用**(可达)。

-- ── tenants:客户公司(实体:独立 id + 审计 + 软删)──
create table tenants (
    id           uuid        primary key,
    name         text        not null,            -- 机器码 slug:'acme';代码/seed 引用,唯一稳定
    display_name text        not null,            -- 展示名:'Acme 公司';UI 用,可改
    status       text        not null,            -- 'active' | 'suspended';闭集,见 types.rs::TenantStatus
    created_by   text,
    created_at   timestamptz not null default (now() at time zone 'utc'),
    updated_by   text,
    updated_at   timestamptz not null default (now() at time zone 'utc'),
    deleted_at   timestamptz
);
-- name 唯一:仅对存活行(软删后可复用同名)——镜像 roles_name_alive_uidx
create unique index tenants_name_alive_uidx on tenants (name) where deleted_at is null;
create trigger tenants_set_updated_at
    before update on tenants for each row execute function set_updated_at_utc();
-- status 闭集:DB 侧 check 与应用侧 TenantStatus 枚举双保险
alter table tenants add constraint tenants_status_ck
    check (status in ('active', 'suspended'));

-- ── tenant_members:用户↔租户成员资格(**事实**,非实体)──
-- 一行 = 一句"用户 X 在租户 Y 里是 Z 角色";撤销 = 删行。故不套 base-entity(镜像 user_roles)。
-- **primary key (user_id, tenant_id) 就是 1:N 多租户的全部代价** —— 对照 idm.user_roles 的
-- (user_id, role_id),少的正是 tenant 这一维,所以那张表表达不了"同一人在两租户同角色"。
create table tenant_members (
    user_id    uuid        not null references users (id) on delete cascade,
    tenant_id  uuid        not null references tenants (id),
    role       text        not null,              -- 'admin' | 'member';租户级,见 types.rs::TenantRole
    granted_by text,
    granted_at timestamptz not null default (now() at time zone 'utc'),
    primary key (user_id, tenant_id)
);
create index tenant_members_tenant_id_idx on tenant_members (tenant_id);  -- 按租户反查成员
-- role 闭集:与 TenantRole 枚举双保险。**存 DB 裸值('admin'),不是 claim 的 wire 串('tn:admin')**
alter table tenant_members add constraint tenant_members_role_ck
    check (role in ('admin', 'member'));

-- ── user_active_tenant:当前激活租户(**状态**,一人一行)──
-- 为什么要状态化:idm 的 RoleRepo::roles_for_user 只收 user_id,收不到"哪个租户"
-- → per-request 的租户选择不可能在 idm 内部发生 → 只能落表。见 spec §4.1。
create table user_active_tenant (
    user_id    uuid        primary key references users (id) on delete cascade,
    tenant_id  uuid        not null references tenants (id),
    updated_at timestamptz not null default (now() at time zone 'utc')
);
```

- [ ] **Step 3: 写 down 迁移**

写入 `migrations/idm/0004_add_tenants.down.sql`(照 `0002_add_roles.down.sql`:非首个迁移,**不删共用函数**):

```sql
-- 反序 drop(FK 依赖:user_active_tenant/tenant_members → tenants)。
-- set_updated_at_utc() 是 0001 建的共用函数,**不在此删**。
-- ⚠️ 这不是"回滚",是"重来":drop 掉的成员资格无法恢复。
drop table if exists user_active_tenant;
drop table if exists tenant_members;
drop trigger if exists tenants_set_updated_at on tenants;
drop table if exists tenants;
```

- [ ] **Step 4: 跑迁移验证**

```bash
just up && just migrate-idm
```

Expected: `Applied 4/migrate add tenants`。
失败排查:`just migrate-idm-info` 看状态;`just migrate-idm-revert` 回退重来。

- [ ] **Step 5: 写类型**

创建 `src/features/tenants/types.rs`:

```rust
//! 租户类型。**闭集枚举而非裸 String** —— 照 closed-enums skill:
//! 有限已知取值必须是枚举,否则前端生成的 union 会漂移成 string。

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 租户状态。DB 侧有 `tenants_status_ck` check 约束双保险。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
}

impl TenantStatus {
    /// DB 裸值。
    ///
    /// **没有配套的 `parse_db`** —— P1 从不把 status 读回来:`memberships` 的过滤
    /// (`status = 'active'`)写在 SQL 里,应用侧拿不到也不需要这一列。
    /// 等真有端点要展示租户状态时再加,那时它才不是死代码。
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// **租户级**角色。与平台级的 `infra::authz::RoleName` 是两回事 ——
/// 平台角色骑在租户边界之上,租户角色关在租户边界之内。见 spec §4.5。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Admin,
    Member,
}

impl TenantRole {
    /// DB 裸值(`tenant_members.role` 列 + API 响应)。**不带 `tn:` 前缀。**
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// JWT claim 里的 wire 串。**必须与 `RoleName::TenantAdmin.as_str()` 逐字相等** ——
    /// 这是等式不是巧合(spec §4.5):TenantRoleRepo push 它,Policy 按它查权限。
    /// P2 接线时会有测试钉住这条等式。
    pub fn wire(self) -> &'static str {
        match self {
            Self::Admin => "tn:admin",
            Self::Member => "tn:member",
        }
    }

    /// 从 DB 裸值解析。未知值 → None(fail-closed)。
    pub fn parse_db(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// 一条**有效**成员资格(已过滤停用/软删租户,见 `TenantRepo::memberships` 契约)。
/// 带上 name/display_name 是因为 P2 的 `GET /auth/tenants` 要它们 —— 三张表同 schema,join 合法。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub role: TenantRole,
}

// 刻意**没有** `Tenant` 实体 struct:P1 没有任何方法返回一整个租户
// (`upsert_tenant` 收散参,`memberships` 返回 `Membership`)。
// 等 P2 的 `GET /auth/tenants` 或租户管理端点真要它时再加。
```

- [ ] **Step 6: 写模块入口**

创建 `src/features/tenants/mod.rs`:

```rust
//! 租户:成员资格与激活租户的存储。
//!
//! **住在 idm schema**(不是 app)—— 铸 token 的进程(Mount::Idm)没有 app_pool,
//! 而「每租户一套角色」要求铸币时就知道租户。见 spec §2.1。
//!
//! P1 只有存储层,**无 HTTP 端点** —— 切换/列表端点在 P2,且必须挂 `/auth/` 前缀
//! (nginx 只把 `/{public,frontend,admin}/auth/` 分流进 idm 进程)。

pub mod types;

pub use types::{Membership, TenantRole, TenantStatus};
```

> ⚠️ **本 Task 只有 `types`** —— `repo` 模块 Task 2 才建。现在就写 `pub mod repo;` 会让
> `just check` 直接挂(模块不存在)。Task 2 的 Step 1 会把 `pub mod repo;` 和
> `pub use repo::{..}` 加进来。

修改 `src/features/mod.rs`,按字母序加一行:

```rust
pub mod tenants;
```

- [ ] **Step 7: 编译验证**

```bash
just check && just lint
```

Expected: 零错误、零警告。
若报 `unused` —— P1 阶段类型还没人用,在 `mod.rs` 的 `pub use` 已导出即可满足;若仍报,**不要加 `#[allow(dead_code)]`**,检查是不是漏了 `pub`。

- [ ] **Step 8: 提交(先问用户)**

```bash
git add migrations/idm/0004_add_tenants.up.sql migrations/idm/0004_add_tenants.down.sql \
        src/features/tenants/mod.rs src/features/tenants/types.rs src/features/mod.rs
git commit -m "feat(tenants): add tenants/members/active-tenant tables and types"
```

---

### Task 2: TenantRepo trait + 内存实现 + 内存对拍

**Files:**
- Create: `src/features/tenants/repo/mod.rs`
- Create: `src/features/tenants/repo/memory.rs`
- Create: `tests/tenant_repo_conformance.rs`

**Interfaces:**
- Consumes: Task 1 的 `Membership` / `Tenant` / `TenantRole` / `TenantStatus`
- Produces: `TenantRepo` trait(6 个方法,签名见 Step 1)、`InMemoryTenantRepo::new()`

- [ ] **Step 0: 把 `repo` 挂进模块树**

`src/features/tenants/mod.rs` 加两行(Task 1 刻意没加 —— 那时 `repo/` 还不存在):

```rust
pub mod repo;
pub mod types;

pub use repo::{InMemoryTenantRepo, TenantRepo};   // PgTenantRepo 在 Task 3 加
pub use types::{Membership, TenantRole, TenantStatus};
```

- [ ] **Step 1: 写 trait 契约**

创建 `src/features/tenants/repo/mod.rs`(照 `src/features/profile/repo/mod.rs` —— **const SQL 路子,不引 sea-query**):

```rust
//! 租户仓储:契约 + 两实现装配点。
//! **与 widget 的刻意差异**:本模块查询全为固定语句 → 直接 const SQL(sqlx 静态串),
//! 不引 sea-query/Iden/COLS —— 那套是给动态查询(可选 filter/分页)的,这里没有。
//! (与 profile/repo/mod.rs 同口径。)

mod memory;
// `mod postgres;` 在 Task 3 加 —— 现在加,文件不存在,编译挂。

use async_trait::async_trait;
use uuid::Uuid;

use super::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

pub use memory::InMemoryTenantRepo;

/// 仓储端口。
///
/// **消费方只有三个**,别加第四个的方法(YAGNI):
/// 1. `TenantRoleRepo`(P2,组合根)—— 铸币时读 `memberships` / `active`
/// 2. 切换端点(P2)—— `membership` 校验 + `set_active`
/// 3. `seed::apply`(P2)—— `upsert_tenant` / `upsert_member`
#[async_trait]
pub trait TenantRepo: Send + Sync {
    /// 该用户的全部**有效**成员资格。
    ///
    /// **契约(不可协商)**:恒 join tenants 并过滤 `deleted_at is null and status = 'active'`。
    /// 这样"停用租户"复用「成员被踢,下次 refresh 自动掉出」的同一机制 ——
    /// ≤ IDM_ACCESS_TTL_SECS 内自动失效,无需撤销名单。见 spec §4.4。
    /// 这是 `base_select()` 的同位物:过滤写在契约里,不留给调用方记。
    ///
    /// 顺序:按 `granted_at` 升序(最早加入的在前)—— `TenantRoleRepo` 的
    /// `.or(ms.first())` 回退依赖这个顺序,不是随意的。
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError>;

    /// 单条成员资格校验(切换端点的安全支点)。**同样过滤停用/软删租户。**
    /// 非成员 → `Ok(None)`(路由译 404,不是 403 —— 不泄露该租户存在)。
    async fn membership(&self, user_id: Uuid, tenant_id: Uuid)
        -> Result<Option<Membership>, AppError>;

    /// 当前激活租户 id。未设 → `None`。
    /// **不校验它是否仍是有效成员** —— 那是调用方的事(`TenantRoleRepo` 用
    /// `active.and_then(|t| ms.iter().find(..)).or(ms.first())` 做回退)。
    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError>;

    /// 设置激活租户(upsert)。**不校验成员资格** —— 调用方必须先 `membership()` 校验。
    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError>;

    /// 建/替租户(seed 用)。按 `id` upsert。
    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError>;

    /// 建/替成员资格(seed 用)。按 `(user_id, tenant_id)` upsert。
    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError>;
}
```

- [ ] **Step 2: 写失败的契约测试**

创建 `tests/tenant_repo_conformance.rs`。

**先只写内存入口** —— PG 入口在 Task 3。头注释照 `profile_repo_conformance.rs` 的口径:

```rust
//! TenantRepo 契约一致性:同一批断言对 InMemory 与 Pg 各跑一遍(镜像 widget_repo_conformance)。
//! 钉:memberships 过滤停用/软删租户、granted_at 升序、membership 非成员回 None、
//!    set_active upsert、active 回环。
//!
//! **本测试连 idm role**(非 `#[sqlx::test]` 默认的 app role/`DATABASE_URL`)——
//! tenants 表在 idm schema,app role 的 search_path=app 物理碰不到。形状照
//! `search_repo_conformance.rs`,不是 widget/profile。
//!
//! **无每测试隔离的临时库**(表跨测试运行共享)⇒ 契约里恒用全新 `Uuid::now_v7()` 造数据,
//! 且**绝不断言全表 count/total**。

use baserust::features::tenants::{Membership, TenantRepo, TenantRole, TenantStatus};
use uuid::Uuid;

/// 契约本体。
/// `user_id` 由调用方准备 —— PG 侧 `tenant_members.user_id` 有 FK 到 `users`,
/// 必须先插一行真 user;内存侧没有 FK,随便一个 uuid 即可。
async fn tenant_repo_contract(repo: &dyn TenantRepo, user_id: Uuid) {
    // ── 全新 id:表跨运行共享,不能撞行 ──
    let t_alive = Uuid::now_v7();
    let t_suspended = Uuid::now_v7();

    // 空态:什么都没有
    assert_eq!(repo.memberships(user_id).await.unwrap(), vec![]);
    assert_eq!(repo.active(user_id).await.unwrap(), None);
    assert_eq!(repo.membership(user_id, t_alive).await.unwrap(), None);

    // 建两个租户:一个 active、一个 suspended
    repo.upsert_tenant(t_alive, &format!("acme-{t_alive}"), "Acme", TenantStatus::Active, None)
        .await
        .unwrap();
    repo.upsert_tenant(
        t_suspended,
        &format!("dead-{t_suspended}"),
        "Dead Corp",
        TenantStatus::Suspended,
        None,
    )
    .await
    .unwrap();

    // 两个都加成员
    repo.upsert_member(user_id, t_alive, TenantRole::Admin, None).await.unwrap();
    repo.upsert_member(user_id, t_suspended, TenantRole::Member, None).await.unwrap();

    // ── 契约核心:**停用的租户不出现在 memberships 里** ──
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 1, "suspended 租户必须被过滤掉");
    assert_eq!(ms[0].tenant_id, t_alive);
    assert_eq!(ms[0].display_name, "Acme");
    assert_eq!(ms[0].role, TenantRole::Admin);

    // membership 单查同样过滤
    assert!(repo.membership(user_id, t_alive).await.unwrap().is_some());
    assert_eq!(
        repo.membership(user_id, t_suspended).await.unwrap(),
        None,
        "suspended 租户的 membership 单查也必须回 None"
    );

    // ── set_active / active 回环 ──
    repo.set_active(user_id, t_alive).await.unwrap();
    assert_eq!(repo.active(user_id).await.unwrap(), Some(t_alive));
    // upsert 语义:再设一次覆盖,不是插第二行
    repo.set_active(user_id, t_suspended).await.unwrap();
    assert_eq!(repo.active(user_id).await.unwrap(), Some(t_suspended));

    // ── upsert_member 是替换,不是插重 ──
    repo.upsert_member(user_id, t_alive, TenantRole::Member, None).await.unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 1, "同 (user,tenant) 再 upsert 必须替换而非新增");
    assert_eq!(ms[0].role, TenantRole::Member);

    // ── granted_at 升序(TenantRoleRepo 的 .or(ms.first()) 回退依赖它)──
    let t_second = Uuid::now_v7();
    repo.upsert_tenant(t_second, &format!("beta-{t_second}"), "Beta", TenantStatus::Active, None)
        .await
        .unwrap();
    repo.upsert_member(user_id, t_second, TenantRole::Member, None).await.unwrap();
    let ms = repo.memberships(user_id).await.unwrap();
    assert_eq!(ms.len(), 2);
    assert_eq!(ms[0].tenant_id, t_alive, "先加入的必须在前(granted_at 升序)");
    assert_eq!(ms[1].tenant_id, t_second);
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_tenant_contract() {
    let repo = baserust::features::tenants::InMemoryTenantRepo::new();
    tenant_repo_contract(&repo, Uuid::now_v7()).await;
}
```

- [ ] **Step 3: 跑测试确认它失败**

```bash
cargo test --test tenant_repo_conformance
```

Expected: **编译失败**,报 `InMemoryTenantRepo` 未定义 / `repo` 模块未找到。
这是对的 —— 还没写实现。

- [ ] **Step 4: 写内存实现**

创建 `src/features/tenants/repo/memory.rs`(照 `profile/repo/memory.rs`:`std::sync::Mutex`,不是 tokio):

```rust
//! 内存实现 —— 脚手架默认,无需数据库即可跑通全链路。
//! 镜像 PG 的「memberships 过滤 suspended/软删 + granted_at 升序」语义(conformance 对拍钉住)。

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

#[derive(Clone)]
struct TenantRow {
    name: String,
    display_name: String,
    status: TenantStatus,
    deleted_at: Option<OffsetDateTime>,
}

#[derive(Clone)]
struct MemberRow {
    role: TenantRole,
    granted_at: OffsetDateTime,
}

/// 一把锁覆盖三张表 —— 与 PG 侧同一个原子段口径(镜像 widget 的 MemStore 手法)。
#[derive(Default)]
struct MemStore {
    tenants: HashMap<Uuid, TenantRow>,
    /// (user_id, tenant_id) -> MemberRow
    members: HashMap<(Uuid, Uuid), MemberRow>,
    active: HashMap<Uuid, Uuid>,
}

pub struct InMemoryTenantRepo {
    store: Mutex<MemStore>,
}

impl InMemoryTenantRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(MemStore::default()),
        }
    }
}

impl Default for InMemoryTenantRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStore {
    /// 镜像 PG 的 `join tenants where deleted_at is null and status = 'active'`。
    /// 这是契约,不是优化 —— 见 repo/mod.rs 的 `memberships` doc。
    fn alive_membership(&self, user_id: Uuid, tenant_id: Uuid) -> Option<Membership> {
        let m = self.members.get(&(user_id, tenant_id))?;
        let t = self.tenants.get(&tenant_id)?;
        if t.deleted_at.is_some() || t.status != TenantStatus::Active {
            return None;
        }
        Some(Membership {
            tenant_id,
            name: t.name.clone(),
            display_name: t.display_name.clone(),
            role: m.role,
        })
    }
}

#[async_trait]
impl TenantRepo for InMemoryTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        let mut rows: Vec<(OffsetDateTime, Membership)> = store
            .members
            .iter()
            .filter(|((u, _), _)| *u == user_id)
            .filter_map(|((u, t), m)| store.alive_membership(*u, *t).map(|ms| (m.granted_at, ms)))
            .collect();
        // granted_at 升序;同刻用 tenant_id 兜底,保证确定性(镜像 PG 的 ORDER BY granted_at, tenant_id)
        rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.tenant_id.cmp(&b.1.tenant_id)));
        Ok(rows.into_iter().map(|(_, m)| m).collect())
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        Ok(store.alive_membership(user_id, tenant_id))
    }

    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        Ok(self.store.lock().expect("锁未中毒").active.get(&user_id).copied())
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        self.store.lock().expect("锁未中毒").active.insert(user_id, tenant_id);
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        _by: Option<String>,
    ) -> Result<(), AppError> {
        self.store.lock().expect("锁未中毒").tenants.insert(
            id,
            TenantRow {
                name: name.to_string(),
                display_name: display_name.to_string(),
                status,
                deleted_at: None,
            },
        );
        Ok(())
    }

    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        _by: Option<String>,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 替换语义:granted_at **保留**(镜像 PG 的 on conflict do update 不碰 granted_at)——
        // 否则 memberships 的升序会因改个角色就跳位,.or(ms.first()) 的回退目标跟着变。
        let granted_at = store
            .members
            .get(&(user_id, tenant_id))
            .map(|m| m.granted_at)
            .unwrap_or_else(OffsetDateTime::now_utc);
        store.members.insert((user_id, tenant_id), MemberRow { role, granted_at });
        Ok(())
    }
}
```

- [ ] **Step 5: 跑测试确认通过**

```bash
cargo test --test tenant_repo_conformance
```

Expected: `test memory_satisfies_tenant_contract ... ok`

- [ ] **Step 6: 全量 + lint**

```bash
just check && just test && just lint
```

Expected: 全绿、零警告。

- [ ] **Step 7: 提交(先问用户)**

```bash
git add src/features/tenants/repo/ tests/tenant_repo_conformance.rs
git commit -m "feat(tenants): add TenantRepo port with in-memory impl and contract test"
```

---

### Task 3: PG 实现 + PG 对拍入口 + justfile 接线

**Files:**
- Create: `src/features/tenants/repo/postgres.rs`
- Modify: `src/features/tenants/repo/mod.rs`(挂 `mod postgres;`)
- Modify: `src/features/tenants/mod.rs`(导出 `PgTenantRepo`)
- Modify: `tests/tenant_repo_conformance.rs`(加 PG 入口)
- Modify: `justfile:47`

**Interfaces:**
- Consumes: Task 2 的 `TenantRepo` trait
- Produces: `PgTenantRepo::new(pool: PgPool)`

- [ ] **Step 1: 写 PG 实现**

创建 `src/features/tenants/repo/postgres.rs`(照 `profile/repo/postgres.rs`:const SQL):

```rust
//! Postgres 实现。固定语句 const SQL(sqlx 对 `&'static str` 天然 SqlSafe,无需 AssertSqlSafe)。
//! **连的是 idm role**(search_path=idm),表名无 schema 前缀靠 role 配置落位。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::TenantRepo;
use crate::features::tenants::types::{Membership, TenantRole, TenantStatus};
use crate::infra::error::AppError;

pub struct PgTenantRepo {
    pool: PgPool,
}

impl PgTenantRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// **契约写死在 SQL 里**:下面两条读路径都必须 join tenants + 过滤软删/停用
// (见 repo/mod.rs 的 `memberships` doc)。这是 base_select() 的同位物 ——
// 只有两条读路径,各自内联比抽一个常量更短;第三条读路径出现时再抽。

const MEMBERSHIPS_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role \
     from tenant_members m join tenants t on t.id = m.tenant_id \
     where m.user_id = $1 and t.deleted_at is null and t.status = 'active' \
     order by m.granted_at, m.tenant_id";

const MEMBERSHIP_SQL: &str = "select m.tenant_id, t.name, t.display_name, m.role \
     from tenant_members m join tenants t on t.id = m.tenant_id \
     where m.user_id = $1 and m.tenant_id = $2 \
       and t.deleted_at is null and t.status = 'active'";

const ACTIVE_SQL: &str = "select tenant_id from user_active_tenant where user_id = $1";

const SET_ACTIVE_SQL: &str = "insert into user_active_tenant (user_id, tenant_id) \
     values ($1, $2) \
     on conflict (user_id) do update set \
       tenant_id = excluded.tenant_id, \
       updated_at = (now() at time zone 'utc')";

const UPSERT_TENANT_SQL: &str = "insert into tenants \
     (id, name, display_name, status, created_by, updated_by) \
     values ($1, $2, $3, $4, $5, $5) \
     on conflict (id) do update set \
       name = excluded.name, \
       display_name = excluded.display_name, \
       status = excluded.status, \
       updated_by = excluded.updated_by, \
       deleted_at = null";

/// `granted_at` **不在 do update 集里** —— 改角色不该让成员"重新加入"(会打乱
/// memberships 的升序,进而改变 TenantRoleRepo 的 .or(ms.first()) 回退目标)。
/// 内存实现镜像了这条(memory.rs::upsert_member 保留 granted_at),conformance 钉住。
const UPSERT_MEMBER_SQL: &str = "insert into tenant_members \
     (user_id, tenant_id, role, granted_by) \
     values ($1, $2, $3, $4) \
     on conflict (user_id, tenant_id) do update set \
       role = excluded.role, \
       granted_by = excluded.granted_by";

/// DB 的 role 裸值 → 枚举。**未知值 = 坏数据**(DB 有 check 约束,理论到不了这);
/// 到了就是 Internal,不猜、不降级 —— fail-closed。
fn parse_role(s: &str) -> Result<TenantRole, AppError> {
    TenantRole::parse_db(s).ok_or_else(|| {
        tracing::error!(role = s, "tenant_members.role 出现闭集外的值,check 约束被绕过?");
        AppError::Internal
    })
}

#[async_trait]
impl TenantRepo for PgTenantRepo {
    async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError> {
        let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(MEMBERSHIPS_SQL)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "查 memberships 失败");
                AppError::Internal
            })?;
        rows.into_iter()
            .map(|(tenant_id, name, display_name, role)| {
                Ok(Membership {
                    tenant_id,
                    name,
                    display_name,
                    role: parse_role(&role)?,
                })
            })
            .collect()
    }

    async fn membership(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Membership>, AppError> {
        let row: Option<(Uuid, String, String, String)> = sqlx::query_as(MEMBERSHIP_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "查 membership 失败");
                AppError::Internal
            })?;
        row.map(|(tenant_id, name, display_name, role)| {
            Ok(Membership {
                tenant_id,
                name,
                display_name,
                role: parse_role(&role)?,
            })
        })
        .transpose()
    }

    async fn active(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        let row: Option<(Uuid,)> = sqlx::query_as(ACTIVE_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "查 active tenant 失败");
                AppError::Internal
            })?;
        Ok(row.map(|(id,)| id))
    }

    async fn set_active(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        sqlx::query(SET_ACTIVE_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "设置 active tenant 失败");
                AppError::Internal
            })?;
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        id: Uuid,
        name: &str,
        display_name: &str,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<(), AppError> {
        sqlx::query(UPSERT_TENANT_SQL)
            .bind(id)
            .bind(name)
            .bind(display_name)
            .bind(status.as_db())
            .bind(by)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "upsert tenant 失败");
                AppError::Internal
            })?;
        Ok(())
    }

    async fn upsert_member(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role: TenantRole,
        by: Option<String>,
    ) -> Result<(), AppError> {
        sqlx::query(UPSERT_MEMBER_SQL)
            .bind(user_id)
            .bind(tenant_id)
            .bind(role.as_db())
            .bind(by)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "upsert tenant member 失败");
                AppError::Internal
            })?;
        Ok(())
    }
}
```

- [ ] **Step 2: 挂进模块树**

`src/features/tenants/repo/mod.rs` —— 把 Task 2 留的那句注释换成真代码:

```rust
mod memory;
mod postgres;
// ...
pub use memory::InMemoryTenantRepo;
pub use postgres::PgTenantRepo;
```

`src/features/tenants/mod.rs` —— 补上 `PgTenantRepo`:

```rust
pub use repo::{InMemoryTenantRepo, PgTenantRepo, TenantRepo};
```

- [ ] **Step 3: 加 PG 对拍入口**

追加到 `tests/tenant_repo_conformance.rs` 末尾。**照 `search_repo_conformance.rs`,不是 widget** —— 见本计划顶部的约束表:

```rust
// ── 入口 2:PG(需 --features pg-conformance + idm role 跑着的 pg)──
// **不用 `#[sqlx::test]`**:它建临时库并用 `DATABASE_URL`(`just test-pg` 里连的是 app role),
// 而 tenants 在 idm schema、须以 idm role 连接 —— 显式建池,读 IDM_DATABASE_URL
// (缺省回退本地 compose 的 idm role)。镜像 search_repo_conformance 的 harness。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::tenant_repo_contract;
    use baserust::features::tenants::PgTenantRepo;
    use uuid::Uuid;

    async fn connect() -> sqlx::PgPool {
        let url = std::env::var("IDM_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://idm:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let pool = sqlx::PgPool::connect(&url)
            .await
            .expect("连 idm role 失败(先 `just up` + `just migrate-idm`)");
        sqlx::migrate!("migrations/idm")
            .run(&pool)
            .await
            .expect("跑 migrations/idm 失败(幂等,应可重复跑)");
        pool
    }

    /// `tenant_members.user_id` 有 FK 到 `users` —— PG 侧必须先插一行真 user。
    /// 内存侧没有 FK,故这一步只在 PG 入口。
    async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query("insert into users (id, username, email_verified) values ($1, $2, false)")
            .bind(id)
            .bind(format!("tenant-contract-{id}"))
            .execute(pool)
            .await
            .expect("插测试 user 失败");
        id
    }

    #[tokio::test]
    async fn pg_satisfies_tenant_contract() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool);
        tenant_repo_contract(&repo, user_id).await;
    }

    /// **软删过滤补验(只 PG 侧)** —— 内存契约验不了这一半:`TenantRepo` 没有「软删租户」
    /// 方法(P1 的 seed/切换都用不上,YAGNI 没加),内存的 MemStore 又是私有的,测试造不出
    /// `deleted_at` 状态。PG 侧可以用 raw SQL 直接盖 `deleted_at` 绕过 trait 造出该状态。
    /// (镜像 profile_repo_conformance 用临时 CHECK 约束造写入失败来测回滚的手法 ——
    /// PG-only 的断言允许单独加在 `mod pg` 里,不进共享契约。)
    #[tokio::test]
    async fn pg_memberships_filters_soft_deleted_tenant() {
        let pool = connect().await;
        let user_id = seed_user(&pool).await;
        let repo = PgTenantRepo::new(pool.clone());

        let t = Uuid::now_v7();
        repo.upsert_tenant(
            t,
            &format!("softdel-{t}"),
            "Soon Deleted",
            baserust::features::tenants::TenantStatus::Active,
            None,
        )
        .await
        .unwrap();
        repo.upsert_member(user_id, t, baserust::features::tenants::TenantRole::Admin, None)
            .await
            .unwrap();

        // 软删前:可见
        assert!(repo.membership(user_id, t).await.unwrap().is_some());

        // raw SQL 直接软删(绕过 trait —— trait 刻意没有这个方法)
        sqlx::query("update tenants set deleted_at = (now() at time zone 'utc') where id = $1")
            .bind(t)
            .execute(&pool)
            .await
            .expect("软删 tenant 失败");

        // 软删后:memberships 和 membership 都必须过滤掉它
        assert_eq!(
            repo.membership(user_id, t).await.unwrap(),
            None,
            "软删的租户 membership 单查必须回 None"
        );
        assert!(
            repo.memberships(user_id).await.unwrap().iter().all(|m| m.tenant_id != t),
            "软删的租户不得出现在 memberships 里"
        );
    }
}
```

- [ ] **Step 4: 跑 PG 对拍,预期它会暴露真问题**

```bash
just up && just migrate-idm
IDM_DATABASE_URL="postgres://idm:pwd@localhost:5821/baserust?sslmode=disable" \
  cargo test --features pg-conformance --test tenant_repo_conformance -- --nocapture
```

Expected: **三个测试都过**(`memory_satisfies_tenant_contract` + `pg_satisfies_tenant_contract` + `pg_memberships_filters_soft_deleted_tenant`)。

**若 `seed_user` 报列不存在** —— `users` 表的真实列见 `rust-idm/migrations/0001_init_idm.up.sql:17-35`,以真码为准调整 insert 语句(`username` 非空、`email` 可空)。这一步是本 Task 唯一需要看上游真码的地方。

**若 PG 过而内存挂(或反之)** —— 那正是这套契约存在的意义:两边语义漂了。**别改测试去迁就实现**,先想清楚哪边对。

- [ ] **Step 5: 接进 justfile ⚠️ 最易漏的一步**

`justfile:47` 的 `test-pg` 那行末尾加 `--test tenant_repo_conformance`:

```
test-pg: pg-test-grant
    DATABASE_URL="{{app_db_url}}" cargo test --features pg-conformance --test widget_repo_conformance --test policy_repo_test --test event_bus_conformance --test profile_repo_conformance --test search_repo_conformance --test tenant_repo_conformance -- --nocapture
```

**为什么必须手动加**:cargo 的 `--test` 是白名单。不加 → PG 侧**永远不跑**,而内存侧照常绿 → 正是这套契约要防的漂移,却在 CI 里悄无声息。

`IDM_DATABASE_URL` 不用在 justfile 里设 —— `set dotenv-load := true`(`justfile:2`)会读 `.env`,且测试代码有 localhost 回退。

- [ ] **Step 6: 跑完整 PG 套件**

```bash
just test-pg
```

Expected: 全部 conformance 绿,含新加的 `pg_satisfies_tenant_contract`。

- [ ] **Step 7: 全量验收**

```bash
just check && just test && just lint
```

Expected: 全绿、零警告。

```bash
# 零 env 也能跑(内存模式是默认,不是降级)
env -u APP_DB_HOST -u IDM_DB_HOST cargo test
```

Expected: 绿。

- [ ] **Step 8: 提交(先问用户)**

```bash
git add src/features/tenants/repo/postgres.rs src/features/tenants/repo/mod.rs \
        tests/tenant_repo_conformance.rs justfile
git commit -m "feat(tenants): add Postgres TenantRepo impl and PG conformance entry"
```

---

## P1 出口验收

```bash
just check && just test && just lint      # 全绿、零警告
just test-pg                              # 含 pg_satisfies_tenant_contract
env -u APP_DB_HOST -u IDM_DB_HOST cargo test   # 零 env 内存模式绿
just dev                                  # 起得来 —— P1 没碰 app 侧,行为应与今天完全一致
```

**P1 的成功标准是"什么都没变"** —— 三张表建好了,`TenantRepo` 两个实现对拍一致,但**没有任何代码消费它**。`just dev` 起来的服务与 P1 之前逐字节等价。

这一刀的价值不是功能,是**验证范式**:如果 const SQL 路子、idm role 的对拍 harness、闭集枚举这三样在 P1 走通了,P2–P4 就只是按同一套模式铺开。

## 下一步

P1 落地 + 你实际跑过之后再写 **P2 计划**(铸币与切换:`TenantRoleRepo` 装饰器、`split_tenant`、`AppClaims.tenant`、两个切换端点、seed 接线)。那时你会有真实反馈 —— 比如 const SQL 是不是真的够用、`users` 表的 insert 到底要几列 —— P2 的计划会更准。

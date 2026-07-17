# 多租户设计 · baserust

> 日期:2026-07-16
> 状态:待评审(v2 —— 已过 68 agent 对抗性评审,49 条 findings 全部收编)
> 范围:B2B SaaS 多租户隔离,一个用户可属多个租户并可切换

---

## 0. 给不熟悉多租户的人

**多租户 = 一套部署同时服务多个互不可见的客户公司。**

本仓已有两种"隔离",都**不是**多租户,别混:

1. **模块隔离**:`app` / `idm` / `content` / `search` 四个 PG schema,各自的 role 与 `search_path`,跨 schema join 物理不通(`scripts/initdb/00-roles-schemas.sh:11-25`)。这是**按功能切**的,四个 schema 里装的都是全体客户的数据。
2. **用户级归属**:`Access::{All, Own(uuid)}`(`src/infra/authz.rs:428-463`),已打通到 SQL 层(`src/features/widget/repo/postgres.rs:66-68`)。这是"我只看得见我建的 widget"。

多租户是第三种,与 (2) 的区别是全部要害:

- 归属是**个人**边界 —— `admin` 拿到 `widget:read:all` 就能合法越过它。
- 租户是**组织**边界 —— 租户内的 admin 也有 `read:all`,但那个 all **只能 all 到自己租户为止**。

> **租户边界不是权限能突破的东西,它是权限生效的容器。**
> `read:all` 里的 "all" 到底 all 到哪,就是本设计要回答的唯一问题。

推论:多租户**不能**靠"加一条 `Perm`"实现。它不是一条权限,它是所有权限的作用域上限。

### 0.1 怎么读本文的代码引用

`rust-idm` / `rust-content` **不是本仓的目录**,是 `Cargo.toml:12,17` 的 git tag 依赖。本文引用它们时写 `rust-idm/src/token.rs:19`,要看真码去 `~/.cargo/git/checkouts/` 或本地副本 `/Users/ggg/privte/rust-idm`。`cat rust-idm/...` 在仓库根目录会 no such file。

---

## 1. 已确定的需求

| # | 需求 | 来源 |
|---|---|---|
| R1 | B2B SaaS,多家客户公司,A 公司绝不能看见 B 公司数据 | 用户确认 |
| R2 | **一个用户账号可同时属于多家公司,需要跨公司切换**(真实存在外部顾问/代理商) | 用户二次确认,成本已摊开 |
| R3 | 因 R2,角色是**每租户一套**(同一人在 A 是 admin、在 B 是 user) | R2 的推论 |
| R4 | 租户由平台后台开通;成员由租户内部邀请 | 用户确认 |
| R5 | 首刀范围:`widget` + `content` 上租户轴;`profile` / `search` 不上 | 用户确认 |

### 1.1 「0 租户」是常规状态,不是边角 ⚠️

**R4 是产品意图,不是当前代码的事实。** `POST /api/v1/public/auth/register` 仍在 `public_router()` 里、仍是公开自助注册,本设计**不删它也不闸它**(邀请流在 §7 被推迟)。

⇒ 新注册用户 0 membership ⇒ `TenantClaimsExtender` 返回 `tenant: None` ⇒ **铸出的 token 没有 tenant claim**。

**这是互联网上每一次 register 的必经路径,不是边角。** 因此:

- `AppClaims.tenant: Option<Uuid>` —— **必须是 Option**,照 `token.rs:15` `#[serde(default)] roles` 的既有先例(顺带解决存量 token 无该字段的解码问题)
- `Tenant` extractor 在 claim 无 tenant 时 → **401**,**绝不 nil 兜底**
- 0 租户用户的可达面:**只有 `/me`(返回 `tenant: null`)与 `/auth/tenants`(返回空数组)**。其余全 401
- 成员被踢出唯一租户 → 回到同一状态,复用同一条路径。**不为它加抽象**

---

## 2. 架构:为什么只有一种形状

三个独立设计者(最小改动 / 安全优先 / 拓扑原生)收敛到同一架构。不是偏好,是四条约束把路堵死:

| 约束 | 证据 | 后果 |
|---|---|---|
| `TokenClaims` 无扩展字段 | `rust-idm/src/token.rs:19-29` | tenant **只能夹在 `roles: Vec<String>` 里偷渡** |
| `issue_session` 是私有方法 | `rust-idm/src/service.rs:251` | 无法自己铸 token |
| `LoginInput` 无 tenant 字段 | `rust-idm/src/input.rs:15-18` | "登录到某租户"没有入口 |
| **`Mount::Idm` 进程没有 `app_pool`** | `src/app/state.rs:106`(`needs_app = App\|Both`)、`:125-129` | **租户表必须落 idm schema** |

> 末条的精确表述:`Mount::Idm` 进程有 `idm_pool` **和** `search_pool`(`state.rs:213-217` 同样由 `needs_idm` 门控)。堵死路的不是"只有一个 pool",是**没有 `app_pool`**。

### 2.1 推导链(每一步被前一步逼出)

1. R2 选了 1:N → R3 角色每租户一套
2. 铁律:app 进程只 decode JWT,**roles 在 claim 里**,不查 idm 库
3. ⇒ `roles` 必须在**铸币时**填对 ⇒ 铸币时必须知道是哪个租户
4. ⇒ membership 必须是**铸币进程够得着**的 ⇒ 落 **idm schema**
5. ⇒ 但 `rust-idm` **库**不必知道 —— `RoleRepo` 是 `Arc<dyn RoleRepo>` 注入的(`rust-idm/src/service.rs:89-93`)

**是"每租户一套角色"把租户拽进了 idm 侧,不是租户天生属于 idm。**
(反事实:若选 1:1,租户可纯归 app,app 每请求查一次即可,idm 全程不知情。)

### 2.2 三个层次,别混

| | 是什么 | 谁写 | 知不知道租户 |
|---|---|---|---|
| `rust-idm` crate | 上游通用认证库 | 作为独立通用库维护 | **永远不知道** |
| idm schema / idm 进程 | 部署单元 + PG schema | **baserust 自己** | 知道 |
| app schema / app 进程 | 业务数据与逻辑 | baserust 自己 | 知道 |

**"表住 idm schema" ≠ "租户归 rust-idm 拥有"。** `migrations/idm/0004_*`、`TenantRepo`、`TenantClaimsExtender` 全是 baserust 的代码。
(v0.6.0 给 idm 加的只有 `extra` 字段 + `ClaimsExtender`/`session_owner` 两个通用原语 —— 它们不认识「租户」。)

### 2.3 职责归属判据

> **铸 token 时需要它 → idm 侧。否则 → app 侧。**

| 职责 | 归谁 |
|---|---|
| `tenants` / `tenant_members` / `user_active_tenant` | idm schema,baserust 代码 |
| **平台**角色(`superadmin` / `admin` / `user`) | `idm.user_roles`(现状不动) |
| **租户**角色(`tn:admin` / `tn:member`) | `idm.tenant_members.role` |
| tenant → claim 的翻译 | `src/features/auth/token.rs`(claim 形状的实际所在) |
| `TenantClaimsExtender` / `InProcessTenantDirectory` | `src/app/adapters/`(同时耦合 idm 库与 TenantRepo → 只能在组合根) |
| 数据带 `tenant_id` + 查询层过滤 | app,各 feature 的 repo |
| `Access` 的租户轴 | `src/infra/authz.rs` |
| 租户计费 / 配额 / 设置(未来) | app schema,普通业务模块,照 `adding-a-feature` |

**推论(反直觉,忘了会在生产 500)**:切换租户 / 邀请成员的端点**必须挂 `/auth/` 前缀** —— `deploy/nginx.conf` 里 `^/api/v1/(public|frontend|admin)/auth/` 是唯一把请求分流进 idm 进程的规则,只有那里读得到 `tenant_members`;路由到 app 进程则一签名就 panic(`NoopSigner`,`src/features/auth/token.rs:172-178`)。

### 2.4 租户进 claim 的通道:`idm::ClaimsExtender` ⚠️

**rust-idm 是本项目自己的仓库**(`github.com/GGGLHHH/rust-idm`,本地 `../rust-idm`)。
它的 `src/token.rs` 模块头**自己写着**「app 可注入自定义 claims(tenant_id/权限位…)」——
意图一直在,只是承载它的字段从没建。v0.6.0 补上:

| 新增 | 是什么 |
|---|---|
| `TokenClaims::extra: serde_json::Value` | app 的自定义 claim 载荷。idm **不解释内容**,只负责运到 signer |
| `trait ClaimsExtender` | 可选端口,`issue_session` 里问一次「这人还有什么该进 claim」。**位置与 `roles_for_user` 对称** |
| `AuthServiceBuilder::claims_extender` | 装它。不装 = `extra` 恒 `Null`,行为同 v0.5.0 |

**为什么非得动 idm**:`TokenSigner::sign` 是**同步**的,只拿得到 `&TokenClaims`,不能 await
一次查库 —— 「签发时去查这人的租户」在 signer 里做不到。值必须由 idm 在 `issue_session` 里
先查好递进来。

baserust 侧:`app/adapters/tenant_claims.rs` 的 `TenantClaimsExtender` 实现它,
`auth/token.rs` 的 `sign()` 从 `extra` 读出 → `AppClaims.tenant`。

> ### 曾经的错法(别走回去)
>
> v0.5.0 没有 `extra`,于是 P2 第一版把 tenant 编码成 `t:{uuid}` **塞进 `roles: Vec<String>`**
> 走私,再在 sign 里摘出;租户角色则做成 `RoleName::TenantAdmin`(`tn:admin`)混在同一个数组里。
> 那个设计的连锁代价:
>
> - 租户 id 变成了「角色」⇒ 污染角色闭集,所有按角色判定的授权闸对它**结构性失明**
>   (它们查 `RoleName::is_tenant_scoped()`,而 `t:` 按构造就解析不成 `RoleName`);
> - `tn:admin` 成了 `RoleName` 变体 ⇒ 被 `Policy` 映射成**平台范围**的 `:all` 权限,而
>   `Policy` 没有租户维度 ⇒ **一家 5 人公司的管理员成了全平台 widget/content 的事实管理员**;
> - 泄漏路径要靠三处手写 `starts_with("t:")` 各自记得堵,`/auth/me` 每次多一次三表 join;
> - 为了看住上面这些,又长出三层防护闸 + 三个只为看守它们而存在的测试。
>
> 补上 `extra` 之后,以上**全部删除**(净 −174 行)。教训不是「哨兵写错了」,而是:
> **绕过自己能改的库,代价会连锁**。

---

## 3. 数据模型

### 3.1 idm schema(新)

```sql
-- migrations/idm/0004_add_tenants.up.sql
create table tenants (
  id uuid primary key,
  name text not null,                      -- 机器码 slug;对外 DTO 字段名也叫 name,不叫 slug
  display_name text not null,
  status text not null,                    -- 'active' | 'suspended',闭集枚举,照 closed-enums skill
  created_by text, created_at timestamptz not null default now(),
  updated_by text, updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
create unique index tenants_name_alive_uidx on tenants (name) where deleted_at is null;

create table tenant_members (
  user_id    uuid not null references users(id) on delete cascade,
  tenant_id  uuid not null references tenants(id),
  role       text not null,                -- 'admin' | 'member';与 RoleName::TenantAdmin/TenantMember 同源,见 §4.2
  seq        uuid not null,                -- Uuid::now_v7();**排序键**,见下
  granted_by text,
  granted_at timestamptz not null default now(),  -- 审计:何时加入。**不是排序键**
  primary key (user_id, tenant_id)         -- ← R2 的全部代价,就是这一维
);
-- role 取值约束:DB 侧 check + 应用侧 TenantRole enum 双保险(§4.2)
alter table tenant_members add constraint tenant_members_role_ck
  check (role in ('admin', 'member'));

create table user_active_tenant (
  user_id    uuid primary key references users(id) on delete cascade,
  tenant_id  uuid not null references tenants(id),   -- 有 FK:与 tenant_members 同 schema、同 role,理由同
  updated_at timestamptz not null default now()
);
```

对照 `idm.user_roles primary key (user_id, role_id)`(`rust-idm/migrations/0002_add_roles.up.sql:24-30`)—— 少的就是 `tenant_id`。`tenant_members` 把它补回来,**补在 baserust 自己的 migration 里,不动上游**。
(注:baserust 的 `migrations/idm/0001-0003` 是从 rust-idm 逐份拷来的;**0004 是本仓自有、不回填上游** —— 这条隐含约定自此分叉,迁移文件里已写明。)

三张表同 schema、同 role、同 pool → `TenantRepo` 内部 join 合法,**不违反禁跨 schema join**。

> ⚠️ **`seq` 是排序键,`granted_at` 只是审计时间戳 —— 两个职责刻意分离。**
> 别拿 `granted_at` 排序:它是墙钟,既会被 NTP 回拨、也可能在同一微秒内打平,而这个顺序决定
> §4.1 的 `.or(ms.first())` 回退目标,即**用户默认落进哪家公司**。`seq` 是应用侧
> `Uuid::now_v7()`,照搬 `widgets.id` 的既有范式(`widget/repo/postgres.rs` 注释原文:
> 「v7 单列严格全序」),uuid crate 保证同进程内按创建序单调 —— 不打平、不受 NTP 影响。
> `upsert_member` 改角色时 **`seq` / `granted_at` / `granted_by` 三者全冻结**:它们共同描述
> 「何时、被谁加进来」这一次事件,改角色不让它重新发生。
>
> **本表的时间戳用裸 `now()`,不用全仓其他迁移的 `(now() at time zone 'utc')`** —— 后者是双重
> 转换(timestamptz → naive → 按 session TimeZone 解释回来),而 timestamptz 本就与时区无关。
>
> **但它在本仓不是 bug**:sqlx 在每条连接的 startup packet 里无条件硬编码 `TimeZone=UTC`
> (`sqlx-postgres/src/connection/establish.rs:33`),该 packet 是 `PGC_S_CLIENT`,优先级压过
> `ALTER ROLE SET` 与 `postgresql.conf`。app / seed / migrate / 测试全经 sqlx ⇒ 老写法恒等于 `now()`。
> 实测(同一时刻,`alter role idm set timezone='Asia/Shanghai'` 之下):
> `psql: TimeZone=Asia/Shanghai, source=user, 偏移 8:00:00` vs `sqlx: TimeZone=UTC, source=client, 偏移 0`。
>
> 裸 `now()` 只是少绕一圈 + 不把正确性押在「写入方恰好是 sqlx」上(非 sqlx 的写入方 —— 手工 psql
> 运维、外部 ETL、换驱动 —— 会真的偏 8 小时)。**其余 11 个迁移的老写法是可读性债,不是正确性
> bug,该单独 cleanup、不必急。**

### 3.2 app schema

**编号是 0005,不是 0004** —— `migrations/app/0004_create_outbox` 已占用。新迁移编号一律取 `ls migrations/<schema>/ | tail -1` 的下一个,**别照抄本文的数字**。两个 schema 的编号各自独立,不要求对齐。

> ⚠️ **手写文件名,不要用 `just migrate-add`** —— 它生成时间戳前缀,违反本仓的 4 位顺序编号约定
> (`.claude/skills/adding-a-feature/SKILL.md:41` 已记录此坑)。时间戳一旦应用进 `_sqlx_migrations`,
> 后续正常建的顺序编号迁移版本号会**低于**它 → 撞 sqlx 乱序守卫,卡死下一个迁移。
> P1 实施时真踩到了这个坑,已修。

```sql
-- migrations/app/0005_widgets_tenant.up.sql —— 只加列,可空、无 default
alter table widgets add column tenant_id uuid;
```

```sql
-- migrations/app/0006_widgets_tenant_enforce.up.sql —— backfill 之后才跑(见 §3.3)
alter table widgets alter column tenant_id set not null;
create index widgets_tenant_alive_idx on widgets (tenant_id) where deleted_at is null;
```

裸 uuid、**无 FK**(跨 schema,照 `migrations/app/0003_create_profiles.up.sql:7-8` 已注明为什么禁 FK)。

> **绝不给 `tenant_id` 加 `default`。** 理由两条:
> (a) `add column ... not null default 'X'` 在 PG 里的语义就是**一次写进迁移的全量 backfill** —— 正是 §3.3 禁止的"迁移替你猜"。
> (b) 更隐蔽:本仓 SQL 全是 sea-query 拼串、**零条 `sqlx::query!` 宏**,INSERT 漏写 tenant_id 列**没有任何编译期检查**。留着 default 就是给"INSERT 漏列"发的静默通行证 —— §5.2 承诺的"漏传编译不过"只保住函数签名,保不住签名到 SQL 之间那一段。

`content.tenant_id` 已存在且 `not null`(`migrations/content/0001_init_content.up.sql:18`),只需收编,无需 DDL。

### 3.3 迁移与 backfill 顺序(钉死,反了即漏洞)

**先真值来源 → 再 backfill → 再收紧约束 → 最后才开读侧闸。**

反了的话,攻击者今天用 `content` 那个可伪造的 `tenant_id` 字段预植的行,会在开闸瞬间落进受害租户。

| 步 | 动作 | 身份 |
|---|---|---|
| 1 | `migrations/idm/0004` 建三张表 | idm role |
| 2 | seed 灌 `[[tenants]]` + membership | idm role |
| 3 | `migrations/app/0005` 加可空列 | app role |
| 4 | **手工 backfill** | **见下** |
| 5 | `migrations/app/0006` set not null + 建索引 | app role |
| 6 | 开读侧闸(§5 的代码全上) | — |

**第 4 步的执行身份必须写实**:`app` role 的 `search_path` 只有 `app`,读不到 `idm.tenant_members` —— 跨 schema 映射对它同样不可达。所以 backfill **不是**一句能自动算出归属的 SQL,而是:

```sql
-- 由 DBA/超级用户执行,或临时 role 同时授 app+idm 的 USAGE。
-- 存量 widget 全部归 demo 租户 —— 这是一个人工决定,不是算出来的。
update app.widgets set tenant_id = '<seed.toml 里 [[tenants]] 声明的那个 id>' where tenant_id is null;
```

**存量 backfill 不写进迁移。** owner→tenant 映射跨 schema 拿不到,迁移替你猜 = 把数据搬进错租户。

**回滚**:down 迁移照仓库既有范式就是 drop(`migrations/app/0003_create_profiles.down.sql` = drop table;`migrations/idm/0002_add_roles.down.sql` = 反序 drop 并注明共用函数留给 0001)。

- `idm/0004.down.sql`:按 `user_active_tenant` → `tenant_members` → `tenants` 反序 drop(FK 依赖顺序)
- `app/0005.down.sql`:`alter table widgets drop column tenant_id`
- **明写:down 是单向销毁。** app 侧 drop column 会丢掉第 4 步手工 backfill 的全部结果,重新 up 之后必须重跑 backfill。这不是"回滚",是"重来"。

### 3.4 实施阶段 ⚠️ 最重要的一节

**每阶段以 `just check && just test && just lint` 全绿 + 可独立 merge 为出口。**

| 阶段 | 内容 | 出口 | 约 |
|---|---|---|---|
| **P1 存储** | `migrations/idm/0004` + `src/features/tenants/`(types / repo trait / memory / postgres)+ repo conformance 测试。**app 侧零改动** | `just test` 绿;新表存在但无人读 | 400 行 |
| **P2 铸币与切换** | idm v0.6.0(`extra` + `ClaimsExtender` + `session_owner`)、`TenantClaimsExtender`、`AppClaims.tenant: Option<Uuid>`、`auth/port.rs` 的 `TenantDirectory` + 组合根适配器、seed 灌 dev 租户、`GET /auth/tenants`、`PUT /auth/active-tenant`、审计事件、`tests/tenant_api.rs` | 绿,**可部署**。tenant 进了 claim,但没人拿它过滤 —— 行为与今天完全一致 | 400 行 |
| **P3 数据落列** ✅ | `migrations/app/0005`(可空)→ 手工 backfill → `0006`(not null + 索引 + **唯一约束收进租户**)。 | 绿。数据带上了标签,闸还没开 | 200 行 |
| **P4 开闸** ✅ | `Access` 重塑 + `data_access` / `row_access` + `WidgetRepo` 复合键 + 10 个 handler + SSE(逐帧租户过滤 + `exp` 截流)+ `WidgetEvent` 带 tenant + content 收编 + profile `row_access` + `NO_TENANT` 头像 | 绿。**隔离生效** | **~900 行** |
| **P5 验收** ✅ | `tests/tenant_isolation_api.rs`(黑盒端到端)+ conformance 的 isolation 契约(repo 层,memory↔PG)+ 各测试探针带 tenant | 绿 | 300 行 |

> **P4 是原子的,切不开,是整个工程的风险集中点。**
> `Access` 字段变私有 + `data_access` 改签名 + `WidgetRepo` 7 个方法加首参 —— 这三处一动,widget / content / profile / tests 同时编译失败。别指望中途 `just check` 变绿,写完 P4 全部才会绿。
> 但它是 ~900 行,不是 2500 —— P1/P2/P3/P5 都已各自绿过。**不要试图把 2500 行一次性写完。**

> ### 实施踩到的两个坑(spec 原本没警告)
>
> **① 唯一约束是「加 tenant_id 列」最容易漏的一维。** `widgets_name_unique_alive` 原本是
> `unique (name)` **全局唯一**。上租户轴后必须变成 `unique (tenant_id, name)` —— 否则两家
> 公司不能有同名 widget(功能 bug),更糟的是它成了个**跨租户存在性预言机**:试名字看
> 201/409 就能枚举别家有什么。**通则:租户轴上的每个唯一约束都要把 tenant_id 加进去。**
> (子表 `widget_tags (widget_id, label)` 不用改 —— widget_id 已传递性属于某租户。)已在 `0006`。
>
> **② PG 的 `COLS`(SELECT 列)与 `Widget` 结构体必须同步 —— 而编译期查不出。** 给 `Widget`
> 加 `tenant_id` 字段后,内存实现的 `to_widget()` 手写拷贝,编译器逼你加;但 PG 靠
> `FromRow` **按列名运行期匹配**,`COLS` 少一列 = `no column found for name: tenant_id`,
> 只有 PG conformance 跑起来才炸(sea-query 拼串,非 `sqlx::query!` 宏,无编译期检查)。
> **这正是 conformance 内存↔PG 对拍存在的理由:内存绿 ≠ PG 绿。**
>
> ### 隔离的防御是三层正交的,不是一个测试
>
> 「A 永远看不到 B」是全称否定,测试证不完。实际的防御:
> - **类型系统**:`WidgetRepo` 每个方法 `TenantId` 非 Option 首参 —— handler 想「查所有租户」
>   不可表达,且租户唯一来源是 `Tenant` extractor(已验签 claim)。漏洞**编译期**就写不出。
> - **conformance isolation 契约**(repo 层,memory↔PG):守 repo 的租户过滤逻辑。repo 变异 → 红。
> - **黑盒 `tenant_isolation_api`**(整条链):守 extractor 装了、claim 进了 repo、0 租户 401。
> - 单个 repo 变异**不会**让黑盒红 —— 因为 handler 的 `allows_created_by` 是纵深第二道闸兜住了。
>   这是纵深的**特征**不是缺陷:黑盒证明「至少一道在」,conformance 证明「repo 那道对」,
>   两者缺一不可。

---

## 4. Token 与切换

### 4.1 租户怎么进 claim

`TenantClaimsExtender`(组合根)在铸币时被问一次,返回 `{"tenant": "<uuid>"}`:

```rust
// src/app/adapters/tenant_claims.rs
#[async_trait]
impl ClaimsExtender for TenantClaimsExtender {
    async fn extra_for(&self, user_id: Uuid) -> Result<serde_json::Value, IdmError> {
        // memberships 已过滤停用/软删租户(§4.4)、按 seq 升序。
        // 失败不吞:租户读不到就该让登录炸,而不是静默降级成 0 租户。
        let ms = self.tenants.memberships(user_id).await.map_err(..)?;
        // 「active 未设」与「active 指向已失效租户」被 memberships 坍缩成同一结果
        // (没有任何 is_active)⇒ 两者都回退到最早加入的那个。
        // 0 租户(register 的常规出口,§1.1)→ None → claim 无 tenant。
        let tenant = ms.iter().find(|m| m.is_active).or(ms.first()).map(|m| m.tenant_id);
        serde_json::to_value(ExtraClaims { tenant })
    }
}
```

**为什么租户选择必须状态化**:`extra_for` 只收 `user_id`,收不到「哪个租户」—— per-request
的选择不可能在铸币时凭空发生,只能落 `user_active_tenant` 表。register / login / refresh
三个入口全部汇流到 `issue_session`,它每次都重问一遍 extender ⇒「改 active 表 + 调 `refresh()`」
就是切租户。

**它只在铸币路径上跑**:`me()` / `update_me()` 不碰 `ClaimsExtender`。这是重点不是巧合 ——
`/auth/me` 是全站最热的认证端点,不该为一个它根本不用的租户 id 去 join 三张表。
(旧的 `RoleRepo` 装饰器方案做不到:`roles_for_user` 被这三条路径共用。)

### 4.2 `sign()` 读 `extra` ⚠️

```rust
// src/features/auth/token.rs
fn extra_claims(extra: &serde_json::Value) -> Result<ExtraClaims, IdmError> {
    if extra.is_null() {
        return Ok(ExtraClaims::default());   // 没装 extender —— 合法,行为同 v0.5.0
    }
    // **非 Null 但形状不对 = wiring bug ⇒ 拒签,绝不 unwrap_or_default()**。
    // 静默签出一枚少了 tenant 的 token = 静默降权/越权:没有异常、没有日志,
    // 只有用户看见了不该看见的数据。宁可让登录炸。
    serde_json::from_value(extra.clone()).map_err(..)
}
```

`ExtraClaims` 是**强类型**的(生产方与消费方都在本仓,idm 只负责运输)。
加新的自定义 claim = 在 `ExtraClaims` 加字段 + 在对应 extender 里填。

**roles 不再兼职**:它只装平台角色闭集。`token.rs` 有一条回归测试钉死
`a_role_named_like_the_old_sentinel_is_just_a_role` —— 叫 `t:{uuid}` 的角色现在只是个
名字古怪的普通角色,不是租户。

### 4.3 第二条铸币路径:`mint_scoped` ⚠️

`AppTokenSigner::mint_scoped`(`src/features/auth/token.rs:58`)是 **pub 的第二条铸币路径,不经过 `sign()`**,直接手搓 `AppClaims`,且第三个参数就是 `roles: Vec<String>`。

**决定**:tenant 只能是 `mint_scoped` 的一个**独立强类型入参**:

```rust
pub fn mint_scoped(user_id: Uuid, username: &str, roles: Vec<String>,
                   tenant: Option<TenantId>,          // ← 独立入参,不从 roles 解析
                   scope: Vec<Perm>, ttl: Duration) -> Result<String, AppError>
```

`mint_scoped` **不经 idm 的 `issue_session`,故也不经 `ClaimsExtender`** —— tenant 由调用方作为独立入参直接给。

### 4.4 `TenantRepo::memberships` 的契约 ⚠️

**停用/软删租户必须真的切断访问。** `memberships` 是 `base_select()` 的同位物,把过滤写死在契约里:

```rust
/// 该用户的全部**有效**成员资格,含「哪条是当前激活的」(`Membership::is_active`)。
/// 恒 join tenants 并过滤 `t.deleted_at is null and t.status = 'active'` ——
/// 三张表同 schema,内部 join 合法(§3.1)。
/// 这样"停用租户"复用「成员被踢,下次 refresh 自动掉出」的同一机制:
/// ≤ IDM_ACCESS_TTL_SECS 内自动失效,无需撤销名单。
/// 顺序:按 `seq` 升序(最早加入的在前)—— §4.1 的 `.or(ms.first())` 回退依赖它。
async fn memberships(&self, user_id: Uuid) -> Result<Vec<Membership>, AppError>;
```

**`active` 刻意不是独立方法。** 它由同一条查询 `left join user_active_tenant` 算成每条的
`is_active`。理由:两个已知消费方(§4.1 铸币、§4.9 租户列表)都同时要「成员资格 + 谁激活」,
**从没有单独查 active 的场景** —— 拆开只会让每次铸币多一次往返,且两次读非同一快照
(并发 set_active 时铸币路径会读到不一致的组合)。

「active 未设」与「active 指向一个已失效(停用/软删/已退出)的租户」**刻意坍缩**成同一结果:
没有任何一条 `is_active = true`。§4.1 的回退逻辑对两者处理本就相同(都退到 `.first()`)。

§8 加用例:停用租户后 refresh → 该 tenant 不再进 claim(若是唯一租户则进 §1.1 的 0 租户态)。

### 4.5 两级角色是**两个类型**,不是一个枚举的两组变体 ⚠️

| | 平台角色 | 租户角色 |
|---|---|---|
| 类型 | `infra::authz::RoleName` | `features::tenants::TenantRole` |
| 值 | `superadmin` / `admin` / `user` | `admin` / `member`(DB 裸值) |
| 存哪 | `idm.user_roles` | `idm.tenant_members.role` |
| 怎么获得 | 后台 `PUT /users/{id}/roles` | 成员资格 |
| 进 claim 吗 | 进 `roles` | **P2 不进** —— 见下 |
| 映射成 `Perm` 吗 | 是(`Policy`) | **否** |

**`TenantRole` 绝不能是 `RoleName` 的变体。** 试过一次,后果是本设计最严重的一个洞:
`Policy` 是平台级的、没有租户维度,于是 `tn:admin` 被映射成**平台范围**的
`WidgetReadAll` / `ContentWriteAll` / `ContentDelete`…—— 而 P4 的 repo 租户过滤还没落地,
那些 `:all` 就是字面意思。**当上一家 5 人小公司的管理员 = 成为全平台 widget/content
的事实管理员**,正好与「A 公司不能看 B 公司数据」相反。

当时代码里写了句注释「P4 之前不要给任何人授租户角色」—— 没有任何东西执行它:
`TenantRoleRepo` 见到一行 `tenant_members` 就自动把 `tn:admin` 签进 claim。而三层防护闸
(seed 只灌 PLATFORM / list_roles 过滤 / role_names_by_ids 拒绝)守的**全是授予路径**,
claim 是从 `tenant_members` 来的,根本不过那三道闸。

两个类型让这件事**编译不过**。随之删除:`RoleName::{TenantAdmin,TenantMember}`、
`PLATFORM`/`ALL` 分裂、`is_tenant_scoped()`、`TenantRole::claim()`、`tn:` 线上串、
三层防护闸、以及三个只为看守它们而存在的测试。

`RoleName::ALL` 恢复成**一个**常量、三个变体。它的双重身份(可授予目录 **且** 权限映射源)
是对的 —— **前提是它只装平台角色**:能被授予的 ⟺ 能映射到平台权限的。

**P2 的 claim 里没有租户角色**:今天没有任何消费方。「我在这家公司能干什么」是权限问题,
P4/P5 让 `/permissions/me` 按租户回答才是对的形状,不是往 claim 里塞一个角色串。

### 4.6 角色定义保持全局(Clerk 模型)

**定义全局、授予按租户。不做每租户自定义角色。**

理由:`role_permissions` 主键 `(role_name, permission)` 无 tenant 列 → 改它 = 迁移改主键 + `policy_repo.rs` 两个函数全改 + `Policy::from_roles` 签名改 + `Policy::by_role` 键变 `(tenant, role)` + **38 处 `require_scoped` 全部改签名**;且 `Arc<Policy>` 在 `router.rs:95` 被烘焙进 `from_fn_with_state`,per-request 换 policy 本就不可能;更要命的是每租户自定义 ⇒ app 无法静态解析 role→perm ⇒ 必须把 permission 塞 claim ⇒ **撞 4KB cookie 上限**(Keycloak 真实案例:~200 个 role claim 撑爆 8KB header,失败模式是 431 或静默截断)。

⇒ 选全局定义:`policy_repo.rs` **零改动**,`migrations/app/0002` 零改动,38 处 RBAC 闸零改动。

**触发升级**:客户要自定义角色时,先问能不能用"预置角色改显示名"糊过去。

### 4.7 token 里只放当前激活租户的角色

不放全部租户的角色映射。Auth0 / WorkOS / Clerk 三家一致。

把全 membership 塞 token、让后端按请求选 = **把签发方的 membership 校验下放到每个端点,漏一次即越权**。

### 4.8 没有「泄漏收口点」了

旧设计需要在两处显式剥离哨兵(`sign()` 一处、`me()` → `UserResponse` 一处),因为
`AuthService` 用同一个 `RoleRepo` 服务两条路径,而只有一条经过 `sign()`。

**现在不需要**:租户走 `extra` → `AppClaims.tenant`,`roles` 从头到尾只装平台角色。
没有东西可泄漏,`strip_tenant_sentinel` 及其测试已删除。

这是「正确的位置」自带的好处 —— 不是修出来的。

### 4.9 切换流程

两个端点,**必须落 `/api/v1/frontend/auth/` 前缀**(理由见 2.3):

- `GET /api/v1/frontend/auth/tenants` → `[{id, name, display_name, role, active}]`
  (`name` 与 §3.1 的列名一致,**不叫 slug**;`role` 取值 `"admin" | "member"`,是 DB 里的裸值不是 `tn:` 前缀的 wire 串)
- `PUT /api/v1/frontend/auth/active-tenant` body `{tenant_id}` → 200 `AuthResponse` + set-cookie
  (PUT 全量替换,禁 PATCH,照 API 约定)

**这两个端点写在 `src/features/auth/routes.rs` 里**,不新开模块 —— 因为 `set_auth_cookies`(`routes.rs:47`)是**模块私有 fn**,新模块调不到。(备选:提为 `pub(crate)`。但切租户本就是认证域动作,写在 auth 里更诚实。)

流程:

1. `CurrentUser` → 无/非法 access token → **401**
2. **先取 refresh cookie**(无 → 401)—— **副作用前置检查**:必须在 `set_active` **之前**取,否则会出现"active 改了但 token 没换"的不一致
3. `tenants.membership(user.id, tenant_id)` 查 idm schema —— **非成员 → 404**(不是 403,不泄露该租户存在)
   > **这是整个方案的安全支点**:客户端说的 tenant 只是一个**请求**,不是断言;它只到达签发方(idm 进程)且经 membership 校验;资源 API 永远只读已签名的 claim,**绝不从 header / query / body 读 active tenant**。
4. `tenants.set_active(user.id, tenant_id)` upsert `user_active_tenant`
5. `state.auth.refresh(&refresh)`:idm 撤旧 session → 建新 session(**新 jti**)→ 重问一遍 `TenantClaimsExtender`(此时读到的 active 已是新租户)→ 重签 access(带新 tenant claim)+ **新 refresh**
6. `set_auth_cookies(jar, &outcome, state.cookie_secure)` —— **refresh cookie 必须整条轮换**,旧 refresh 一次性、已被 revoke
7. `emit(&state.idm_outbox, AuthEventType::TenantSwitched, ...)` —— **必须用 `success_data(..)` 组 payload 再合并租户字段,别手搓 `json!`**:投影器的 `AuthEventData` 要求 `occurred_at`/`channel`/`outcome`,缺一个整条被当**毒消息 ack 丢弃**(事件进得了 outbox 却永不进 `auth_events` 读模型,且**没有任何测试会红** —— P2 实施时真踩到了,是冒烟的日志抓的)。
   >
   > ⚠️ **未完:`from_tenant`/`to_tenant` 目前只到 outbox,进不了读模型。** `auth_event` 表是固定 schema(无 raw/JSON 列),投影器只映射它认识的列,额外字段静默丢弃 ⇒ 后台审计只看得到「某人在某时切了租户」,看不到「从哪切到哪」—— 而那正是这个事件的价值。
   > 补法有先例:`identifier_attempted`/`failure_reason` 就是事件类型专属列(对其他事件恒 NULL)。照它加两列,要动 8 个文件:`migrations/search/0002_create_auth_event.up.sql`、`auth_audit/projector.rs`、`auth_audit/repo/{memory,postgres}.rs`、`auth_audit/types.rs`、`auth/types.rs`、`auth/emit.rs`、`tests/auth_audit_api.rs`。
   **理由**:auth 模块每条状态变更路径都 emit(`routes.rs` 里 11 个调用点),而"用户跨越组织边界"是审计价值最高的事件之一。`emit.rs:20` 的 `event_type` 是闭集枚举 → 要加一个 `TenantSwitched` 变体
8. 返回新 `AuthResponse`

**refresh token 绑 user、不绑租户**(WorkOS 模型):refresh 承载"你是谁",access 承载"你现在在哪个租户、什么角色"。Auth0 把 refresh 绑 org 的后果是实测过的坑(`auth0-spa-js#1055`:开 refresh token 后无法静默切 org)。本仓天然合规 —— `sessions` 表本就没有 tenant 列。

**失败分支**:refresh 已过期 → 401 → 前端重新登录;但 `user_active_tenant` 已改,重登即落新租户(状态化的意外好处)。

**登录路径零改动** —— `TenantClaimsExtender` 已在 `issue_session` 里跑。

---

## 5. 授权改动

### 5.1 `src/infra/authz.rs` —— 四个方法**全部**给出

⚠️ **只改 `allows` 是致命的**:widget 的三个实际调用点(`get_widget` / `ensure_may_write` / SSE)用的全是 `allows_created_by`。不改它的签名,它照样编译通过、`Rows::All` 照样无条件 return true —— **类型防线在主路径上静默失效**,正是要避免的 fail-open。

```rust
/// 租户标识。唯一生产构造点 = 已验签的 tenant claim(from_claim,只有 auth/token.rs 调)。
/// 刻意没有 Default / From<Uuid> / nil 兜底 —— 想凭空造一个租户过滤条件,
/// 得写出 `TenantId::from_claim(..)` 这个名字,review 一眼看见,grep 一次全中。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

/// 请求的租户上下文。extractor 只读 extension(中间件是唯一真相源,不重复验签)。
/// 无 → 401:与 TokenScope「空 = 无限制」的语义**刻意相反** —— 空租户绝不等于全租户。
#[derive(Clone, Copy, Debug)]
pub struct Tenant(pub TenantId);

/// 数据可见域 = 租户闸(硬,不可为空)× 行级 ownership(软)。
/// 保持 Copy(SSE 的 stream::unfold((sub, access), ..) 把它 move 进流状态)。
/// 字段私有 + 无公开构造函数 ⇒ 构造点唯一:Policy::data_access。
#[derive(Clone, Copy, Debug)]
pub struct Access { tenant: TenantId, rows: Rows }

/// `All` 语义**收窄**:不再是"表内全部",而是"**本租户内**全部"。
#[derive(Clone, Copy, Debug)]
pub enum Rows { All, Own(Uuid) }

impl Access {
    /// repo 过滤用:租户永远参与查询,永远不是 Option。
    pub fn tenant(self) -> TenantId { self.tenant }

    /// 行的租户是**必填实参**。老签名 allows(owner) 编译不过。
    pub fn allows(self, row_tenant: Uuid, owner: Uuid) -> bool {
        self.tenant.get() == row_tenant
            && match self.rows { Rows::All => true, Rows::Own(me) => me == owner }
    }

    /// ⚠️ 同样必须加 row_tenant —— widget 的三个调用点走的是这个,不是 allows。
    /// 保留原语义:非 UUID 脏值('system' / NULL)在 Own 下一律不可见。
    pub fn allows_created_by(self, row_tenant: Uuid, created_by: Option<&str>) -> bool { .. }

    /// 不变。
    pub fn owner_filter(self) -> Option<Uuid> { .. }
}

impl Policy {
    /// 新签名:tenant 是实参(Arc<Policy> 在 router.rs:95 被烘焙进 from_fn_with_state,
    /// per-request 换 policy 不可能 ⇒ 只能走实参)。
    pub fn data_access(&self, user: &AuthUser, scope: &[Perm],
                       all_perm: Perm, tenant: TenantId) -> Access;

    /// 给**不上租户轴**的模块(profile)用:只判 ownership,不碰租户。
    /// 这样 profile 真正零租户耦合,也保住「Access 恒带租户闸」的诚实性 ——
    /// 而不是让它传一个自比自的恒真租户(那是在教人写洞,同 §6.1 的标准)。
    pub fn row_access(&self, user: &AuthUser, scope: &[Perm], all_perm: Perm) -> Rows;
}
```

### 5.2 repo trait:复合键 `(tenant, id)`

```rust
#[async_trait]
pub trait WidgetRepo: Send + Sync {
    /// tenant 非 Option:漏传编译不过。租户过滤恒在查询层 —— 与 owner 同理,
    /// 内存事后筛会让分页 / total 错。owner 仍可 None(租户内看全部)。
    async fn list(&self, tenant: TenantId, page: &PageParams, owner: Option<&str>,
                  sort_by: WidgetSortField, order: SortOrder) -> Result<Page<Widget>, AppError>;
    /// 复合键查找:别租户的 id → NotFound(404,不泄露存在)。
    /// 不是"先按 id 查出来、再让 handler 判租户"—— 那条路一定会有人忘。
    async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Widget, AppError>;
    // create / update / soft_delete / create_with_tags / tags_of 同 —— 7 个方法全加 TenantId 首参
}
```

这是 OWASP 的"所有按 id 的查找都用复合键 `(tenant_id, resource_id)`",但**用 Rust 类型系统而非数据库强制**。

**读侧:租户谓词只写一处。** 今天 owner 谓词在 `postgres.rs` 写了三遍(行查询 `:67` / COUNT `:85` / cursor `:106`),漏一处则 total 与 items 不一致。把租户下沉进 `base_select(tenant)`(它自己的注释已写着"所有读的唯一起手式,防各方法漏写过滤")。

**写侧:`Widget` 类型加 `tenant_id` 字段**(DTO 不暴露、不接受),INSERT 显式写列。因为没有 default 兜底(§3.2),漏列 = PG 报 not-null 违约,不是静默落错租户。

### 5.3 为什么不上 Postgres RLS

**不做,留作第二层。**

理由:类型系统兜底(`TenantId` 非 Option 首参)在**内存模式下也生效**,而 CI 默认跑的就是内存模式;RLS 在内存实现里没有等价物,直接违反 `*_conformance` 内存↔PG 对拍。

**触发**:出现绕过 repo 的 raw SQL / BI 直连 / 报表任务。届时是 non-owner runtime role + `FORCE ROW LEVEL SECURITY` + per-request `SET LOCAL` 事务,作为**第二层**,不替代 repo 里的租户参数。

---

## 6. 评审发现的洞(必须在 P4 同 PR 修)

### 6.1 `widget_stats` —— public 端点无 token,造不出 `TenantId`

```rust
// src/features/widget/routes.rs:235-239  public_router,无 CurrentUser
pub async fn widget_stats(State(state): State<AppState>) -> ... {
    Ok(Json(WidgetStats { total: state.widgets.count(None).await? }))
}
```

**决定:挪进 frontend 组** + 加 `Tenant` extractor + 从 `src/infra/openapi.rs:224` 的 PUBLIC 白名单摘掉 + `op_perms.rs` 加一条 `LoginOnly`。
`widget/mod.rs:44-45` 的 `public_router()` 摘空后**删掉函数**,并删 `router.rs` 里两处 merge。

代价:widget 不再演示 "public 端点" 形态。**这是正确的** —— 多租户下"public + 租户数据"本身就是反模式,留着它当样板是在教人写洞。若确需 public 样板,另找一个真无租户语义的端点演示。

### 6.2 消费 `state.widgets` 的 handler 穷举(**10 个**,不是 11)

`grep -rn 'state\.widgets' src/` = 9 个调用点 / 10 个 handler。逐个拍死:

| handler | 现在有 Access? | tenant 从哪来 | 改法 |
|---|---|---|---|
| `list_widgets` :78 | ✅ | `Tenant` extractor | `data_access(.., tenant.0)` |
| `create_widget` :106 | ❌ | `Tenant` extractor | repo 首参 |
| `get_widget` :134 | ✅(`allows_created_by`) | `Tenant` extractor | 复合键 get + 新签名 |
| `update_widget` :169 | 经 `ensure_may_write` | ↓ | ↓ |
| `delete_widget` :221 | 经 `ensure_may_write` | ↓ | ↓ |
| **`ensure_may_write` :181-196** | ✅(`allows_created_by`) | `Tenant` 参数 | **update+delete 的共用闸,租户判定放这里,两个 handler 不用各写一遍** |
| `widget_stats` :237 | ❌ public | — | 见 §6.1,挪组 |
| `my_widget_count` :257 | ❌ | `Tenant` extractor | repo 首参 |
| `purge_preview` | ❌ | `Tenant` extractor | repo 首参 |
| `admin_list_widgets` :325-342 | ❌ | `Tenant` extractor | 见 §6.3 |
| `widget_events` :366 | ✅ | `Tenant` extractor | 单列 —— 它走 EventBus 不走 `state.widgets`,见 §6.4 |

### 6.3 `admin_list_widgets` —— 语义必须拍死

```rust
require_scoped(&user.0, &scope.0, Perm::UsersAdmin)?;   // 闸
state.widgets.list_enriched(/* owner */ None, ...)      // ← 泄露行:跨租户
```

**决定:降级为"本租户全部"**,加 `Tenant` extractor 传 `tenant.0`。

### 6.4 SSE:两个洞,不是一个

**(a) 开流即冻结**:`routes.rs:375` 算出 `access` 后 `:381` move 进 `stream::unfold` 流状态,`:384` 每帧只读不重算;`:394` 还主动 `keep_alive(15s)` —— **流能活过 token 过期**。
→ **随 exp 截流**(~5 行):`verify_with_scope` 已 decode 出 `AppClaims.exp` 但丢掉了 —— 改成随 `(AuthUser, Vec<Perm>, Option<TenantId>, Exp)` 一起返回 → middleware insert `TokenExp` → `.take_until(sleep_until(exp))`。

**(b) 消费端没东西可过滤** ⚠️:`WidgetEvent` 三个变体**没有任何 tenant 字段**,只有 `owner()`。
→ `WidgetEvent` 加 `tenant(&self) -> Uuid`;`Created`/`Updated` 从 `widget.tenant_id` 取;**`Deleted` 变体必须新增 `tenant_id: Uuid` 字段** —— 理由与 `created_by` **逐字同源**(`events.rs:30-31` 的注释:"删除后行已软删,订阅侧无从回查"),把这句抄进新字段的注释。
→ SSE 逐帧改 `access.allows_created_by(event.tenant(), event.owner())`。
→ PG NOTIFY / NATS subject 保持全局,过滤纯在消费端(§7)。

### 6.5 `content` 的伪造面 —— **4 个** DTO,分两类

| DTO | 行 | 方向 | 决定 |
|---|---|---|---|
| `UploadForm` | types.rs:191 | Deserialize | **删字段**(伪造面) |
| `CreateContentRequest` | types.rs:215 | Deserialize,`#[garde(skip)]` 零校验 | **删字段**(伪造面,**主 JSON 建内容端点读的就是它**) |
| `PrepareUploadRequest` | types.rs:304 | Deserialize | **删字段**(伪造面) |
| `ContentResponse` | types.rs:75 | **Serialize,只出不进** | **保留** —— 不是伪造面;留着能让前端看见自己在哪个租户 |

`Uuid::nil()` 共 **5 处,其中 4 处在 content**:`types.rs:334`、`routes.rs:111`、`:158`、`:189-192`(multipart 解析客户端 `tenant_id` 的分支 —— **整个分支删掉**)。全换成 claim 里的 tenant。
`fetch_content_owned`(`routes.rs:33-48`)加租户比对。

**第 5 处在 profile,见 §6.6。**

安全评估结论:当前**不是活漏洞**(list 恒查 nil,无读路径能读到非 nil 对象),但收编顺序必须照 §3.3。

### 6.6 profile 不上轴,但它引用的 content 上了轴 ⚠️

R5 说 profile 不上租户轴。但 profile **往 content 写数据**:

- **`profile/routes.rs:286`** 上传头像时硬写 `tenant_id: Uuid::nil()`。
  **决定(P4 实施时修正了本节原方案)**:头像 content 落 `NO_TENANT`(= `Uuid::nil()`,`profile/routes.rs` 的具名常量),
  **不是** claim 里的 tenant —— 头像是全局身份的一部分,与 `display_name` 同级、跟人走:你换公司,脸不换。
  用 claim 的租户会让同一张头像随人在公司间移动而时隐时现。

  > ⚠️ 本节原写「复用 §3.2 那个 demo 租户 id」。**那是错的**:demo 租户由 dev seed 造,
  > prod 的 `SEED_FILE` 里没有 `[[tenants]]` —— 那个 id 在生产环境不存在,等于把全平台的头像
  > 挂到一个悬空引用上。`NO_TENANT` 与真租户**不可能碰撞**:真租户 id 全部来自
  > `seed::tenant_id_for`(uuid v5),v5 永不为 nil。它也读不出来 —— `/contents/{id}` 的租户闸
  > 会 404 掉它,头像只经下面那个显式例外出。
- **`GET /profiles/{user_id}/avatar`(`routes.rs:129-177`)是租户闸的显式例外**。它刻意去掉了 owner 闸(注释原文:"本端点契约就是『这个用户的公开头像』")。
  **决定**:保留例外,写进 §10 验收(改成"除 `/profiles/{id}/avatar` 外"),理由:头像 = 全局身份的可视化,同 `display_name`。
- `profile/routes.rs:98` 的 `data_access` → 改用 **`row_access`**(§5.1),profile 真正零租户耦合。

**`search` 是真零改动** —— `src/features/search/` 只有 `repo/ mod.rs projector.rs rebuild.rs types.rs`,**没有 routes.rs、没有 HTTP 端点**,`grep -rn 'Access|data_access' src/features/search/` 零命中。

---

## 7. 刻意不做(带触发条件)

| 不做 | 触发条件 |
|---|---|
| **平台级跨租户管理员**(客服看客户数据) | 客服第一次问"我怎么看客户的数据"。届时加 `Rows::AllTenants` + 一个 `platform:*:all` perm,`allows` 里那条 `self.tenant.get() == row_tenant` 短路掉。**注:开通租户本身不需要它** —— 那是 `tenants` 表的 CRUD,不是跨租户读业务数据(见 §7.1)。 |
| **租户自助邀请流程**(R4 的 UI/端点) | 第一个客户要自己加人。首刀靠 seed + 手工 SQL 建 membership。**届时端点必须落 `/frontend/auth/` 前缀。** |
| **闸住 public register** | 邀请流落地时一并做。在那之前 0 租户是常规状态(§1.1)。 |
| **每租户自定义角色定义** | 客户要自定义角色 —— 先问能不能用"预置角色改显示名"糊过去。理由见 §4.6。 |
| **Postgres RLS** | 出现绕过 repo 的 raw SQL / BI 直连 / 报表任务。理由见 §5.3。 |
| **切租户后旧 access token 即时失效** | 合规明文要求 <1min。唯一旋钮是 **`IDM_ACCESS_TTL_SECS`**(注意 `IDM_` 前缀 —— config 用 `Env::raw()` 无前缀剥离,写成 `ACCESS_TTL_SECS` 会被**静默忽略**)。默认 900,**建议 → 120**。建撤销名单 = 让 app 查 idm 库 = 违反固定架构。 |
| **profile 加租户** | 要做"租户管理员只能看本租户成员"。profile = 全局身份(与密码同级,跟人走)。见 §6.6。 |
| **EventBus 按租户分 subject** | 威胁模型升级到"别租户数据不许进本进程内存"。现状:NATS/PG 全局广播,过滤在消费端逐帧(靠 §6.4(b) 加的 `tenant()`);别租户的帧会进本进程内存但出不去。 |
| **S3 key 加租户前缀** | 要按租户桶策略 / 存储层纵深。跨租户猜 key 实际不可行(两段都是 uuid v7、S3 非公开、读要 presign)。 |
| **多 tab 开不同租户** | 用户抱怨。cookie 是浏览器级单例,org-scoped token 放 cookie 就只能同时一个租户(Clerk 为此改成每 tab 独立 active org + `getToken`)。 |
| **app 侧校验 tenant claim 是已知租户** | 引入第二个签发方。现状只有一个 issuer、一把私钥,tenant 值签发时已过 membership 校验且 FK 到 `tenants`;停用/软删由 §4.4 的 `memberships` 契约在铸币侧拦。 |
| **存量 backfill 写进迁移** | 永不。理由见 §3.3。 |

### 7.1 superadmin 怎么开通租户(**不是**跨租户读)

`tenants` 表的 CRUD 是**平台运营端点**,首刀靠 seed + 手工 SQL(§7 第 2 行)。它读写的是 `idm.tenants`,不是任何业务模块的租户数据 —— 因此**不需要** `Rows::AllTenants`,与"客服看客户 widget"是两回事。§5.1 的 `Access` 把 superadmin 也关进租户闸,只影响它读**业务数据**,不影响它管租户。

---

## 8. 测试策略

| 测试 | 内容 |
|---|---|
| `tests/widget_repo_conformance.rs` | 契约全部加 tenant;**新增 `tenant_isolation` 用例**,memory / PG 双跑 |
| `tests/tenant_isolation_api.rs`(新) | 黑盒:A 租户令牌打 B 租户的 id **全 404**;切租户后新旧 token 行为;**停用租户后 refresh → 该 tenant 不再进 claim**;**拓扑断言**:`/frontend/auth/tenants` 在 `Mount::Idm` 下 200、在 `Mount::App` 下 404 |
| `tests/rbac_scope_test.rs` | **新增**:`list_roles()` ∩ `{TenantAdmin, TenantMember}` = ∅(§4.5 的提权闸) |
| `tests/widget_api.rs`、`openapi_authz_test.rs`、`support/mod.rs` | 探针令牌带 tenant,**且与被打行同租户** —— 否则正向断言被租户闸污染成假红 |

内存实现能复刻全部语义(`memberships` / `active` / `set_active` 都是平凡 map;两张表的 `on delete cascade` 永不触发 —— idm 的 user 与本设计的 tenant 都是软删,`delete_me` 走 `users.soft_delete` 不是 DELETE)。

---

## 9. 文件清单

**实估 2000–2500 行,分五阶段(§3.4)。**

**新增**
`migrations/idm/0004_add_tenants.{up,down}.sql`
`migrations/app/0005_widgets_tenant.{up,down}.sql`、`migrations/app/0006_widgets_tenant_enforce.{up,down}.sql`
`src/features/tenants/{mod,types}.rs`、`src/features/tenants/repo/{mod,memory,postgres}.rs`
`src/app/adapters/tenant_role_repo.rs`
`tests/tenant_isolation_api.rs`

> 切换端点**不新开模块**,写进 `src/features/auth/routes.rs`(§4.9)。

**改动**
`src/app/{state,router,seed}.rs`(state 的包装点见 §2.4)
`seed.toml`、**`seed.prod.toml.example`** —— ⚠️ `seed.prod.toml` **被 .gitignore 挡着**(含真密码,`justfile:122-123` 检查它不存在就报错让你先 cp;`docker-compose.prod.yml:88,92` 挂载它)。**改不到它,只能改模板 + 在 README 提醒部署者重 cp。**
`src/infra/{authz,op_perms,openapi}.rs`
`src/features/auth/{token,middleware,types,routes,emit}.rs`
`src/features/users/{routes,service}.rs`(§4.5 的 `PLATFORM` 过滤)
`src/features/widget/{mod,repo/*,service,routes,events,types}.rs`
`src/features/content/{routes,types}.rs`
`src/features/profile/routes.rs`(:98 改 `row_access`;**:286 的 `tenant_id: Uuid::nil()` → `PLATFORM_TENANT`**)
测试若干

**seed 样例**(`seed.toml` / `seed.prod.toml.example` 同形):

```toml
[[tenants]]
id = "00000000-0000-0000-0000-000000000001"   # 显式 id,§3.3 第 4 步的 backfill 目标
name = "demo"
display_name = "Demo Corp"
status = "active"

[[accounts]]
username = "alice"
# ...
tenants = [{ tenant = "demo", role = "admin" }]   # 不填 → 0 租户 → 除 /me 外全 401
```

---

## 10. 验收(每条可粘贴执行)

```bash
# 1. 基线
just check && just test && just lint          # 零警告(clippy -D warnings)

# 2. 内存模式(零 env)全绿
env -u APP_DB_HOST -u IDM_DB_HOST just test

# 3. 跨租户隔离 —— A 租户令牌打 B 租户任意资源 id 全 404(不是 403)
cargo test --test tenant_isolation_api

# 4. 拓扑:/frontend/auth/tenants 在 Idm 下 200、App 下 404
cargo test --test tenant_isolation_api topology

# 5. 提权闸:租户角色不是 RoleName 的变体 —— **由类型保证,无需测试**
#    (TenantRole 与 RoleName 是两个类型;想把前者塞进后者的 ALL 会编译失败)

# 6. 构造点唯一
grep -rn "TenantId::from_claim" src/         # 只准命中 src/features/auth/middleware.rs

# 7. **回归**:roles 不再兼职运租户(旧走私通道已删,别回去)
grep -rn '"t:"\|tn:admin\|split_tenant\|TenantRoleRepo' src/   # 只准命中解释历史的注释
cargo test --lib a_role_named_like_the_old_sentinel_is_just_a_role

# 8. **链是活的**(P2 第一版就死在这:没有任何代码能创建租户,冒烟靠手插 SQL 才"绿")
cargo test --lib seeded_tenants_give_the_user_real_memberships
cargo test --test tenant_api
```

**人工确认项**(测试盖不住的):

- [ ] 切租户后旧 access token 在 ≤ `IDM_ACCESS_TTL_SECS` 内仍见旧租户 —— **已知窗口,须写进 README**
- [ ] `/profiles/{id}/avatar` 是租户闸的**显式例外**(§6.6),不是漏网
- [ ] `seed.prod.toml.example` 已更新,且 README 提醒部署者重新 cp

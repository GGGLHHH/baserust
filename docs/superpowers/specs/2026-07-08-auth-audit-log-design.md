# 认证审计日志 — auth event 全生命周期审计流(CQRS 读模型)

日期:2026-07-08 · 状态:待实现(v2 — 落定进程拓扑与发射模型)

## 目标

给用户认证加**全面审计日志**:登录全生命周期的每个认证事件落成不可变记录,同时服务四类用途——

1. **安全审计/告警**:所有尝试(含失败)带 IP/UA/失败原因,支撑暴力破解检测、令牌盗用检测、取证;
2. **用户可见活动 + 设备管理**:给用户看"最近登录/当前设备/登录地点",可按会话撤销;
3. **admin 后台排查**:后台按用户查登录历史、按 IP/结果过滤,排查工单;
4. **合规不可变留痕**:append-only、明确保留期(统一 **90 天**)。

复用**已跑通的 CQRS 链**(idm.outbox → relay → JetStream `events.idm.>` → 投影器 → 读模型表,
现用于 `search.admin_user_index`)。新增一个 `auth.*` 事件族 + 一个投影器 + 一张分区读模型表,不加新基建类别。

## 进程拓扑(定架构的前提)

同一 baserust 二进制按 `Mount` 分进程部署,nginx 按前缀劈:

- **idm 进程**(`src/bin/idm.rs`,`Mount::Idm`,`needs_idm`):serve `^/api/v1/(public|frontend|admin)/auth/*`,
  持 JWT 签发私钥,连 **idm schema**;**user-admin 端点 + 现有 search projector 也在此进程**。
- **app 进程**(`src/main.rs`,`Mount::App`):serve widgets/content/profiles,连 app/content schema,不持签发密钥。
- `Mount::Both`:本地/dev 单进程。

**关键约束**:per-schema role 隔离 → idm 进程只能写 **idm schema**(写不了 app.outbox)。故所有 auth 事件写 **`idm.outbox`**。
本审计特性**几乎完全是 idm 进程的活**(发射、投影、查询端点全在 idm 进程),app 进程不涉及。

## 架构:idm 进程 handler 层发射 → 复用现成 CQRS 链

```
idm 进程                                                     idm 进程(后台)
┌─ auth HTTP handlers (src/features/auth/routes.rs) ─┐       ┌─ auth_event projector ─┐
│  login / admin_login / refresh / logout /          │       │ 新 durable consumer     │
│  logout_all / change_password / register /         │       │ 只认 auth.*             │
│  delete_me                                         │       └───────────┬────────────┘
│    │ ① 调 idm::AuthService(拿 outcome / 失败原因)   │                   ▼
│    │ ② 就地取 ClientContext{ip,ua,request_id,       │        auth_event (search schema,
│    │    channel}(HTTP 边界天然有)                   │           按月分区, append-only)
│    ▼                                               │                   │
│  ③ 写 idm.outbox 一条 auth.* 事件                   │        ┌──────────┴───────────┐
└────────────────────┬───────────────────────────────┘        ▼                      ▼
                     ▼                                admin 查询端点(idm 进程)  90d 保留 job
        idm.outbox ─ relay(零改)─▶ JetStream events.idm.auth.*(流零改)
```

**单一发射源 = idm 进程的 auth handler 层**。ClientContext(ip/ua/request_id/channel)就在这一层的 HTTP 请求里,
**天然可得,不穿透 idm crate**。crate 保持 HTTP-agnostic。

**idm crate 只做小改**(纯 Rust,**零迁移**):

1. **登录失败原因回传**:`login` 让 handler 能区分 `unknown_user` / `bad_password`(HTTP 仍统一返 401,防枚举由 app handler 保证不变)。
2. **`AuthOutcome` 暴露 `session_id`**(= 现有 `sessions.id`,读现列):供 login/register/refresh 成功事件记会话。
3. **emit 口**:暴露一个把事件写进 `idm.outbox` 的公共方法(复用现有 `emit_outbox` 机制),供 handler 调用。

**富化落点 = 投影器**(idm 进程,写读模型行时):事件只带原始 `ip`/`user_agent`;geo(MaxMind)、UA 解析(woothee)
在投影时做,依赖只活在 baserust。

## 事件目录(`type` 值 + 关键 payload)

**发射源统一 = idm 进程 auth handler 层 → `idm.outbox`**(`event_type` 前缀 `auth.`)。

| type | outcome | 关键字段 | 说明 |
|---|---|---|---|
| `auth.login_succeeded` | success | user_id, session_id, channel | 验密通过、发会话 |
| `auth.login_failed` | failure | identifier_attempted, failure_reason | reason ∈ unknown_user / bad_password / account_locked / rate_limited |
| `auth.admin_access_denied` | failure | user_id, channel=admin | 凭据对但无 admin:login;handler 已即刻撤销刚铸会话 |
| `auth.refreshed` | success | user_id, session_id | 刷新轮换(prev_session_id 血缘 = Phase 3) |
| `auth.refresh_reuse_detected` | failure | user_id?, session_id | 已撤销/已轮换 refresh 被再次提交 = 盗用信号(**Phase 3**) |
| `auth.logged_out` | success | user_id, session_id | 单会话登出 |
| `auth.logout_all` | success | user_id | 撤全部会话 |
| `auth.session_revoked` | success | user_id, session_id, actor | 撤指定会话;actor 可能是 admin(**Phase 3**) |
| `auth.password_changed` | success | user_id | 改密(连带撤全会话) |
| `auth.registered` | success | user_id, session_id | 注册即登录 |
| `auth.account_deleted` | success | user_id | 注销账户(delete_me) |

**outbox `aggregate_id`(NOT NULL uuid)**:有 user_id 时填 user_id;登录失败(未知用户)无 user_id → 填 `Uuid::nil()` 哨兵,
真实线索(`identifier_attempted`)在 payload。

## 读模型表 `auth_event`(search schema,按月分区)

```sql
-- 高频只增 + 90 天统一保留 → Postgres 原生按月分区(RANGE occurred_at)。
-- 保留期到 = DROP 旧分区(秒级、走分区裁剪),不做行删 → 天然 append-only。
-- 分区表主键必须含分区键 → PK (occurred_at, id)。id 仍 uuid v7 供时间序 keyset。
create table auth_event (
    -- 事件身份
    id                   uuid        not null,                 -- v7,投影时生成
    event_type           text        not null,
    occurred_at          timestamptz not null,                 -- 分区键 = 源端事件发生时刻
    channel              text        not null,                 -- public | admin
    auth_method          text        not null default 'password',
    -- 主体
    user_id              uuid,                                 -- 失败且用户不存在时 null(哨兵 nil → 存 null)
    identifier_attempted text,                                 -- 提交的用户名/邮箱原文(不脱敏)
    session_id           uuid,                                 -- = jti,关联 idm.sessions
    prev_session_id      uuid,                                 -- refresh 轮换血缘(Phase 3 填,Phase 1 恒 null)
    actor                text,                                 -- 触发者;通常=user_id,撤别人会话时为 admin
    -- 结果
    outcome              text        not null,                 -- success | failure
    failure_reason       text,                                 -- 见事件目录
    -- 来源(原始,事件携带)
    ip                   inet,                                 -- 可信解析后的客户端 IP
    forwarded_chain      text,                                 -- 原始 X-Forwarded-For 全文,取证用
    user_agent           text,                                 -- 原始 UA
    request_id           text,                                 -- x-request-id,串联应用日志/trace
    -- 派生(投影器富化;Phase 1 恒 null,Phase 2 填)
    country              text,
    city                 text,
    asn                  bigint,
    isp_org              text,
    is_datacenter        boolean,
    os                   text,
    browser              text,
    device_type          text,
    -- 溯源/投影
    event_seq            bigint      not null,                 -- idm.outbox 行 id,幂等去重键
    projected_at         timestamptz not null default (now() at time zone 'utc'),
    primary key (occurred_at, id)
) partition by range (occurred_at);

-- 幂等:append-only,不用水位 upsert。同一 idm outbox 行只投一次 → 唯一键去重。
-- 分区表 unique 须含分区键 → (event_seq, occurred_at)。ON CONFLICT DO NOTHING 吸收重投。
create unique index auth_event_dedup_uidx on auth_event (event_seq, occurred_at);
-- 查询索引:按用户查历史(admin/用户活动)、按 IP 聚合(安全)。
create index auth_event_user_time_idx on auth_event (user_id, occurred_at desc);
create index auth_event_ip_time_idx   on auth_event (ip, occurred_at desc) where ip is not null;
```

**幂等**:与 search 投影的"seq 水位 upsert"不同——auth_event 是 **append-only、多行/用户**,幂等靠
`INSERT ... ON CONFLICT (event_seq, occurred_at) DO NOTHING`(同一 outbox 行重投被唯一键吸收)。投影器无状态。

**维度采集点速查**:

- **idm crate 内部知道(经返回值/错误给 handler)**:event_type 语义, user_id, identifier_attempted, session_id,
  outcome, failure_reason, occurred_at。
- **idm 进程 handler 层天然可得(HTTP 边界)**:ip, forwarded_chain, user_agent, request_id, channel。
- **派生(投影器富化,Phase 2)**:country, city, asn, isp_org, is_datacenter, os, browser, device_type。

## 正确性要点

- **可信代理解析(IP 反伪造)**:idm 进程在 nginx 后。**不信** `X-Forwarded-For` 最左(可伪造)。
  按"信任 N 层代理"从**右**数取 `ip`;`forwarded_chain` 存全文备查。N 由配置定(默认信 1 层 nginx)。
- **防枚举不变**:idm crate 把失败原因回给 handler,但 HTTP 响应仍由 handler 统一返 401(同码同文案)——
  原因只进审计事件,不进响应体。
- **发射非事务(已知天花板)**:成功事件在 handler 拿到 outcome 后写 `idm.outbox`,与 idm crate 内的
  session 落库**非同一事务**(idm 现有 session 写本就非事务)。极小崩溃窗口可能丢一条审计行。
  审计容忍此边;要真·同事务需把 session 写改成事务性 + crate 内发射(重构,`ponytail:` 注释钉住升级路径)。

## 富化 + 依赖(Phase 2)

- **GeoIP**:`maxminddb` 读 MaxMind **GeoLite2-City**(country/city)+ **GeoLite2-ASN**(asn/isp_org)。
  `is_datacenter` 由 ASN org 关键字/机房 ASN 名单派生(启发式,`ponytail:` 钉升级到威胁情报库)。
  **db 文件供给**:打进 Docker 镜像(GeoLite2 免费需注册下载,构建期拉);启动缺文件 → geo 列留 null,不 fail。
- **UA 解析**:`woothee`(纯 Rust、无外部数据)→ os/browser/device_type。要更准再换 `uaparser`(`ponytail:` 钉)。
- 富化只在投影器,失败降级写 null 不毒化(投影不因一条脏 UA/未知 IP 卡死)。

## 保留期(统一 90 天)

- 分区粒度**月**;后台 job(idm 进程,随 relay/projector 同 tick 或独立循环)DROP `occurred_at < now()-90d` 的整月分区。
- 90 天窗口 ≈ 3–4 个活跃分区。刷新事件全量记也不控采样——靠分区丢弃控量。
- **隐私**:IP/UA/identifier 均 PII,不脱敏(用户决策)。合规靠 90 天保留期 + append-only,不靠脱敏。

## 查询端点(idm 进程,`needs_idm` 路由)

**admin(`users:admin` 下,镜像 `list_users`)**:

- `GET /admin/users/{id}/auth-events` — 某用户认证历史,keyset 翻页(occurred_at/id),过滤 event_type/outcome/时间窗。
- `GET /admin/auth-events` — 全局审计流(安全评审),过滤 ip/outcome/failure_reason/时间窗。

**frontend(当前用户自己,Phase 3)**:

- `GET /frontend/auth/activity` — 本人最近认证事件(带 geo/device 展示)。
- `GET /frontend/auth/sessions` — 活跃会话列表(`idm.sessions` where revoked_at is null,join 每会话最新
  `login_succeeded`/`refreshed` 拿设备/地点),标记当前会话。
- `DELETE /frontend/auth/sessions/{session_id}` — 撤指定设备会话 → idm 新增 `revoke_session(user_id, session_id)` 能力。

## 分期(writing-plans 的天然切块)

- **Phase 1 — 事件 + 读模型 + admin 查询(核心)**
  - **idm crate(rust-idm 仓,零迁移)**:`login` 回传失败原因、`AuthOutcome` 暴露 `session_id`、暴露 emit 口;切新 tag。
  - **baserust**:auth handler 层发射 auth.* → idm.outbox;新 auth_event projector + `migrations/search/000X` 分区表 +
    保留 job + admin 两个端点。**先原始维度,geo/device 列恒 null,prev_session_id 恒 null**。
- **Phase 2 — 富化**:maxminddb + woothee,投影器填 geo/asn/device;db 文件供给接线。
- **Phase 3 — 用户可见 + 血缘 + 按会话撤销**:idm `sessions` 加 `prev_session_id` 列(**rust-idm 仓 + baserust
  `migrations/idm/` 两处**)+ `revoke_session` + `refresh_reuse_detected`;frontend activity/sessions/revoke 端点。

## 改动面(Phase 1)

**rust-idm 仓(`github.com/GGGLHHH/rust-idm`,`path="../rust-idm"` 联调,完成切新 tag)—— 纯 Rust,零迁移**:

- `login`:区分"用户不存在"与"密码错",把原因回给调用方(新 error 变体或 richer 返回;HTTP 语义仍由 baserust handler 收口)。
- `AuthOutcome` 加 `session_id: Uuid`(login/register/refresh 均经 `issue_session`,填新会话 id);`logout` 返回被撤会话 id。
- 暴露公共 emit:如 `AuthService::record_event(event_type, aggregate_id, payload)` 或一个 `pub` 的 idm-schema outbox 写入口,
  复用 `emit_outbox`,供 baserust handler 写 `idm.outbox`。

**baserust 仓**:

- `infra/audit.rs` 或新 `ClientContext` 提取器:从 `X-Forwarded-For`(可信代理解析)+ `User-Agent` + `x-request-id` 组装。
- `features/auth/routes.rs`:各 handler 成功/失败路径调 idm emit 口写 auth.* 事件(带 ClientContext + outcome/reason)。
- 新 `src/features/auth_audit/`:projector(镜像 `search/projector.rs`,新 durable 名、只认 `auth.*`)+ repo(insert + list 查询)+ 查询端点 + 富化模块(Phase 2 前留桩)。
- 迁移 `migrations/search/000X_create_auth_event.*`(分区表 + 初始若干月分区 + 索引)。
- 装配:`state.rs` 加 `build_auth_projector`、`BackgroundTasks` 加字段、`runtime.rs` 加 spawn;保留 job 同法接线。
- `op_perms.rs` 各新端点一行;`authz.rs` 若需新 Perm 则加(否则复用 `UsersAdmin`)。
- JetStream 流已订 `events.idm.>`,projector 认 `auth.*` type 即可,**流零改**。

## 测试

1. **idm crate 单测**(rust-idm 仓,镜像 `injected_clock_drives_session_expiry` харness):`login` 未知用户/错密码返回可区分的原因;
   `AuthOutcome.session_id` 与落库 session 一致;emit 口写出 outbox 行(镜像 `idm_outbox_contract`)。
2. **handler 发射测**(baserust,镜像 `users_api.rs` in-memory oneshot):登录成功/失败/admin 无权/登出各跑一遍 →
   断言对应 auth.* 写进 idm.outbox(payload 形状 + aggregate_id 哨兵)。
3. **projector 单测**(镜像 `search/projector` 测):吃各 `auth.*` envelope → 写 `auth_event` 行断言;幂等(同 event_seq 重投不重复行);
   脏 UA/未知 IP 富化降级 null 不 panic。
4. **可信代理解析单测**:伪造 XFF 链 + 信任层数 → 解析出正确客户端 IP;最左伪造值不被采信。
5. **集成**(baserust,PG `#[sqlx::test]` + `bootstrap` search schema):落行后 admin 端点分页/过滤断言;跨月分区 → 跑保留 job →
   断言 >90d 分区被 DROP、内含数据消失。

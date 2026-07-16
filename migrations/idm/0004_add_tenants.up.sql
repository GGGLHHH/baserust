-- 多租户:tenants(实体)+ tenant_members(事实)+ user_active_tenant(状态)。
-- **为什么落 idm 而非 app**:铸 token 的进程(Mount::Idm)没有 app_pool(src/app/state.rs:106),
-- 而「每租户一套角色」要求铸币时就知道是哪个租户 → membership 必须铸币进程够得着。
-- 详见 docs/superpowers/specs/2026-07-16-multitenancy-design.md §2.1。
-- set_updated_at_utc() 已由 0001 在 idm schema 建好,本迁移**同 schema 直接复用**(可达)。
--
-- **本迁移的时间戳用裸 now(),不跟全仓其他迁移的 `(now() at time zone 'utc')`。**
-- 那个写法是双重转换:timestamptz →(at time zone 'utc')→ naive timestamp → 存回 timestamptz
-- 列时按 session TimeZone 重新解释。timestamptz 本身就与时区无关,这一趟纯属画蛇添足。
--
-- **它在本仓不是 bug**:sqlx 在每条连接的 startup packet 里**无条件硬编码 TimeZone=UTC**
-- (sqlx-postgres/src/connection/establish.rs:33),而 startup packet 是 `PGC_S_CLIENT`,
-- 优先级**压过** `ALTER ROLE SET`(PGC_S_USER)与 postgresql.conf(PGC_S_FILE)。
-- app / seed / migrate / 测试**全部**经 sqlx ⇒ session TimeZone 恒为 UTC ⇒ 老写法恒等于 now()。
-- 实测(同一时刻,`alter role idm set timezone='Asia/Shanghai'` 之下):
--   psql 会话: TimeZone=Asia/Shanghai | source=user   | 老写法偏移 = 08:00:00
--   sqlx 会话: TimeZone=UTC           | source=client | 老写法偏移 = 00:00:00
--
-- 所以裸 now() 只是**少绕一圈**,不是在修一个活的漏洞:
--   (a) 读者不必先知道「sqlx 钉了 UTC」才能确信这列是对的;
--   (b) 非 sqlx 的写入方(手工 psql 运维、外部 ETL、未来换驱动)会真的偏 8 小时 —— 上面那行
--       psql 输出就是证据。老写法把正确性押在「写入方恰好是 sqlx」上,裸 now() 不押。
-- 全仓其余 11 个迁移的老写法是**可读性债,不是正确性 bug**,该单独 cleanup、不必急。

-- ── tenants:客户公司(实体:独立 id + 审计 + 软删)──
create table tenants (
    id           uuid        primary key,
    name         text        not null,            -- 机器码 slug:'acme';代码/seed 引用,唯一稳定
    display_name text        not null,            -- 展示名:'Acme 公司';UI 用,可改
    status       text        not null,            -- 'active' | 'suspended';闭集,见 types.rs::TenantStatus
    created_by   text,
    created_at   timestamptz not null default now(),
    updated_by   text,
    updated_at   timestamptz not null default now(),
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
--
-- **FK 策略刻意不对称**:user_id 挂 cascade(用户没了,成员资格自然没意义),
-- tenant_id **不挂 cascade** —— 租户只软删、不硬删(spec §4.4 拿软删当安全控制)。
-- 没有 cascade 意味着 `delete from tenants` 在还有成员时会被 FK 拒绝,这正是想要的:
-- 别顺手给它补 cascade,那会让一次误删 tenants 行静默清空全部成员资格、绕过软删这道闸。
--
-- **seq = 排序键,granted_at = 审计时间戳,两个职责刻意分离。**
-- 为什么不能拿 granted_at 当排序键:它是墙钟,既会被 NTP 回拨、也可能在同一微秒内打平 ——
-- 而这个顺序决定 TenantRoleRepo 的 `.or(ms.first())` 回退目标,即**用户默认落进哪家公司**。
-- seq 是应用侧 `Uuid::now_v7()`,照搬 widgets.id 的既有范式(widget/repo/postgres.rs 的
-- 注释原文:「v7 单列严格全序」)。uuid crate 保证同进程内按创建序单调(v7.rs 的 doc:
-- "All UUIDs generated through this method by the same process are guaranteed to be ordered
-- by their creation",机制是每毫秒重播种的计数器)—— 不会打平、不受 NTP 回拨影响。
-- 内存与 PG 各自生成各自的 seq(值不同、顺序语义相同),镜像 widget::create() 的做法。
create table tenant_members (
    user_id    uuid        not null references users (id) on delete cascade,
    tenant_id  uuid        not null references tenants (id),
    role       text        not null,              -- 'admin' | 'member';租户级,见 types.rs::TenantRole
    seq        uuid        not null,              -- Uuid::now_v7();排序键,见上
    granted_by text,                              -- 只在 INSERT 落;改角色不动它(与 granted_at 同一事件)
    granted_at timestamptz not null default now(),-- 审计:何时加入。**不是排序键**
    primary key (user_id, tenant_id)
);
create index tenant_members_tenant_id_idx on tenant_members (tenant_id);  -- 按租户反查成员
-- role 闭集:与 TenantRole 枚举双保险。**存 DB 裸值('admin'),不是 JWT claim 串('tn:admin')**
alter table tenant_members add constraint tenant_members_role_ck
    check (role in ('admin', 'member'));

-- ── user_active_tenant:当前激活租户(**状态**,一人一行)──
-- 为什么要状态化:idm 的 RoleRepo::roles_for_user 只收 user_id,收不到"哪个租户"
-- → per-request 的租户选择不可能在 idm 内部发生 → 只能落表。见 spec §4.1。
-- tenant_id 同样刻意不挂 cascade,理由同 tenant_members。
create table user_active_tenant (
    user_id    uuid        primary key references users (id) on delete cascade,
    tenant_id  uuid        not null references tenants (id),
    updated_at timestamptz not null default now()
);
-- updated_at 归触发器,不归写方 —— 全仓凡有 updated_at 的表都是这个范式
-- (users/sessions/roles/widgets/profiles 无一例外)。写方手写 `updated_at = now()`
-- 会让任何忘了写的路径静默留下陈旧时间戳。
-- 语义是「最近一次**写入**」而非「最近一次**变更**」:set_active 用
-- `where ... is distinct from ...` 守卫,值没变就不 UPDATE、触发器也就不触发。
create trigger user_active_tenant_set_updated_at
    before update on user_active_tenant for each row execute function set_updated_at_utc();

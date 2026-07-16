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
-- **FK 策略刻意不对称**:user_id 挂 cascade(用户没了,成员资格自然没意义),
-- tenant_id **不挂 cascade** —— 租户只软删、不硬删(spec §4.4 拿软删当安全控制)。
-- 没有 cascade 意味着 `delete from tenants` 在还有成员时会被 FK 拒绝,这正是想要的:
-- 别顺手给它补 cascade,那会让一次误删 tenants 行静默清空全部成员资格、绕过软删这道闸。
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
-- tenant_id 同样刻意不挂 cascade,理由同 tenant_members。
create table user_active_tenant (
    user_id    uuid        primary key references users (id) on delete cascade,
    tenant_id  uuid        not null references tenants (id),
    updated_at timestamptz not null default (now() at time zone 'utc')
);
-- updated_at 归触发器,不归写方 —— 全仓凡有 updated_at 的表都是这个范式
-- (users/sessions/roles/widgets/profiles 无一例外)。写方手写 `updated_at = now()`
-- 会让任何忘了写的路径静默留下陈旧时间戳。
create trigger user_active_tenant_set_updated_at
    before update on user_active_tenant for each row execute function set_updated_at_utc();

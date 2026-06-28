-- idm RBAC:roles + user_roles(多对多 role-only)。permissions 属业务授权策略,不在脚手架。
-- name=机器码(代码/JWT 引用,唯一稳定);display_name=展示名(UI,可改)。
-- set_updated_at_utc() 已由 0001 在 idm schema 建好,本迁移**同 schema 直接复用**(可达)。

-- ── roles:角色定义(实体:有独立 id + 审计 + 软删)──
create table roles (
    id           uuid        primary key,
    name         text        not null,            -- 机器码:'admin'/'editor';代码/JWT 引用,唯一稳定
    display_name text        not null,            -- 展示名:'管理员'/'编辑者';UI 用,可改
    created_by   text,
    created_at   timestamptz not null default (now() at time zone 'utc'),
    updated_by   text,
    updated_at   timestamptz not null default (now() at time zone 'utc'),
    deleted_at   timestamptz
);
-- name 唯一:仅对存活行(软删后可复用同名)
create unique index roles_name_alive_uidx on roles (name) where deleted_at is null;
create trigger roles_set_updated_at
    before update on roles for each row execute function set_updated_at_utc();

-- ── user_roles:用户↔角色多对多(**事实**,非实体)──
-- 一行 = 一句"用户 X 拥有角色 Y";撤销 = 删行。故不套 base-entity:
-- 无 updated_by(关系不被修改)、无 deleted_at(没有"软假");只记 granted_by/at(谁何时授予)。
create table user_roles (
    user_id    uuid        not null references users (id) on delete cascade,
    role_id    uuid        not null references roles (id) on delete cascade,
    granted_by text,
    granted_at timestamptz not null default (now() at time zone 'utc'),
    primary key (user_id, role_id)
);
create index user_roles_role_id_idx on user_roles (role_id);  -- 按角色反查用户(如删角色前列出受影响用户)

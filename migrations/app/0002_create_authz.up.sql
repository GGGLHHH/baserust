-- app 侧授权(authz 归 app):权限词表 catalog + role→权限映射。
-- **enum(src/infra/authz.rs 的 Perm)仍是 enforcement 唯一真相**;这两张表是其持久化/可运行时改的镜像。
-- idm 0002 头注已明:"permissions 属业务授权策略,不在脚手架(idm)" → 故落 app schema。
-- seed.toml 幂等引导这两张表(见 src/app/policy_repo.rs::seed_authz);Policy 设 APP_DB_HOST 时读表、否则读 seed.toml。

-- ① permissions:权限词表(catalog)。key = Perm wire 串(代码闭集的镜像);description 人读说明。
-- 非实体、无软删:词表由 enum 决定、不在运行期 CRUD;启动期校验 seed 声明 == 闭集(SeedData::assert_permission_catalog)。
create table permissions (
    key         text        primary key,
    description text        not null,
    created_at  timestamptz not null default (now() at time zone 'utc')
);

-- ② role_permissions:role→权限映射(**事实表**,照 idm.user_roles 范式)。
-- 一行 = 一句"角色 X 有权限 Y";撤销 = 删行;无 updated_by/deleted_at(关系不被改、无软删)。
-- role_name:**跨 schema 标识引用** idm.roles.name(非 FK —— 禁跨 schema join;JWT 本就带 role name)。
-- permission:**同 schema FK** → permissions(key),引用完整性(不能授一个不存在的权限)。
create table role_permissions (
    role_name  text        not null,
    permission text        not null references permissions (key),
    granted_by text,
    granted_at timestamptz not null default (now() at time zone 'utc'),
    primary key (role_name, permission)
);
-- 按权限反查角色(如"哪些角色有 widgets:delete")。
create index role_permissions_permission_idx on role_permissions (permission);

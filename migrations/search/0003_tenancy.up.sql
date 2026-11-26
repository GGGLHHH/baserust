-- 多租户(单机):search schema 的两张读模型改造。设计见 baserust-stack docs/superpowers/specs/2026-11-25-multi-tenant-design.md
-- §4.4 / §4.5 / §6.1 / §6.3。
--
-- 1) 原 admin_user_index(一个账号一行)改名为 **account_index**:账号目录,**全局**(不分租户、不开 RLS,
--    进 tests/rls_audit.rs 的 GLOBAL_TABLES)。数据原样保留 —— 它是成员行账号列的来源:成员事件
--    (tenant.member_*)只带 tenant_id / user_id / 状态 / 角色,加入租户时从这里抄 username / 显示名等。
-- 2) 新建 admin_user_index = **租户成员索引**,主键 (tenant_id, user_id),一个成员关系一行;ENABLE + FORCE RLS。
--    成员关系在 idm 库里(跨 schema,迁移读不到),所以**建出来是空的**:升级后跑一次 rebuild_search 回填
--    (读 idm 的租户 + 成员关系 + 账号 + app 的资料,每个成员关系一行),之后由投影器按事件维护。
-- 3) auth_event 加 tenant_id(可空:登录失败等事件没有租户)。auth_event 仍是平台级表(只有平台管理员看,
--    走 search_system 池),不开 RLS。

-- ── 1) 账号目录 ──
alter table admin_user_index rename to account_index;
alter index admin_user_index_pkey rename to account_index_pkey;
alter index admin_user_index_roles_idx rename to account_index_roles_idx;
alter index admin_user_index_created_at_idx rename to account_index_created_at_idx;

-- 账号目录只由投影器 / rebuild_search(search_system,BYPASSRLS)写;运行时账号(请求路径)只读。
-- auth_event(平台级认证审计)同理:只由投影器 / 清理任务经 search_system 写。
-- 运行时账号名可配(SEARCH_DB_USER),迁移里不写死:收回「除 owner 外、非 BYPASSRLS 账号」对它们的写权限。
-- 部署脚本 10-tenancy-roles.sh 每次按「全部表」重授 DML,所以那里也有同样的收回(两处一致)。
do $$
declare r record;
begin
    for r in select ro.rolname, t.tbl
               from pg_roles ro
              cross join (values ('account_index'), ('auth_event')) as t (tbl)
              where ro.rolname <> current_user
                and ro.rolname !~ '^pg_'
                and not ro.rolsuper
                and not ro.rolbypassrls
                and (has_table_privilege(ro.oid, t.tbl, 'INSERT')
                  or has_table_privilege(ro.oid, t.tbl, 'UPDATE')
                  or has_table_privilege(ro.oid, t.tbl, 'DELETE'))
    loop
        execute format('revoke insert, update, delete on %I from %I', r.tbl, r.rolname);
    end loop;
end $$;

-- ── 2) 租户成员索引 ──
-- 账号列(username … deleted + idm_seq;display_name + profile_seq)是 account_index 的副本,user.* /
-- profile.updated 更新该用户在所有租户里的行;成员列(roles = 租户角色、status、removed + member_seq)
-- 只由 tenant.member_* 写。removed = 已移出(墓碑:留着水位,旧的 member_added 重投不会把人加回来)。
create table admin_user_index (
    tenant_id      uuid        not null,
    user_id        uuid        not null,
    username       text,
    email          text,
    email_verified boolean     not null default false,
    display_name   text,
    created_at     timestamptz,
    deleted        boolean     not null default false,
    idm_seq        bigint,
    profile_seq    bigint,
    roles          text[]      not null default '{}',
    status         text,
    removed        boolean     not null default false,
    member_seq     bigint,
    updated_at     timestamptz not null default (now() at time zone 'utc'),
    primary key (tenant_id, user_id),
    constraint admin_user_index_tenant_not_nil check (tenant_id <> '00000000-0000-0000-0000-000000000000')
);
-- 账号事件按 user_id 改该用户的全部行。
create index admin_user_index_user_idx on admin_user_index (user_id);
-- 列表默认按 created_at 排(租户内);角色过滤用 GIN(同原表的取舍:搜索走 ILIKE,不建文本索引)。
create index admin_user_index_tenant_created_idx on admin_user_index (tenant_id, created_at);
create index admin_user_index_roles_idx on admin_user_index using gin (roles);

alter table admin_user_index enable row level security;
alter table admin_user_index force row level security;
create policy tenant_isolation on admin_user_index
    using      (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ── 3) 认证审计记租户 ──
alter table auth_event add column tenant_id uuid;
alter table auth_event add constraint auth_event_tenant_not_nil
    check (tenant_id is null or tenant_id <> '00000000-0000-0000-0000-000000000000');
create index auth_event_tenant_time_idx on auth_event (tenant_id, occurred_at desc) where tenant_id is not null;

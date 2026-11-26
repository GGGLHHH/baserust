-- 多租户身份模型(spec §4.1 / §4.7):tenants + tenant_members + member_roles;roles 加 scope;sessions 加 tenant_id。
-- 再建默认租户、把存活账号加为它的成员、把 user_roles 复制进它的 member_roles。
-- 无 schema 前缀:同 0001-0003,靠 idm role 的 search_path=idm 落位。idm 表不开 RLS(身份权威,登录要跨租户查)。

-- ── tenants:租户(实体:审计 + 软删)──
create table tenants (
    id         uuid        primary key,                      -- uuid v7;默认租户是固定常量
    slug       text        not null,                         -- 全局唯一,**删除后也不复用**
    name       text        not null,
    status     text        not null default 'active'
                           check (status in ('active', 'suspended')),
    created_by text,
    created_at timestamptz not null default (now() at time zone 'utc'),
    updated_by text,
    updated_at timestamptz not null default (now() at time zone 'utc'),
    deleted_at timestamptz
);
-- slug 唯一**不带** deleted_at 条件:软删后 slug 仍占着(防旧链接 / 旧书签指到新租户)
create unique index tenants_slug_uidx on tenants (slug);
create trigger tenants_set_updated_at
    before update on tenants for each row execute function set_updated_at_utc();

-- ── tenant_members:账号 ↔ 租户的成员关系 ──
-- 移出 = 删行(连带 member_roles);停用 = status inactive(关系与角色保留)。
create table tenant_members (
    tenant_id    uuid        not null references tenants (id),
    user_id      uuid        not null references users (id) on delete cascade,
    status       text        not null default 'active'
                             check (status in ('active', 'inactive')),
    last_used_at timestamptz,                                -- 最近一次进入该租户;登录默认进最近的
    added_by     text,
    added_at     timestamptz not null default (now() at time zone 'utc'),
    primary key (tenant_id, user_id)
);
create index tenant_members_user_id_idx on tenant_members (user_id);  -- 登录时按人查所属租户

-- ── member_roles:成员在该租户内的租户角色(事实,同 user_roles 不套 base-entity)──
create table member_roles (
    tenant_id  uuid        not null,
    user_id    uuid        not null,
    role_id    uuid        not null references roles (id) on delete cascade,
    granted_by text,
    granted_at timestamptz not null default (now() at time zone 'utc'),
    primary key (tenant_id, user_id, role_id),
    foreign key (tenant_id, user_id) references tenant_members (tenant_id, user_id) on delete cascade
);
create index member_roles_role_id_idx on member_roles (role_id);

-- ── roles.scope:平台角色(经 user_roles)/ 租户角色(经 member_roles)。读取时按它过滤 ──
-- 由消费方的角色闭集决定,RoleRepo::upsert 每次按传入值校正。
alter table roles
    add column scope text not null default 'tenant' check (scope in ('platform', 'tenant'));

-- ── sessions.tenant_id:会话所在租户;NULL = 平台上下文 ──
alter table sessions add column tenant_id uuid references tenants (id);
create index sessions_tenant_active_idx on sessions (tenant_id, user_id)
    where revoked_at is null and tenant_id is not null;  -- 移出成员 / 停用租户时按租户吊销

-- ── 默认租户 + 存量回填 ──
insert into tenants (id, slug, name, created_by, updated_by)
values ('00000000-0000-0000-0000-000000000001', 'default', '默认组织', 'system', 'system')
on conflict do nothing;

-- 每个存活账号成为默认租户的 active 成员
insert into tenant_members (tenant_id, user_id, status, added_by)
select '00000000-0000-0000-0000-000000000001', u.id, 'active', 'system'
from users u
where u.deleted_at is null
on conflict do nothing;

-- user_roles **复制**进默认租户的 member_roles(不搬:平台角色留在 user_roles,两边都按 scope 过滤读取)
insert into member_roles (tenant_id, user_id, role_id, granted_by)
select '00000000-0000-0000-0000-000000000001', ur.user_id, ur.role_id, 'system'
from user_roles ur
join users u on u.id = ur.user_id and u.deleted_at is null
on conflict do nothing;

-- superadmin 是平台角色;升级后仍能用后台:在默认租户兼任 admin(spec §4.7)。
-- 角色不存在(未跑过 seed 的空库)时两句都是空操作;之后 seed 的 upsert 会按代码闭集再校正 scope。
update roles set scope = 'platform' where name = 'superadmin' and deleted_at is null;

insert into member_roles (tenant_id, user_id, role_id, granted_by)
select '00000000-0000-0000-0000-000000000001', ur.user_id, admin.id, 'system'
from user_roles ur
join roles sa on sa.id = ur.role_id and sa.name = 'superadmin' and sa.deleted_at is null
join roles admin on admin.name = 'admin' and admin.deleted_at is null
join users u on u.id = ur.user_id and u.deleted_at is null
on conflict do nothing;

-- 升级前登录的有效会话归进默认租户:否则 refresh 沿用 NULL 租户 → 平台上下文,老账号要手动选一次组织。
-- 只回填仍是默认租户 active 成员的账号(上面刚加的);已吊销的会话不动。
update sessions s
   set tenant_id = '00000000-0000-0000-0000-000000000001'
 where s.tenant_id is null
   and s.revoked_at is null
   and exists (select 1 from tenant_members m
                where m.tenant_id = '00000000-0000-0000-0000-000000000001'
                  and m.user_id = s.user_id
                  and m.status = 'active');

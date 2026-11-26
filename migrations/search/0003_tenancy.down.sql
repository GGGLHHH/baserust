-- 回退 0003_tenancy:删成员索引(成员关系的投影,源头在 idm,丢了可再投影)、账号目录改回 admin_user_index、
-- auth_event 去掉 tenant_id(已记录的租户信息丢失)。

drop index if exists auth_event_tenant_time_idx;
alter table auth_event drop constraint if exists auth_event_tenant_not_nil;
alter table auth_event drop column if exists tenant_id;

drop table if exists admin_user_index;

alter index account_index_created_at_idx rename to admin_user_index_created_at_idx;
alter index account_index_roles_idx rename to admin_user_index_roles_idx;
alter index account_index_pkey rename to admin_user_index_pkey;
alter table account_index rename to admin_user_index;

-- 多租户之前运行时账号对这张表有 DML(0003 收回过):还给「能读它、非 BYPASSRLS」的账号。
do $$
declare r record;
begin
    for r in select ro.rolname
               from pg_roles ro
              where ro.rolname <> current_user
                and ro.rolname !~ '^pg_'
                and not ro.rolsuper
                and not ro.rolbypassrls
                and has_table_privilege(ro.oid, 'admin_user_index', 'SELECT')
    loop
        execute format('grant insert, update, delete on admin_user_index to %I', r.rolname);
    end loop;
end $$;

drop index if exists sessions_tenant_active_idx;
alter table sessions drop column if exists tenant_id;
alter table roles drop column if exists scope;
drop table if exists member_roles;
drop table if exists tenant_members;
drop trigger if exists tenants_set_updated_at on tenants;
drop table if exists tenants;

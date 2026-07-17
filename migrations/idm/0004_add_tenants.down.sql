-- 反序 drop(FK 依赖:user_active_tenant/tenant_members → tenants)。
-- set_updated_at_utc() 是 0001 建的共用函数,**不在此删**。
-- ⚠️ 这不是"回滚",是"重来":drop 掉的成员资格无法恢复。
drop trigger if exists user_active_tenant_set_updated_at on user_active_tenant;
drop table if exists user_active_tenant;
drop table if exists tenant_members;
drop trigger if exists tenants_set_updated_at on tenants;
drop table if exists tenants;

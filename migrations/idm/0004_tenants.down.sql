-- 回滚前先把默认租户里**租户作用域**的成员角色对回 user_roles:升级后在默认租户授出的角色
-- (新注册账号的 user、后台给成员加的 admin 等)只在 member_roles 里,直接删表就丢了;回到 0003 的
-- 单租户模型后它们只能靠 user_roles 表达。平台角色本来就在 user_roles,别的租户的角色在单租户模型里没有
-- 对应位置,都不动 / 不写回。两句都必须在删 roles.scope 之前跑。
--
-- 1. 先对账:up 只**复制**不搬,user_roles 里还留着升级前的租户角色行。升级后在默认租户被撤掉的角色、
--    被停用(status = 'inactive')或被移出的成员,这些旧行还在 —— 不删就会在回滚后复活。
--    所以删掉 user_roles 里租户作用域、但在默认租户 active 成员的 member_roles 里没有的行。
delete from user_roles ur
using roles r
where r.id = ur.role_id
  and r.scope = 'tenant'
  and not exists (
      select 1
      from member_roles mr
      join tenant_members m on m.tenant_id = mr.tenant_id
                           and m.user_id = mr.user_id
                           and m.status = 'active'
      where mr.tenant_id = '00000000-0000-0000-0000-000000000001'
        and mr.user_id = ur.user_id
        and mr.role_id = ur.role_id
  );

-- 2. 再写回:只取默认租户 **active** 成员的租户角色(停用的成员回滚后不该有角色);已有的行不重复。
insert into user_roles (user_id, role_id, granted_by)
select mr.user_id, mr.role_id, mr.granted_by
from member_roles mr
join tenant_members m on m.tenant_id = mr.tenant_id
                     and m.user_id = mr.user_id
                     and m.status = 'active'
join roles r on r.id = mr.role_id and r.scope = 'tenant'
where mr.tenant_id = '00000000-0000-0000-0000-000000000001'
on conflict do nothing;

drop index if exists sessions_tenant_active_idx;
alter table sessions drop column if exists tenant_id;
alter table roles drop column if exists scope;
drop table if exists member_roles;
drop table if exists tenant_members;
drop trigger if exists tenants_set_updated_at on tenants;
drop table if exists tenants;

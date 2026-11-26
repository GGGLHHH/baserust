-- 多租户(spec §6.1):平台角色只取平台级权限、租户角色只取租户级权限。旧版 seed 给 superadmin 配了全部权限
-- (含 widgets:* / contents:* / admin:login 这些租户级权限)、给 admin 配过 profiles:* 等,升级后这些行
-- 在启动载入时被 WARN 并忽略(Policy::from_roles)。这里一次性删掉闭集内角色的**跨作用域**存量行,让启动不再刷 WARN;
-- 以后新出现的跨作用域行(运维手改 / 下游改闭集)仍由载入时的 WARN 兜着。
--
-- 角色作用域(RoleName::scope):superadmin = 平台;admin、user = 租户。
-- 平台级权限(Perm::scope == Platform):users:admin、tenants:admin、profiles:read、profiles:write、profiles:write:all。
-- 闭集外的角色名(下游自定义)作用域未知,不动。
delete from role_permissions
 where (role_name = 'superadmin'
        and permission not in ('users:admin', 'tenants:admin', 'profiles:read', 'profiles:write', 'profiles:write:all'))
    or (role_name in ('admin', 'user')
        and permission in ('users:admin', 'tenants:admin', 'profiles:read', 'profiles:write', 'profiles:write:all'));

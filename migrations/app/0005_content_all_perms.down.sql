-- 无条件删这两权限的全部 role_permissions 行,再删 permissions catalog 行。
-- 不按 granted_by 过滤:seed_authz 用 'system'、本迁移用 'migration' 写的是**同一逻辑行**
-- (ON CONFLICT DO NOTHING 可互换),按 'migration' 过滤会在 seed-on-start 部署上留下
-- 'system' 行,让随后的 `delete from permissions` 撞 role_permissions→permissions 的 FK 卡死回滚。
delete from role_permissions where permission in ('contents:read:all', 'contents:write:all');
delete from permissions where key in ('contents:read:all', 'contents:write:all');

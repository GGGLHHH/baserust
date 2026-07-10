-- 只删本迁移写入的行(granted_by='migration'),不动运维手工授出的同名权限;
-- permissions 行若仍被引用(手工授权)会被 FK 挡下 —— 此时先处理引用行再重跑 down。
delete from role_permissions
where permission in ('contents:read:all', 'contents:write:all')
  and granted_by = 'migration';
delete from permissions where key in ('contents:read:all', 'contents:write:all');

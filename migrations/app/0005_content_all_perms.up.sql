-- Perm 闭集新增 contents:read:all / contents:write:all(content 行级 ownership 的越权 mode)。
-- 存量部署的 permissions/role_permissions 由旧 seed 写入,prod 默认 seed_on_start 关闭 ——
-- 不补行会让 superadmin/admin 升级后对他人 content 的单条端点全部 404(fail-closed 回归)。
-- 幂等(ON CONFLICT DO NOTHING),与 seed_authz 并存安全;description 与 Perm::description 同源。
insert into permissions (key, description) values
    ('contents:read:all', '查看所有人的内容(而非仅自己)'),
    ('contents:write:all', '修改 / 删除任何人的内容(而非仅自己)')
on conflict (key) do nothing;

insert into role_permissions (role_name, permission, granted_by) values
    ('superadmin', 'contents:read:all', 'migration'),
    ('superadmin', 'contents:write:all', 'migration'),
    ('admin', 'contents:read:all', 'migration'),
    ('admin', 'contents:write:all', 'migration')
on conflict (role_name, permission) do nothing;

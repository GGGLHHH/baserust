delete from role_permissions where permission in ('contents:read:all', 'contents:write:all');
delete from permissions where key in ('contents:read:all', 'contents:write:all');

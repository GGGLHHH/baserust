-- 先删引用方(role_permissions FK → permissions),再删被引用方。
drop table if exists role_permissions;
drop table if exists permissions;

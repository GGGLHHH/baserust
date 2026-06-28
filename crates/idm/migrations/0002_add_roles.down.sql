drop table if exists user_roles;
drop trigger if exists roles_set_updated_at on roles;
drop table if exists roles;
-- set_updated_at_utc() 是 0001 建的、users/sessions 仍在用,本迁移**不删**(留给 0001 down)。

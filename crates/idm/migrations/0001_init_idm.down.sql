drop trigger if exists sessions_set_updated_at on sessions;
drop trigger if exists user_password_set_updated_at on user_password;
drop trigger if exists users_set_updated_at on users;
drop table if exists sessions;
drop table if exists user_password;
drop table if exists users;
-- idm 自有函数,本 migration 自包含 → down 最后删掉(不留垃圾)。
drop function if exists set_updated_at_utc();

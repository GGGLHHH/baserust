drop trigger if exists profiles_set_updated_at on profiles;
drop table if exists profiles;
-- set_updated_at_utc() 是 0001 的共用函数,归 0001 的 down 管,这里不动。

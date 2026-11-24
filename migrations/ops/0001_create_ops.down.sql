drop table if exists log_record;
drop table if exists db_op_hour;
drop table if exists route_hour;
drop table if exists metric_hour;
drop table if exists metric_minute;
drop function if exists add_buckets(bigint[], bigint[]);

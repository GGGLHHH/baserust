-- 日志归属的服务(app / idm):分进程时 = 进程身份,单进程开发时按接口前缀 / 代码模块推断
-- (见 infra/monitor/store.rs 的 classify_service)。后台日志页按它筛选。
alter table log_record add column service text not null default 'app';
create index log_record_service_ts_idx on log_record (service, ts desc);

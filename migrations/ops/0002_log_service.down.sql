drop index if exists log_record_service_ts_idx;
alter table log_record drop column if exists service;

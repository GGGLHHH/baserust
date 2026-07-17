-- ⚠️ **down 是单向销毁,不是「回滚」**。
-- drop column 会丢掉手工 backfill 的全部结果(那是人工决定的归属,不是算出来的)——
-- 重新 up 之后必须**重跑 backfill**,否则 0006 的 set not null 会直接失败。
alter table widgets drop column tenant_id;

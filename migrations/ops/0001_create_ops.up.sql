-- ops schema:后台「系统监控」的历史指标与日志(运维数据,与业务数据分开存)。
-- 分层保留(参照 CloudWatch 的降采样做法):分钟级 15 天 / 小时级 13 个月 / 接口与数据库明细(小时)30 天 / 日志 15 天。
-- 过期数据由进程内的保留任务按小时删(见 app/monitoring.rs)。
-- 延迟直方图存成固定分桶计数数组(桶界见 infra/monitor/hist.rs):可以跨时间相加,任意时间段都能重算分位数。

-- 数组逐元素相加(小时表 upsert 累加直方图用)。
create function add_buckets(a bigint[], b bigint[]) returns bigint[]
language sql immutable as $$
  select coalesce(array_agg(coalesce(x, 0) + coalesce(y, 0) order by ord), '{}')
  from unnest(a, b) with ordinality as t(x, y, ord)
$$;

-- 进程级汇总。分钟表与小时表同结构:计数类为该时间段内的增量,读数类为该时间段内的最大值。
create table metric_minute (
    instance            text        not null,  -- app / idm / combined
    bucket              timestamptz not null,  -- 时间段起点(UTC,整分 / 整点)
    requests            bigint      not null,
    errors_4xx          bigint      not null,
    errors_5xx          bigint      not null,
    latency_buckets     bigint[]    not null,
    db_calls            bigint      not null,
    db_latency_buckets  bigint[]    not null,
    outbox_published    bigint      not null,
    outbox_failures     bigint      not null,
    projector_processed bigint      not null,
    projector_failed    bigint      not null,
    in_flight_max       bigint      not null,
    pool_in_use_max     bigint      not null,
    pool_max            bigint      not null,
    sse_max             bigint      not null,
    projector_pending_max bigint    not null,
    rss_bytes_max       bigint,
    cpu_percent_max     double precision,
    primary key (instance, bucket)
);
create index metric_minute_bucket_idx on metric_minute (bucket);

create table metric_hour (like metric_minute including all);

-- 按接口(路由模板)的小时明细。
create table route_hour (
    instance        text        not null,
    bucket          timestamptz not null,
    method          text        not null,
    route           text        not null,
    requests        bigint      not null,
    errors_4xx      bigint      not null,
    errors_5xx      bigint      not null,
    latency_buckets bigint[]    not null,
    primary key (instance, bucket, method, route)
);
create index route_hour_bucket_idx on route_hour (bucket);

-- 按数据库操作(仓储方法)的小时明细。
create table db_op_hour (
    instance        text        not null,
    bucket          timestamptz not null,
    operation       text        not null,
    calls           bigint      not null,
    latency_buckets bigint[]    not null,
    primary key (instance, bucket, operation)
);
create index db_op_hour_bucket_idx on db_op_hour (bucket);

-- 日志:WARN 及以上 + 失败请求(5xx)+ 慢请求。字段对齐 OpenTelemetry 日志数据模型
-- (Timestamp / SeverityText / Body / Resource(instance)/ Attributes),请求上下文单独成列方便筛选。
create table log_record (
    id          bigint generated always as identity primary key,
    ts          timestamptz not null,
    instance    text        not null,
    severity    text        not null,  -- WARN / ERROR
    target      text        not null,  -- 产生日志的模块
    body        text        not null,
    request_id  text,
    method      text,
    route       text,
    status      integer,
    duration_ms double precision,
    attributes  jsonb       not null default '{}'
);
create index log_record_ts_idx on log_record (ts desc);
create index log_record_request_idx on log_record (request_id) where request_id is not null;
create index log_record_severity_ts_idx on log_record (severity, ts desc);

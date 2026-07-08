-- 认证审计读模型(CQRS)。projector 从 events.idm.auth.* 投影;append-only(只 insert/select)。
-- 无 schema 前缀:靠 search role 的 search_path=search 落位(同 admin_user_index)。
-- Phase 1:普通表 + 90 天 DELETE 保留(分区是后续规模优化,表结构前向兼容)。
create table auth_event (
    id                   uuid        primary key,               -- v7,投影时生成;兼作 keyset 排序键
    event_type           text        not null,                  -- auth.login_succeeded / ...
    occurred_at          timestamptz not null,                  -- 源事件发生时刻(保留/时间过滤按它)
    channel              text        not null,                  -- public | admin
    auth_method          text        not null default 'password',
    -- 主体
    user_id              uuid,                                  -- 失败且用户不存在时 null
    identifier_attempted text,                                  -- 提交的用户名/邮箱原文(不脱敏)
    session_id           uuid,                                  -- = jti,关联 idm.sessions
    prev_session_id      uuid,                                  -- refresh 血缘(Phase 3;Phase 1 恒 null)
    actor                text,                                  -- 触发者;撤别人会话时为 admin
    -- 结果
    outcome              text        not null,                  -- success | failure
    failure_reason       text,                                  -- unknown_user / bad_password / no_admin_perm / ...
    -- 来源(原始)
    ip                   inet,
    forwarded_chain      text,
    user_agent           text,
    request_id           text,
    -- 派生(Phase 2 填;Phase 1 恒 null)
    country              text,
    city                 text,
    asn                  bigint,
    isp_org              text,
    is_datacenter        boolean,
    os                   text,
    browser              text,
    device_type          text,
    -- 溯源
    event_seq            bigint      not null,                  -- idm.outbox 行 id;auth 事件唯一来源 → 单列去重
    projected_at         timestamptz not null default (now() at time zone 'utc')
);
-- 幂等:同一 idm outbox 行重投一次 → 唯一键吸收(projector INSERT ... ON CONFLICT DO NOTHING)。
create unique index auth_event_seq_uidx on auth_event (event_seq);
-- 某用户历史(admin/用户活动);全局审计流按 ip 聚合(安全);keyset 翻页按 id v7。
create index auth_event_user_time_idx on auth_event (user_id, occurred_at desc);
create index auth_event_ip_time_idx   on auth_event (ip, occurred_at desc) where ip is not null;
create index auth_event_id_idx        on auth_event (id desc);
-- 保留:DELETE WHERE occurred_at < now()-90d 走它。
create index auth_event_occurred_idx  on auth_event (occurred_at);

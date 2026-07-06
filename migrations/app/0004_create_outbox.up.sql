-- outbox:事务性发件箱(transactional outbox)。app schema 侧,镜像 idm 侧同名表(rust-idm
-- migrations/0003_add_outbox.up.sql)——列/索引形状一致,列同形是刻意的:两侧后续都要跑同一套 relay。
-- 领域写(如 profile upsert)与事件记录同一事务落地,后台轮询(poll_unpublished)取未发布行发到
-- 外部总线,发完 mark_published 标记。
-- 无 schema 前缀:同 0001/0002/0003,靠 app role 的 search_path=app 落位。
create table outbox (
    id           bigserial   primary key,
    event_type   text        not null,
    aggregate_id uuid        not null,
    payload      jsonb       not null,
    created_at   timestamptz not null default (now() at time zone 'utc'),
    published_at timestamptz
);
-- 未发布行的部分索引:poll_unpublished(WHERE published_at IS NULL ORDER BY id)走它。
create index outbox_unpublished_idx on outbox (id) where published_at is null;

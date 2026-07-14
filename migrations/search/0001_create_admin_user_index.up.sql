-- admin_user_index:CQRS 读模型(去规范化)。idm 事件写 username/email/email_verified/roles/created_at/deleted+idm_seq;
-- profile 事件写 display_name+profile_seq。两源列不相交。双水位守卫乱序/重放(见 projector)。
create table admin_user_index (
    user_id        uuid        primary key,
    username       text,
    email          text,
    email_verified boolean     not null default false,
    display_name   text,
    roles          text[]      not null default '{}',
    created_at     timestamptz,
    deleted        boolean     not null default false,
    idm_seq        bigint,
    profile_seq    bigint,
    updated_at     timestamptz not null default (now() at time zone 'utc')
);
-- 搜索走 ILIKE '%term%'(大小写不敏感 + 前导通配),text_pattern_ops/B-tree 均无法命中 → username/display_name
-- 不建文本索引:admin_user_index 是有界读模型(用户量级),管理端搜索 seq-scan 可接受。真要子串加速,
-- 则 `CREATE EXTENSION pg_trgm` 后对 username/display_name 建 GIN(gin_trgm_ops)。roles 用 GIN;created_at 区间。
create index admin_user_index_roles_idx on admin_user_index using gin (roles);
create index admin_user_index_created_at_idx on admin_user_index (created_at);

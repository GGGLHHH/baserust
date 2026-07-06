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
-- 前缀/模糊搜索(P4 用):username/display_name 加 text_pattern_ops 支持 LIKE 'x%';roles 用 GIN;created_at 区间。
create index admin_user_index_username_idx on admin_user_index (username text_pattern_ops);
create index admin_user_index_display_name_idx on admin_user_index (display_name text_pattern_ops);
create index admin_user_index_roles_idx on admin_user_index using gin (roles);
create index admin_user_index_created_at_idx on admin_user_index (created_at);

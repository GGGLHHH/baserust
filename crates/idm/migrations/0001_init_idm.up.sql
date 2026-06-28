-- idm schema 第一版:users + user_password + sessions。
-- 无 schema 前缀:靠 idm role 的 search_path=idm 落位(对齐 app 的写法)。
-- 时间统一 UTC timestamptz;updated_at 由本 schema **自有**的触发器函数维护。

-- updated_at 自动维护函数:idm **自建一份**。app schema 的同名函数跨 schema 不可达
-- (idm role 的 search_path=idm、且对 app schema 无 USAGE),故各 schema 各建一份、互不冲突。
create or replace function set_updated_at_utc()
returns trigger as $$
begin
    new.updated_at = (now() at time zone 'utc');
    return new;
end;
$$ language plpgsql;

-- ── users:账户主体 + 审计 + 软删 ──
-- username 是主登录标识(必填、唯一);email 可选(有则唯一,也可当登录标识)。去掉 name(username 兼显示)。
create table users (
    id             uuid        primary key,
    username       text        not null,                        -- 登录标识 + 显示,唯一稳定
    email          text,                                        -- 可选邮箱;归一为小写,有则唯一、可登录
    email_verified boolean     not null default false,
    created_by     text,
    created_at     timestamptz not null default (now() at time zone 'utc'),
    updated_by     text,
    updated_at     timestamptz not null default (now() at time zone 'utc'),
    deleted_at     timestamptz
);
-- username 唯一(仅存活行,软删后可复用);email 可选 → 仅对有值的存活行唯一
create unique index users_username_alive_uidx on users (username) where deleted_at is null;
create unique index users_email_alive_uidx on users (email)
    where email is not null and deleted_at is null;
-- 存活 + keyset(id v7 单列全序)翻页/计数索引
create index users_alive_id_idx on users (id desc) where deleted_at is null;
create trigger users_set_updated_at
    before update on users for each row execute function set_updated_at_utc();

-- ── user_password:凭据分表(1:1,随 user 级联删)──
-- 故意精简:无 created_by/updated_by —— 操作者恒为该 user 本人(= user_id)。
create table user_password (
    user_id             uuid        primary key references users (id) on delete cascade,
    password_hash       text        not null,                   -- argon2id PHC 串(盐内嵌)
    password_updated_at timestamptz not null default (now() at time zone 'utc'),
    created_at          timestamptz not null default (now() at time zone 'utc'),
    updated_at          timestamptz not null default (now() at time zone 'utc')
);
create trigger user_password_set_updated_at
    before update on user_password for each row execute function set_updated_at_utc();

-- ── sessions:refresh token 落地(只存 SHA-256 hash)──
-- 生命周期用 revoked_at(撤销语义已够,不用软删 deleted_at);id 同时作 JWT 的 jti。
create table sessions (
    id          uuid        primary key,
    user_id     uuid        not null references users (id) on delete cascade,
    token_hash  text        not null,                            -- refresh token 的 SHA-256(base64url)
    expires_at  timestamptz not null,
    revoked_at  timestamptz,
    created_by  text,
    created_at  timestamptz not null default (now() at time zone 'utc'),
    updated_by  text,
    updated_at  timestamptz not null default (now() at time zone 'utc')
);
create unique index sessions_token_hash_uidx on sessions (token_hash);                 -- refresh 校验按 hash 查
create index sessions_user_active_idx on sessions (user_id) where revoked_at is null;  -- logout-all
create trigger sessions_set_updated_at
    before update on sessions for each row execute function set_updated_at_utc();

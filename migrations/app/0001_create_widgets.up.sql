-- widget 示例域 + **基础实体范式**:审计字段 + 软删除,供后续业务表照抄。
-- 时间统一 UTC TIMESTAMPTZ;updated_at 由触发器自动维护(对齐 Go migrationv2/app)。
-- 基础四字段:created_by / created_at / updated_at / deleted_at。
create table widgets (
    id          uuid        primary key,
    name        text        not null,
    created_by  text,                                                   -- 谁创建(无 auth 时为 NULL)
    created_at  timestamptz not null default (now() at time zone 'utc'),
    updated_by  text,                                                   -- 谁最后更新(改名/软删都会盖)
    updated_at  timestamptz not null default (now() at time zone 'utc'),
    deleted_at  timestamptz                                             -- 软删除标记(NULL = 存活)
);

-- 存活过滤 + cursor keyset 排序键 id(v7) 的部分索引:
-- 服务 ORDER BY id DESC WHERE deleted_at IS NULL 的翻页/计数(v7 单列即严格全序)。
create index widgets_alive_id_idx
    on widgets (id desc) where deleted_at is null;

-- updated_at 自动维护:任何 UPDATE 前盖成当前 UTC(对齐 Go 的 update_updated_at_column)。
-- 函数命名通用,后续业务表可复用同一函数,只各自建触发器。
create or replace function set_updated_at_utc()
returns trigger as $$
begin
    new.updated_at = (now() at time zone 'utc');
    return new;
end;
$$ language plpgsql;

create trigger widgets_set_updated_at
    before update on widgets
    for each row execute function set_updated_at_utc();

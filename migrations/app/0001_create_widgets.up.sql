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

-- name 在**存活行内全局唯一**(软删后可复用同名):演示"DB 约束违例下钻成 409 而非 500"。
-- 部分唯一索引(WHERE deleted_at IS NULL):唯一性只管存活行,软删后名字可被新行复用。
-- (示意性:真实业务常用 (created_by, name) 复合唯一;那需处理 created_by 为 NULL 的 NULL-distinct 语义。)
create unique index widgets_name_unique_alive
    on widgets (name) where deleted_at is null;

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

-- 子表(多对一挂 widgets):演示**父子双表事务**范式。
-- `create_with_tags` 在**一个事务**里建 1 个 widget + N 个 tag;任一 tag 撞 (widget_id, label)
-- 唯一约束 → 整笔回滚(widget 也不落库)。这是单条语句演示不出的"全有或全无"。
create table widget_tags (
    id          uuid        primary key,
    widget_id   uuid        not null references widgets (id),
    label       text        not null,
    created_at  timestamptz not null default (now() at time zone 'utc')
);

-- 同一 widget 下 label 唯一 —— 子表的失败触发点(批内重复 → 23505 → 回滚父行)。
create unique index widget_tags_widget_label_unique
    on widget_tags (widget_id, label);

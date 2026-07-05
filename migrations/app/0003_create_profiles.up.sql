-- profile 域:用户资料(姓名/电话/头像),与 idm user 1:1。
-- 照 widgets 的基础实体范式,两处刻意差异:
-- 1. **无 deleted_at**:profile 没有删除语义(不提供 DELETE 端点),与 user 同生死;
--    软删除范式只在"有删除语义的实体"上照抄,别为范式加死列。
-- 2. **user_id 即主键**:1:1 关系,单独 id 列是废话;天然防一人多行。
create table profiles (
    -- idm user 的 id。**跨 schema 引用用标识、禁 FK**(app/idm 物理隔离,见 CLAUDE.md):
    -- user 是否存在由 app 层经 UserDirectory 端口裁决,不靠库约束。
    user_id     uuid        primary key,
    -- 显示名(单字段,不拆姓/中/名):脚手架不猜文化姓名结构,展示与排序统一用它。
    display_name text,
    phone       text,
    -- content 模块的 content id。同为跨模块引用 → 标识非 FK(content 在独立 schema);
    -- 悬空(content 被删)由读侧富化降级处理(avatar_url = null),不炸列表。
    avatar_content_id uuid,
    created_by  text,
    created_at  timestamptz not null default (now() at time zone 'utc'),
    updated_by  text,
    updated_at  timestamptz not null default (now() at time zone 'utc')
);

-- updated_at 自动维护:复用 0001 的共用函数,只建自己的触发器(范式即如此)。
create trigger profiles_set_updated_at
    before update on profiles
    for each row execute function set_updated_at_utc();

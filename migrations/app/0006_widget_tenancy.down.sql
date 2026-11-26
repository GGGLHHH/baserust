-- 回退 0006_widget_tenancy:关 RLS、删策略 / 约束 / 索引 / tenant_id 列,索引恢复成 0001 / 0005 的单租户形状。
-- 注意:回退后名字回到**全局**唯一 —— 不同租户里有同名存活 widget 时,重建唯一索引会失败(23505),
-- 要先人工改名 / 软删再回退。数据本身不删(各租户的行合到一起,租户信息丢失)。

drop policy if exists tenant_isolation on widget_tags;
drop policy if exists tenant_isolation on widgets;
alter table widget_tags no force row level security;
alter table widget_tags disable row level security;
alter table widgets     no force row level security;
alter table widgets     disable row level security;

drop index if exists widget_tags_tenant_widget_idx;
drop index if exists widgets_alive_name_id_idx;
create index widgets_alive_name_id_idx
    on widgets (name COLLATE "C", id) where deleted_at is null;
drop index if exists widgets_alive_id_idx;
create index widgets_alive_id_idx
    on widgets (id desc) where deleted_at is null;
drop index if exists widgets_name_unique_alive;
create unique index widgets_name_unique_alive
    on widgets (name) where deleted_at is null;

alter table widget_tags drop constraint if exists widget_tags_tenant_not_nil;
alter table widgets     drop constraint if exists widgets_tenant_not_nil;
alter table widget_tags drop column if exists tenant_id;
alter table widgets     drop column if exists tenant_id;

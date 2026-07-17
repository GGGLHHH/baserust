-- ⚠️ 回退唯一约束到全局:若此刻两个租户已各有同名 widget,**本迁移会失败** —— 那是对的,
-- 它诚实地告诉你「数据已经用上了租户维度,退不回去了」,而不是替你删一行。
drop index if exists widgets_tenant_name_unique_alive;
create unique index widgets_name_unique_alive
    on widgets (name) where deleted_at is null;

drop index if exists widgets_tenant_alive_idx;
alter table widgets alter column tenant_id drop not null;

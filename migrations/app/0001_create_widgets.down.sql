-- 先删子表(有 FK 指向 widgets;否则 drop widgets 因被引用而失败)。
drop table if exists widget_tags;
drop index if exists widgets_name_unique_alive;
drop trigger if exists widgets_set_updated_at on widgets;
drop table if exists widgets;
-- 函数最后删(可能被后续业务表的触发器共用;此处脚手架仅 widgets 用,安全删)。
drop function if exists set_updated_at_utc();

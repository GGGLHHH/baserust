-- 多租户(单机):widget 按租户隔离。设计见 baserust-stack docs/superpowers/specs/2026-11-25-multi-tenant-design.md §4.4 / §4.7。
--
-- * widgets、widget_tags 都带 tenant_id(子表不靠子查询判归属,策略各看各的列)。
-- * 已有数据全部归默认租户 00000000-0000-0000-0000-000000000001;tag 从父行回填。
-- * nil UUID 永远不是合法租户(CHECK 拒);tenant_id not null(widget 没有「不属于任何租户」的行)。
-- * 唯一 / keyset 索引以 tenant_id 打头:名字只在租户内唯一,列表 / 翻页走 (tenant_id, …) 索引
--   (仓储 SQL 显式写 tenant_id = $1,RLS 是第二道防线)。
-- * RLS:ENABLE + FORCE(owner 也受约束);仓储每个方法在事务里先 set_config('app.tenant_id', …, true) 再查。
--   不设 app.tenant_id 时读不到、也写不进任何行。
-- 顺序:加列 → 回填 → not null + CHECK → 索引 → 开 RLS(owner 有 BYPASSRLS,回填照样放在开 RLS 之前)。

-- ── 1) 加列 + 回填 ──
alter table widgets add column tenant_id uuid;
update widgets set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;

alter table widget_tags add column tenant_id uuid;
update widget_tags t set tenant_id = w.tenant_id from widgets w where w.id = t.widget_id;

-- ── 2) not null + nil 永远不是合法租户 ──
alter table widgets     alter column tenant_id set not null;
alter table widget_tags alter column tenant_id set not null;
alter table widgets     add constraint widgets_tenant_not_nil     check (tenant_id <> '00000000-0000-0000-0000-000000000000');
alter table widget_tags add constraint widget_tags_tenant_not_nil check (tenant_id <> '00000000-0000-0000-0000-000000000000');

-- ── 3) (tenant_id, …) 索引(名字沿用,代码注释 / 文档里的引用不用改)──
-- 名字在**本租户**存活行内唯一(软删后可复用):别的租户可以同名。
drop index if exists widgets_name_unique_alive;
create unique index widgets_name_unique_alive
    on widgets (tenant_id, name) where deleted_at is null;
-- 默认序 keyset / offset / 计数:WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY id。
drop index if exists widgets_alive_id_idx;
create index widgets_alive_id_idx
    on widgets (tenant_id, id desc) where deleted_at is null;
-- sort_by=name 的 keyset:(name COLLATE "C", id),前面加 tenant_id(collation 必须与查询的 sort_expr 一致)。
drop index if exists widgets_alive_name_id_idx;
create index widgets_alive_name_id_idx
    on widgets (tenant_id, name COLLATE "C", id) where deleted_at is null;
-- tag 按 (tenant_id, widget_id) 取(tags_of)。(widget_id, label) 唯一照旧:widget id 全局唯一,不必带租户。
create index widget_tags_tenant_widget_idx
    on widget_tags (tenant_id, widget_id);

-- ── 4) RLS(USING 与 WITH CHECK 同一表达式;没设 app.tenant_id → nullif 成 NULL → 谁都不匹配)──
alter table widgets enable row level security;
alter table widgets force row level security;
create policy tenant_isolation on widgets
    using      (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table widget_tags enable row level security;
alter table widget_tags force row level security;
create policy tenant_isolation on widget_tags
    using      (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- **backfill 之后才跑**(spec §3.3 第 5 步)。库里还有 tenant_id is null 的行时本迁移会失败 ——
-- 那是**特性**:它逼你先做完第 4 步的人工归属决定,而不是让约束替你猜。
alter table widgets alter column tenant_id set not null;

-- 租户是所有读的**第一谓词**(base_select 里),软删过滤是第二个 —— 索引照这个顺序。
create index widgets_tenant_alive_idx on widgets (tenant_id) where deleted_at is null;

-- ⚠️ **唯一约束必须收进租户维度** —— 这是「加 tenant_id 列」最容易漏的一类。
--
-- 原索引是 `unique (name) where deleted_at is null`,**全局唯一**。上了租户轴之后它有两个后果:
--   ① 功能:两家毫无关系的公司不能有同名 widget —— Acme 建了「月度报表」,Globex 就建不了。
--   ② 安全:它是个**跨租户探测器**。Globex 挨个试名字、看 201 还是 409,就能枚举出 Acme
--      有哪些 widget。一行数据没泄,名字全泄了。
--
-- 通则:**租户轴上的每一个唯一约束,都要把 tenant_id 加进去**;不然它就是一个跨租户的
-- 存在性预言机。(子表的 `widget_tags (widget_id, label)` 不用改 —— widget_id 已经传递性地
-- 属于某个租户,两家各自的 widget 可以有同名 label。)
drop index widgets_name_unique_alive;
create unique index widgets_tenant_name_unique_alive
    on widgets (tenant_id, name) where deleted_at is null;

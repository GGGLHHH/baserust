-- cursor keyset 按 (name, id) 的复合索引:服务 sort_by=name 的 keyset 翻页
-- (ORDER BY name COLLATE "C" <dir>, id <dir>,谓词同键)。
--
-- COLLATE "C" 必须与查询里 sort_expr 的 collation 一致,否则索引不可用 ——
-- 且 keyset 谓词与 ORDER BY 口径分叉会**直接漏行**(offset 下同样的不一致只是顺序难看)。
--
-- 一条覆盖两个方向:PG 可反向扫描复合索引(asc/desc 整体反转即可,无需各建一条)。
-- 部分索引(WHERE deleted_at IS NULL)对齐列表查询的存活过滤。
create index widgets_alive_name_id_idx
    on widgets (name COLLATE "C", id) where deleted_at is null;

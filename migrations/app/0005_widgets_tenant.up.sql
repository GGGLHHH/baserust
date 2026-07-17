-- widget 上租户轴 —— **只加可空列**,不 backfill、不收紧。
--
-- 顺序是安全约束不是洁癖(spec §3.3):真值来源(idm 三张表 + seed)→ 加列 → **手工 backfill**
-- → 收紧约束(0006)→ 最后才开读侧闸。反了的话,今天用 content 那个可伪造的 tenant_id
-- 字段预植的行,会在开闸瞬间落进受害租户。
--
-- ⚠️ **绝不给 tenant_id 加 default**,两条理由:
-- (a) `add column ... not null default 'X'` 在 PG 里的语义就是**一次写进迁移的全量 backfill**
--     —— 正是下面禁止的「迁移替你猜归属」。
-- (b) 更隐蔽:本仓 SQL 全是 sea-query 拼串、**零条 sqlx::query! 宏**,INSERT 漏写 tenant_id
--     没有任何编译期检查。留着 default 就是给「INSERT 漏列」发的静默通行证 —— repo 签名上那个
--     非 Option 的 TenantId 首参只保住函数签名,保不住签名到 SQL 之间那一段。
--
-- 裸 uuid、**无 FK**:跨 schema(tenants 住 idm),照 0003_create_profiles 的既有理由。
alter table widgets add column tenant_id uuid;

comment on column widgets.tenant_id is
    '所属租户(idm.tenants.id)。标识引用非 FK —— 跨 schema。0006 之前可空(backfill 窗口)。';

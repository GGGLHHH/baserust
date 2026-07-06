//! search 读模型行类型 —— 对应 `migrations/search` 的 `admin_user_index` 表(CQRS 投影,
//! idm + profile 双源写、双水位)。

use time::OffsetDateTime;
use uuid::Uuid;

/// `admin_user_index` 一行。**idm 源列**(username/email/email_verified/roles/created_at/deleted +
/// `idm_seq`)与 **profile 源列**(display_name + `profile_seq`)**不相交** —— 各自独立水位守卫
/// 乱序/重放,互不覆盖对方的字段(见 `repo::SearchIndexRepo`)。
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AdminUserIndexRow {
    pub user_id: Uuid,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub created_at: Option<OffsetDateTime>,
    pub deleted: bool,
    pub idm_seq: Option<i64>,
    pub profile_seq: Option<i64>,
}

/// `SearchIndexRepo::query` 的过滤条件。`username` 是**仅 username** 的模糊子串(大小写不敏感);
/// `q` 是 username/display_name 的模糊子串(大小写不敏感)——两者是不同的过滤,都给出时 AND 组合。
/// `roles_any`/`roles_none` 是 roles 集合的交集判定;`created_from`/`created_to` 是闭区间。
/// 全部字段留空 = 不过滤(除固定的 `username IS NOT NULL AND !deleted` 基线,见 repo 实现)。
#[derive(Debug, Clone, Default)]
pub struct IndexQuery {
    pub username: Option<String>,
    pub q: Option<String>,
    pub roles_any: Vec<String>,
    pub roles_none: Vec<String>,
    pub created_from: Option<OffsetDateTime>,
    pub created_to: Option<OffsetDateTime>,
}

/// 排序键白名单(防注入 —— 不接受任意列名字符串)。字符串列(Username/DisplayName/Email)排序时
/// PG 侧加 `COLLATE "C"`(字节序,与内存 `Ord` parity);`CreatedAt` 是时间戳,无需 collation。
/// 全部键 `None` 值一律落最后(`NULLS LAST`),不随方向翻转。
#[derive(Debug, Clone, Copy)]
pub enum IndexSort {
    CreatedAt,
    Username,
    DisplayName,
    Email,
}

/// `query` 结果。`total` 仅 offset 分页 + `with_total` 时为 `Some`;`next_after` 仅 cursor 分页且
/// 还有下一页时为 `Some`(两者不会同时有值 —— 分页模式互斥)。
#[derive(Debug)]
pub struct IndexQueryResult {
    pub rows: Vec<AdminUserIndexRow>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

//! search 的**领域模型**:CQRS 读模型行、查询条件、排序键、查询结果 —— 对应 `migrations/search` 的两张表:
//!
//! - `account_index`(账号目录,**全局**,一个账号一行):idm 账号列 + profile 显示名。`tenant.member_added`
//!   落成员行时从这里抄账号列(成员事件只带 tenant_id / user_id / 状态 / 角色)。
//! - `admin_user_index`(**租户成员索引**,主键 `(tenant_id, user_id)`,按租户 RLS):一个成员关系一行,
//!   账号列是账号目录的副本(`user.*` / `profile.updated` 更新该用户在所有租户里的行),成员列(租户角色 /
//!   状态 / 是否已移出)只由 `tenant.member_*` 写。后台「成员」列表读它(spec §4.5 / §6.3)。
//!
//! 三个来源(idm 账号、profile、idm 成员)的列**不相交**,各自独立水位(`idm_seq` / `profile_seq` /
//! `member_seq`)守卫乱序 / 重放,互不覆盖对方的字段(见 `ports::SearchIndexRepo`)。
//! 纯 Rust;数据库行映射在 `adapters::postgres`。

use time::OffsetDateTime;
use uuid::Uuid;

use crate::kernel::tenant::TenantId;

/// `account_index` 一行(账号目录,全局)。**idm 源列**(username/email/email_verified/roles/created_at/deleted +
/// `idm_seq`)与 **profile 源列**(display_name + `profile_seq`)不相交。`roles` = **平台角色**(`user.roles_set`)。
#[derive(Debug, Clone, PartialEq)]
pub struct AccountIndexRow {
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

/// `admin_user_index` 一行(租户成员索引)。账号列(username … deleted + `idm_seq` / display_name +
/// `profile_seq`)是账号目录的副本;成员列(`roles` = **租户角色**、`status`、`removed` + `member_seq`)
/// 只由成员事件写。`removed` = 已移出该租户(墓碑,保住水位:旧的 `member_added` 重投不会把人加回来)。
#[derive(Debug, Clone, PartialEq)]
pub struct AdminUserIndexRow {
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub deleted: bool,
    pub idm_seq: Option<i64>,
    pub profile_seq: Option<i64>,
    /// 该租户内的租户角色名。
    pub roles: Vec<String>,
    /// 成员状态(idm `MemberStatus` 的线上串:`active` / `inactive`);只来过账号列、还没来成员事件时为 `None`。
    pub status: Option<String>,
    pub removed: bool,
    pub member_seq: Option<i64>,
}

impl AdminUserIndexRow {
    /// 某租户里某账号的空行(成员行的起点:账号列从账号目录抄,没有就留空)。
    pub fn empty(tenant_id: TenantId, user_id: Uuid) -> Self {
        Self {
            tenant_id,
            user_id,
            username: None,
            email: None,
            email_verified: false,
            display_name: None,
            created_at: None,
            deleted: false,
            idm_seq: None,
            profile_seq: None,
            roles: Vec::new(),
            status: None,
            removed: false,
            member_seq: None,
        }
    }
}

/// `SearchIndexRepo::query` 的过滤条件。`username` 是**仅 username** 的模糊子串(大小写不敏感);
/// `q` 是 username/display_name 的模糊子串(大小写不敏感)——两者是不同的过滤,都给出时 AND 组合。
/// `roles_any`/`roles_none` 是(租户)roles 集合的交集判定;`created_from`/`created_to` 是闭区间。
/// 全部字段留空 = 不过滤(除固定的 `username IS NOT NULL AND !deleted AND !removed` 基线,见 repo 实现)。
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
/// 行类型:成员列表(`query`)是 [`AdminUserIndexRow`],平台账号列表(`query_accounts`)是 [`AccountIndexRow`]。
#[derive(Debug)]
pub struct IndexQueryResult<T = AdminUserIndexRow> {
    pub rows: Vec<T>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

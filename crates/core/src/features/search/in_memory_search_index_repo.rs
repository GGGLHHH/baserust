//! search 仓储端口的**内存适配器** —— 脚手架默认(零 DB 跑测试)。守卫在 Rust 里手写:同一把锁内取行(无则空行)、
//! 比较 `sequence` 与该行当前水位,过了才写对应源列 + 推进水位。**镜像 PG 的 `WHERE idm_seq IS NULL
//! OR idm_seq < excluded.idm_seq`**——`watermark_applies` 就是该 `IS NULL OR <` 的 Rust 版。
//!
//! 两张表各一个 map:账号目录(`user_id` → 行)与租户成员索引(`(tenant, user_id)` → 行)。账号事件写账号目录
//! 并同步该用户的全部成员行;成员事件写成员行,新行的账号列从账号目录抄(镜像 PG 的 `insert … select … from
//! account_index`)。内存实现没有 RLS:读方法按 `tenant` 参数过滤,这是唯一防线。

use std::cmp::{Ordering, Reverse};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::search::model::{
    AccountCreated, AccountIndexRow, AccountUpdated, AdminUserIndexRow, IndexQuery,
    IndexQueryResult, IndexSort,
};
use crate::features::search::search_index_repo::SearchIndexRepo;
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort_order::SortOrder;
use crate::kernel::tenant_id::TenantId;

/// `Option<T>` 比较,None 恒落最后(镜像 PG `NULLS LAST`——不随方向翻转,只有 `Some` 值按 `order` 排)。
fn compare_optional_in_order<T: Ord>(
    left: Option<T>,
    right: Option<T>,
    order: SortOrder,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => match order {
            SortOrder::Asc => left.cmp(&right),
            SortOrder::Desc => right.cmp(&left),
        },
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// 守卫判定:镜像 SQL `WHERE col IS NULL OR col < excluded.col`——水位未见过(`None`)一律放行,
/// 否则新 `sequence` 须严格大于当前水位。
fn watermark_applies(sequence: i64, current: Option<i64>) -> bool {
    current.is_none_or(|watermark| sequence > watermark)
}

/// 未见过的 user_id 的默认空行(partial row 的起点:某一源事件先到,另一源列留空/默认)。
fn empty_account(user_id: Uuid) -> AccountIndexRow {
    AccountIndexRow {
        user_id,
        username: None,
        email: None,
        email_verified: false,
        display_name: None,
        roles: Vec::new(),
        created_at: None,
        deleted: false,
        idm_sequence: None,
        profile_sequence: None,
    }
}

/// 新成员行:账号列(连同两个账号水位)从账号目录抄,没有账号行就留空。
fn new_member(
    accounts: &HashMap<Uuid, AccountIndexRow>,
    tenant: TenantId,
    user_id: Uuid,
) -> AdminUserIndexRow {
    let mut row = AdminUserIndexRow::new(tenant, user_id);
    if let Some(account) = accounts.get(&user_id) {
        row.username = account.username.clone();
        row.email = account.email.clone();
        row.email_verified = account.email_verified;
        row.display_name = account.display_name.clone();
        row.created_at = account.created_at;
        row.deleted = account.deleted;
        row.idm_sequence = account.idm_sequence;
        row.profile_sequence = account.profile_sequence;
    }
    row
}

#[derive(Default)]
struct Store {
    accounts: HashMap<Uuid, AccountIndexRow>,
    members: HashMap<(TenantId, Uuid), AdminUserIndexRow>,
}

impl Store {
    /// 账号事件:先守卫写账号目录,再逐行守卫写该用户的全部成员行(各行各自的 `idm_seq`)。
    fn apply_idm(
        &mut self,
        user_id: Uuid,
        sequence: i64,
        on_account: impl FnOnce(&mut AccountIndexRow),
        on_member: impl Fn(&mut AdminUserIndexRow),
    ) {
        let account = self
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(sequence, account.idm_sequence) {
            on_account(account);
            account.idm_sequence = Some(sequence);
        }
        let user_rows = self.members.values_mut().filter(|r| r.user_id == user_id);
        for row in user_rows {
            if watermark_applies(sequence, row.idm_sequence) {
                on_member(row);
                row.idm_sequence = Some(sequence);
            }
        }
    }

    /// 成员事件:没有行就新建(账号列从账号目录抄),再按 `member_seq` 守卫写成员列。
    fn apply_member(
        &mut self,
        tenant: TenantId,
        user_id: Uuid,
        sequence: i64,
        on_member: impl FnOnce(&mut AdminUserIndexRow),
    ) {
        let accounts = &self.accounts;
        let row = self
            .members
            .entry((tenant, user_id))
            .or_insert_with(|| new_member(accounts, tenant, user_id));
        if watermark_applies(sequence, row.member_sequence) {
            on_member(row);
            row.member_sequence = Some(sequence);
        }
    }
}

/// 搜索投影仓储的内存实现(脚手架默认 / 测试替身):账号目录 + 租户成员索引两个 map 共用一把锁。
#[derive(Default)]
pub struct InMemorySearchIndexRepo {
    store: Mutex<Store>,
}

impl InMemorySearchIndexRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Store> {
        self.store.lock().expect("锁未中毒")
    }
}

#[async_trait]
impl SearchIndexRepo for InMemorySearchIndexRepo {
    async fn apply_user_created(
        &self,
        account: AccountCreated<'_>,
        sequence: i64,
    ) -> Result<(), AppError> {
        let AccountCreated {
            user_id,
            username,
            email,
            email_verified,
            roles,
            created_at,
        } = account;
        self.lock().apply_idm(
            user_id,
            sequence,
            |account_row| {
                account_row.username = Some(username.to_owned());
                account_row.email = email.map(str::to_owned);
                account_row.email_verified = email_verified;
                account_row.roles = roles.to_vec();
                account_row.created_at = Some(created_at);
                account_row.deleted = false;
            },
            |member_row| {
                member_row.username = Some(username.to_owned());
                member_row.email = email.map(str::to_owned);
                member_row.email_verified = email_verified;
                member_row.created_at = Some(created_at);
                member_row.deleted = false;
            },
        );
        Ok(())
    }

    async fn apply_user_updated(
        &self,
        account: AccountUpdated<'_>,
        sequence: i64,
    ) -> Result<(), AppError> {
        let AccountUpdated {
            user_id,
            username,
            email,
            email_verified,
        } = account;
        self.lock().apply_idm(
            user_id,
            sequence,
            |account_row| {
                account_row.username = Some(username.to_owned());
                account_row.email = email.map(str::to_owned);
                account_row.email_verified = email_verified;
            },
            |member_row| {
                member_row.username = Some(username.to_owned());
                member_row.email = email.map(str::to_owned);
                member_row.email_verified = email_verified;
            },
        );
        Ok(())
    }

    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError> {
        // 平台角色只在账号目录;成员行的 roles 是租户角色,不动(也不推进成员行的 idm_seq)。
        let mut store = self.lock();
        let account = store
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(sequence, account.idm_sequence) {
            account.roles = roles.to_vec();
            account.idm_sequence = Some(sequence);
        }
        Ok(())
    }

    async fn apply_user_deleted(&self, user_id: Uuid, sequence: i64) -> Result<(), AppError> {
        self.lock().apply_idm(
            user_id,
            sequence,
            |a| a.deleted = true,
            |m| m.deleted = true,
        );
        Ok(())
    }

    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        sequence: i64,
    ) -> Result<(), AppError> {
        let mut store = self.lock();
        let account = store
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(sequence, account.profile_sequence) {
            account.display_name = display_name.map(str::to_owned);
            account.profile_sequence = Some(sequence);
        }
        let user_rows = store.members.values_mut().filter(|r| r.user_id == user_id);
        for row in user_rows {
            if watermark_applies(sequence, row.profile_sequence) {
                row.display_name = display_name.map(str::to_owned);
                row.profile_sequence = Some(sequence);
            }
        }
        Ok(())
    }

    async fn apply_member_added(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError> {
        self.lock()
            .apply_member(tenant, user_id, sequence, |member_row| {
                member_row.status = Some(status.to_owned());
                member_row.roles = roles.to_vec();
                member_row.removed = false;
            });
        Ok(())
    }

    async fn apply_member_updated(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        sequence: i64,
    ) -> Result<(), AppError> {
        self.lock()
            .apply_member(tenant, user_id, sequence, |member_row| {
                member_row.status = Some(status.to_owned());
            });
        Ok(())
    }

    async fn apply_member_roles_set(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[String],
        sequence: i64,
    ) -> Result<(), AppError> {
        self.lock()
            .apply_member(tenant, user_id, sequence, |member_row| {
                member_row.roles = roles.to_vec();
            });
        Ok(())
    }

    async fn apply_member_removed(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        sequence: i64,
    ) -> Result<(), AppError> {
        self.lock()
            .apply_member(tenant, user_id, sequence, |m| m.removed = true);
        Ok(())
    }

    async fn apply_tenant_deleted(&self, tenant: TenantId, sequence: i64) -> Result<(), AppError> {
        let mut store = self.lock();
        let tenant_rows = store.members.values_mut().filter(|r| r.tenant_id == tenant);
        for row in tenant_rows {
            if watermark_applies(sequence, row.member_sequence) {
                row.removed = true;
                row.member_sequence = Some(sequence);
            }
        }
        Ok(())
    }

    async fn rebuild_account(&self, row: AccountIndexRow) -> Result<(), AppError> {
        // 无守卫:直接整行替换/插入(重建 bin 的语义 —— 快照覆写,不比较水位)。
        self.lock().accounts.insert(row.user_id, row);
        Ok(())
    }

    async fn rebuild_member(&self, row: AdminUserIndexRow) -> Result<(), AppError> {
        self.lock()
            .members
            .insert((row.tenant_id, row.user_id), row);
        Ok(())
    }

    async fn get_account(&self, user_id: Uuid) -> Result<Option<AccountIndexRow>, AppError> {
        Ok(self.lock().accounts.get(&user_id).cloned())
    }

    async fn get_member(
        &self,
        tenant: TenantId,
        user_id: Uuid,
    ) -> Result<Option<AdminUserIndexRow>, AppError> {
        Ok(self.lock().members.get(&(tenant, user_id)).cloned())
    }

    async fn query(
        &self,
        tenant: TenantId,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError> {
        // 只看本租户(内存实现没有 RLS,参数是唯一防线);已移出的成员永不出现。
        let candidates: Vec<AdminUserIndexRow> = self
            .lock()
            .members
            .values()
            .filter(|row| row.tenant_id == tenant && !row.removed)
            .cloned()
            .collect();
        Ok(run_query(candidates, filter, sort, order, page))
    }

    async fn query_accounts(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult<AccountIndexRow>, AppError> {
        let candidates: Vec<AccountIndexRow> = self.lock().accounts.values().cloned().collect();
        Ok(run_query(candidates, filter, sort, order, page))
    }
}

/// 两种读模型行(账号目录 / 成员索引)共用的查询视图:内存 `query` / `query_accounts` 的过滤、排序、
/// 分页口径只写一份(镜像 PG 两边共用同一套 filter 构造)。
trait QueryRow: Clone {
    fn user_id(&self) -> Uuid;
    fn username(&self) -> Option<&str>;
    fn display_name(&self) -> Option<&str>;
    fn email(&self) -> Option<&str>;
    fn roles(&self) -> &[String];
    fn created_at(&self) -> Option<OffsetDateTime>;
    fn deleted(&self) -> bool;
}

impl QueryRow for AccountIndexRow {
    fn user_id(&self) -> Uuid {
        self.user_id
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn roles(&self) -> &[String] {
        &self.roles
    }
    fn created_at(&self) -> Option<OffsetDateTime> {
        self.created_at
    }
    fn deleted(&self) -> bool {
        self.deleted
    }
}

impl QueryRow for AdminUserIndexRow {
    fn user_id(&self) -> Uuid {
        self.user_id
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn roles(&self) -> &[String] {
        &self.roles
    }
    fn created_at(&self) -> Option<OffsetDateTime> {
        self.created_at
    }
    fn deleted(&self) -> bool {
        self.deleted
    }
}

/// 模糊搜的针:trim 后非空才生效,统一小写(大小写不敏感 contains,同 pg ILIKE 的直觉口径)。
fn search_needle(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
}

/// `value` 含 `needle`(`needle` 已小写;`value` 为 `None` 不算含)。
fn contains_ignore_case(value: Option<&str>, needle: &str) -> bool {
    value.is_some_and(|v| v.to_lowercase().contains(needle))
}

/// 一行是否命中基线(半行 username 未落地、已删账号永不出现)+ 动态 filter。
/// `needle` 是 `q`(username / display_name 子串),`username_needle` 只比 username,两者 AND 组合。
fn matches_filter<R: QueryRow>(
    row: &R,
    filter: &IndexQuery,
    needle: Option<&str>,
    username_needle: Option<&str>,
) -> bool {
    let roles = row.roles();
    row.username().is_some()
        && !row.deleted()
        && needle.is_none_or(|query_needle| {
            contains_ignore_case(row.username(), query_needle)
                || contains_ignore_case(row.display_name(), query_needle)
        })
        && username_needle.is_none_or(|n| contains_ignore_case(row.username(), n))
        && (filter.roles_any.is_empty() || roles.iter().any(|r| filter.roles_any.contains(r)))
        && (filter.roles_none.is_empty() || !roles.iter().any(|r| filter.roles_none.contains(r)))
        && filter
            .created_from
            .is_none_or(|from| row.created_at().is_some_and(|c| c >= from))
        && filter
            .created_to
            .is_none_or(|to| row.created_at().is_some_and(|c| c <= to))
}

/// 基线 + 动态 filter + 排序 + 分页。
fn run_query<R: QueryRow>(
    candidates: Vec<R>,
    filter: &IndexQuery,
    sort: IndexSort,
    order: SortOrder,
    page: &PageParams,
) -> IndexQueryResult<R> {
    let needle = search_needle(filter.query.as_deref());
    let username_needle = search_needle(filter.username.as_deref());
    let mut rows: Vec<R> = candidates
        .into_iter()
        .filter(|row| matches_filter(row, filter, needle.as_deref(), username_needle.as_deref()))
        .collect();

    // 排序:选定键(None 落最后,不随方向翻转)+ user_id 兜底(同键值时定序,方向随 order)。
    rows.sort_by(|left, right| {
        let primary = match sort {
            IndexSort::CreatedAt => {
                compare_optional_in_order(left.created_at(), right.created_at(), order)
            }
            IndexSort::Username => {
                compare_optional_in_order(left.username(), right.username(), order)
            }
            IndexSort::DisplayName => {
                compare_optional_in_order(left.display_name(), right.display_name(), order)
            }
            IndexSort::Email => compare_optional_in_order(left.email(), right.email(), order),
        };
        primary.then_with(|| match order {
            SortOrder::Asc => left.user_id().cmp(&right.user_id()),
            SortOrder::Desc => right.user_id().cmp(&left.user_id()),
        })
    });

    match page {
        PageParams::Offset {
            page,
            size,
            with_total,
        } => {
            let total = with_total.then_some(rows.len() as u64);
            let start = ((page.saturating_sub(1)) * size) as usize;
            let page_rows = if start >= rows.len() {
                Vec::new()
            } else {
                let end = (start as u64 + size).min(rows.len() as u64) as usize;
                rows[start..end].to_vec()
            };
            IndexQueryResult {
                rows: page_rows,
                total,
                next_after: None,
            }
        }
        PageParams::Cursor { after, limit } => {
            // cursor 分支恒按 user_id keyset,忽略 sort(镜像 pg 实现,换排序键会破翻页正确性),
            // 但方向跟 order 走(镜像 idm `PgUserRepo::list`)——只有默认 created_at 排序时
            // handler 才放行 cursor,这时 order 是唯一有意义的方向信号,不能悄悄扣死升序。
            match order {
                SortOrder::Asc => rows.sort_by_key(|r| r.user_id()),
                SortOrder::Desc => rows.sort_by_key(|r| Reverse(r.user_id())),
            }
            let mut page_rows: Vec<R> = rows
                .into_iter()
                .filter(|row| {
                    after.is_none_or(|anchor| match order {
                        SortOrder::Asc => row.user_id() > anchor,
                        SortOrder::Desc => row.user_id() < anchor,
                    })
                })
                .collect();
            let has_more = page_rows.len() as u64 > *limit;
            page_rows.truncate(*limit as usize);
            let next_after = if has_more {
                page_rows.last().map(|r| r.user_id())
            } else {
                None
            };
            IndexQueryResult {
                rows: page_rows,
                total: None,
                next_after,
            }
        }
    }
}

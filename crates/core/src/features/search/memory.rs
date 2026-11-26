//! search 仓储端口的**内存适配器** —— 脚手架默认(零 DB 跑测试)。守卫在 Rust 里手写:同一把锁内取行(无则空行)、
//! 比较 `seq` 与该行当前水位,过了才写对应源列 + 推进水位。**镜像 PG 的 `WHERE idm_seq IS NULL
//! OR idm_seq < excluded.idm_seq`**——`watermark_applies` 就是该 `IS NULL OR <` 的 Rust 版。
//!
//! 两张表各一个 map:账号目录(`user_id` → 行)与租户成员索引(`(tenant, user_id)` → 行)。账号事件写账号目录
//! 并同步该用户的全部成员行;成员事件写成员行,新行的账号列从账号目录抄(镜像 PG 的 `insert … select … from
//! account_index`)。内存实现没有 RLS:读方法按 `tenant` 参数过滤,这是唯一防线。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::features::search::model::{
    AccountIndexRow, AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort,
};
use crate::features::search::ports::SearchIndexRepo;
use crate::kernel::error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

/// `Option<T>` 比较,None 恒落最后(镜像 PG `NULLS LAST`——不随方向翻转,只有 `Some` 值按 `order` 排)。
fn cmp_opt_dir<T: Ord>(a: Option<T>, b: Option<T>, order: SortOrder) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => match order {
            SortOrder::Asc => a.cmp(&b),
            SortOrder::Desc => b.cmp(&a),
        },
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// 守卫判定:镜像 SQL `WHERE col IS NULL OR col < excluded.col`——水位未见过(`None`)一律放行,
/// 否则新 `seq` 须严格大于当前水位。
fn watermark_applies(seq: i64, current: Option<i64>) -> bool {
    current.is_none_or(|cur| seq > cur)
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
        idm_seq: None,
        profile_seq: None,
    }
}

/// 新成员行:账号列(连同两个账号水位)从账号目录抄,没有账号行就留空。
fn new_member(store: &Store, tenant: TenantId, user_id: Uuid) -> AdminUserIndexRow {
    let mut row = AdminUserIndexRow::empty(tenant, user_id);
    if let Some(a) = store.accounts.get(&user_id) {
        row.username = a.username.clone();
        row.email = a.email.clone();
        row.email_verified = a.email_verified;
        row.display_name = a.display_name.clone();
        row.created_at = a.created_at;
        row.deleted = a.deleted;
        row.idm_seq = a.idm_seq;
        row.profile_seq = a.profile_seq;
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
        seq: i64,
        on_account: impl FnOnce(&mut AccountIndexRow),
        on_member: impl Fn(&mut AdminUserIndexRow),
    ) {
        let acc = self
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(seq, acc.idm_seq) {
            on_account(acc);
            acc.idm_seq = Some(seq);
        }
        for row in self.members.values_mut().filter(|r| r.user_id == user_id) {
            if watermark_applies(seq, row.idm_seq) {
                on_member(row);
                row.idm_seq = Some(seq);
            }
        }
    }

    /// 成员事件:没有行就新建(账号列从账号目录抄),再按 `member_seq` 守卫写成员列。
    fn apply_member(
        &mut self,
        tenant: TenantId,
        user_id: Uuid,
        seq: i64,
        on_member: impl FnOnce(&mut AdminUserIndexRow),
    ) {
        if !self.members.contains_key(&(tenant, user_id)) {
            let row = new_member(self, tenant, user_id);
            self.members.insert((tenant, user_id), row);
        }
        let row = self
            .members
            .get_mut(&(tenant, user_id))
            .expect("上面刚保证存在");
        if watermark_applies(seq, row.member_seq) {
            on_member(row);
            row.member_seq = Some(seq);
        }
    }
}

#[derive(Default)]
pub struct InMemorySearchIndexRepo {
    store: Mutex<Store>,
}

impl InMemorySearchIndexRepo {
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
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        roles: &[String],
        created_at: OffsetDateTime,
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock().apply_idm(
            user_id,
            seq,
            |a| {
                a.username = Some(username.to_owned());
                a.email = email.map(str::to_owned);
                a.email_verified = email_verified;
                a.roles = roles.to_vec();
                a.created_at = Some(created_at);
                a.deleted = false;
            },
            |m| {
                m.username = Some(username.to_owned());
                m.email = email.map(str::to_owned);
                m.email_verified = email_verified;
                m.created_at = Some(created_at);
                m.deleted = false;
            },
        );
        Ok(())
    }

    async fn apply_user_updated(
        &self,
        user_id: Uuid,
        username: &str,
        email: Option<&str>,
        email_verified: bool,
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock().apply_idm(
            user_id,
            seq,
            |a| {
                a.username = Some(username.to_owned());
                a.email = email.map(str::to_owned);
                a.email_verified = email_verified;
            },
            |m| {
                m.username = Some(username.to_owned());
                m.email = email.map(str::to_owned);
                m.email_verified = email_verified;
            },
        );
        Ok(())
    }

    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        // 平台角色只在账号目录;成员行的 roles 是租户角色,不动(也不推进成员行的 idm_seq)。
        let mut store = self.lock();
        let acc = store
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(seq, acc.idm_seq) {
            acc.roles = roles.to_vec();
            acc.idm_seq = Some(seq);
        }
        Ok(())
    }

    async fn apply_user_deleted(&self, user_id: Uuid, seq: i64) -> Result<(), AppError> {
        self.lock()
            .apply_idm(user_id, seq, |a| a.deleted = true, |m| m.deleted = true);
        Ok(())
    }

    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        seq: i64,
    ) -> Result<(), AppError> {
        let mut store = self.lock();
        let acc = store
            .accounts
            .entry(user_id)
            .or_insert_with(|| empty_account(user_id));
        if watermark_applies(seq, acc.profile_seq) {
            acc.display_name = display_name.map(str::to_owned);
            acc.profile_seq = Some(seq);
        }
        for row in store.members.values_mut().filter(|r| r.user_id == user_id) {
            if watermark_applies(seq, row.profile_seq) {
                row.display_name = display_name.map(str::to_owned);
                row.profile_seq = Some(seq);
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
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock().apply_member(tenant, user_id, seq, |m| {
            m.status = Some(status.to_owned());
            m.roles = roles.to_vec();
            m.removed = false;
        });
        Ok(())
    }

    async fn apply_member_updated(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        status: &str,
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock().apply_member(tenant, user_id, seq, |m| {
            m.status = Some(status.to_owned());
        });
        Ok(())
    }

    async fn apply_member_roles_set(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock().apply_member(tenant, user_id, seq, |m| {
            m.roles = roles.to_vec();
        });
        Ok(())
    }

    async fn apply_member_removed(
        &self,
        tenant: TenantId,
        user_id: Uuid,
        seq: i64,
    ) -> Result<(), AppError> {
        self.lock()
            .apply_member(tenant, user_id, seq, |m| m.removed = true);
        Ok(())
    }

    async fn apply_tenant_deleted(&self, tenant: TenantId, seq: i64) -> Result<(), AppError> {
        for row in self
            .lock()
            .members
            .values_mut()
            .filter(|r| r.tenant_id == tenant)
        {
            if watermark_applies(seq, row.member_seq) {
                row.removed = true;
                row.member_seq = Some(seq);
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

macro_rules! impl_query_row {
    ($t:ty) => {
        impl QueryRow for $t {
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
    };
}
impl_query_row!(AccountIndexRow);
impl_query_row!(AdminUserIndexRow);

/// 基线(半行 username 未落地、已删账号永不出现)+ 动态 filter + 排序 + 分页。
fn run_query<T: QueryRow>(
    candidates: Vec<T>,
    filter: &IndexQuery,
    sort: IndexSort,
    order: SortOrder,
    page: &PageParams,
) -> IndexQueryResult<T> {
    // q 非空才生效(大小写不敏感 contains,同 pg ILIKE 的直觉口径)。
    let needle = filter
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    // username:仅 username 的子串(独立于上面的 q),trim 后非空才生效,与 q AND 组合。
    let username_needle = filter
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    let contains = |v: Option<&str>, n: &str| v.is_some_and(|v| v.to_lowercase().contains(n));

    let mut rows: Vec<T> = candidates
        .into_iter()
        .filter(|row| {
            row.username().is_some()
                && !row.deleted()
                && needle
                    .as_deref()
                    .is_none_or(|n| contains(row.username(), n) || contains(row.display_name(), n))
                && username_needle
                    .as_deref()
                    .is_none_or(|n| contains(row.username(), n))
                && (filter.roles_any.is_empty()
                    || row.roles().iter().any(|r| filter.roles_any.contains(r)))
                && (filter.roles_none.is_empty()
                    || !row.roles().iter().any(|r| filter.roles_none.contains(r)))
                && filter
                    .created_from
                    .is_none_or(|from| row.created_at().is_some_and(|c| c >= from))
                && filter
                    .created_to
                    .is_none_or(|to| row.created_at().is_some_and(|c| c <= to))
        })
        .collect();

    // 排序:选定键(None 落最后,不随方向翻转)+ user_id 兜底(同键值时定序,方向随 order)。
    rows.sort_by(|a, b| {
        let primary = match sort {
            IndexSort::CreatedAt => cmp_opt_dir(a.created_at(), b.created_at(), order),
            IndexSort::Username => cmp_opt_dir(a.username(), b.username(), order),
            IndexSort::DisplayName => cmp_opt_dir(a.display_name(), b.display_name(), order),
            IndexSort::Email => cmp_opt_dir(a.email(), b.email(), order),
        };
        primary.then_with(|| match order {
            SortOrder::Asc => a.user_id().cmp(&b.user_id()),
            SortOrder::Desc => b.user_id().cmp(&a.user_id()),
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
                SortOrder::Desc => rows.sort_by_key(|r| std::cmp::Reverse(r.user_id())),
            }
            let mut page_rows: Vec<T> = rows
                .into_iter()
                .filter(|r| {
                    after.is_none_or(|a| match order {
                        SortOrder::Asc => r.user_id() > a,
                        SortOrder::Desc => r.user_id() < a,
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

//! 内存实现 —— 脚手架默认(零 DB 跑测试)。守卫在 Rust 里手写:同一把锁内取行(无则空行)、
//! 比较 `seq` 与该行当前水位,过了才写对应源列 + 推进水位。**镜像 PG 的 `WHERE idm_seq IS NULL
//! OR idm_seq < excluded.idm_seq`**——`watermark_applies` 就是该 `IS NULL OR <` 的 Rust 版。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AdminUserIndexRow, IndexQuery, IndexQueryResult, IndexSort, SearchIndexRepo};
use crate::infra::error::AppError;
use crate::infra::pagination::PageParams;
use crate::infra::sort::SortOrder;

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
fn empty_row(user_id: Uuid) -> AdminUserIndexRow {
    AdminUserIndexRow {
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

#[derive(Default)]
pub struct InMemorySearchIndexRepo {
    store: Mutex<HashMap<Uuid, AdminUserIndexRow>>,
}

impl InMemorySearchIndexRepo {
    pub fn new() -> Self {
        Self::default()
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
        let mut store = self.store.lock().expect("锁未中毒");
        let row = store.entry(user_id).or_insert_with(|| empty_row(user_id));
        if watermark_applies(seq, row.idm_seq) {
            row.username = Some(username.to_owned());
            row.email = email.map(str::to_owned);
            row.email_verified = email_verified;
            row.roles = roles.to_vec();
            row.created_at = Some(created_at);
            row.deleted = false;
            row.idm_seq = Some(seq);
        }
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
        let mut store = self.store.lock().expect("锁未中毒");
        let row = store.entry(user_id).or_insert_with(|| empty_row(user_id));
        if watermark_applies(seq, row.idm_seq) {
            row.username = Some(username.to_owned());
            row.email = email.map(str::to_owned);
            row.email_verified = email_verified;
            row.idm_seq = Some(seq);
        }
        Ok(())
    }

    async fn apply_roles_set(
        &self,
        user_id: Uuid,
        roles: &[String],
        seq: i64,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let row = store.entry(user_id).or_insert_with(|| empty_row(user_id));
        if watermark_applies(seq, row.idm_seq) {
            row.roles = roles.to_vec();
            row.idm_seq = Some(seq);
        }
        Ok(())
    }

    async fn apply_user_deleted(&self, user_id: Uuid, seq: i64) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let row = store.entry(user_id).or_insert_with(|| empty_row(user_id));
        if watermark_applies(seq, row.idm_seq) {
            row.deleted = true;
            row.idm_seq = Some(seq);
        }
        Ok(())
    }

    async fn apply_profile_updated(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        seq: i64,
    ) -> Result<(), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let row = store.entry(user_id).or_insert_with(|| empty_row(user_id));
        if watermark_applies(seq, row.profile_seq) {
            row.display_name = display_name.map(str::to_owned);
            row.profile_seq = Some(seq);
        }
        Ok(())
    }

    async fn rebuild_upsert(&self, row: AdminUserIndexRow) -> Result<(), AppError> {
        // 无守卫:直接整行替换/插入(重建 bin 的语义 —— 快照覆写,不比较水位)。
        self.store
            .lock()
            .expect("锁未中毒")
            .insert(row.user_id, row);
        Ok(())
    }

    async fn mark_deleted_except(&self, alive: &[Uuid], p_idm: i64) -> Result<usize, AppError> {
        let alive: std::collections::HashSet<Uuid> = alive.iter().copied().collect();
        let mut store = self.store.lock().expect("锁未中毒");
        let mut swept = 0usize;
        for row in store.values_mut() {
            // 已是 deleted 的不重复计数;idm_seq > p_idm 的比快照新,不动(镜像 PG 的 WHERE 守卫)。
            if alive.contains(&row.user_id)
                || row.deleted
                || row.idm_seq.is_some_and(|seq| seq > p_idm)
            {
                continue;
            }
            row.deleted = true;
            row.idm_seq = Some(p_idm);
            swept += 1;
        }
        Ok(swept)
    }

    async fn get(&self, user_id: Uuid) -> Result<Option<AdminUserIndexRow>, AppError> {
        Ok(self.store.lock().expect("锁未中毒").get(&user_id).cloned())
    }

    async fn query(
        &self,
        filter: &IndexQuery,
        sort: IndexSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<IndexQueryResult, AppError> {
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

        let mut rows: Vec<AdminUserIndexRow> = self
            .store
            .lock()
            .expect("锁未中毒")
            .values()
            .filter(|row| {
                // 基线:半行(username 未落地)与软删行永不出现。
                row.username.is_some()
                    && !row.deleted
                    && needle.as_deref().is_none_or(|n| {
                        row.username
                            .as_deref()
                            .is_some_and(|u| u.to_lowercase().contains(n))
                            || row
                                .display_name
                                .as_deref()
                                .is_some_and(|d| d.to_lowercase().contains(n))
                    })
                    && username_needle.as_deref().is_none_or(|n| {
                        row.username
                            .as_deref()
                            .is_some_and(|u| u.to_lowercase().contains(n))
                    })
                    && (filter.roles_any.is_empty()
                        || row.roles.iter().any(|r| filter.roles_any.contains(r)))
                    && (filter.roles_none.is_empty()
                        || !row.roles.iter().any(|r| filter.roles_none.contains(r)))
                    && filter
                        .created_from
                        .is_none_or(|from| row.created_at.is_some_and(|c| c >= from))
                    && filter
                        .created_to
                        .is_none_or(|to| row.created_at.is_some_and(|c| c <= to))
            })
            .cloned()
            .collect();

        // 排序:选定键(None 落最后,不随方向翻转)+ user_id 兜底(同键值时定序,方向随 order)。
        rows.sort_by(|a, b| {
            let primary = match sort {
                IndexSort::CreatedAt => cmp_opt_dir(a.created_at, b.created_at, order),
                IndexSort::Username => {
                    cmp_opt_dir(a.username.as_deref(), b.username.as_deref(), order)
                }
                IndexSort::DisplayName => {
                    cmp_opt_dir(a.display_name.as_deref(), b.display_name.as_deref(), order)
                }
                IndexSort::Email => cmp_opt_dir(a.email.as_deref(), b.email.as_deref(), order),
            };
            primary.then_with(|| match order {
                SortOrder::Asc => a.user_id.cmp(&b.user_id),
                SortOrder::Desc => b.user_id.cmp(&a.user_id),
            })
        });

        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let total = if *with_total {
                    Some(rows.len() as u64)
                } else {
                    None
                };
                let start = ((page.saturating_sub(1)) * size) as usize;
                let page_rows = if start >= rows.len() {
                    Vec::new()
                } else {
                    let end = (start as u64 + size).min(rows.len() as u64) as usize;
                    rows[start..end].to_vec()
                };
                Ok(IndexQueryResult {
                    rows: page_rows,
                    total,
                    next_after: None,
                })
            }
            PageParams::Cursor { after, limit } => {
                // cursor 分支恒按 user_id keyset,忽略 sort(镜像 pg 实现,换排序键会破翻页正确性),
                // 但方向跟 order 走(镜像 idm `PgUserRepo::list`)——只有默认 created_at 排序时
                // handler 才放行 cursor,这时 order 是唯一有意义的方向信号,不能悄悄扣死升序。
                match order {
                    SortOrder::Asc => rows.sort_by(|a, b| a.user_id.cmp(&b.user_id)),
                    SortOrder::Desc => rows.sort_by(|a, b| b.user_id.cmp(&a.user_id)),
                }
                let mut page_rows: Vec<AdminUserIndexRow> = rows
                    .into_iter()
                    .filter(|r| {
                        after.is_none_or(|a| match order {
                            SortOrder::Asc => r.user_id > a,
                            SortOrder::Desc => r.user_id < a,
                        })
                    })
                    .collect();
                let has_more = page_rows.len() as u64 > *limit;
                page_rows.truncate(*limit as usize);
                let next_after = if has_more {
                    page_rows.last().map(|r| r.user_id)
                } else {
                    None
                };
                Ok(IndexQueryResult {
                    rows: page_rows,
                    total: None,
                    next_after,
                })
            }
        }
    }
}

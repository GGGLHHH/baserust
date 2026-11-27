//! `users::UserSearchIndex` 的适配器:桥接 search 模块的 CQRS 读投影(账号目录,`SearchIndexRepo::query_accounts`)。
//! 薄翻译(map + 转调,无业务判断)。组合根唯一同时认识 users + search 两侧具体类型的地方。

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::features::search::{IndexQuery, IndexSort, SearchIndexRepo};
use crate::features::users::{
    UserSearchFilter, UserSearchIndex, UserSearchPage, UserSearchRow, UserSearchSort,
};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort_order::SortOrder;

/// 平台账号列表的搜索 / 排序 / 分页:读 search 的全局账号目录(`account_index`)。
pub struct SearchIndexAdapter {
    inner: Arc<dyn SearchIndexRepo>,
}

impl SearchIndexAdapter {
    #[must_use]
    pub fn new(inner: Arc<dyn SearchIndexRepo>) -> Self {
        Self { inner }
    }
}

fn map_sort(sort: UserSearchSort) -> IndexSort {
    match sort {
        UserSearchSort::CreatedAt => IndexSort::CreatedAt,
        UserSearchSort::Username => IndexSort::Username,
        UserSearchSort::DisplayName => IndexSort::DisplayName,
        UserSearchSort::Email => IndexSort::Email,
    }
}

#[async_trait]
impl UserSearchIndex for SearchIndexAdapter {
    async fn query(
        &self,
        filter: &UserSearchFilter,
        sort: UserSearchSort,
        order: SortOrder,
        page: &PageParams,
    ) -> Result<UserSearchPage, AppError> {
        let query = IndexQuery {
            username: filter.username.clone(),
            query: filter.query.clone(),
            roles_any: filter.roles_any.clone(),
            roles_none: filter.roles_none.clone(),
            created_from: filter.created_from,
            created_to: filter.created_to,
        };
        let result = self
            .inner
            .query_accounts(&query, map_sort(sort), order, page)
            .await?;
        let rows = result
            .rows
            .into_iter()
            .map(|row| UserSearchRow {
                id: row.user_id,
                username: row.username.expect("query 已滤 username IS NOT NULL"),
                email: row.email,
                email_verified: row.email_verified,
                // ponytail: created_at 几乎恒有值——user.created 的 idm_seq 最低、最先落地。
                // username 非空但 created_at 仍空只会是 idm 内部乱序(intra-idm redelivery)的瞬时
                // 窗口:`user.updated` 先落地(置 username,不动 created_at),随后过期的低 seq
                // `user.created` 被 seq 守卫跳过,靠 rebuild_search 自愈;epoch 只是那个窗口内的
                // 无害占位,不影响排序/展示语义。
                created_at: row.created_at.unwrap_or(OffsetDateTime::UNIX_EPOCH),
                roles: row.roles,
                display_name: row.display_name,
            })
            .collect();
        Ok(UserSearchPage {
            rows,
            total: result.total,
            next_after: result.next_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::search::{AccountCreated, InMemorySearchIndexRepo};
    use time::macros::datetime;
    use uuid::Uuid;

    /// 只造账号(不属于任何租户):平台账号列表照样列得出来。
    async fn seed(repo: &InMemorySearchIndexRepo, id: Uuid, username: &str, display_name: &str) {
        repo.apply_user_created(
            AccountCreated {
                user_id: id,
                username,
                email: Some(&format!("{username}@example.com")),
                email_verified: true,
                roles: &["superadmin".to_string()],
                created_at: datetime!(2026-01-01 00:00 UTC),
            },
            1,
        )
        .await
        .unwrap();
        repo.apply_profile_updated(id, Some(display_name), 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn query_filters_by_q_and_maps_fields() {
        let repo = Arc::new(InMemorySearchIndexRepo::new());
        let alice = Uuid::now_v7();
        let bob = Uuid::now_v7();
        seed(&repo, alice, "alice", "Alice A").await;
        seed(&repo, bob, "bob", "Bob B").await;

        let adapter = SearchIndexAdapter::new(repo);
        let filter = UserSearchFilter {
            query: Some("ali".into()),
            ..Default::default()
        };
        let page = PageParams::Offset {
            page: 1,
            size: 10,
            with_total: true,
        };
        let got = adapter
            .query(&filter, UserSearchSort::CreatedAt, SortOrder::Desc, &page)
            .await
            .unwrap();

        assert_eq!(got.total, Some(1));
        assert_eq!(got.rows.len(), 1);
        let row = &got.rows[0];
        assert_eq!(row.id, alice);
        assert_eq!(row.username, "alice");
        assert_eq!(row.email.as_deref(), Some("alice@example.com"));
        assert!(row.email_verified);
        assert_eq!(row.display_name.as_deref(), Some("Alice A"));
        assert_eq!(row.roles, vec!["superadmin".to_string()], "平台角色");
    }

    #[tokio::test]
    async fn sort_passes_through_to_repo() {
        let repo = Arc::new(InMemorySearchIndexRepo::new());
        let alice = Uuid::now_v7();
        let bob = Uuid::now_v7();
        seed(&repo, alice, "alice", "Alice A").await;
        seed(&repo, bob, "bob", "Bob B").await;

        let adapter = SearchIndexAdapter::new(repo);
        let page = PageParams::Offset {
            page: 1,
            size: 10,
            with_total: true,
        };
        let got = adapter
            .query(
                &UserSearchFilter::default(),
                UserSearchSort::DisplayName,
                SortOrder::Asc,
                &page,
            )
            .await
            .unwrap();

        let ids: Vec<Uuid> = got.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![alice, bob]); // "Alice A" < "Bob B"
    }
}

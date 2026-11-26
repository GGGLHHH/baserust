//! `tenants::MemberSearchIndex` 的适配器:桥接 search 模块的**租户成员索引**投影(`SearchIndexRepo::query`,
//! 方法内在租户事务里查,RLS 兜底)。薄翻译(map + 转调,无业务判断)。

use std::sync::Arc;

use async_trait::async_trait;

use crate::features::search::{self, SearchIndexRepo};
use crate::features::tenants::{MemberSearchIndex, MemberSearchPage, MemberSearchRow};
use crate::kernel::error::AppError;
use crate::kernel::pagination::PageParams;
use crate::kernel::sort::SortOrder;
use crate::kernel::tenant::TenantId;

pub struct MemberSearchAdapter {
    inner: Arc<dyn SearchIndexRepo>,
}

impl MemberSearchAdapter {
    pub fn new(inner: Arc<dyn SearchIndexRepo>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl MemberSearchIndex for MemberSearchAdapter {
    async fn query(
        &self,
        tenant: TenantId,
        q: Option<&str>,
        page: &PageParams,
    ) -> Result<MemberSearchPage, AppError> {
        let query = search::IndexQuery {
            q: q.map(str::to_owned),
            ..Default::default()
        };
        let result = self
            .inner
            .query(
                tenant,
                &query,
                search::IndexSort::CreatedAt,
                SortOrder::Desc,
                page,
            )
            .await?;
        let rows = result
            .rows
            .into_iter()
            // 基线过滤已保证 username 非空(半行不出现);防御性跳过,不 panic。
            .filter_map(|row| {
                Some(MemberSearchRow {
                    user_id: row.user_id,
                    username: row.username?,
                    email: row.email,
                    display_name: row.display_name,
                    roles: row.roles,
                    status: row.status,
                })
            })
            .collect();
        Ok(MemberSearchPage {
            rows,
            total: result.total,
            next_after: result.next_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::search::InMemorySearchIndexRepo;
    use crate::kernel::tenant::DEFAULT_TENANT_ID;
    use time::macros::datetime;
    use uuid::Uuid;

    #[tokio::test]
    async fn query_reads_only_that_tenants_members_and_maps_fields() {
        let repo = Arc::new(InMemorySearchIndexRepo::new());
        let other = TenantId::new(Uuid::now_v7()).unwrap();
        let alice = Uuid::now_v7();
        let bob = Uuid::now_v7();
        for (id, name) in [(alice, "alice"), (bob, "bob")] {
            repo.apply_user_created(
                id,
                name,
                None,
                false,
                &[],
                datetime!(2026-01-01 00:00 UTC),
                1,
            )
            .await
            .unwrap();
        }
        repo.apply_member_added(DEFAULT_TENANT_ID, alice, "active", &["admin".into()], 1)
            .await
            .unwrap();
        repo.apply_member_added(other, bob, "inactive", &["user".into()], 1)
            .await
            .unwrap();

        let adapter = MemberSearchAdapter::new(repo);
        let page = PageParams::Offset {
            page: 1,
            size: 10,
            with_total: true,
        };
        let got = adapter.query(DEFAULT_TENANT_ID, None, &page).await.unwrap();
        assert_eq!(got.total, Some(1));
        let row = &got.rows[0];
        assert_eq!((row.user_id, row.username.as_str()), (alice, "alice"));
        assert_eq!(row.roles, vec!["admin".to_string()]);
        assert_eq!(row.status.as_deref(), Some("active"));
        // q 透传
        let none = adapter
            .query(DEFAULT_TENANT_ID, Some("bob"), &page)
            .await
            .unwrap();
        assert!(none.rows.is_empty());
    }
}

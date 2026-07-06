//! 全量回填/重建(bootstrap + 漂移恢复)——从**当前状态**(idm `UserRepo::list` + profile
//! `ProfileRepo::find_by_ids`)灌注 `admin_user_index`,而非从事件流。用途两个:
//! 1) bootstrap:项目上线前已存在的用户(早于事件投影接线)需要一次性建索引;
//! 2) 漂移恢复:projector 挂了 / 消息丢失后,用它把读模型拉回与源真相一致。
//!
//! 供 `src/bin/rebuild_search.rs` 装配调用;核心逻辑抽在这里以便零 DB 单测(内存三仓储)。

use std::collections::HashMap;

use idm::{ListPage, SortDir, UserListFilter, UserRepo, UserSortBy};
use uuid::Uuid;

use super::{AdminUserIndexRow, SearchIndexRepo};
use crate::features::profile::ProfileRepo;
use crate::infra::error::AppError;

/// 每页拉取的用户数——大页降低往返次数,循环到不满页即结束。
const PAGE_LIMIT: u64 = 500;

/// 全量回填投影(bootstrap + 漂移恢复)。水位设为快照 `p_idm`/`p_app`(= 回填时各 outbox 的 max id):
/// 之后 id>P 的新事件才会再覆写,旧重投被 projector 的守卫挡住。**先读 P、再读数据**(P 是下界,
/// 数据集只会比快照时刻更新,保守收敛不会漏)。
///
/// 只回填**存活**用户(`UserRepo::list` 本就只返存活行)——已删用户不进投影,搜索里本就不该出现。
/// 返回写入的行数。
pub async fn rebuild(
    users: &dyn UserRepo,
    profiles: &dyn ProfileRepo,
    index: &dyn SearchIndexRepo,
    p_idm: i64,
    p_app: i64,
) -> Result<usize, AppError> {
    let mut written = 0usize;
    let mut offset = 0u64;
    loop {
        let page = users
            .list(
                &UserListFilter::default(),
                UserSortBy::CreatedAt,
                SortDir::Asc,
                &ListPage::Offset {
                    offset,
                    limit: PAGE_LIMIT,
                    with_total: false,
                },
            )
            .await?;
        let page_len = page.rows.len();
        if page_len == 0 {
            break;
        }

        // 批量取 profile(一条 SQL 解 N+1),按 user_id 建 display_name 映射;缺失 id → None。
        let ids: Vec<Uuid> = page.rows.iter().map(|row| row.id).collect();
        let display_names: HashMap<Uuid, Option<String>> = profiles
            .find_by_ids(&ids)
            .await?
            .into_iter()
            .map(|p| (p.user_id, p.display_name))
            .collect();

        for row in page.rows {
            let display_name = display_names.get(&row.id).cloned().flatten();
            index
                .rebuild_upsert(AdminUserIndexRow {
                    user_id: row.id,
                    username: Some(row.username),
                    email: row.email,
                    email_verified: row.email_verified,
                    display_name,
                    roles: row.roles,
                    created_at: Some(row.created_at),
                    deleted: false,
                    idm_seq: Some(p_idm),
                    profile_seq: Some(p_app),
                })
                .await?;
            written += 1;
        }
        tracing::info!(written, page_len, "rebuild_search 回填进度");

        if (page_len as u64) < PAGE_LIMIT {
            break;
        }
        offset += PAGE_LIMIT;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::profile::{InMemoryProfileRepo, ProfileFields};
    use crate::features::search::InMemorySearchIndexRepo;
    use idm::InMemoryUserRepo;

    #[tokio::test]
    async fn backfills_all_alive_users_with_profile_enrichment_and_watermarks() {
        let users = InMemoryUserRepo::new();
        let profiles = InMemoryProfileRepo::new();
        let index = InMemorySearchIndexRepo::new();

        // 两个存活用户;u1 建了 profile(display_name),u2 没有 → 应回填为 None。
        let u1 = users
            .create("alice", Some("alice@x"), "hash", None)
            .await
            .unwrap();
        let u2 = users
            .create("bob", Some("bob@x"), "hash", None)
            .await
            .unwrap();
        profiles
            .upsert(
                u1.id,
                ProfileFields {
                    display_name: Some("Alice Disp".to_owned()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();

        let written = rebuild(&users, &profiles, &index, 100, 200).await.unwrap();
        assert_eq!(written, 2);

        let row1 = index.get(u1.id).await.unwrap().expect("u1 应已回填");
        assert_eq!(row1.username.as_deref(), Some("alice"));
        assert_eq!(row1.roles, Vec::<String>::new());
        assert_eq!(row1.display_name.as_deref(), Some("Alice Disp"));
        assert_eq!(row1.idm_seq, Some(100));
        assert_eq!(row1.profile_seq, Some(200));
        assert!(!row1.deleted);

        let row2 = index.get(u2.id).await.unwrap().expect("u2 应已回填");
        assert_eq!(row2.username.as_deref(), Some("bob"));
        assert_eq!(row2.display_name, None, "无 profile 的用户应回填 None");
        assert_eq!(row2.idm_seq, Some(100));
        assert_eq!(row2.profile_seq, Some(200));
    }

    #[tokio::test]
    async fn no_alive_users_backfills_zero() {
        let users = InMemoryUserRepo::new();
        let profiles = InMemoryProfileRepo::new();
        let index = InMemorySearchIndexRepo::new();

        let written = rebuild(&users, &profiles, &index, 1, 1).await.unwrap();
        assert_eq!(written, 0);
    }
}

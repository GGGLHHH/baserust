//! 全量回填/重建(bootstrap + 漂移恢复)——从**当前状态**(idm `UserRepo::list` + profile
//! `ProfileRepo::find_by_ids`)灌注 `admin_user_index`,而非从事件流。用途两个:
//! 1) bootstrap:项目上线前已存在的用户(早于事件投影接线)需要一次性建索引;
//! 2) 漂移恢复:projector 挂了 / 消息丢失后,用它把读模型拉回与源真相一致 —— **双向**:
//!    存活用户 upsert 覆写(修"索引说已删、源里还活着"),快照外的残留行扫成已删
//!    (修"源里已删、索引还活着" —— 丢了 `user.deleted` 的那类缺口)。
//!
//! 供 `src/bin/rebuild_search.rs` 装配调用;核心逻辑抽在这里以便零 DB 单测(内存三仓储)。

use std::collections::HashMap;

use async_trait::async_trait;
use idm::{ListPage, SortDir, UserListFilter, UserRepo, UserSortBy};
use uuid::Uuid;

use super::{AdminUserIndexRow, SearchIndexRepo};
use crate::infra::error::AppError;

/// rebuild 的窄端口(端口归消费方,见 cross-module-enrichment skill):只要
/// "user_id → display_name" 批量映射,不吃 profile 模块的整个仓储 trait。
/// 适配在组合根(`app::adapters::ProfileDisplayNames`)。
#[async_trait]
pub trait DisplayNameSource: Send + Sync {
    async fn display_names_by_ids(
        &self,
        user_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Option<String>>, AppError>;
}

/// 每页拉取的用户数——大页降低往返次数,循环到不满页即结束。
const PAGE_LIMIT: u64 = 500;

/// 全量回填投影(bootstrap + 漂移恢复)。水位设为快照 `p_idm`/`p_app`(= 回填时各 outbox 的 max id):
/// 之后 id>P 的新事件才会再覆写,旧重投被 projector 的守卫挡住。**先读 P、再读数据**(P 是下界,
/// 数据集只会比快照时刻更新,保守收敛不会漏)。
///
/// 只回填**存活**用户(`UserRepo::list` 本就只返存活行),回填完再把**不在快照里**的索引行扫成
/// 已删(`mark_deleted_except`)—— 两步才双向收敛:少了扫这一刀,"源里已删、索引还活着"永远修不掉
/// (`list` 不返已删用户 → 那行根本不被触及),而丢一条 `user.deleted` 正是 projector 指名要靠本
/// bin 补的缺口。返回写入的行数(不含扫删的,那条单独记日志)。
///
/// ponytail: 存活 id 全收进内存再一次性扫(百万用户 = 十几 MB Vec,脚手架量级够用);
/// 真到扫不动时改成"给本次 rebuild 打 run_id、扫 run_id 不匹配的行",不必全量攒 id。
pub async fn rebuild(
    users: &dyn UserRepo,
    profiles: &dyn DisplayNameSource,
    index: &dyn SearchIndexRepo,
    p_idm: i64,
    p_app: i64,
) -> Result<usize, AppError> {
    let mut written = 0usize;
    let mut after: Option<Uuid> = None;
    let mut alive: Vec<Uuid> = Vec::new();
    loop {
        // **keyset,不是 offset**:offset 翻页在并发删除下会左移窗口 —— 页 N 与 N+1 之间有人被删,
        // 页 N+1 的末尾那个存活用户就永远不会被返回。它进不了 `alive`,随后被下面的 sweep 扫成
        // deleted(`idm_seq <= p_idm` 守卫救不了它:那道守卫只挡比快照**新**的行)。
        // 即"回填反而删掉活人",且恰好发生在你已经怀疑漂移、跑 rebuild 抢修的时候。
        let page = users
            .list(
                &UserListFilter::default(),
                UserSortBy::CreatedAt,
                SortDir::Asc,
                &ListPage::Cursor {
                    after,
                    limit: PAGE_LIMIT,
                },
            )
            .await?;
        let page_len = page.rows.len();
        if page_len == 0 {
            break;
        }

        // 批量取 display_name(端口内一条 SQL 解 N+1);缺失 id → None。
        let ids: Vec<Uuid> = page.rows.iter().map(|row| row.id).collect();
        alive.extend_from_slice(&ids); // 扫删用:快照里的存活集
        let display_names = profiles.display_names_by_ids(&ids).await?;

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

        // next_after 为 None = 没有下一页(keyset 的终止条件,不看页是否满)。
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }

    // 反向收敛:索引里有、快照里没有的 → 源里已删(或从来就不该在),扫成 deleted。
    let swept = index.mark_deleted_except(&alive, p_idm).await?;
    if swept > 0 {
        tracing::info!(swept, "rebuild_search 扫掉快照外的残留行(源已删/丢事件)");
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::adapters::ProfileDisplayNames;
    use crate::features::profile::{InMemoryProfileRepo, ProfileFields, ProfileRepo};
    use crate::features::search::InMemorySearchIndexRepo;
    use idm::InMemoryUserRepo;
    use std::sync::Arc;

    #[tokio::test]
    async fn backfills_all_alive_users_with_profile_enrichment_and_watermarks() {
        let users = InMemoryUserRepo::new();
        let profiles = Arc::new(InMemoryProfileRepo::new());
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

        let written = rebuild(
            &users,
            &ProfileDisplayNames::new(profiles),
            &index,
            100,
            200,
        )
        .await
        .unwrap();
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

    /// **漂移恢复对删除也得成立**:丢了 `user.deleted`(projector 毒消息跳过 / 流保留期过期,
    /// 两者模块注释都点名了要靠本 bin 补)后,索引里那行还 `deleted=false`、还能被搜到。
    /// rebuild 必须把它扫掉 —— 只 upsert 存活用户的话,`list` 压根不返已删用户,那行永远不被触及,
    /// 重跑多少次都还在(而反向漂移是能修的,这个不对称正说明是漏,不是设计)。
    #[tokio::test]
    async fn rebuild_sweeps_rows_deleted_at_source_but_still_alive_in_index() {
        let users = InMemoryUserRepo::new();
        let profiles = Arc::new(InMemoryProfileRepo::new());
        let index = InMemorySearchIndexRepo::new();

        let alive = users
            .create("alice", Some("alice@x"), "hash", None)
            .await
            .unwrap();
        let ghost = users
            .create("bob", Some("bob@x"), "hash", None)
            .await
            .unwrap();

        // 先建好索引(两人都在、都存活)
        rebuild(
            &users,
            &ProfileDisplayNames::new(profiles.clone()),
            &index,
            100,
            200,
        )
        .await
        .unwrap();
        assert!(!index.get(ghost.id).await.unwrap().unwrap().deleted);

        // bob 在源里被删,但 user.deleted 事件丢了 → 索引仍是 deleted=false
        users.soft_delete(ghost.id, None).await.unwrap();

        // 重跑 rebuild:alice 照常回填,bob 应被扫成 deleted
        let written = rebuild(
            &users,
            &ProfileDisplayNames::new(profiles),
            &index,
            300,
            400,
        )
        .await
        .unwrap();
        assert_eq!(written, 1, "只回填存活的 alice");
        assert!(
            !index.get(alive.id).await.unwrap().unwrap().deleted,
            "存活用户不该被扫"
        );
        let ghost_row = index.get(ghost.id).await.unwrap().unwrap();
        assert!(ghost_row.deleted, "源里已删的残留行必须被扫成 deleted");
        assert_eq!(ghost_row.idm_seq, Some(300), "扫删水位设为本次快照 p_idm");
    }

    /// 扫删守卫:比快照**新**的行(rebuild 期间刚由 projector 投影进来的新用户)不能被扫掉 ——
    /// 否则 rebuild 会把并发投影的新用户误判成"快照外的残留"删掉。
    #[tokio::test]
    async fn sweep_does_not_touch_rows_newer_than_the_snapshot() {
        let users = InMemoryUserRepo::new();
        let profiles = Arc::new(InMemoryProfileRepo::new());
        let index = InMemorySearchIndexRepo::new();

        // 索引里有一行,水位比本次快照 p_idm(100)新 —— 模拟 rebuild 期间刚投影进来的用户
        let newcomer = Uuid::now_v7();
        index
            .rebuild_upsert(AdminUserIndexRow {
                user_id: newcomer,
                username: Some("carol".to_owned()),
                email: None,
                email_verified: false,
                display_name: None,
                roles: vec![],
                created_at: None,
                deleted: false,
                idm_seq: Some(999), // > p_idm
                profile_seq: None,
            })
            .await
            .unwrap();

        rebuild(
            &users,
            &ProfileDisplayNames::new(profiles),
            &index,
            100,
            200,
        )
        .await
        .unwrap();

        assert!(
            !index.get(newcomer).await.unwrap().unwrap().deleted,
            "水位比快照新的行不该被扫(并发投影的新用户)"
        );
    }

    /// **翻页必须收全**:超过一页时,keyset 要把每一页都走到,`alive` 才完整 —— 漏掉任何一个
    /// 存活用户,后面的 sweep 就会把它扫成 deleted(回填反而删活人)。这里跨 `PAGE_LIMIT` 边界,
    /// 钉住循环的终止条件(`next_after.is_none()`,不是"页不满就停")。
    #[tokio::test]
    async fn multi_page_backfill_keeps_every_alive_user() {
        let users = InMemoryUserRepo::new();
        let profiles = Arc::new(InMemoryProfileRepo::new());
        let index = InMemorySearchIndexRepo::new();

        let n = PAGE_LIMIT as usize + 3; // 跨页:一整页 + 零头
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            ids.push(
                users
                    .create(&format!("u{i}"), None, "hash", None)
                    .await
                    .unwrap()
                    .id,
            );
        }

        let written = rebuild(
            &users,
            &ProfileDisplayNames::new(profiles),
            &index,
            100,
            200,
        )
        .await
        .unwrap();
        assert_eq!(
            written, n,
            "每一页的用户都该回填(翻页漏人 = 后面被扫成已删)"
        );
        for id in ids {
            let row = index
                .get(id)
                .await
                .unwrap()
                .expect("每个存活用户都该有索引行");
            assert!(!row.deleted, "存活用户不该被 sweep 扫掉");
        }
    }

    #[tokio::test]
    async fn no_alive_users_backfills_zero() {
        let users = InMemoryUserRepo::new();
        let profiles = Arc::new(InMemoryProfileRepo::new());
        let index = InMemorySearchIndexRepo::new();

        let written = rebuild(&users, &ProfileDisplayNames::new(profiles), &index, 1, 1)
            .await
            .unwrap();
        assert_eq!(written, 0);
    }
}

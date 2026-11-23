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

use super::model::AdminUserIndexRow;
use super::ports::SearchIndexRepo;
use crate::kernel::error::AppError;

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
pub const PAGE_LIMIT: u64 = 500;

/// 全量回填投影(bootstrap + 漂移恢复)。水位设为快照 `p_idm`/`p_app`(= 回填时各 outbox 的 max id):
/// 之后 id>P 的新事件才会再覆写,旧重投被 projector 的守卫挡住。**先读 P、再读数据**(P 是下界,
/// 数据集只会比快照时刻更新,保守收敛不会漏)。
///
/// 只回填**存活**用户(`UserRepo::list` 本就只返存活行)。返回写入的行数。
///
/// **不做"扫掉快照外残留行"那一刀**,尽管模块头注的"漂移恢复"因此对删除只是半程:
/// 要扫,前提是这份存活快照**完整**;而上游分页给不了这个保证 —— idm 的 cursor 谓词恒是
/// `users.id > after`,ORDER BY 却是 `created_at, id`,两把键只是被**假定**一致:`id` 是
/// `Uuid::now_v7()` 在 `pool.begin()` **之前**取的,`created_at` 是事务的 `now()`,池竞争下
/// 两个并发创建完全可能 `id_A < id_B` 而 `created_at_A > created_at_B` → 翻页跳过 A;
/// 而 `UserSortBy` 没有 `Id` 变体,本地无从对齐。换回 offset 也不行(并发删除左移窗口,同样跳)。
/// 快照一旦漏人,扫这一刀就会把**活人**从搜索里删掉 —— 恰好发生在你已怀疑漂移、跑本工具抢修时。
/// 「已删用户还搜得到」是陈旧读;「活人被工具删掉」是工具自己造成的数据损失,后者更坏,
/// 故宁可不收敛也不误删。(用 run_id/时间戳打标再扫**同样不行**:被跳过的用户压根没被 upsert,
/// 标记照样是旧的,一样被扫。)
///
/// 要真正双向收敛,得让扫删**不依赖快照完整**:逐个候选回源点查(`find_by_id`)确认确实不存在
/// 再删 —— 那需要给 `SearchIndexRepo` 加"列出存活行"的端口,是一次独立的改动,不塞进这里。
pub async fn rebuild(
    users: &dyn UserRepo,
    profiles: &dyn DisplayNameSource,
    index: &dyn SearchIndexRepo,
    p_idm: i64,
    p_app: i64,
) -> Result<usize, AppError> {
    let mut written = 0usize;
    let mut after: Option<Uuid> = None;
    loop {
        // keyset 而非 offset:offset 在并发删除下会左移窗口。两者都可能跳行(见上),
        // 但**没有扫删**时跳行只意味着"这轮没刷新到那一行",不会误删,可接受。
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

    Ok(written)
}

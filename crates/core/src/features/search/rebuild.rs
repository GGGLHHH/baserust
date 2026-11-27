//! 全量回填/重建(bootstrap + 漂移恢复)——从**当前状态**(idm `UserRepo::list` / `TenantRepo::list` /
//! `MemberRepo::list_by_tenant` + profile 显示名)灌注账号目录 `account_index` 与租户成员索引
//! `admin_user_index`(**一个成员关系一行**),而非从事件流。用途两个:
//! 1) bootstrap:项目上线前已存在的用户(早于事件投影接线)需要一次性建索引;
//! 2) 漂移恢复:projector 挂了 / 消息丢失后,用它把读模型拉回与源真相一致 —— **双向**:
//!    存活用户 upsert 覆写(修"索引说已删、源里还活着"),快照外的残留行扫成已删
//!    (修"源里已删、索引还活着" —— 丢了 `user.deleted` 的那类缺口)。
//!
//! 供 `src/bin/rebuild_search.rs` 装配调用;核心逻辑抽在这里以便零 DB 单测(内存三仓储)。

use std::collections::HashMap;

use async_trait::async_trait;
use idm::{
    ListPage, MemberRepo, SortDirection, TenantRepo, User, UserListFilter, UserRepo, UserSortBy,
};
use uuid::Uuid;

use super::model::{AccountIndexRow, AdminUserIndexRow};
use super::search_index_repo::SearchIndexRepo;
use crate::kernel::app_error::AppError;
use crate::kernel::tenant_id::TenantId;

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

/// rebuild 读的 idm 源(账号 / 租户 / 成员关系)。打包传参,省得签名越加越长。
pub struct IdmSources<'repo> {
    pub users: &'repo dyn UserRepo,
    pub tenants: &'repo dyn TenantRepo,
    pub members: &'repo dyn MemberRepo,
}

/// 回填时刻两个 outbox 的水位(各自的 max id):回填行的 `*_seq` 就设成它们。两个 `i64` 按名字区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watermarks {
    /// idm.outbox 的水位(账号事件、成员事件共用这一条序列)。
    pub idm: i64,
    /// app.outbox 的水位(资料事件)。
    pub app: i64,
}

/// 回填了多少行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebuildCounts {
    /// 账号目录行数(存活账号)。
    pub accounts: usize,
    /// 成员索引行数(存活租户里、账号也存活的成员关系)。
    pub members: usize,
}

/// 全量回填投影(bootstrap + 漂移恢复)。水位设为快照 `watermarks.idm` / `watermarks.app`(= 回填时 idm / app
/// 两个 outbox 各自的 max id,下称 P):
/// 之后 id>P 的新事件才会再覆写,旧重投被 projector 的守卫挡住。**先读 P、再读数据**(P 是下界,
/// 数据集只会比快照时刻更新,保守收敛不会漏)。
///
/// 只回填**存活**用户(`UserRepo::list` 本就只返存活行);成员索引只回填存活租户(`TenantRepo::list`)
/// 里、账号也存活(`find_by_ids` 查得到)的成员关系,任何状态都写(停用的成员也在成员列表里)。
/// 成员行的 `member_seq` 也设为 `watermarks.idm`(成员事件和账号事件同在 idm.outbox,同一个水位序列)。
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
    idm: IdmSources<'_>,
    profiles: &dyn DisplayNameSource,
    index: &dyn SearchIndexRepo,
    watermarks: Watermarks,
) -> Result<RebuildCounts, AppError> {
    let accounts = rebuild_accounts(idm.users, profiles, index, watermarks).await?;
    let members = rebuild_members(&idm, profiles, index, watermarks).await?;
    tracing::info!(accounts, members, "rebuild_search 回填完成");
    Ok(RebuildCounts { accounts, members })
}

/// 账号目录:存活账号逐页 upsert(无守卫)。
async fn rebuild_accounts(
    users: &dyn UserRepo,
    profiles: &dyn DisplayNameSource,
    index: &dyn SearchIndexRepo,
    watermarks: Watermarks,
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
                SortDirection::Ascending,
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
                .rebuild_account(AccountIndexRow {
                    user_id: row.id,
                    username: Some(row.username),
                    email: row.email,
                    email_verified: row.email_verified,
                    display_name,
                    roles: row.roles,
                    created_at: Some(row.created_at),
                    deleted: false,
                    idm_sequence: Some(watermarks.idm),
                    profile_sequence: Some(watermarks.app),
                })
                .await?;
            written += 1;
        }
        tracing::info!(written, page_len, "rebuild_search 账号目录回填进度");

        // next_after 为 None = 没有下一页(keyset 的终止条件,不看页是否满)。
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }

    Ok(written)
}

/// 成员索引:逐个存活租户、逐页成员关系 → 批量取账号 + 显示名 → 每个成员关系 upsert 一行(无守卫)。
/// 账号已删(`find_by_ids` 查不到)的成员关系跳过 —— 不写行,和事件路径「已删账号不出现在列表里」一致。
async fn rebuild_members(
    idm: &IdmSources<'_>,
    profiles: &dyn DisplayNameSource,
    index: &dyn SearchIndexRepo,
    watermarks: Watermarks,
) -> Result<usize, AppError> {
    let mut written = 0usize;
    let mut tenant_after: Option<Uuid> = None;
    loop {
        let tenants = idm
            .tenants
            .list(&ListPage::Cursor {
                after: tenant_after,
                limit: PAGE_LIMIT,
            })
            .await?;
        for tenant in &tenants.rows {
            let tenant_id = TenantId::try_new(tenant.id)?;
            let mut member_after: Option<Uuid> = None;
            loop {
                let page = idm
                    .members
                    .list_by_tenant(
                        tenant.id,
                        &ListPage::Cursor {
                            after: member_after,
                            limit: PAGE_LIMIT,
                        },
                    )
                    .await?;
                let ids: Vec<Uuid> = page.rows.iter().map(|m| m.user_id).collect();
                let users: HashMap<Uuid, User> = idm
                    .users
                    .find_by_ids(&ids)
                    .await?
                    .into_iter()
                    .map(|u| (u.id, u))
                    .collect();
                let display_names = profiles.display_names_by_ids(&ids).await?;
                for membership in page.rows {
                    let Some(user) = users.get(&membership.user_id) else {
                        continue; // 账号已删:不进成员列表
                    };
                    index
                        .rebuild_member(AdminUserIndexRow {
                            tenant_id,
                            user_id: membership.user_id,
                            username: Some(user.username.clone()),
                            email: user.email.clone(),
                            email_verified: user.email_verified,
                            display_name: display_names.get(&membership.user_id).cloned().flatten(),
                            created_at: Some(user.created_at),
                            deleted: false,
                            idm_sequence: Some(watermarks.idm),
                            profile_sequence: Some(watermarks.app),
                            roles: membership.roles,
                            status: Some(membership.status.as_str().to_owned()),
                            removed: false,
                            member_sequence: Some(watermarks.idm),
                        })
                        .await?;
                    written += 1;
                }
                match page.next_after {
                    Some(next) => member_after = Some(next),
                    None => break,
                }
            }
        }
        tracing::info!(written, "rebuild_search 成员索引回填进度");
        match tenants.next_after {
            Some(next) => tenant_after = Some(next),
            None => break,
        }
    }
    Ok(written)
}

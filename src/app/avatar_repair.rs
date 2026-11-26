//! **旧头像修复**(多租户改造的一次性数据步骤,幂等):把 app.profiles 引用到的头像 content 转成个人内容。
//!
//! 背景:头像是个人内容(`ContentScope::Personal`,content 各表 `tenant_id IS NULL`,spec §4.4)。但改造前的头像
//! 当年写的是 nil 租户,content 迁移 0003 按规则把所有 nil 行回填成了默认租户;改造期间前台自助换头像也曾走
//! `contents/upload` 落进默认租户。头像读取现在只认 Personal,这些旧头像不转过来就会全部显示不出来。
//!
//! 为什么不是 SQL 迁移:"哪些 content 是头像"记在 app.profiles,content 在别的 schema —— 迁移不许跨 schema。
//! 所以放在组合根,两个池各连各的 schema、不 join:
//! 1. app 池读 `profiles.avatar_content_id`(全局表,不开 RLS);
//! 2. content **system 池**(BYPASSRLS,spec §4.4 后台任务账号)在一个事务里把这些 content 及其子行
//!    (content_metadata / object / object_metadata,头像 → 直接派生子内容的 content_derived 关系,和那些子内容本身)
//!    的 tenant_id 置 NULL。
//!
//! 只转**默认租户**里的行(迁移回填的目标);别的租户里的内容即便被引用也不动(正常流程造不出这种引用)。
//! 只转 **owner = 资料主人**的内容(派生子内容也要同一 owner);对不上的计进 `owner_mismatch` 并打 warn。
//! 派生只跟一层:子内容再派生的孙内容和「子 → 孙」关系留在租户里(不制造关系 / 内容作用域错配)。
//! 对象 key 不搬家(`tenants/…` / 旧 key 照旧能读,同迁移 0003 的约定)。已经是个人内容的行不再命中 → 重复跑无副作用。
//! 何时跑:启动时(组合根装配,app + content 都连了 PG 时;与 `seed_authz` 同一处、不受 seed_on_start 门控)
//! 与 `seed` CLI。

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use sqlx::PgPool;
use uuid::Uuid;

/// 一次修复改了多少行(按表)。`avatars` = app.profiles 里引用到的头像 id 数(不是改动数)。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AvatarRepairReport {
    pub avatars: usize,
    pub contents: u64,
    pub content_metadata: u64,
    pub objects: u64,
    pub object_metadata: u64,
    pub derived: u64,
    /// 被引用、在默认租户里、但 owner 不是资料主人的头像 content 数(不转,打 warn)。
    pub owner_mismatch: usize,
}

impl AvatarRepairReport {
    /// 五张表改动行数之和(0 = 这次什么都没改)。
    pub fn rows(&self) -> u64 {
        self.contents + self.content_metadata + self.objects + self.object_metadata + self.derived
    }
}

/// 见模块注释。`app`:连 app schema 的池(运行时账号即可);`content_system`:content 的 system 池(BYPASSRLS)。
#[tracing::instrument(name = "pg.avatar_repair", skip_all)]
pub async fn repair_legacy_avatars(
    app: &PgPool,
    content_system: &PgPool,
) -> anyhow::Result<AvatarRepairReport> {
    // (资料主人, 头像 content id)
    let refs: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "select user_id, avatar_content_id from profiles where avatar_content_id is not null",
    )
    .fetch_all(app)
    .await
    .context("读 app.profiles 的头像引用失败")?;
    let referenced: Vec<Uuid> = refs
        .iter()
        .map(|(_, cid)| *cid)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let mut report = AvatarRepairReport {
        avatars: referenced.len(),
        ..Default::default()
    };
    if referenced.is_empty() {
        return Ok(report);
    }
    let legacy = content::DEFAULT_TENANT_ID;

    let mut tx = content_system
        .begin()
        .await
        .context("content system 池开事务失败")?;
    // 还在默认租户里的被引用内容及其 owner;只转 owner = 资料主人的(头像绑定时就校验过 owner,
    // 对不上的是脏引用,不替它把别人的内容拉成个人内容)。
    let candidates: Vec<(Uuid, Uuid)> =
        sqlx::query_as("select id, owner_id from content where id = any($1) and tenant_id = $2")
            .bind(&referenced)
            .bind(legacy)
            .fetch_all(&mut *tx)
            .await
            .context("查被引用的头像内容失败")?;
    let pairs: HashSet<(Uuid, Uuid)> = refs.iter().map(|(user, cid)| (*cid, *user)).collect();
    let mut owner_of: HashMap<Uuid, Uuid> = HashMap::new();
    for (id, owner) in candidates {
        if pairs.contains(&(id, owner)) {
            owner_of.insert(id, owner);
        } else {
            report.owner_mismatch += 1;
        }
    }
    if report.owner_mismatch > 0 {
        tracing::warn!(
            count = report.owner_mismatch,
            "有头像引用指向 owner 不是资料主人的内容,未转成个人内容"
        );
    }
    let avatars: Vec<Uuid> = owner_of.keys().copied().collect();
    if avatars.is_empty() {
        tx.commit().await.context("提交旧头像修复失败")?;
        return Ok(report);
    }

    // 头像派生出的**直接**子内容(缩略图等)跟着头像走,且 owner 要和头像一致;孙一层不跟(它的派生关系挂在子内容下,
    // 不在这里改,否则会出现「关系是个人、内容还在租户」的错配)。
    let children: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "select d.parent_id, d.content_id, c.owner_id
           from content_derived d join content c on c.id = d.content_id
          where d.parent_id = any($1) and d.tenant_id = $2 and c.tenant_id = $2",
    )
    .bind(&avatars)
    .bind(legacy)
    .fetch_all(&mut *tx)
    .await
    .context("查头像的派生内容失败")?;
    let mut ids = avatars.clone();
    ids.extend(
        children
            .into_iter()
            .filter(|(parent, _, owner)| owner_of.get(parent) == Some(owner))
            .map(|(_, child, _)| child),
    );
    ids.sort_unstable();
    ids.dedup();

    // 派生关系:只改「父是原始头像、子也在这次转换集合里」的那几条(`$1` 只放原始头像 id)。
    report.derived = sqlx::query(
        "update content_derived set tenant_id = null
          where parent_id = any($1) and content_id = any($2) and tenant_id = $3",
    )
    .bind(&avatars)
    .bind(&ids)
    .bind(legacy)
    .execute(&mut *tx)
    .await
    .context("改 content_derived 失败")?
    .rows_affected();
    let exec = |sql: &'static str| sqlx::query(sql).bind(ids.clone()).bind(legacy);
    report.object_metadata = exec(
        "update object_metadata set tenant_id = null
          where tenant_id = $2 and object_id in (select id from object where content_id = any($1))",
    )
    .execute(&mut *tx)
    .await
    .context("改 object_metadata 失败")?
    .rows_affected();
    report.objects =
        exec("update object set tenant_id = null where content_id = any($1) and tenant_id = $2")
            .execute(&mut *tx)
            .await
            .context("改 object 失败")?
            .rows_affected();
    report.content_metadata = exec(
        "update content_metadata set tenant_id = null where content_id = any($1) and tenant_id = $2",
    )
    .execute(&mut *tx)
    .await
    .context("改 content_metadata 失败")?
    .rows_affected();
    report.contents =
        exec("update content set tenant_id = null where id = any($1) and tenant_id = $2")
            .execute(&mut *tx)
            .await
            .context("改 content 失败")?
            .rows_affected();
    tx.commit().await.context("提交旧头像修复失败")?;

    if report.rows() > 0 {
        tracing::info!(?report, "旧头像已转成个人内容");
    }
    Ok(report)
}

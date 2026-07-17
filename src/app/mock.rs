//! mock 样本数据(**dev/demo 专用**)—— 幂等写入 **app schema 的 widget / profile**。同 [`crate::app::seed`]
//! 范式,但跨模块:`mock.toml` 里的 `owner` 是 **username**(标识引用、非 FK),apply 时经 idm
//! `UserRepo` 解析成用户 id(组合根跨模块只读,绝不跨 schema join)。
//!
//! 默认来自仓库根 `mock.toml`(编译期 `include_str!` 嵌入),设 `MOCK_FILE` 读外部覆盖。
//! 只在 **非 prod** + app/idm 同进程 + seed 开启时跑,**绝不进 prod**(无 demo 数据污染)——
//! 见 `AppState::new` 的 gate。挡住它的是那道显式的 `!is_prod()`,**不是**"prod 都分进程"
//! (`IDM_EMBEDDED` 默认 true,prod 单体默认就是 `Both`)。

use std::collections::HashSet;

use anyhow::Context;
use serde::Deserialize;

use crate::app::seed::tenant_id_for;
use crate::features::profile::{ProfileFields, ProfileRepo};
use crate::features::widget::WidgetRepo;
use crate::infra::authz::TenantId;
use crate::infra::pagination::PageParams;
use idm::UserRepo;
use uuid::Uuid;

/// 编译期嵌入的默认 mock(仓库根 `mock.toml`)。`MOCK_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `mock.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_MOCK: &str = include_str!("../../mock.toml");

#[derive(Deserialize)]
pub struct MockData {
    #[serde(default)]
    widgets: Vec<WidgetSeed>,
    #[serde(default)]
    profiles: Vec<ProfileSeed>,
}

#[derive(Deserialize)]
struct WidgetSeed {
    name: String,
    /// owner 的 **username**(标识引用,非 FK);apply 时解析成 `created_by` 用户 id。
    owner: String,
    /// 所属租户的 **slug**(= seed.toml `[[tenants]].name`;标识引用,非 FK)——
    /// apply 时经 `seed::tenant_id_for` 解析成 id(uuid v5,确定性)。
    ///
    /// **它是必填的**:mock 是 dev 数据,归属得人来定,不能让代码替你猜(同 spec §3.3 对
    /// 存量 backfill 的要求 —— owner→tenant 的映射不是算得出来的)。
    tenant: String,
}

/// 样本 profile(1:1 user)。`owner` 是属主 **username**,apply 时解析成 user_id 主键。
/// 字段全可选(profile 各段本就 nullable);头像刻意不放 —— 那要先造 confirmed content,demo 不值。
#[derive(Deserialize)]
struct ProfileSeed {
    owner: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

impl MockData {
    /// 载入:`path`(来自 `Config.mock_file`,即 `MOCK_FILE`)指定的外部文件优先,否则用编译期嵌入的默认。
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let content = match path {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("读 MOCK_FILE {path} 失败"))?,
            None => EMBEDDED_MOCK.to_owned(),
        };
        toml::from_str(&content).context("解析 mock 数据失败")
    }
}

/// 幂等写 mock widget + profile:owner(username)经 idm 解析成用户 id。
/// widget 按 `(created_by, name)` 去重后创建;profile 主键即 user_id → upsert 天然幂等(无需去重集)。
/// **跨模块**:owner 解析读 idm `UserRepo`,数据写 app `WidgetRepo`/`ProfileRepo`(标识引用、不跨 schema join)。
pub async fn apply(
    widgets: &dyn WidgetRepo,
    profiles: &dyn ProfileRepo,
    users: &dyn UserRepo,
    data: &MockData,
) -> anyhow::Result<()> {
    // 已存在的 (tenant, created_by, name) 集合 = 幂等键。
    //
    // ⚠️ **租户必须进幂等键**:name 的唯一性是 (tenant_id, name) 复合的
    // (widgets_tenant_name_unique_alive),两家公司可以有同名 widget —— 少了租户这一维,
    // Globex 的 user-w1 会被 Acme 的那个"去重"掉,静默少建一行。
    // **按租户分别列** —— "列出全部 widget"这件事已经不存在了(list 的首参是 TenantId,
    // 而 mock 跨多家公司)。这不是麻烦,是隔离在起作用。
    // ponytail: 每租户取一页(上限 100);mock 是 demo 小数据,够用。真要大量样本再改 keyset 遍历。
    let tenants: HashSet<TenantId> = data
        .widgets
        .iter()
        .map(|w| TenantId::from_claim(tenant_id_for(w.tenant.trim())))
        .collect();
    let mut seen: HashSet<(Uuid, Option<String>, String)> = HashSet::new();
    for t in &tenants {
        let page = widgets
            .list(
                *t,
                &PageParams::Offset {
                    page: 1,
                    size: 100,
                    with_total: false,
                },
                None,
                Default::default(),
                Default::default(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("列 widget 失败: {e:?}"))?;
        seen.extend(
            page.items
                .into_iter()
                .map(|w| (w.tenant_id, w.created_by, w.name)),
        );
    }

    let mut created = 0usize;
    for w in &data.widgets {
        let owner = w.owner.trim().to_lowercase();
        let user = users.find_by_identifier(&owner).await?.with_context(|| {
            format!("mock widget `{}` 的 owner `{owner}` 在 idm 不存在", w.name)
        })?;
        let by = Some(user.user.id.to_string());
        // 租户 slug → id:确定性派生(uuid v5),与 seed::apply 建租户用的是同一个函数 ——
        // 所以这里不需要查库,也不可能算出不一样的 id。
        let tenant = TenantId::from_claim(tenant_id_for(w.tenant.trim()));
        if seen.contains(&(tenant.get(), by.clone(), w.name.clone())) {
            continue; // 幂等:同 (租户, owner, name) 已存在 → 跳过
        }
        widgets
            .create(tenant, w.name.clone(), by.clone())
            .await
            .map_err(|e| anyhow::anyhow!("建 mock widget `{}` 失败: {e:?}", w.name))?;
        seen.insert((tenant.get(), by, w.name.clone()));
        created += 1;
    }

    // profile:owner(username)解析成 user_id 主键 → upsert(主键即去重,天然幂等,无需 seen 集)。
    for p in &data.profiles {
        let owner = p.owner.trim().to_lowercase();
        let user = users
            .find_by_identifier(&owner)
            .await?
            .with_context(|| format!("mock profile 的 owner `{owner}` 在 idm 不存在"))?;
        let by = Some(user.user.id.to_string());
        profiles
            .upsert(
                user.user.id,
                ProfileFields {
                    display_name: p.display_name.clone(),
                    phone: p.phone.clone(),
                    ..Default::default()
                },
                by,
            )
            .await
            .map_err(|e| anyhow::anyhow!("建 mock profile(owner `{owner}`)失败: {e:?}"))?;
    }

    tracing::info!(
        widgets = data.widgets.len(),
        widgets_created = created,
        profiles = data.profiles.len(),
        "mock 数据已应用(幂等)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::profile::InMemoryProfileRepo;
    use crate::features::widget::InMemoryWidgetRepo;
    use idm::{InMemoryUserRepo, UserRepo};

    /// 幂等:同一份 mock 跑两遍,widget 不重复创建、profile 值稳定。
    #[tokio::test]
    async fn apply_is_idempotent() {
        let users = InMemoryUserRepo::new();
        users.create("admin", None, "h", None).await.unwrap();
        let user = users.create("user", None, "h", None).await.unwrap();
        let widgets = InMemoryWidgetRepo::new();
        let profiles = InMemoryProfileRepo::new();
        let data = MockData {
            widgets: vec![
                WidgetSeed {
                    name: "admin-w".into(),
                    owner: "admin".into(),
                    tenant: "acme".into(),
                },
                WidgetSeed {
                    name: "user-w".into(),
                    owner: "user".into(),
                    tenant: "acme".into(),
                },
            ],
            profiles: vec![ProfileSeed {
                owner: "user".into(),
                display_name: Some("Uma".into()),
                phone: None,
            }],
        };

        apply(&widgets, &profiles, &users, &data).await.unwrap();
        apply(&widgets, &profiles, &users, &data).await.unwrap(); // 二次:幂等,不重复

        let page = widgets
            .list(
                TenantId::from_claim(tenant_id_for("acme")),
                &PageParams::Offset {
                    page: 1,
                    size: 100,
                    with_total: false,
                },
                None,
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2, "二次 apply 不应重复创建 widget");

        let p = profiles
            .get(user.id)
            .await
            .unwrap()
            .expect("profile 应已建");
        assert_eq!(p.display_name.as_deref(), Some("Uma"), "profile 值应稳定");
    }
}

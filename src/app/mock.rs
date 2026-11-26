//! mock 样本数据(**dev/demo 专用**)—— 幂等写入 **app schema 的 widget / profile**。同 [`crate::app::seed`]
//! 范式,但跨模块:`mock.toml` 里的 `owner` 是 **username**(标识引用、非 FK),apply 时经 idm
//! `UserRepo` 解析成用户 id(组合根跨模块只读,绝不跨 schema join)。
//!
//! 默认来自仓库根 `mock.toml`(编译期 `include_str!` 嵌入),设 `MOCK_FILE` 读外部覆盖。
//! 只在 **非 prod** + app/idm 同进程 + seed 开启时跑,**绝不进 prod**(无 demo 数据污染)——
//! 见 `AppState::new` 的 gate。挡住它的是那道显式的 `!is_prod()`,**不是**"prod 都分进程"
//! (`IDM_EMBEDDED` 默认 true,prod 单体默认就是 `Both`)。

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use serde::Deserialize;

use super::seed::{ensure_membership, ensure_tenant, IdmSeedRepos, SeedData, TenantSeed, UserSeed};
use crate::features::profile::{ProfileFields, ProfileRepo};
use crate::features::widget::WidgetRepo;
use crate::kernel::authz::RoleName;
use crate::kernel::pagination::PageParams;
use crate::kernel::tenant::TenantId;

/// 编译期嵌入的默认 mock(仓库根 `mock.toml`)。`MOCK_FILE` 设了则读外部文件覆盖。
/// 注:Docker 构建需把 `mock.toml` 拷进 builder 上下文(见 Dockerfile),否则 `include_str!` 编译失败。
const EMBEDDED_MOCK: &str = include_str!("../../mock.toml");

#[derive(Deserialize)]
pub struct MockData {
    #[serde(default)]
    widgets: Vec<WidgetSeed>,
    #[serde(default)]
    profiles: Vec<ProfileSeed>,
    /// 演示租户(本地试切换租户用),格式同 seed 的 `[[tenants]]`。
    #[serde(default)]
    tenants: Vec<TenantSeed>,
    /// 演示成员关系:把 seed 账号(username)加进某租户(slug),授租户角色。取并集,幂等。
    #[serde(default)]
    members: Vec<MemberSeed>,
    /// 演示账号(格式同 seed 的 `[[users]]`,如一个平台管理员)。经 [`super::seed::apply`] 幂等建号 / 补角色;
    /// superadmin 不许在这里声明(seed 已有那一个,第二个会被拒)。
    #[serde(default)]
    users: Vec<UserSeed>,
}

#[derive(Deserialize)]
struct MemberSeed {
    /// 账号 **username**(seed.toml 里的)。
    username: String,
    /// 租户 slug(本文件 `[[tenants]]` 或 seed 里声明的)。
    tenant: String,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct WidgetSeed {
    name: String,
    /// owner 的 **username**(标识引用,非 FK);apply 时解析成 `created_by` 用户 id。
    owner: String,
    /// 写进哪个租户(slug);缺省 `default`(默认租户)。
    #[serde(default)]
    tenant: Option<String>,
}

/// 同一租户内 mock widget 的幂等键:(created_by, name)。
type WidgetKey = (Option<String>, String);

/// 默认租户的 slug(`seed.toml` 的 `[[tenants]]` 声明;固定 id = `DEFAULT_TENANT_ID`)。
const DEFAULT_TENANT_SLUG: &str = "default";

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
        let data: Self = toml::from_str(&content).context("解析 mock 数据失败")?;
        data.validate_users()?;
        Ok(data)
    }

    /// 演示账号载入即校验(同 seed:角色存在、作用域放对位置),且**不许声明 superadmin**(seed 里那一个是唯一的)。
    fn validate_users(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.users.iter().any(UserSeed::declares_superadmin),
            "mock 的演示账号不许声明 superadmin(只能有一个,由 seed 声明);平台管理员用 platform_admin"
        );
        SeedData::accounts(self.users.clone()).validate()
    }
}

/// 幂等写 mock 演示租户 / 成员关系(idm)+ widget / profile(app):owner(username)经 idm 解析成用户 id。
/// widget 按 `(created_by, name)` 去重后创建;profile 主键即 user_id → upsert 天然幂等(无需去重集);
/// 租户按 slug 找或建、成员关系取并集(与 seed 共用 `ensure_*`)。
/// **跨模块**:owner 解析读 idm `UserRepo`,数据写 app `WidgetRepo`/`ProfileRepo`(标识引用、不跨 schema join)。
pub async fn apply(
    widgets: &dyn WidgetRepo,
    profiles: &dyn ProfileRepo,
    idm: IdmSeedRepos<'_>,
    hasher: &dyn idm::PwHasher,
    data: &MockData,
) -> anyhow::Result<()> {
    let users = idm.users;
    // 演示租户 + 跨租户成员关系(先于 widget:与业务数据无关,只为本地能试切换租户)。
    for t in &data.tenants {
        ensure_tenant(idm.tenants, t, Some("system".to_owned())).await?;
    }
    // 演示账号(租户先建好,账号的成员关系才解析得到 slug)。
    if !data.users.is_empty() {
        super::seed::apply(
            idm,
            hasher,
            &SeedData::accounts(data.users.clone()),
            Some("system".to_owned()),
        )
        .await
        .context("mock 演示账号失败")?;
    }
    for m in &data.members {
        for r in &m.roles {
            let ok = r
                .parse::<RoleName>()
                .is_ok_and(|role| role.scope() == idm::RoleScope::Tenant);
            anyhow::ensure!(ok, "mock 成员 {} 的角色 {r} 不是租户角色", m.username);
        }
        let username = m.username.trim().to_lowercase();
        let user = users
            .find_by_identifier(&username)
            .await?
            .with_context(|| format!("mock 成员 `{username}` 在 idm 不存在"))?
            .user;
        let tenant = idm
            .tenants
            .get_by_slug(&m.tenant)
            .await
            .map_err(|e| anyhow::anyhow!("mock 成员引用的租户 `{}` 不存在: {e:?}", m.tenant))?;
        ensure_membership(idm, tenant.id, user.id, &m.roles, Some("system".to_owned())).await?;
    }

    // widget 按租户写:`tenant`(slug)缺省 = `default`(seed 声明的默认租户)。slug 经 idm 解析成 id ——
    // 租户不存在就报错,不会悄悄落到别处。幂等键 = (租户, created_by, name),每个租户第一次用到时载入已有行。
    // ponytail: 每租户取一页(上限 100);mock 是 demo 小数据,够用。真要大量样本再改 keyset 遍历。
    let mut seen: HashMap<String, (TenantId, HashSet<WidgetKey>)> = HashMap::new();
    let mut created = 0usize;
    for w in &data.widgets {
        let slug = w
            .tenant
            .as_deref()
            .unwrap_or(DEFAULT_TENANT_SLUG)
            .to_owned();
        if !seen.contains_key(&slug) {
            let t = idm.tenants.get_by_slug(&slug).await.map_err(|e| {
                anyhow::anyhow!("mock widget `{}` 的租户 `{slug}` 不存在: {e:?}", w.name)
            })?;
            let tenant = TenantId::new(t.id)
                .map_err(|e| anyhow::anyhow!("租户 `{slug}` 的 id 非法: {e:?}"))?;
            let existing = widgets
                .list(
                    tenant,
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
                .map_err(|e| anyhow::anyhow!("列租户 `{slug}` 的 widget 失败: {e:?}"))?;
            let keys = existing
                .items
                .into_iter()
                .map(|w| (w.created_by, w.name))
                .collect();
            seen.insert(slug.clone(), (tenant, keys));
        }
        let (tenant, keys) = seen.get_mut(&slug).expect("上面刚插入");
        let owner = w.owner.trim().to_lowercase();
        let user = users.find_by_identifier(&owner).await?.with_context(|| {
            format!("mock widget `{}` 的 owner `{owner}` 在 idm 不存在", w.name)
        })?;
        let by = Some(user.user.id.to_string());
        if keys.contains(&(by.clone(), w.name.clone())) {
            continue; // 幂等:同租户 + 同 owner + 同 name 已存在 → 跳过
        }
        widgets
            .create(*tenant, w.name.clone(), by.clone())
            .await
            .map_err(|e| anyhow::anyhow!("建 mock widget `{}` 失败: {e:?}", w.name))?;
        keys.insert((by, w.name.clone()));
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
        tenants = data.tenants.len(),
        members = data.members.len(),
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
    use idm::{
        InMemoryMemberRepo, InMemoryRoleRepo, InMemoryTenantRepo, InMemoryUserRepo, MemberRepo,
        RoleRepo, TenantRepo, UserRepo,
    };

    /// 嵌入的 mock.toml 能载入(演示账号过 seed 校验);声明 superadmin / 角色写错位置的演示账号载入即报错。
    #[test]
    fn mock_users_are_validated_on_load() {
        MockData::load(None).expect("嵌入的 mock.toml 应能载入");
        let bad = |users: &str| {
            let data: MockData = toml::from_str(users).unwrap();
            data.validate_users().unwrap_err().to_string()
        };
        let err = bad(r#"[[users]]
username = "root2"
password = "p"
platform_roles = ["superadmin"]"#);
        assert!(err.contains("superadmin"), "{err}");
        bad(r#"[[users]]
username = "x"
password = "p"
platform_roles = ["admin"]"#);
        bad(r#"[[users]]
username = "x"
password = "p"
platform_roles = ["nope"]"#);
    }

    /// 幂等:同一份 mock 跑两遍,widget 不重复创建、profile 值稳定、演示租户 / 成员关系不重复。
    #[tokio::test]
    async fn apply_is_idempotent() {
        let users = InMemoryUserRepo::new();
        let roles = InMemoryRoleRepo::sharing_with(&users);
        let tenants = InMemoryTenantRepo::sharing_with(&users);
        let members = InMemoryMemberRepo::sharing_with(&users);
        roles
            .upsert("user", "普通用户", idm::RoleScope::Tenant, None)
            .await
            .unwrap();
        let repos = IdmSeedRepos {
            users: &users,
            roles: &roles,
            tenants: &tenants,
            members: &members,
        };
        // 默认租户(seed 建的;mock widget 缺省 tenant 写进它)
        tenants
            .upsert_fixed(
                crate::kernel::tenant::DEFAULT_TENANT_ID.as_uuid(),
                "default",
                "默认组织",
                None,
            )
            .await
            .unwrap();
        users.create("admin", None, "h", None).await.unwrap();
        let user = users.create("user", None, "h", None).await.unwrap();
        let widgets = InMemoryWidgetRepo::new();
        let profiles = InMemoryProfileRepo::new();
        let data = MockData {
            widgets: vec![
                WidgetSeed {
                    name: "admin-w".into(),
                    owner: "admin".into(),
                    tenant: None,
                },
                WidgetSeed {
                    name: "user-w".into(),
                    owner: "user".into(),
                    tenant: None,
                },
                WidgetSeed {
                    name: "user-w".into(),
                    owner: "user".into(),
                    tenant: Some("demo".into()),
                },
            ],
            profiles: vec![ProfileSeed {
                owner: "user".into(),
                display_name: Some("Uma".into()),
                phone: None,
            }],
            tenants: vec![toml::from_str(
                r#"slug = "demo"
name = "演示组织""#,
            )
            .unwrap()],
            members: vec![MemberSeed {
                username: "user".into(),
                tenant: "demo".into(),
                roles: vec!["user".into()],
            }],
            users: vec![toml::from_str(
                r#"username = "pa"
password = "pwd"
platform_roles = ["platform_admin"]"#,
            )
            .unwrap()],
        };

        apply(&widgets, &profiles, repos, &idm::FakeHasher, &data)
            .await
            .unwrap();
        apply(&widgets, &profiles, repos, &idm::FakeHasher, &data)
            .await
            .unwrap(); // 二次:幂等,不重复

        let ms = members.memberships_for_user(user.id).await.unwrap();
        assert_eq!(ms.len(), 1, "演示租户成员关系只建一次");
        assert_eq!(ms[0].tenant.slug, "demo");
        assert_eq!(ms[0].roles, vec!["user".to_owned()]);

        let list = |tenant: TenantId| {
            let widgets = &widgets;
            async move {
                widgets
                    .list(
                        tenant,
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
                    .unwrap()
                    .items
            }
        };
        let in_default = list(crate::kernel::tenant::DEFAULT_TENANT_ID).await;
        assert_eq!(in_default.len(), 2, "二次 apply 不应重复创建 widget");
        let demo = tenants.get_by_slug("demo").await.unwrap();
        let in_demo = list(TenantId::new(demo.id).unwrap()).await;
        assert_eq!(in_demo.len(), 1, "写进声明的租户(同名不撞默认租户那条)");

        let p = profiles
            .get(user.id)
            .await
            .unwrap()
            .expect("profile 应已建");
        assert_eq!(p.display_name.as_deref(), Some("Uma"), "profile 值应稳定");

        // 演示平台管理员:建一次、带平台角色 platform_admin
        let pa = users
            .find_by_identifier("pa")
            .await
            .unwrap()
            .expect("演示账号应已建")
            .user;
        assert_eq!(
            roles.roles_for_user(pa.id).await.unwrap(),
            vec!["platform_admin".to_owned()]
        );
    }
}

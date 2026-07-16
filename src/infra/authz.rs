//! 授权(AuthZ)—— **归 app**。idm 只给身份事实(token 里的 roles),"role/scope 能干什么"全在这。
//!
//! 三份真相,各归其位:
//! - **权限词表**(有哪些 `Perm`)= 本文件的封闭枚举,拼错=编译错;
//! - **role→权限映射** = `seed.toml` 的 `[[roles]].permissions`(唯一真相),启动期载进 [`Policy`];
//! - **user→role** = idm 库 → JWT claim(运行期事实,不进文件)。
//!
//! 判定全在 app 进程内存完成:token 带 roles,[`Policy`] 把 roles 展开成权限,**绝不查 idm 库**
//! —— 契合"app 进程只 decode JWT"的拓扑。`scope` 是 per-token 子集(只收窄、不放大)。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::error::AppError;
use idm::AuthUser;

/// 权限词表的**唯一真相**(封闭集)。handler 用变体 `Perm::WidgetWrite`,拼错=编译错。
/// wire 串(TOML / JWT scope)经 `rename` 映射;未知串 → 反序列化失败 → 启动期挡住(fail-fast)。
/// 加权限 = 加一个变体 + `rename`,别处不动。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub enum Perm {
    #[serde(rename = "widgets:read")]
    WidgetRead,
    /// 越权读:看**所有人**的 widget(否则只看自己创建的)。这是 ownership 的 mode 开关。
    #[serde(rename = "widgets:read:all")]
    WidgetReadAll,
    #[serde(rename = "widgets:write")]
    WidgetWrite,
    /// 越权写:改/删**任何人**的 widget(否则只动自己创建的)。write 侧 ownership mode 开关,
    /// 与 `contents:write:all` / `profiles:write:all` 同范式 —— widget 是被照抄的样板模块,
    /// 读侧有 `widgets:read:all` 而写侧没有,copy 出去的模块就会继承"读自己的、写所有人的"。
    #[serde(rename = "widgets:write:all")]
    WidgetWriteAll,
    #[serde(rename = "widgets:delete")]
    WidgetDelete,
    #[serde(rename = "contents:read")]
    ContentRead,
    /// 越权读:看**所有人**的 content(否则只看自己 owner 的)。ownership 的 mode 开关,仿 widgets:read:all。
    #[serde(rename = "contents:read:all")]
    ContentReadAll,
    #[serde(rename = "contents:write")]
    ContentWrite,
    /// 越权写:改/删**任何人**的 content。write 侧 ownership mode 开关,仿 profiles:write:all。
    #[serde(rename = "contents:write:all")]
    ContentWriteAll,
    #[serde(rename = "contents:delete")]
    ContentDelete,
    #[serde(rename = "users:admin")]
    UsersAdmin,
    /// 后台准入(backend gate)。`/api/v1/admin` 组闸 + admin_login 自查用它。
    /// 与 `users:admin` **拆开**:admin+superadmin 皆持(能进后台);`users:admin` 仍 superadmin 专属
    /// (用户管理 + 跨用户列全 widget 等真·超管操作)。故名为 admin 的账号能登后台,但仍够不到 superadmin 专属端点。
    #[serde(rename = "admin:login")]
    AdminLogin,
    #[serde(rename = "profiles:read")]
    ProfileRead,
    #[serde(rename = "profiles:write")]
    ProfileWrite,
    /// 越权写:改**任何人**的 profile(否则只能改自己)。write 侧的 ownership mode 开关,
    /// 镜像 `widgets:read:all` 的 qualifier+implies 范式。
    #[serde(rename = "profiles:write:all")]
    ProfileWriteAll,
}

impl Perm {
    /// 全部变体(catalog / round-trip 测试用)。
    ///
    /// **加变体必须补这里,但没有任何东西会替你发现漏了** —— 说清楚免得误信:`ALL` 是数组字面量,
    /// 加变体不会让它编译失败;round-trip 测试遍历的正是 `ALL`,漏掉的变体只是从不被测。
    /// 真正会拦你的是 `resource()`/`action()`/`qualifier()`/`description()` 那几个**穷尽 match**
    /// (编译不过)—— 它们逼你回来改这个 impl,但补 `ALL` 仍靠自觉。
    /// 而 `ALL` 是**运行期**载荷:superadmin 全权(`default_permissions`)、OpenAPI scope 目录、
    /// seed 权限词表都从它派生 —— 漏一个变体 = superadmin 静默缺权 + 该 scope 不进文档 + 不入库,
    /// 且两个看似能拦住的测试都拦不住(它们两边都从 `ALL` 派生,自洽通过)。
    /// 要根治:用声明宏单源展开 enum + `ALL` + 各投影,让"漏项"不可表达。
    pub const ALL: [Perm; 15] = [
        Perm::WidgetRead,
        Perm::WidgetReadAll,
        Perm::WidgetWrite,
        Perm::WidgetWriteAll,
        Perm::WidgetDelete,
        Perm::ContentRead,
        Perm::ContentReadAll,
        Perm::ContentWrite,
        Perm::ContentWriteAll,
        Perm::ContentDelete,
        Perm::UsersAdmin,
        Perm::AdminLogin,
        Perm::ProfileRead,
        Perm::ProfileWrite,
        Perm::ProfileWriteAll,
    ];

    /// 三段约定 `domain:verb[:qualifier]` 的**第一段**(资源)。从变体投影,**绝不运行期 split wire 串**。
    /// 这些投影是 permission 一等概念的"字段",按需派生、零存储;wire 串与内部比较都不靠它们。
    pub fn resource(&self) -> &'static str {
        match self {
            Perm::WidgetRead
            | Perm::WidgetReadAll
            | Perm::WidgetWrite
            | Perm::WidgetWriteAll
            | Perm::WidgetDelete => "widgets",
            Perm::ContentRead
            | Perm::ContentReadAll
            | Perm::ContentWrite
            | Perm::ContentWriteAll
            | Perm::ContentDelete => "contents",
            Perm::UsersAdmin => "users",
            Perm::AdminLogin => "admin",
            Perm::ProfileRead | Perm::ProfileWrite | Perm::ProfileWriteAll => "profiles",
        }
    }

    /// **第二段**(动作)。
    pub fn action(&self) -> &'static str {
        match self {
            Perm::WidgetRead | Perm::WidgetReadAll => "read",
            Perm::WidgetWrite | Perm::WidgetWriteAll => "write",
            Perm::WidgetDelete => "delete",
            Perm::ContentRead | Perm::ContentReadAll => "read",
            Perm::ContentWrite | Perm::ContentWriteAll => "write",
            Perm::ContentDelete => "delete",
            Perm::UsersAdmin => "admin",
            Perm::AdminLogin => "login",
            Perm::ProfileRead => "read",
            Perm::ProfileWrite | Perm::ProfileWriteAll => "write",
        }
    }

    /// **第三段**(限定词,可选)。`read:all` 的 `all`;只读投影,**不是**存储字段、**不是** `read` 上的开关。
    /// 注意这里是 `_ => None` 兜底,**不穷尽** —— 加 `*All` 变体忘了列进来不会编译失败,
    /// 只会让 `wire()` 少掉 `:all` 段、与 serde rename 对不上(`perm_wire_matches_projection` 会红)。
    pub fn qualifier(&self) -> Option<&'static str> {
        match self {
            Perm::WidgetReadAll
            | Perm::WidgetWriteAll
            | Perm::ContentReadAll
            | Perm::ContentWriteAll
            | Perm::ProfileWriteAll => Some("all"),
            _ => None,
        }
    }

    /// wire 串 `resource:action[:qualifier]`(从投影合成)。与 serde rename 同源 ——
    /// `perm_wire_matches_projection` 测试钉死两者不漂移。
    pub fn wire(&self) -> String {
        match self.qualifier() {
            Some(q) => format!("{}:{}:{q}", self.resource(), self.action()),
            None => format!("{}:{}", self.resource(), self.action()),
        }
    }

    /// **蕴含**:持有本权限即隐含持有这些。`read:all ⇒ read`(能看全部必然能看)。
    /// [`Policy::from_roles`] 载入期与 [`Policy::require_scoped`] scope 判定都按它展开 →
    /// 从根消除"只给 `read:all` 漏 `read` → 顶层 `require_scoped(read)` 先 403"的配置坑。
    /// 目前**单层**(被蕴含项自身无再蕴含);将来出现链式 A⇒B⇒C,需在展开处做传递闭包。
    pub fn implies(&self) -> &'static [Perm] {
        match self {
            Perm::WidgetReadAll => &[Perm::WidgetRead],
            Perm::WidgetWriteAll => &[Perm::WidgetWrite],
            Perm::ContentReadAll => &[Perm::ContentRead],
            Perm::ContentWriteAll => &[Perm::ContentWrite],
            Perm::ProfileWriteAll => &[Perm::ProfileWrite],
            _ => &[],
        }
    }

    /// 人读说明(落 `permissions` 表 / 权限清单)。曾在 `seed.toml` `[[permissions]]`,
    /// 现收进代码 —— **enum 是唯一真相**,词表不再另存镜像。
    pub fn description(&self) -> &'static str {
        match self {
            Perm::WidgetRead => "查看自己创建的 widget",
            Perm::WidgetReadAll => "查看所有人的 widget(而非仅自己)",
            Perm::WidgetWrite => "创建 / 修改自己创建的 widget",
            Perm::WidgetWriteAll => "修改 / 删除任何人的 widget(而非仅自己创建的)",
            Perm::WidgetDelete => "删除 widget",
            Perm::ContentRead => "查看内容 / 下载 / 列对象与元数据",
            Perm::ContentReadAll => "查看所有人的内容(而非仅自己)",
            Perm::ContentWrite => "创建 / 上传 / 修改内容与元数据",
            Perm::ContentWriteAll => "修改 / 删除任何人的内容(而非仅自己)",
            Perm::ContentDelete => "删除内容",
            Perm::UsersAdmin => "用户管理(superadmin 专属)",
            Perm::AdminLogin => {
                "后台准入:登进 /admin 组(admin + superadmin 皆持;与 users:admin 拆开)"
            }
            Perm::ProfileRead => "查看任意用户资料",
            Perm::ProfileWrite => "修改自己的资料",
            Perm::ProfileWriteAll => "修改任何人的资料(而非仅自己)",
        }
    }
}

/// 角色名的**唯一真相**(封闭集)。角色本身不做动态 CRUD(角色**有哪些权限**才可运行时改,
/// 见 `role_permissions` 表);故角色集编进代码。wire 串经 `rename`,与 idm.roles.name / JWT
/// claim / `role_permissions.role_name` 同源。加角色 = 加变体 + 补 `ALL`/`display_name`/`default_permissions`。
///
/// # 两级角色 —— 加变体前先看清它属于哪一级(spec §4.5)
///
/// - **平台角色**(`Superadmin`/`Admin`/`User`):骑在租户边界**之上**,存 `idm.user_roles`,
///   可经后台 `PUT /users/{id}/roles` 授予 ⇒ 必须进 [`RoleName::PLATFORM`]。
/// - **租户角色**(`TenantAdmin`/`TenantMember`):关在租户边界**之内**,存
///   `idm.tenant_members.role`,只能靠成员资格获得 ⇒ **绝不可进 `PLATFORM`**,否则就是一条
///   提权路径(见 `PLATFORM` 的 doc)。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub enum RoleName {
    #[serde(rename = "superadmin")]
    Superadmin,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
    /// **租户级** admin(`tn:admin`)。与平台 `Admin` 是两回事 —— 见本枚举的 doc。
    #[serde(rename = "tn:admin")]
    TenantAdmin,
    /// **租户级** 普通成员(`tn:member`)。
    #[serde(rename = "tn:member")]
    TenantMember,
}

impl RoleName {
    /// **可授予的平台角色目录** —— `ALL` 一拆为二的那一半。
    ///
    /// ⚠️ **租户角色绝不可进这里**,否则是一条完整的跨租户提权路径:
    /// `seed::apply` 拿它 upsert 进 `idm.roles` → `GET /admin/auth/roles`(`list_roles`)把它当
    /// 候选发给后台 UI → `PUT /users/{id}/roles`(`set_user_roles`)能把 `tn:admin` 授进
    /// `idm.user_roles` → `TenantRoleRepo` 第一行 `inner.roles_for_user()` 原样返回它 → 签进 claim。
    /// **结果:一个从没被邀请进任何租户的人,在回退挑中的那个租户里就是 admin。**
    ///
    /// `assert_no_escalation` 挡不住 —— 它只要求授予方持有被授角色的全部 perm,而
    /// 「`tn:admin` 的权限 ⊆ superadmin 的 `Perm::ALL`」恰恰**保证**闸必过。
    ///
    /// 消费方:`seed::apply` 的 `idm.roles` upsert、seed.toml 账号引用校验、
    /// `users` 模块的 `list_roles`/`set_user_roles` 入参校验。
    pub const PLATFORM: [RoleName; 3] = [RoleName::Superadmin, RoleName::Admin, RoleName::User];

    /// 全部变体(**含租户角色**)。加变体必补这里 —— 同 `Perm::ALL`,**漏了没有任何东西会发现**
    /// (数组字面量,不编译失败;round-trip 测试遍历的就是它)。`as_str()` 的穷尽 match 会逼你
    /// 回到本 impl,但补 `ALL` 靠自觉。
    ///
    /// 消费方(**只准是这三类**,别拿它去 seed `idm.roles`):`from_str`(claim 里的 `tn:*`
    /// 必须解析得出)、`Policy::from_roles` 的权限映射、`role_permissions` 表的 bootstrap。
    pub const ALL: [RoleName; 5] = [
        RoleName::Superadmin,
        RoleName::Admin,
        RoleName::User,
        RoleName::TenantAdmin,
        RoleName::TenantMember,
    ];

    /// wire 串(== serde `rename`;单一来源,`role_name_wire_matches` 测试钉死不漂移)。
    ///
    /// `tn:admin`/`tn:member` **必须与 `TenantRole::claim()` 逐字相等** —— 这是等式不是巧合
    /// (spec §4.5):`TenantRoleRepo` push 它,`Policy` 按它查权限。
    /// `tenant_role_claim_matches_role_name` 测试钉住。
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "superadmin",
            RoleName::Admin => "admin",
            RoleName::User => "user",
            RoleName::TenantAdmin => "tn:admin",
            RoleName::TenantMember => "tn:member",
        }
    }

    /// 是不是**租户级**角色(`tn:` 前缀)。平台角色目录/授予路径靠它过滤。
    pub fn is_tenant_scoped(&self) -> bool {
        matches!(self, RoleName::TenantAdmin | RoleName::TenantMember)
    }

    /// 人读显示名(seed idm.roles.display_name)。
    pub fn display_name(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "超级管理员",
            RoleName::Admin => "管理员",
            RoleName::User => "普通用户",
            RoleName::TenantAdmin => "租户管理员",
            RoleName::TenantMember => "租户成员",
        }
    }

    /// **bootstrap 默认**权限(seed 写进 `role_permissions`,`ON CONFLICT DO NOTHING` 不覆盖运行期改动)。
    /// superadmin = `Perm::ALL`(随闭集自动增长,消除"加权限忘补超管"漂移)。运行期真值以库为准。
    pub fn default_permissions(&self) -> Vec<Perm> {
        match self {
            RoleName::Superadmin => Perm::ALL.to_vec(),
            RoleName::Admin => vec![
                Perm::WidgetRead,
                Perm::WidgetReadAll,
                Perm::WidgetWrite,
                Perm::WidgetWriteAll,
                Perm::WidgetDelete,
                Perm::ContentRead,
                Perm::ContentReadAll,
                Perm::ContentWrite,
                Perm::ContentWriteAll,
                Perm::ContentDelete,
                Perm::ProfileRead,
                Perm::ProfileWrite,
                Perm::ProfileWriteAll,
                Perm::AdminLogin,
            ],
            RoleName::User => vec![
                Perm::WidgetRead,
                Perm::ContentRead,
                Perm::ContentWrite,
                Perm::ProfileRead,
                Perm::ProfileWrite,
            ],
            // ── 租户级:**绝不含任何平台级 perm**(`UsersAdmin` / `AdminLogin`)。 ──
            // 那两个是「骑在租户边界之上」的能力:UsersAdmin 能管所有租户的用户、AdminLogin
            // 是后台入口。租户 admin 只在自己那家公司里是 admin —— 它的 `:all` 限定符
            // (WidgetReadAll 等)在 P4 开闸后语义会**收窄**成「本租户内全部」,因为
            // repo 已先按 tenant 过滤过(spec §5.1)。在那之前它就是普通的 read:all,
            // 所以 P4 之前**不要**给任何人授租户角色。
            RoleName::TenantAdmin => vec![
                Perm::WidgetRead,
                Perm::WidgetReadAll,
                Perm::WidgetWrite,
                Perm::WidgetWriteAll,
                Perm::WidgetDelete,
                Perm::ContentRead,
                Perm::ContentReadAll,
                Perm::ContentWrite,
                Perm::ContentWriteAll,
                Perm::ContentDelete,
                Perm::ProfileRead,
                Perm::ProfileWrite,
            ],
            RoleName::TenantMember => vec![
                Perm::WidgetRead,
                Perm::WidgetWrite,
                Perm::ContentRead,
                Perm::ContentWrite,
                Perm::ProfileRead,
                Perm::ProfileWrite,
            ],
        }
    }
}

impl RoleName {
    /// wire 串集合 → 闭集,**lossy**:不在闭集的(存量部署遗留 / 手工 INSERT 的旧角色名)
    /// 跳过 + warn,绝不 panic —— 一行脏数据不该打挂整个读路径(login/me/用户列表/权限清单)。
    /// closed-enums skill 的「数据异常就炸」只背书单写者不变量;角色行存在版本偏斜面(旧 seed、运维手改)。
    pub fn parse_lossy<I: IntoIterator<Item = String>>(roles: I) -> Vec<RoleName> {
        roles
            .into_iter()
            .filter_map(|r| match r.parse() {
                Ok(role) => Some(role),
                Err(_) => {
                    Self::warn_unknown(&r);
                    None
                }
            })
            .collect()
    }

    /// 闭集外角色名的统一告警口径:每进程每名 **一次**(该路径在热读位置 —— list 每行 /
    /// me 每请求,一条存量脏数据不该刷屏)。parse_lossy 与角色目录过滤共用。
    pub fn warn_unknown(role: &str) {
        static WARNED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
            std::sync::OnceLock::new();
        let warned = WARNED.get_or_init(Default::default);
        if warned.lock().unwrap().insert(role.to_owned()) {
            tracing::warn!(role = %role, "角色名不在 RoleName 闭集内,读模型跳过(存量脏数据?)");
        }
    }
}

/// wire 串(JWT claim / idm.roles.name)→ 枚举,给读模型强类型化用(镜像 `AuthEventType::FromStr`)。
impl std::str::FromStr for RoleName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 经 ALL × as_str 查表:不再手写第三份 wire 映射(serde rename / as_str 之外),加变体零改动。
        RoleName::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("未知角色名: {s}"))
    }
}

/// role → 权限集。默认从 `RoleName::default_permissions()` 派生(见 `app::seed::SeedData::policy`);
/// 设 `APP_DB_HOST` 时改从 `role_permissions` 表载(运行期可改)。装进 `AppState`
/// (`Arc`,廉价 Clone)。**不可变**:载入一次,运行期只读。
#[derive(Default, Debug)]
pub struct Policy {
    by_role: HashMap<String, HashSet<Perm>>,
}

impl Policy {
    /// 从 (role 名, 权限) 序列构建。同名 role 的权限取并集;权限为空的 role 也建条目(算"已覆盖")。
    /// **载入期按 `implies` 展开**(`read:all ⇒ read`):配 `read:all` 即自动有 `read`,从根消除漏底权 footgun。
    pub fn from_roles(roles: impl IntoIterator<Item = (String, Vec<Perm>)>) -> Self {
        let mut by_role: HashMap<String, HashSet<Perm>> = HashMap::new();
        for (role, perms) in roles {
            let set = by_role.entry(role).or_default();
            for p in perms {
                set.insert(p);
                set.extend(p.implies().iter().copied());
            }
        }
        Self { by_role }
    }

    /// 用户(经其 roles)拥有的全部权限并集。
    pub fn perms_for(&self, roles: &[String]) -> HashSet<Perm> {
        roles
            .iter()
            .filter_map(|r| self.by_role.get(r))
            .flatten()
            .copied()
            .collect()
    }

    /// **RBAC gate**:用户的 role 给了该权限 → Ok,否则 → 403。token 里的 roles 内存展开,不查库。
    pub fn require(&self, user: &AuthUser, perm: Perm) -> Result<(), AppError> {
        self.require_scoped(user, &[], perm)
    }

    /// **RBAC + scope gate**:有效权限 = `role 权限 ∩ scope`(`scope` 空 = 无 scope 限制,即满 role 权限)。
    /// scope 只能收窄不能放大 —— 降权令牌(PAT/第三方)即便 role 够,scope 没给也拒。
    pub fn require_scoped(
        &self,
        user: &AuthUser,
        scope: &[Perm],
        perm: Perm,
    ) -> Result<(), AppError> {
        let role_grants = self.perms_for(&user.roles).contains(&perm); // role 侧已在 from_roles 展开 implies
                                                                       // scope 侧同样吃 implies:scope 含 `read:all` 即视为含 `read`,与 role 侧一致,降权令牌不踩漏底权坑。
        let in_scope = scope.is_empty()
            || scope.contains(&perm)
            || scope.iter().any(|s| s.implies().contains(&perm));
        if role_grants && in_scope {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// **多权限 AND**:全部通过才放行(逐个 [`Self::require_scoped`],role ∩ scope 语义不变)。
    /// 空切片 = 恒 Ok(无要求);调用方别拿空表当"禁止"用。
    pub fn require_all(
        &self,
        user: &AuthUser,
        scope: &[Perm],
        perms: &[Perm],
    ) -> Result<(), AppError> {
        perms
            .iter()
            .try_for_each(|&p| self.require_scoped(user, scope, p))
    }

    /// **多权限 OR**:任一通过即放行,全败 → 403。空切片 = 恒 403(无可满足支)。
    pub fn require_any(
        &self,
        user: &AuthUser,
        scope: &[Perm],
        perms: &[Perm],
    ) -> Result<(), AppError> {
        if perms
            .iter()
            .any(|&p| self.require_scoped(user, scope, p).is_ok())
        {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// **数据可见域(ownership mode)**:边缘的 RBAC∩scope 推出"能不能看全部"——有 `all_perm`(经
    /// `require_scoped`,故 role 与 scope 都参与)→ [`Access::All`],否则只看自己 → [`Access::Own`]。
    /// 这是三轴的扣点:类型级判定(RBAC∩scope)**参数化**行级 ownership;真正的过滤在查询里(见 `Access`)。
    pub fn data_access(&self, user: &AuthUser, scope: &[Perm], all_perm: Perm) -> Access {
        if self.require_scoped(user, scope, all_perm).is_ok() {
            Access::All
        } else {
            Access::Own(user.id)
        }
    }

    /// 启动期不变量:每个被账号引用的 role 都得有策略条目(漏配=该 role 永远拿不到权限,是 wiring 错)。
    /// 失败即拒启动 —— 同 `AuthService::build` 缺端口即 panic 的 fail-fast 哲学。
    pub fn assert_roles_covered<'a>(
        &self,
        roles: impl IntoIterator<Item = &'a str>,
    ) -> anyhow::Result<()> {
        for r in roles {
            anyhow::ensure!(
                self.by_role.contains_key(r),
                "角色 `{r}` 无授权策略条目(seed.toml 漏配 permissions)"
            );
        }
        Ok(())
    }
}

/// **数据可见域(行级 ownership)**。RBAC∩scope 在边缘算出它(见 [`Policy::data_access`]),
/// 真正的过滤**在查询/service 里**执行——这是 ownership 与 RBAC/scope 的本质差异:它需要"那行的 owner"。
/// `All` = 看全部(不加 owner 过滤);`Own(id)` = 只看 `created_by == id` 的行。
#[derive(Clone, Copy, Debug)]
pub enum Access {
    All,
    Own(Uuid),
}

impl Access {
    /// 某行(owner = `created_by`)在本可见域内是否可见。list 用它过滤;**读路径**单条不可见 → 调用方通常返 404
    /// (不泄露存在);**写权型 ownership**(资源本就任意可读,如 profile PUT)可返 403,见 profile routes。
    pub fn allows(&self, owner: Uuid) -> bool {
        match self {
            Access::All => true,
            Access::Own(me) => *me == owner,
        }
    }

    /// 同 [`Access::allows`],但吃实体的 `created_by: Option<String>`(用户 id 字符串)。
    /// 非 UUID('system'/NULL/历史脏值)→ `Own` 下一律不可见(只有 `All` 放行)。
    pub fn allows_created_by(&self, created_by: Option<&str>) -> bool {
        match self {
            Access::All => true,
            Access::Own(_) => created_by
                .and_then(|s| Uuid::parse_str(s).ok())
                .is_some_and(|o| self.allows(o)),
        }
    }

    /// **list 用的 owner 过滤**:`All` → `None`(不过滤,看全部);`Own(id)` → `Some(id)`(查询里 `created_by = id`)。
    /// ownership 过滤落在**查询层**(repo)才对分页正确 —— 边缘只产出这个过滤,不在内存里事后筛。
    pub fn owner_filter(&self) -> Option<Uuid> {
        match self {
            Access::All => None,
            Access::Own(id) => Some(*id),
        }
    }
}

/// 当前请求令牌携带的 scope(per-token 权限子集)。鉴权中间件验过 token 后塞进 extensions;
/// **空 = 无 scope 限制**(第一方满权令牌)。非空 = 降权令牌,有效权限再 ∩ 它。
///
/// extractor:只读 extension,无则空(未认证由 `CurrentUser` 先 401 挡掉,这里不重复判)。
#[derive(Clone, Debug, Default)]
pub struct TokenScope(pub Vec<Perm>);

impl<S: Send + Sync> FromRequestParts<S> for TokenScope {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<TokenScope>()
            .cloned()
            .unwrap_or_default())
    }
}

/// 租户标识。**唯一生产构造点 = 已验签的 tenant claim**(`from_claim`,只有 `auth/token.rs` 该调)。
///
/// 刻意**没有** `Default` / `From<Uuid>` / nil 兜底 —— 想凭空造一个租户过滤条件,得写出
/// `TenantId::from_claim(..)` 这个名字:review 一眼看见,`grep` 一次全中。
/// 这是整套隔离的**主防线**(spec §5.1):测试只能证明你想到的路径,类型系统能挡住你没想到的。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    /// 从**已验签**的 claim 造。名字刻意刺眼 —— 见 `TenantId` 的 doc。
    pub fn from_claim(id: Uuid) -> Self {
        Self(id)
    }

    pub fn get(self) -> Uuid {
        self.0
    }
}

/// 请求的租户上下文。extractor 只读 extension(中间件是唯一真相源,不重复验签)。
///
/// **无 → 401**:与 `TokenScope` 的「空 = 无限制」**刻意相反** —— 空租户绝不等于全租户。
/// 缺席有两种合法来源:0 租户用户(register 的常规出口,spec §1.1)、存量无该字段的 token。
#[derive(Clone, Copy, Debug)]
pub struct Tenant(pub TenantId);

impl<S: Send + Sync> FromRequestParts<S> for Tenant {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Tenant>()
            .copied()
            .ok_or(AppError::Unauthorized)
    }
}

/// `Option<Tenant>`:**允许 0 租户**的端点用(如 `GET /auth/tenants` —— 0 租户该返回空数组
/// 而不是 401)。碰租户数据的端点用裸 `Tenant`(缺席即 401),别用这个。
impl<S: Send + Sync> OptionalFromRequestParts<S> for Tenant {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Tenant>().copied())
    }
}

/// 组闸:需登录(`/api/v1/frontend` 组)。粗过滤:extensions 无 `AuthUser`(`auth::authenticate`
/// 没验出人)→ 401 统一 `ErrorBody`。细粒度(perm/scope/ownership)仍归端点内三轴 ——
/// 本闸只是防御纵深第一层。注:axum `.layer()` 只包已注册路由,组内未知路径仍走 fallback 404、不过闸。
pub async fn require_login(req: Request, next: Next) -> Response {
    if req.extensions().get::<AuthUser>().is_none() {
        return AppError::Unauthorized.into_response();
    }
    next.run(req).await
}

/// 组闸:登录 + `admin:login`(`/api/v1/admin` 组 = 后台准入)。**走 `require_scoped`(role ∩ scope)**,
/// 与端点内闸、openapi_authz 探针同一评估语义 —— 降权令牌(scope 未含 admin:login)即便 role 够也挡。
/// 闸的是**准入**(admin+superadmin 皆过);组内 superadmin 专属端点(如列全 widget)再各自 gate `users:admin`。
/// state 直接吃 `Arc<Policy>`(infra 不 import app 的 AppState,守分层)。
pub async fn require_admin_login(
    State(policy): State<Arc<Policy>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return AppError::Unauthorized.into_response();
    };
    let scope = req
        .extensions()
        .get::<TokenScope>()
        .cloned()
        .unwrap_or_default();
    if let Err(e) = policy.require_scoped(&user, &scope.0, Perm::AdminLogin) {
        return e.into_response();
    }
    next.run(req).await
}

// ── 端点:当前令牌的有效权限。"能干什么"归 app(authz 拥有此概念,端点就住这;
//    infra 引 AppState 有 openapi::doc_routes 先例)。idm 的 /auth/me 只给身份事实,不回答权限
//    —— idm 进程的 policy 是 seed 嵌入副本,PG 模式下与 app 会漂,放那边文档会说谎。 ──

/// `GET /permissions/me` 响应。`roles` 来自 token claim;`permissions` 是**有效**集:
/// role 展开(含 implies)∩ scope 收窄,wire 串排序输出。
#[derive(Serialize, utoipa::ToSchema)]
pub struct MyPermissionsResponse {
    /// token claim 里的角色名(闭集,生成前端 union)。
    pub roles: Vec<RoleName>,
    /// 有效权限(闭集,wire 串序输出)。前端按钮显隐 / codegen accessPolicies `has()` 的数据源。
    pub permissions: Vec<Perm>,
}

/// 当前令牌能干什么(仅登录零 perm —— 自我操作范式;问"能干什么"本身不需要先有权限)。
/// 逐 perm 走 [`Policy::require_scoped`] 过滤:与所有闸同一评估路径,零漂移;
/// 降权令牌得到 scope 收窄后的真实集。
#[utoipa::path(
    get,
    path = "/permissions/me",
    tag = "me",
    responses(
        (status = 200, description = "当前令牌的角色与有效权限(role ∩ scope,排序)", body = MyPermissionsResponse),
        (status = 401, description = "未认证", body = crate::infra::error::ErrorBody)
    )
)]
pub async fn get_my_permissions(
    State(state): State<crate::app::state::AppState>,
    user: crate::infra::audit::CurrentUser,
    scope: TokenScope,
) -> crate::infra::extract::Json<MyPermissionsResponse> {
    let mut permissions: Vec<Perm> = state
        .policy
        .perms_for(&user.0.roles)
        .into_iter()
        .filter(|&p| state.policy.require_scoped(&user.0, &scope.0, p).is_ok())
        .collect();
    permissions.sort_by_key(|p| p.wire()); // 仍按 wire 串序,JSON 输出不变
    let roles = RoleName::parse_lossy(user.0.roles.clone());
    crate::infra::extract::Json(MyPermissionsResponse { roles, permissions })
}

/// 本端点的 router,composition root 挂 frontend 组(app 进程,policy 权威侧)。
pub fn router() -> utoipa_axum::router::OpenApiRouter<crate::app::state::AppState> {
    utoipa_axum::router::OpenApiRouter::new().routes(utoipa_axum::routes!(get_my_permissions))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(roles: &[&str]) -> AuthUser {
        AuthUser {
            id: Uuid::nil(),
            username: "u".to_owned(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// round-trip:每个变体的 wire 串(serde rename)== `resource:action[:qualifier]` 三段投影。
    /// 守住"变体 ↔ wire ↔ 投影"不漂移 —— 加变体忘补 `ALL`/投影/`rename` 都会挂这里。
    #[test]
    fn perm_wire_matches_projection() {
        for p in Perm::ALL {
            let wire = serde_json::to_value(p).unwrap();
            let wire = wire.as_str().unwrap();
            let mut seg = wire.split(':');
            assert_eq!(seg.next(), Some(p.resource()), "{wire}: resource");
            assert_eq!(seg.next(), Some(p.action()), "{wire}: action");
            assert_eq!(seg.next(), p.qualifier(), "{wire}: qualifier");
            assert_eq!(seg.next(), None, "{wire}: 多余段");
        }
    }

    // ── 两级角色的提权闸(spec §4.5 / §10 验收 5)──

    /// **`PLATFORM` ∩ 租户角色 = ∅** —— 这是整条提权链的根闸。
    /// 若哪天有人图省事把 `TenantAdmin` 塞进 `PLATFORM`,`seed::apply` 就会把它 upsert 进
    /// `idm.roles`,它随即成为后台可授予的**平台**角色 —— 一个从没被邀请进任何租户的人
    /// 就能拿到 `tn:admin`,在回退挑中的租户里当 admin。
    #[test]
    fn platform_catalog_excludes_tenant_roles() {
        for r in RoleName::PLATFORM {
            assert!(
                !r.is_tenant_scoped(),
                "{} 是租户角色,绝不可进 PLATFORM —— 见 RoleName::PLATFORM 的 doc",
                r.as_str()
            );
        }
        // 反向:ALL 里除去 PLATFORM 的,必须全是租户角色(防「加了平台角色只补 ALL 忘补 PLATFORM」)
        for r in RoleName::ALL {
            if !RoleName::PLATFORM.contains(&r) {
                assert!(
                    r.is_tenant_scoped(),
                    "{} 既不在 PLATFORM 又不是租户角色 —— 加平台角色要同时补 PLATFORM",
                    r.as_str()
                );
            }
        }
    }

    /// 租户角色**绝不含平台级 perm**。`UsersAdmin`(管所有租户的用户)与 `AdminLogin`
    /// (后台入口)都是骑在租户边界之上的能力 —— 租户 admin 只在自己那家公司里是 admin。
    #[test]
    fn tenant_roles_hold_no_platform_perms() {
        for r in RoleName::ALL.iter().filter(|r| r.is_tenant_scoped()) {
            let perms = r.default_permissions();
            for forbidden in [Perm::UsersAdmin, Perm::AdminLogin] {
                assert!(
                    !perms.contains(&forbidden),
                    "{} 不该持有平台级权限 {:?}",
                    r.as_str(),
                    forbidden
                );
            }
        }
    }

    /// `RoleName::TenantAdmin.as_str()` 必须与 `TenantRole::claim()` **逐字相等** ——
    /// 这是等式不是巧合(spec §4.5):`TenantRoleRepo` push `claim()`,`Policy` 按
    /// `as_str()` 查权限。两边任一改了名字,claim 里的角色就查不到权限、静默变成零权限。
    #[test]
    fn tenant_role_claim_matches_role_name() {
        use crate::features::tenants::TenantRole;
        assert_eq!(TenantRole::Admin.claim(), RoleName::TenantAdmin.as_str());
        assert_eq!(TenantRole::Member.claim(), RoleName::TenantMember.as_str());
    }

    /// RoleName: `as_str()` == serde rename(不漂移);superadmin 默认持全权闭集。
    #[test]
    fn parse_lossy_skips_unknown_roles_without_panic() {
        // 存量脏角色名(旧 seed / 手工 INSERT)只跳过,绝不打挂读路径。
        let roles = vec!["admin".to_owned(), "editor".to_owned(), "user".to_owned()];
        assert_eq!(
            RoleName::parse_lossy(roles),
            vec![RoleName::Admin, RoleName::User]
        );
    }

    #[test]
    fn role_name_wire_matches() {
        for r in RoleName::ALL {
            let wire = serde_json::to_value(r).unwrap();
            assert_eq!(
                wire.as_str(),
                Some(r.as_str()),
                "{r:?}: as_str ↔ serde rename"
            );
        }
        assert_eq!(
            RoleName::Superadmin.default_permissions().len(),
            Perm::ALL.len(),
            "superadmin 默认应持全权闭集"
        );
    }

    /// implies:角色只配 `read:all`(漏 `read`)→ 载入期自动补 `read`,顶层 read 闸不再 403。
    #[test]
    fn read_all_implies_read_role_and_scope() {
        let policy = Policy::from_roles([("mgr".to_owned(), vec![Perm::WidgetReadAll])]);
        // role 侧:perms_for 已含被蕴含的 read
        let perms = policy.perms_for(&["mgr".to_owned()]);
        assert!(perms.contains(&Perm::WidgetRead), "read:all 应蕴含 read");
        assert!(perms.contains(&Perm::WidgetReadAll));
        let u = user(&["mgr"]);
        assert!(
            policy.require(&u, Perm::WidgetRead).is_ok(),
            "顶层 read 闸不应 403"
        );
        assert!(matches!(
            policy.data_access(&u, &[], Perm::WidgetReadAll),
            Access::All
        ));
        // scope 侧:降权令牌 scope=[read:all] 也视为含 read
        assert!(policy
            .require_scoped(&u, &[Perm::WidgetReadAll], Perm::WidgetRead)
            .is_ok());
    }

    /// 多权限组合子:AND 缺一即拒、OR 任一即过;scope 收窄与 implies 语义同 require_scoped。
    #[test]
    fn require_all_and_any_combinators() {
        let policy = Policy::from_roles([
            ("ops".to_owned(), vec![Perm::WidgetRead, Perm::WidgetDelete]),
            ("aud".to_owned(), vec![Perm::UsersAdmin]),
        ]);
        let both = user(&["ops"]);
        let admin_only = user(&["aud"]);
        let need = [Perm::WidgetRead, Perm::WidgetDelete];
        // AND:全有 → Ok;role 缺(aud 无 read/delete)→ Err
        assert!(policy.require_all(&both, &[], &need).is_ok());
        assert!(policy.require_all(&admin_only, &[], &need).is_err());
        // AND:scope 收窄掉 delete → Err(role 够也不行)
        assert!(policy
            .require_all(&both, &[Perm::WidgetRead], &need)
            .is_err());
        // OR:任一支过即 Ok(aud 走 users:admin 支)
        let either = [Perm::WidgetRead, Perm::UsersAdmin];
        assert!(policy.require_any(&admin_only, &[], &either).is_ok());
        assert!(policy.require_any(&both, &[], &either).is_ok());
        // OR:两支全无 → Err
        assert!(policy
            .require_any(&user(&["nobody"]), &[], &either)
            .is_err());
        // OR + scope 收窄:scope 只给 users:admin → read 支被收窄,靠 admin 支过
        assert!(policy
            .require_any(&admin_only, &[Perm::UsersAdmin], &either)
            .is_ok());
        // OR + scope 收窄:scope 与两支皆不交 → 全败
        assert!(policy
            .require_any(&both, &[Perm::UsersAdmin], &either)
            .is_err());
        // OR:implies 经由生效(read:all 蕴含 read → read 支过)
        let p2 = Policy::from_roles([("mgr".to_owned(), vec![Perm::WidgetReadAll])]);
        assert!(p2.require_any(&user(&["mgr"]), &[], &either).is_ok());
    }

    // ── 组闸中间件:小 Router + Extension 注入,黑盒断言状态码 ──
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{middleware, Extension, Router};
    use tower::ServiceExt;

    async fn gate_status(app: Router, uri: &str) -> StatusCode {
        app.oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// require_login:无 AuthUser → 401;有 → 放行。
    #[tokio::test]
    async fn require_login_gates_unauthenticated() {
        let app = Router::new()
            .route("/t", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_login));
        assert_eq!(gate_status(app, "/t").await, StatusCode::UNAUTHORIZED);

        let app = Router::new()
            .route("/t", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_login))
            .layer(Extension(user(&["user"]))); // 外层先跑,注入 AuthUser
        assert_eq!(gate_status(app, "/t").await, StatusCode::OK);
    }

    /// require_admin_login:401(未登录)/ 403(role 无 perm)/ 403(role 够但 scope 收窄)/ 放行。
    #[tokio::test]
    async fn require_admin_login_gates_role_and_scope() {
        let policy = Arc::new(Policy::from_roles([(
            "root".to_owned(),
            vec![Perm::AdminLogin],
        )]));
        let mk = |u: Option<AuthUser>, scope: Option<TokenScope>| {
            let mut app = Router::new().route("/t", get(|| async { "ok" })).layer(
                middleware::from_fn_with_state(policy.clone(), require_admin_login),
            );
            if let Some(u) = u {
                app = app.layer(Extension(u));
            }
            if let Some(s) = scope {
                app = app.layer(Extension(s));
            }
            app
        };
        // 未登录 → 401
        assert_eq!(
            gate_status(mk(None, None), "/t").await,
            StatusCode::UNAUTHORIZED
        );
        // role 无 admin:login → 403
        assert_eq!(
            gate_status(mk(Some(user(&["user"])), None), "/t").await,
            StatusCode::FORBIDDEN
        );
        // role 够、scope 收窄(未含 admin:login)→ 403(降权令牌不得穿闸)
        assert_eq!(
            gate_status(
                mk(
                    Some(user(&["root"])),
                    Some(TokenScope(vec![Perm::WidgetRead]))
                ),
                "/t"
            )
            .await,
            StatusCode::FORBIDDEN
        );
        // role 够、scope 空(满权令牌)→ 放行
        assert_eq!(
            gate_status(mk(Some(user(&["root"])), None), "/t").await,
            StatusCode::OK
        );
    }
}

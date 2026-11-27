//! 授权(AuthZ)—— **归 app**。idm 只给身份事实(token 里的 roles),"role/scope 能干什么"全在这。
//!
//! 三份真相,各归其位:
//! - **权限词表**(有哪些 `Permission`)= 本文件的封闭枚举,拼错=编译错;
//! - **role→权限映射** = `seed.toml` 的 `[[roles]].permissions`(唯一真相),启动期载进 [`Policy`];
//! - **user→role** = idm 库 → JWT claim(运行期事实,不进文件)。
//!
//! 判定全在 app 进程内存完成:token 带 roles,[`Policy`] 把 roles 展开成权限,**绝不查 idm 库**
//! —— 契合"app 进程只 decode JWT"的拓扑。`scope` 是 per-token 子集(只收窄、不放大)。
//!
//! 这里是授权的**核心**(词表 + 判定),纯 Rust。从请求里取 token scope、组闸中间件、
//! `/permissions/me` 端点、`Permission`/`RoleName` 的 OpenAPI schema 归 HTTP 适配 `infra::authorization`。

use std::collections::{HashMap, HashSet};
use std::iter;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use idm::{AuthUser, RoleScope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::kernel::app_error::AppError;

/// [`Policy::permissions_for`] 的入参:平台角色与(当前)租户角色两组角色名。
#[derive(Clone, Copy, Debug, Default)]
pub struct RoleNames<'roles> {
    /// 平台角色(token `roles`)。
    pub platform: &'roles [String],
    /// 租户角色(token `tenant_roles`)。
    pub tenant: &'roles [String],
}

/// 权限的**作用域**(spec §4.3)。有效权限 = 平台角色给的**平台级**权限 ∪ 当前租户角色给的**租户级**权限;
/// 平台角色不自动获得任何租户的租户级权限,租户角色也拿不到平台级权限。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PermissionScope {
    /// 平台级:跨租户的管理能力(账号管理、系统监控、租户管理、按 id 读写全局资料)。只由平台角色(token `roles`)授予。
    Platform,
    /// 租户级:租户内的业务能力(widget、content、后台准入…)。只由当前租户角色(`tenant_roles`)授予,
    /// 且 token 必须带当前租户,否则 403 `tenant_required`。
    Tenant,
}

impl From<RoleScope> for PermissionScope {
    fn from(scope: RoleScope) -> Self {
        match scope {
            RoleScope::Platform => PermissionScope::Platform,
            RoleScope::Tenant => PermissionScope::Tenant,
        }
    }
}

/// 权限词表的**唯一真相**(封闭集)。handler 用变体 `Permission::WidgetWrite`,拼错=编译错。
/// wire 串(TOML / JWT scope)经 `rename` 映射;未知串 → 反序列化失败 → 启动期挡住(fail-fast)。
/// 加权限 = 加一个变体 + `rename`,别处不动。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Permission {
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
    /// 账号管理(平台级):建号 / 改账号信息 / 重置密码 / 删号 / 授平台角色、后台改任意人的资料。
    /// 平台管理员与 superadmin 都持;对**持有平台角色的账号**动手另要 [`Permission::PlatformRoles`](只有 superadmin)。
    #[serde(rename = "users:admin")]
    UsersAdmin,
    /// 租户管理(平台级):建 / 改名 / 停用租户、管理任意租户的成员。平台管理员与 superadmin 都持。
    #[serde(rename = "tenants:admin")]
    TenantsAdmin,
    /// 运维(平台级,superadmin 独占):后台「系统监控」(实时 / 历史指标 / 日志查询)。
    #[serde(rename = "ops:read")]
    OpsRead,
    /// 认证审计(平台级,superadmin 独占):登录日志查询 / 统计 / 实时流、某账号的认证事件。
    #[serde(rename = "audit:read")]
    AuditRead,
    /// 平台角色管理(平台级,superadmin 独占):授予 / 撤销平台角色(任命平台管理员),
    /// 以及对**持有任一平台角色的账号**做账号管理写操作、在组织里改角色 / 移出(防接管)。
    /// superadmin 角色本身不经任何接口授予 / 撤销(只由 seed 声明),这条权限也授不出它。
    #[serde(rename = "platform:roles")]
    PlatformRoles,
    /// 本租户成员列表(租户级):租户管理员看「成员」页。
    #[serde(rename = "members:read")]
    MembersRead,
    /// 本租户成员管理(租户级):按用户名把已有账号加进本租户、设租户角色、移出。**不能**建账号 / 改密 / 删号
    /// (账号是全局的,那是平台级 `users:admin`)。
    #[serde(rename = "members:admin")]
    MembersAdmin,
    /// 后台准入(backend gate,租户级)。`/api/v1/admin` 组闸 + admin_login 自查用它。
    /// 与平台级权限**拆开**:租户 admin 持它进后台;平台角色(平台管理员 / superadmin)凭任一平台级权限进后台。
    /// 故名为 admin 的租户管理员能登后台,但够不到账号管理 / 监控等平台能力。
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

impl Permission {
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
    pub const ALL: [Permission; 21] = [
        Permission::WidgetRead,
        Permission::WidgetReadAll,
        Permission::WidgetWrite,
        Permission::WidgetWriteAll,
        Permission::WidgetDelete,
        Permission::ContentRead,
        Permission::ContentReadAll,
        Permission::ContentWrite,
        Permission::ContentWriteAll,
        Permission::ContentDelete,
        Permission::UsersAdmin,
        Permission::TenantsAdmin,
        Permission::OpsRead,
        Permission::AuditRead,
        Permission::PlatformRoles,
        Permission::MembersRead,
        Permission::MembersAdmin,
        Permission::AdminLogin,
        Permission::ProfileRead,
        Permission::ProfileWrite,
        Permission::ProfileWriteAll,
    ];

    /// 三段约定 `domain:verb[:qualifier]` 的**第一段**(资源)。从变体投影,**绝不运行期 split wire 串**。
    /// 这些投影是 permission 一等概念的"字段",按需派生、零存储;wire 串与内部比较都不靠它们。
    #[must_use]
    pub fn resource(&self) -> &'static str {
        match self {
            Permission::WidgetRead
            | Permission::WidgetReadAll
            | Permission::WidgetWrite
            | Permission::WidgetWriteAll
            | Permission::WidgetDelete => "widgets",
            Permission::ContentRead
            | Permission::ContentReadAll
            | Permission::ContentWrite
            | Permission::ContentWriteAll
            | Permission::ContentDelete => "contents",
            Permission::UsersAdmin => "users",
            Permission::TenantsAdmin => "tenants",
            Permission::OpsRead => "ops",
            Permission::AuditRead => "audit",
            Permission::PlatformRoles => "platform",
            Permission::MembersRead | Permission::MembersAdmin => "members",
            Permission::AdminLogin => "admin",
            Permission::ProfileRead | Permission::ProfileWrite | Permission::ProfileWriteAll => {
                "profiles"
            }
        }
    }

    /// **第二段**(动作)。
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Permission::WidgetRead | Permission::WidgetReadAll => "read",
            Permission::WidgetWrite | Permission::WidgetWriteAll => "write",
            Permission::WidgetDelete => "delete",
            Permission::ContentRead | Permission::ContentReadAll => "read",
            Permission::ContentWrite | Permission::ContentWriteAll => "write",
            Permission::ContentDelete => "delete",
            Permission::UsersAdmin | Permission::TenantsAdmin | Permission::MembersAdmin => "admin",
            Permission::MembersRead | Permission::OpsRead | Permission::AuditRead => "read",
            // 「平台角色」:动作即管理平台角色(`platform:roles`,用户 2026-11-26 定名,不硬凑动词)
            Permission::PlatformRoles => "roles",
            Permission::AdminLogin => "login",
            Permission::ProfileRead => "read",
            Permission::ProfileWrite | Permission::ProfileWriteAll => "write",
        }
    }

    /// **第三段**(限定词,可选)。`read:all` 的 `all`;只读投影,**不是**存储字段、**不是** `read` 上的开关。
    /// 注意这里是 `_ => None` 兜底,**不穷尽** —— 加 `*All` 变体忘了列进来不会编译失败,
    /// 只会让 `wire()` 少掉 `:all` 段、与 serde rename 对不上(`perm_wire_matches_projection` 会红)。
    #[must_use]
    pub fn qualifier(&self) -> Option<&'static str> {
        match self {
            Permission::WidgetReadAll
            | Permission::WidgetWriteAll
            | Permission::ContentReadAll
            | Permission::ContentWriteAll
            | Permission::ProfileWriteAll => Some("all"),
            _ => None,
        }
    }

    /// wire 串 `resource:action[:qualifier]`(从投影合成)。与 serde rename 同源 ——
    /// `perm_wire_matches_projection` 测试钉死两者不漂移。
    #[must_use]
    pub fn wire(&self) -> String {
        match self.qualifier() {
            Some(qualifier) => format!("{}:{}:{qualifier}", self.resource(), self.action()),
            None => format!("{}:{}", self.resource(), self.action()),
        }
    }

    /// **蕴含**:持有本权限即隐含持有这些。`read:all ⇒ read`(能看全部必然能看)。
    /// [`Policy::new`] 载入期与 [`Policy::require_scoped`] scope 判定都按它展开 →
    /// 从根消除"只给 `read:all` 漏 `read` → 顶层 `require_scoped(read)` 先 403"的配置坑。
    /// 目前**单层**(被蕴含项自身无再蕴含);将来出现链式 A⇒B⇒C,需在展开处做传递闭包。
    #[must_use]
    pub fn implies(&self) -> &'static [Permission] {
        match self {
            Permission::WidgetReadAll => &[Permission::WidgetRead],
            Permission::WidgetWriteAll => &[Permission::WidgetWrite],
            Permission::ContentReadAll => &[Permission::ContentRead],
            Permission::ContentWriteAll => &[Permission::ContentWrite],
            Permission::ProfileWriteAll => &[Permission::ProfileWrite],
            _ => &[],
        }
    }

    /// 作用域(**穷尽 match**:加变体编译不过,逼你判断它是平台级还是租户级)。
    ///
    /// `admin:login`(后台准入)是**租户级**:租户管理员靠它进后台。平台管理员不靠它 —— 持有任一平台级
    /// 权限即可进后台(见 [`Policy::require_admin_entry`])。
    #[must_use]
    pub fn scope(&self) -> PermissionScope {
        match self {
            // 资料全局一份(spec §6.2):按 id 读 / 改任何人的资料是平台级能力,租户管理员没有;
            // 本人读 / 改自己的资料走 `/profiles/me`(仅登录,不需要权限)。
            Permission::UsersAdmin
            | Permission::TenantsAdmin
            | Permission::OpsRead
            | Permission::AuditRead
            | Permission::PlatformRoles
            | Permission::ProfileRead
            | Permission::ProfileWrite
            | Permission::ProfileWriteAll => PermissionScope::Platform,
            Permission::WidgetRead
            | Permission::WidgetReadAll
            | Permission::WidgetWrite
            | Permission::WidgetWriteAll
            | Permission::WidgetDelete
            | Permission::ContentRead
            | Permission::ContentReadAll
            | Permission::ContentWrite
            | Permission::ContentWriteAll
            | Permission::ContentDelete
            | Permission::MembersRead
            | Permission::MembersAdmin
            | Permission::AdminLogin => PermissionScope::Tenant,
        }
    }

    /// 人读说明(落 `permissions` 表 / 权限清单)。曾在 `seed.toml` `[[permissions]]`,
    /// 现收进代码 —— **enum 是唯一真相**,词表不再另存镜像。
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Permission::WidgetRead => "查看自己创建的 widget",
            Permission::WidgetReadAll => "查看所有人的 widget(而非仅自己)",
            Permission::WidgetWrite => "创建 / 修改自己创建的 widget",
            Permission::WidgetWriteAll => "修改 / 删除任何人的 widget(而非仅自己创建的)",
            Permission::WidgetDelete => "删除 widget",
            Permission::ContentRead => "查看内容 / 下载 / 列对象与元数据",
            Permission::ContentReadAll => "查看所有人的内容(而非仅自己)",
            Permission::ContentWrite => "创建 / 上传 / 修改内容与元数据",
            Permission::ContentWriteAll => "修改 / 删除任何人的内容(而非仅自己)",
            Permission::ContentDelete => "删除内容",
            Permission::UsersAdmin => {
                "账号管理:建号 / 改账号信息 / 重置密码 / 删号、后台改资料(平台级;平台管理员 + superadmin)"
            }
            Permission::TenantsAdmin => {
                "租户管理:建 / 改名 / 停用租户、管理任意租户的成员(平台级;平台管理员 + superadmin)"
            }
            Permission::OpsRead => "运维:系统监控、历史指标、日志查询(superadmin 独占)",
            Permission::AuditRead => "认证审计:登录日志查询 / 统计 / 实时流(superadmin 独占)",
            Permission::PlatformRoles => {
                "平台角色管理:任命 / 撤销平台管理员,管理持有平台角色的账号(superadmin 独占)"
            }
            Permission::MembersRead => "查看本租户的成员列表(租户级)",
            Permission::MembersAdmin => {
                "管理本租户的成员:按用户名加入已有账号、设租户角色、移出(租户级;不能建账号 / 改密 / 删号)"
            }
            Permission::AdminLogin => {
                "后台准入:登进 /admin 组(admin + superadmin 皆持;与 users:admin 拆开)"
            }
            Permission::ProfileRead => "按 id 查看任意用户资料(平台级;本人读自己走 /profiles/me)",
            Permission::ProfileWrite => "按 id 修改资料(平台级;本人改自己走 /profiles/me)",
            Permission::ProfileWriteAll => "按 id 修改任何人的资料(平台级,而非仅自己)",
        }
    }
}

/// 角色名的**唯一真相**(封闭集)。角色本身不做动态 CRUD(角色**有哪些权限**才可运行时改,
/// 见 `role_permissions` 表);故角色集编进代码。wire 串经 `rename`,与 idm.roles.name / JWT
/// claim / `role_permissions.role_name` 同源。加角色 = 加变体 + 补 `ALL`/`display_name`/`scope`/`default_permissions`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum RoleName {
    /// 超级管理员(平台角色,**只有一个**,只由 seed 声明,不经任何接口授予 / 撤销)。
    #[serde(rename = "superadmin")]
    Superadmin,
    /// 平台管理员(平台角色):superadmin 独占项(运维 / 认证审计 / 平台角色管理)以外的平台能力。
    #[serde(rename = "platform_admin")]
    PlatformAdmin,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
}

impl RoleName {
    /// 全部变体(seed / 目录 / round-trip 测试用)。
    /// 加变体必补这里 —— 同 `Permission::ALL`,**漏了没有任何东西会发现**(数组字面量,不编译失败;
    /// round-trip 测试遍历的就是它)。`as_str()` 的穷尽 match 会逼你回到本 impl,但补 `ALL` 靠自觉。
    pub const ALL: [RoleName; 4] = [
        RoleName::Superadmin,
        RoleName::PlatformAdmin,
        RoleName::Admin,
        RoleName::User,
    ];

    /// wire 串(== serde `rename`;单一来源,`role_name_wire_matches` 测试钉死不漂移)。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "superadmin",
            RoleName::PlatformAdmin => "platform_admin",
            RoleName::Admin => "admin",
            RoleName::User => "user",
        }
    }

    /// 角色作用域(seed 写 idm `roles.scope`):superadmin / platform_admin 是**平台角色**(经 `user_roles`、进 JWT `roles`);
    /// admin / user 是**租户角色**(经 `member_roles` 按租户授予)。同一角色名只属于一类(spec §4.1)。
    #[must_use]
    pub fn scope(&self) -> RoleScope {
        match self {
            RoleName::Superadmin | RoleName::PlatformAdmin => RoleScope::Platform,
            RoleName::Admin | RoleName::User => RoleScope::Tenant,
        }
    }

    /// 人读显示名(seed idm.roles.display_name)。
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "超级管理员",
            RoleName::PlatformAdmin => "平台管理员",
            RoleName::Admin => "管理员",
            RoleName::User => "普通用户",
        }
    }

    /// **bootstrap 默认**权限(seed 写进 `role_permissions`,`ON CONFLICT DO NOTHING` 不覆盖运行期改动)。
    /// 每个角色只配**与自己作用域相同**的权限(跨作用域的行载入时会被忽略,见 [`Policy::new`])。
    /// superadmin = 全部**平台级**权限(随闭集自动增长,消除"加平台权限忘补超管"漂移);它的租户级能力
    /// 来自在租户里兼任的租户角色(默认租户的 admin)。platform_admin = 全部平台级权限**减去** superadmin 独占的
    /// [`SUPERADMIN_ONLY`](运维 / 认证审计 / 平台角色管理)。运行期真值以库为准。
    #[must_use]
    pub fn default_permissions(&self) -> Vec<Permission> {
        let platform = Permission::ALL
            .into_iter()
            .filter(|p| p.scope() == PermissionScope::Platform);
        match self {
            RoleName::Superadmin => platform.collect(),
            RoleName::PlatformAdmin => platform.filter(|p| !SUPERADMIN_ONLY.contains(p)).collect(),
            RoleName::Admin => vec![
                Permission::WidgetRead,
                Permission::WidgetReadAll,
                Permission::WidgetWrite,
                Permission::WidgetWriteAll,
                Permission::WidgetDelete,
                Permission::ContentRead,
                Permission::ContentReadAll,
                Permission::ContentWrite,
                Permission::ContentWriteAll,
                Permission::ContentDelete,
                Permission::MembersRead,
                Permission::MembersAdmin,
                Permission::AdminLogin,
            ],
            RoleName::User => vec![
                Permission::WidgetRead,
                Permission::ContentRead,
                Permission::ContentWrite,
            ],
        }
    }
}

/// superadmin 独占的平台级权限:平台管理员默认不给(运维、认证审计、平台角色管理)。
pub const SUPERADMIN_ONLY: [Permission; 3] = [
    Permission::OpsRead,
    Permission::AuditRead,
    Permission::PlatformRoles,
];

/// 这组**原始**平台角色名(`user_roles` 原样,未经闭集过滤)里有没有平台角色 —— 防接管闸用它判断目标账号。
/// 闭集内按 [`RoleName::scope`];**闭集外的名字一律算平台角色**(fail-closed:`user_roles` 里本就只该有平台角色,
/// 运维手工塞的未知角色可能持有真权限,宁可让 superadmin 来管,也不让闸因脏数据失明)。闭集内的租户角色
/// (多租户之前遗留在 `user_roles` 的 admin / user 行,不生效)不算。
#[must_use]
pub fn holds_platform_role(raw_role_names: &[String]) -> bool {
    raw_role_names
        .iter()
        .any(|n| RoleName::from_str(n).map_or(true, |r| r.scope() == RoleScope::Platform))
}

impl RoleName {
    /// wire 串集合 → 闭集,**lossy**:不在闭集的(存量部署遗留 / 手工 INSERT 的旧角色名)
    /// 跳过 + warn,绝不 panic —— 一行脏数据不该打挂整个读路径(login/me/用户列表/权限清单)。
    /// closed-enums skill 的「数据异常就炸」只背书单写者不变量;角色行存在版本偏斜面(旧 seed、运维手改)。
    #[must_use]
    pub fn parse_lossy<I: IntoIterator<Item = String>>(roles: I) -> Vec<RoleName> {
        roles
            .into_iter()
            .filter_map(|name| match name.parse() {
                Ok(role) => Some(role),
                Err(_) => {
                    Self::warn_unknown(&name);
                    None
                }
            })
            .collect()
    }

    /// 闭集外角色名的统一告警口径:每进程每名 **一次**(该路径在热读位置 —— list 每行 /
    /// me 每请求,一条存量脏数据不该刷屏)。parse_lossy 与角色目录过滤共用。
    ///
    /// # Panics
    ///
    /// 记录「已告警名字」的进程级锁中毒(别的线程持锁时 panic)时 panic —— 不去取中毒锁里的数据。
    pub fn warn_unknown(role: &str) {
        static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
        let warned = WARNED.get_or_init(Default::default);
        let first_time = warned
            .lock()
            .expect("告警去重锁未中毒(持锁区只做一次 HashSet::insert)")
            .insert(role.to_owned());
        if first_time {
            tracing::warn!(role = %role, "角色名不在 RoleName 闭集内,读模型跳过(存量脏数据?)");
        }
    }
}

/// wire 串(JWT claim / idm.roles.name)→ 枚举,给读模型强类型化用(镜像 `AuthEventType::FromStr`)。
impl FromStr for RoleName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // 经 ALL × as_str 查表:不再手写第三份 wire 映射(serde rename / as_str 之外),加变体零改动。
        RoleName::ALL
            .into_iter()
            .find(|r| r.as_str() == value)
            .ok_or_else(|| format!("未知角色名: {value}"))
    }
}

/// role → 权限集。默认从 `RoleName::default_permissions()` 派生(见 `app::seed::SeedData::policy`);
/// 设 `APP_DB_HOST` 时改从 `role_permissions` 表载(运行期可改)。装进 `AppState`
/// (`Arc`,廉价 Clone)。**不可变**:启动时载入一次,运行期只读。
///
/// **作用域**(spec §4.3):平台角色(token `roles`)只贡献平台级权限,当前租户角色(`tenant_roles`)只贡献
/// 租户级权限;token 没带当前租户时租户角色一律不算。闭集内角色的跨作用域映射行载入时 WARN 并忽略(§6.1)。
#[derive(Default, Debug)]
pub struct Policy {
    by_role: HashMap<String, HashSet<Permission>>,
}

/// [`Policy::require_all`] / [`Policy::require_any`] 要检查的东西:两组权限按名字区分,不靠参数位置。
#[derive(Clone, Copy, Debug)]
pub struct PermissionCheck<'permissions> {
    /// 令牌的 per-token scope(降权令牌);空 = 不收窄,即满 role 权限。
    pub scope: &'permissions [Permission],
    /// 要检查的权限(AND / OR 由调用的方法决定)。
    pub required: &'permissions [Permission],
}

impl Policy {
    /// 从 (role 名, 权限) 序列构建。同名 role 的权限取并集;权限为空的 role 也建条目(算"已覆盖")。
    /// **载入期按 `implies` 展开**(`read:all ⇒ read`):配 `read:all` 即自动有 `read`,从根消除漏底权 footgun。
    ///
    /// **跨作用域的行 WARN 并忽略**(spec §6.1):`RoleName` 闭集内的角色作用域已知(`RoleName::scope`),
    /// 映射到别的作用域的权限(如库里遗留的 `superadmin → widgets:read`)不进策略。闭集外的角色名
    /// (测试 / 下游自定义)作用域未知,载入时不过滤 —— 判定时 [`Self::permissions_for`] 仍按权限作用域只取对的那一半。
    pub fn new(roles: impl IntoIterator<Item = (String, Vec<Permission>)>) -> Self {
        let mut by_role: HashMap<String, HashSet<Permission>> = HashMap::new();
        for (role, permissions) in roles {
            let role_scope: Option<PermissionScope> = RoleName::from_str(&role)
                .ok()
                .map(|r| PermissionScope::from(r.scope()));
            let set = by_role.entry(role.clone()).or_default();
            for permission in permissions {
                if let Some(mismatched) = role_scope.filter(|scope| *scope != permission.scope()) {
                    tracing::warn!(
                        role = %role,
                        permission = %permission.wire(),
                        role_scope = ?mismatched,
                        permission_scope = ?permission.scope(),
                        "role_permissions 行跨了作用域(平台角色只取平台级权限、租户角色只取租户级权限),忽略该行"
                    );
                    continue;
                }
                set.insert(permission);
                set.extend(permission.implies().iter().copied());
            }
        }
        Self { by_role }
    }

    /// 平台角色 + 租户角色给的权限并集:平台角色**只贡献平台级**权限,租户角色**只贡献租户级**权限。
    /// 纯按角色算,不看 token 有没有当前租户 —— 判定请求用 [`Self::permissions_of`]。
    #[must_use]
    pub fn permissions_for(&self, roles: RoleNames<'_>) -> HashSet<Permission> {
        let RoleNames {
            platform: platform_roles,
            tenant: tenant_roles,
        } = roles;
        let pick = |roles: &[String], scope: PermissionScope| -> Vec<Permission> {
            roles
                .iter()
                .filter_map(|r| self.by_role.get(r))
                .flatten()
                .copied()
                .filter(|p| p.scope() == scope)
                .collect()
        };
        pick(platform_roles, PermissionScope::Platform)
            .into_iter()
            .chain(pick(tenant_roles, PermissionScope::Tenant))
            .collect()
    }

    /// 某个已认证身份按角色拿到的权限(未 ∩ scope)。**没有当前租户时租户角色不算**(防御:token 带了
    /// `tenant_roles` 却缺 `tenant_id` 是畸形令牌,不让它借租户角色拿权)。
    #[must_use]
    pub fn permissions_of(&self, user: &AuthUser) -> HashSet<Permission> {
        let tenant_roles: &[String] = if user.tenant_id.is_some() {
            &user.tenant_roles
        } else {
            &[]
        };
        self.permissions_for(RoleNames {
            platform: &user.roles,
            tenant: tenant_roles,
        })
    }

    /// **RBAC gate**:用户的 role 给了该权限 → Ok,否则 → 403。token 里的 roles 内存展开,不查库。
    pub fn require(&self, user: &AuthUser, permission: Permission) -> Result<(), AppError> {
        self.require_scoped(user, &[], permission)
    }

    /// **RBAC + scope gate**:有效权限 = `role 权限 ∩ scope`(`scope` 空 = 无 scope 限制,即满 role 权限)。
    /// scope 只能收窄不能放大 —— 降权令牌(PAT/第三方)即便 role 够,scope 没给也拒。
    ///
    /// 租户级权限要求 token 带**当前租户**:没有 → `AppError::TenantRequired`(403 `tenant_required`),
    /// 不论角色(平台管理员也一样,不能借平台角色读租户数据)。
    pub fn require_scoped(
        &self,
        user: &AuthUser,
        scope: &[Permission],
        permission: Permission,
    ) -> Result<(), AppError> {
        if permission.scope() == PermissionScope::Tenant && user.tenant_id.is_none() {
            return Err(AppError::TenantRequired);
        }
        // role 侧已在 from_roles 展开 implies。
        let role_grants = self.permissions_of(user).contains(&permission);
        // scope 侧同样吃 implies:scope 含 `read:all` 即视为含 `read`,与 role 侧一致,降权令牌不踩漏底权坑。
        let in_scope = scope.is_empty()
            || scope.contains(&permission)
            || scope.iter().any(|s| s.implies().contains(&permission));
        if role_grants && in_scope {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// **多权限 AND**:全部通过才放行(逐个 [`Self::require_scoped`],role ∩ scope 语义不变)。
    /// `check.required` 空 = 恒 Ok(无要求);调用方别拿空表当"禁止"用。
    pub fn require_all(&self, user: &AuthUser, check: PermissionCheck<'_>) -> Result<(), AppError> {
        check
            .required
            .iter()
            .try_for_each(|&permission| self.require_scoped(user, check.scope, permission))
    }

    /// **多权限 OR**:任一通过即放行,全败 → 403。`check.required` 空 = 恒 403(无可满足支)。
    pub fn require_any(&self, user: &AuthUser, check: PermissionCheck<'_>) -> Result<(), AppError> {
        if check
            .required
            .iter()
            .any(|&permission| self.require_scoped(user, check.scope, permission).is_ok())
        {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// **平台角色闸(防接管)**:`roles` = 要授出的平台角色名,或目标账号**现有**的原始平台角色名(`user_roles` 原样)。
    /// 里面有平台角色(见 [`holds_platform_role`],闭集外名字算平台角色)→ 操作者须持 `platform:roles`
    /// (经 [`Self::require_scoped`],role ∩ scope),否则 403;没有 → 放行(普通账号由各端点自己的闸管)。
    /// 账号管理(改信息 / 改资料 / 重置密码 / 删号 / 改角色)与组织成员接口(改角色 / 移出)共用这一道。
    pub fn require_platform_role_authority(
        &self,
        user: &AuthUser,
        scope: &[Permission],
        roles: &[String],
    ) -> Result<(), AppError> {
        if holds_platform_role(roles) {
            self.require_scoped(user, scope, Permission::PlatformRoles)
        } else {
            Ok(())
        }
    }

    /// **后台准入**(`/admin` 组闸与后台登录共用,spec §4.2「当前租户角色或平台角色里有后台权限」):
    /// 当前租户里有 `admin:login`,**或**持有任一平台级权限(平台管理员,不必属于任何租户)。
    /// 都经 [`Self::require_scoped`](role ∩ scope)判定;可选的「准入权限」清单见 [`admin_entry_permissions`]
    /// (OpenAPI 文档按同一份清单注入)。拒绝:没有当前租户且没有任何平台级权限 → `TenantRequired`,否则 `Forbidden`。
    pub fn require_admin_entry(
        &self,
        user: &AuthUser,
        scope: &[Permission],
    ) -> Result<(), AppError> {
        if admin_entry_permissions()
            .into_iter()
            .any(|p| self.require_scoped(user, scope, p).is_ok())
        {
            return Ok(());
        }
        if user.tenant_id.is_none() && !self.has_platform_permission(&user.roles) {
            Err(AppError::TenantRequired)
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// **后台登录挑进哪里**(spec §4.2 后台登录 + Task 10b):`tenants` = 有效成员关系
    /// `(租户 id, 该租户里的角色)`,按 `last_used_at` 倒序。
    /// - 第一个「租户角色给了 `admin:login`」的租户 → `Ok(Some(id))`(平台角色不参与这一步:平台管理员在某租户里
    ///   只是普通成员,不因平台权限就进那个租户);
    /// - 都没有、但平台角色给了任一平台级权限 → `Ok(None)`(平台上下文);
    /// - 否则:一个有效成员关系都没有 → `TenantRequired`(前端显示「还没加入任何组织」),有 → `Forbidden`。
    ///
    /// 与 [`Self::require_admin_entry`] 同一准入口径(登录后的 token 必然过组闸);那边判一个已定的 token,这里挑 token 进哪里。
    pub fn admin_login_entry<'roles>(
        &self,
        platform_roles: &[String],
        tenants: impl IntoIterator<Item = (Uuid, &'roles [String])>,
    ) -> Result<Option<Uuid>, AppError> {
        let mut any_membership = false;
        for (tenant, roles) in tenants {
            any_membership = true;
            if self
                .permissions_for(RoleNames {
                    platform: &[],
                    tenant: roles,
                })
                .contains(&Permission::AdminLogin)
            {
                return Ok(Some(tenant));
            }
        }
        if self.has_platform_permission(platform_roles) {
            Ok(None)
        } else if any_membership {
            Err(AppError::Forbidden)
        } else {
            Err(AppError::TenantRequired)
        }
    }

    /// 平台角色给了任一平台级权限(= 平台管理员,可不属于任何租户进后台)。
    fn has_platform_permission(&self, platform_roles: &[String]) -> bool {
        self.permissions_for(RoleNames {
            platform: platform_roles,
            tenant: &[],
        })
        .iter()
        .any(|p| p.scope() == PermissionScope::Platform)
    }

    /// **数据可见域(ownership mode)**:边缘的 RBAC∩scope 推出"能不能看全部"——有 `all_permission`(经
    /// `require_scoped`,故 role 与 scope 都参与)→ [`Access::All`],否则只看自己 → [`Access::Own`]。
    /// 这是三轴的扣点:类型级判定(RBAC∩scope)**参数化**行级 ownership;真正的过滤在查询里(见 `Access`)。
    #[must_use]
    pub fn data_access(
        &self,
        user: &AuthUser,
        scope: &[Permission],
        all_permission: Permission,
    ) -> Access {
        if self.require_scoped(user, scope, all_permission).is_ok() {
            Access::All
        } else {
            Access::Own(user.id)
        }
    }

    /// 启动期不变量:每个被账号引用的 role 都得有策略条目(漏配=该 role 永远拿不到权限,是 wiring 错)。
    /// 失败即拒启动 —— 同 `AuthService::build` 缺端口即 panic 的 fail-fast 哲学。
    pub fn assert_roles_covered<'role>(
        &self,
        roles: impl IntoIterator<Item = &'role str>,
    ) -> anyhow::Result<()> {
        for role in roles {
            anyhow::ensure!(
                self.by_role.contains_key(role),
                "角色 `{role}` 无授权策略条目(seed.toml 漏配 permissions)"
            );
        }
        Ok(())
    }
}

/// 后台准入可凭的权限(任一即可):租户级的 `admin:login` + 全部平台级权限。
/// [`Policy::require_admin_entry`] 与 OpenAPI 的 admin 组注入共用这一份(文档与执行同源)。
#[must_use]
pub fn admin_entry_permissions() -> Vec<Permission> {
    iter::once(Permission::AdminLogin)
        .chain(
            Permission::ALL
                .into_iter()
                .filter(|p| p.scope() == PermissionScope::Platform),
        )
        .collect()
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
    #[must_use]
    pub fn allows(&self, owner: Uuid) -> bool {
        match self {
            Access::All => true,
            Access::Own(me) => *me == owner,
        }
    }

    /// 同 [`Access::allows`],但吃实体的 `created_by: Option<String>`(用户 id 字符串)。
    /// 非 UUID('system'/NULL/历史脏值)→ `Own` 下一律不可见(只有 `All` 放行)。
    #[must_use]
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
    #[must_use]
    pub fn owner_filter(&self) -> Option<Uuid> {
        match self {
            Access::All => None,
            Access::Own(id) => Some(*id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::tenant_id::DEFAULT_TENANT_ID;

    /// 平台上下文身份:只有平台角色。
    fn user(roles: &[&str]) -> AuthUser {
        AuthUser::new(
            Uuid::nil(),
            "u".to_owned(),
            roles.iter().map(|s| s.to_string()).collect(),
        )
    }

    /// 在默认租户里、带租户角色的身份。
    fn member(tenant_roles: &[&str]) -> AuthUser {
        user(&[]).in_tenant(
            DEFAULT_TENANT_ID.as_uuid(),
            tenant_roles.iter().map(|s| s.to_string()).collect(),
        )
    }

    /// 每个变体都标了作用域;平台级 = 账号管理、租户管理、**资料**(资料全局一份,spec §6.2:
    /// 租户管理员不能改所有人的资料);各角色的默认权限与角色作用域一致
    /// (否则载入时被当成跨作用域行忽略,默认策略自己就会 WARN)。
    #[test]
    fn perm_scopes_cover_all_variants() {
        let platform: Vec<Permission> = Permission::ALL
            .into_iter()
            .filter(|p| p.scope() == PermissionScope::Platform)
            .collect();
        assert_eq!(
            platform,
            vec![
                Permission::UsersAdmin,
                Permission::TenantsAdmin,
                Permission::OpsRead,
                Permission::AuditRead,
                Permission::PlatformRoles,
                Permission::ProfileRead,
                Permission::ProfileWrite,
                Permission::ProfileWriteAll,
            ]
        );
        // superadmin 独占三项都是平台级
        for permission in SUPERADMIN_ONLY {
            assert_eq!(
                permission.scope(),
                PermissionScope::Platform,
                "{permission:?}"
            );
        }
        assert_eq!(
            Permission::ALL
                .iter()
                .filter(|permission| permission.scope() == PermissionScope::Tenant)
                .count(),
            Permission::ALL.len() - platform.len()
        );
        // 成员管理是租户级:租户管理员(admin)默认两样都有,普通成员(user)一样没有,平台角色不给
        for permission in [Permission::MembersRead, Permission::MembersAdmin] {
            assert_eq!(
                permission.scope(),
                PermissionScope::Tenant,
                "{permission:?}"
            );
            assert!(
                RoleName::Admin.default_permissions().contains(&permission),
                "admin 应持 {permission:?}"
            );
            assert!(
                !RoleName::User.default_permissions().contains(&permission),
                "user 不该持 {permission:?}"
            );
            assert!(
                !RoleName::Superadmin
                    .default_permissions()
                    .contains(&permission),
                "平台角色不给 {permission:?}"
            );
        }
        for role in RoleName::ALL {
            let role_scope = PermissionScope::from(role.scope());
            for permission in role.default_permissions() {
                assert_eq!(
                    permission.scope(),
                    role_scope,
                    "{role:?} 的默认权限 {permission:?} 跨了作用域"
                );
                for implied in permission.implies() {
                    assert_eq!(implied.scope(), permission.scope(), "implies 不得跨作用域");
                }
            }
        }
    }

    /// 资料是全局的:租户角色(含租户管理员)默认不带任何 `profiles:*`,平台管理员带全部;
    /// 即使旧库里还有 admin → profiles:write:all 的行,当租户角色用也拿不到(跨作用域行被忽略)。
    #[test]
    fn profile_perms_are_platform_only() {
        for role in [RoleName::Admin, RoleName::User] {
            assert!(
                role.default_permissions()
                    .iter()
                    .all(|p| p.resource() != "profiles"),
                "{role:?} 不该默认持有资料权限"
            );
        }
        let superadmin_permissions = RoleName::Superadmin.default_permissions();
        for permission in [
            Permission::ProfileRead,
            Permission::ProfileWrite,
            Permission::ProfileWriteAll,
        ] {
            assert!(
                superadmin_permissions.contains(&permission),
                "superadmin 应持 {permission:?}"
            );
        }
        let legacy = Policy::new([(
            "admin".to_owned(),
            vec![Permission::AdminLogin, Permission::ProfileWriteAll],
        )]);
        let tenant_admin = member(&["admin"]);
        assert!(matches!(
            legacy.require(&tenant_admin, Permission::ProfileWriteAll),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            legacy.data_access(&tenant_admin, &[], Permission::ProfileWriteAll),
            Access::Own(_)
        ));
    }

    /// 平台角色只贡献平台级、租户角色只贡献租户级;没有当前租户时租户级权限 → TenantRequired。
    #[test]
    fn platform_and_tenant_roles_contribute_only_their_scope() {
        let policy = Policy::new([
            // 闭集外角色名:载入不过滤,判定时按权限作用域取
            (
                "mixed".to_owned(),
                vec![Permission::UsersAdmin, Permission::WidgetRead],
            ),
        ]);
        let as_platform = policy.permissions_for(RoleNames {
            platform: &["mixed".to_owned()],
            tenant: &[],
        });
        assert_eq!(as_platform, HashSet::from([Permission::UsersAdmin]));
        let as_tenant = policy.permissions_for(RoleNames {
            platform: &[],
            tenant: &["mixed".to_owned()],
        });
        assert_eq!(as_tenant, HashSet::from([Permission::WidgetRead]));

        // 平台上下文:平台级过,租户级 → tenant_required(不是普通 403)
        let platform_only = user(&["mixed"]);
        assert!(policy
            .require(&platform_only, Permission::UsersAdmin)
            .is_ok());
        assert!(matches!(
            policy.require(&platform_only, Permission::WidgetRead),
            Err(AppError::TenantRequired)
        ));
        // 租户里:租户角色给租户级,不给平台级
        let tenant_member = member(&["mixed"]);
        assert!(policy
            .require(&tenant_member, Permission::WidgetRead)
            .is_ok());
        assert!(matches!(
            policy.require(&tenant_member, Permission::UsersAdmin),
            Err(AppError::Forbidden)
        ));
        // 畸形令牌:有 tenant_roles 没 tenant_id → 租户角色不算
        let mut malformed = user(&[]);
        malformed.tenant_roles = vec!["mixed".to_owned()];
        assert!(policy.permissions_of(&malformed).is_empty());
    }

    /// 后台准入:租户里的 admin:login,或任一平台级权限;都不满足时按有没有租户区分 403 的机器码。
    #[test]
    fn admin_entry_by_tenant_admin_login_or_platform_perm() {
        let policy = default_policy();
        // 租户管理员:靠默认租户里的 admin:login
        assert!(policy.require_admin_entry(&member(&["admin"]), &[]).is_ok());
        // 平台管理员:不属于任何租户也能进(凭 users:admin / tenants:admin)
        let superadmin = user(&["superadmin"]);
        assert!(policy.require_admin_entry(&superadmin, &[]).is_ok());
        assert!(policy
            .require_admin_entry(&superadmin, &[Permission::TenantsAdmin])
            .is_ok());
        // scope 收窄掉全部准入权限 → Forbidden(角色够也不行)
        assert!(matches!(
            policy.require_admin_entry(&superadmin, &[Permission::WidgetRead]),
            Err(AppError::Forbidden)
        ));
        // 普通成员 → Forbidden;没租户也没平台权限 → TenantRequired
        assert!(matches!(
            policy.require_admin_entry(&member(&["user"]), &[]),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            policy.require_admin_entry(&user(&[]), &[]),
            Err(AppError::TenantRequired)
        ));
    }

    /// 后台登录挑租户:最近用过的租户里没有 admin:login → 跳到下一个有的;都没有 → 有平台权限进平台上下文,
    /// 没有 → 有成员关系 Forbidden / 一个都没有 TenantRequired。平台角色不让「没有 admin:login 的租户」入选。
    #[test]
    fn admin_login_entry_picks_first_tenant_with_admin_login() {
        let policy = default_policy();
        let (tenant1, tenant2, tenant3) = (
            Uuid::from_u128(11),
            Uuid::from_u128(12),
            Uuid::from_u128(13),
        );
        let user_roles = vec!["user".to_owned()];
        let admin_roles = vec!["admin".to_owned()];
        let none: Vec<String> = vec![];
        let superadmin_roles = vec!["superadmin".to_owned()];

        let pick = |platform: &[String], tenants: &[(Uuid, &Vec<String>)]| {
            policy.admin_login_entry(platform, tenants.iter().map(|(t, r)| (*t, r.as_slice())))
        };
        assert_eq!(
            pick(
                &none,
                &[
                    (tenant1, &user_roles),
                    (tenant2, &admin_roles),
                    (tenant3, &admin_roles)
                ]
            )
            .unwrap(),
            Some(tenant2),
            "按顺序挑第一个有 admin:login 的"
        );
        assert_eq!(
            pick(&superadmin_roles, &[(tenant1, &user_roles)]).unwrap(),
            None,
            "平台上下文"
        );
        assert_eq!(pick(&superadmin_roles, &[]).unwrap(), None);
        assert_eq!(
            pick(
                &superadmin_roles,
                &[(tenant1, &user_roles), (tenant2, &admin_roles)]
            )
            .unwrap(),
            Some(tenant2),
            "有后台权限的租户优先于平台上下文"
        );
        assert!(matches!(
            pick(&none, &[(tenant1, &user_roles)]),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(pick(&none, &[]), Err(AppError::TenantRequired)));
        // 租户角色名塞进平台角色不算平台权限
        assert!(matches!(
            pick(&admin_roles, &[]),
            Err(AppError::TenantRequired)
        ));
    }

    /// 默认策略(同 seed 的 RoleName 默认映射)。
    fn default_policy() -> Policy {
        Policy::new(
            RoleName::ALL
                .iter()
                .map(|r| (r.as_str().to_owned(), r.default_permissions())),
        )
    }

    /// 闭集内角色的跨作用域映射行(如旧库里的 superadmin → widgets:read)载入时忽略。
    #[test]
    fn cross_scope_rows_of_known_roles_are_ignored() {
        let policy = Policy::new([
            (
                "superadmin".to_owned(),
                vec![Permission::UsersAdmin, Permission::WidgetRead],
            ),
            (
                "admin".to_owned(),
                vec![Permission::UsersAdmin, Permission::AdminLogin],
            ),
        ]);
        // superadmin 当租户角色用也拿不到 widgets:read —— 那一行根本没进策略
        assert!(policy
            .permissions_for(RoleNames {
                platform: &[],
                tenant: &["superadmin".to_owned()],
            })
            .is_empty());
        assert_eq!(
            policy.permissions_for(RoleNames {
                platform: &["superadmin".to_owned()],
                tenant: &[],
            }),
            HashSet::from([Permission::UsersAdmin])
        );
        // admin 当平台角色用拿不到 users:admin
        assert!(policy
            .permissions_for(RoleNames {
                platform: &["admin".to_owned()],
                tenant: &[],
            })
            .is_empty());
        assert_eq!(
            policy.permissions_for(RoleNames {
                platform: &[],
                tenant: &["admin".to_owned()],
            }),
            HashSet::from([Permission::AdminLogin])
        );
    }

    /// round-trip:每个变体的 wire 串(serde rename)== `resource:action[:qualifier]` 三段投影。
    /// 守住"变体 ↔ wire ↔ 投影"不漂移 —— 加变体忘补 `ALL`/投影/`rename` 都会挂这里。
    #[test]
    fn perm_wire_matches_projection() {
        for permission in Permission::ALL {
            let wire = serde_json::to_value(permission).unwrap();
            let wire = wire.as_str().unwrap();
            let mut segments = wire.split(':');
            assert_eq!(
                segments.next(),
                Some(permission.resource()),
                "{wire}: resource"
            );
            assert_eq!(segments.next(), Some(permission.action()), "{wire}: action");
            assert_eq!(segments.next(), permission.qualifier(), "{wire}: qualifier");
            assert_eq!(segments.next(), None, "{wire}: 多余段");
        }
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

    /// 作用域闭集(spec §4.1 + 2026-11-26 角色补充):superadmin / platform_admin 是平台角色,admin / user 是租户角色。
    #[test]
    fn role_scope_platform_for_platform_roles() {
        for role in RoleName::ALL {
            let expect = if matches!(role, RoleName::Superadmin | RoleName::PlatformAdmin) {
                RoleScope::Platform
            } else {
                RoleScope::Tenant
            };
            assert_eq!(role.scope(), expect, "{role:?}");
        }
        assert_eq!(RoleName::PlatformAdmin.as_str(), "platform_admin");
        assert_eq!(
            "platform_admin".parse::<RoleName>(),
            Ok(RoleName::PlatformAdmin)
        );
        assert_eq!(RoleName::PlatformAdmin.display_name(), "平台管理员");
    }

    /// 平台管理员默认 = 全部平台级权限减去 superadmin 独占三项;superadmin 仍是全部平台级(含新权限)。
    #[test]
    fn platform_admin_defaults_exclude_superadmin_only() {
        let platform_admin_permissions: HashSet<Permission> = RoleName::PlatformAdmin
            .default_permissions()
            .into_iter()
            .collect();
        let superadmin_permissions: HashSet<Permission> = RoleName::Superadmin
            .default_permissions()
            .into_iter()
            .collect();
        for permission in SUPERADMIN_ONLY {
            assert!(
                !platform_admin_permissions.contains(&permission),
                "平台管理员不该有 {permission:?}"
            );
            assert!(
                superadmin_permissions.contains(&permission),
                "superadmin 应有 {permission:?}"
            );
        }
        for permission in [
            Permission::UsersAdmin,
            Permission::TenantsAdmin,
            Permission::ProfileRead,
            Permission::ProfileWrite,
            Permission::ProfileWriteAll,
        ] {
            assert!(
                platform_admin_permissions.contains(&permission),
                "平台管理员应有 {permission:?}"
            );
        }
        assert_eq!(
            platform_admin_permissions.len() + SUPERADMIN_ONLY.len(),
            superadmin_permissions.len()
        );
        // 平台管理员凭平台级权限进后台(不属于任何租户也行)
        let policy = default_policy();
        assert!(policy
            .require_admin_entry(&user(&["platform_admin"]), &[])
            .is_ok());
    }

    /// 目标账号是否持平台角色:闭集内按作用域;闭集外的名字算(fail-closed);遗留的租户角色行不算。
    #[test]
    fn holds_platform_role_is_fail_closed() {
        let to_strings = |names: &[&str]| names.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(holds_platform_role(&to_strings(&["superadmin"])));
        assert!(holds_platform_role(&to_strings(&["platform_admin"])));
        assert!(
            holds_platform_role(&to_strings(&["auditor"])),
            "闭集外 → 算平台角色"
        );
        assert!(
            !holds_platform_role(&to_strings(&["admin", "user"])),
            "遗留租户角色行不算"
        );
        assert!(!holds_platform_role(&[]));
    }

    /// 平台角色闸:目标 / 授出的角色里有平台角色 → 要 platform:roles(superadmin 有,平台管理员没有;scope 收窄掉也不行)。
    #[test]
    fn platform_role_authority_requires_platform_roles() {
        let policy = default_policy();
        let to_strings = |names: &[&str]| names.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let superadmin = user(&["superadmin"]);
        let platform_admin = user(&["platform_admin"]);
        for target in [
            to_strings(&["superadmin"]),
            to_strings(&["platform_admin"]),
            to_strings(&["legacy"]),
        ] {
            assert!(policy
                .require_platform_role_authority(&superadmin, &[], &target)
                .is_ok());
            assert!(matches!(
                policy.require_platform_role_authority(&platform_admin, &[], &target),
                Err(AppError::Forbidden)
            ));
            assert!(matches!(
                policy.require_platform_role_authority(
                    &superadmin,
                    &[Permission::UsersAdmin],
                    &target
                ),
                Err(AppError::Forbidden)
            ));
        }
        // 普通账号 → 不设这道闸
        assert!(policy
            .require_platform_role_authority(&platform_admin, &[], &to_strings(&[]))
            .is_ok());
        assert!(policy
            .require_platform_role_authority(&member(&["admin"]), &[], &to_strings(&["user"]))
            .is_ok());
    }

    #[test]
    fn role_name_wire_matches() {
        for role in RoleName::ALL {
            let wire = serde_json::to_value(role).unwrap();
            assert_eq!(
                wire.as_str(),
                Some(role.as_str()),
                "{role:?}: as_str ↔ serde rename"
            );
        }
        assert_eq!(
            RoleName::Superadmin.default_permissions().len(),
            Permission::ALL
                .iter()
                .filter(|p| p.scope() == PermissionScope::Platform)
                .count(),
            "superadmin 默认应持全部平台级权限"
        );
    }

    /// implies:角色只配 `read:all`(漏 `read`)→ 载入期自动补 `read`,顶层 read 闸不再 403。
    #[test]
    fn read_all_implies_read_role_and_scope() {
        let policy = Policy::new([("mgr".to_owned(), vec![Permission::WidgetReadAll])]);
        // role 侧:permissions_for 已含被蕴含的 read
        let permissions = policy.permissions_for(RoleNames {
            platform: &[],
            tenant: &["mgr".to_owned()],
        });
        assert!(
            permissions.contains(&Permission::WidgetRead),
            "read:all 应蕴含 read"
        );
        assert!(permissions.contains(&Permission::WidgetReadAll));
        let manager = member(&["mgr"]);
        assert!(
            policy.require(&manager, Permission::WidgetRead).is_ok(),
            "顶层 read 闸不应 403"
        );
        assert!(matches!(
            policy.data_access(&manager, &[], Permission::WidgetReadAll),
            Access::All
        ));
        // scope 侧:降权令牌 scope=[read:all] 也视为含 read
        assert!(policy
            .require_scoped(
                &manager,
                &[Permission::WidgetReadAll],
                Permission::WidgetRead
            )
            .is_ok());
    }

    /// 多权限组合子:AND 缺一即拒、OR 任一即过;scope 收窄与 implies 语义同 require_scoped。
    #[test]
    fn require_all_and_any_combinators() {
        let policy = Policy::new([
            (
                "ops".to_owned(),
                vec![Permission::WidgetRead, Permission::WidgetDelete],
            ),
            ("aud".to_owned(), vec![Permission::UsersAdmin]),
        ]);
        // ops 的权限是租户级(租户角色),aud 的 users:admin 是平台级(平台角色)
        let both = member(&["ops"]);
        let mut admin_only = member(&[]);
        admin_only.roles = vec!["aud".to_owned()];
        let need = [Permission::WidgetRead, Permission::WidgetDelete];
        // AND:全有 → Ok;role 缺(aud 无 read/delete)→ Err
        let check = |scope, required| PermissionCheck { scope, required };
        assert!(policy.require_all(&both, check(&[], &need)).is_ok());
        assert!(policy.require_all(&admin_only, check(&[], &need)).is_err());
        // AND:scope 收窄掉 delete → Err(role 够也不行)
        assert!(policy
            .require_all(&both, check(&[Permission::WidgetRead], &need))
            .is_err());
        // OR:任一支过即 Ok(aud 走 users:admin 支)
        let either = [Permission::WidgetRead, Permission::UsersAdmin];
        assert!(policy.require_any(&admin_only, check(&[], &either)).is_ok());
        assert!(policy.require_any(&both, check(&[], &either)).is_ok());
        // OR:两支全无 → Err
        assert!(policy
            .require_any(&member(&["nobody"]), check(&[], &either))
            .is_err());
        // OR + scope 收窄:scope 只给 users:admin → read 支被收窄,靠 admin 支过
        assert!(policy
            .require_any(&admin_only, check(&[Permission::UsersAdmin], &either))
            .is_ok());
        // OR + scope 收窄:scope 与两支皆不交 → 全败
        assert!(policy
            .require_any(&both, check(&[Permission::UsersAdmin], &either))
            .is_err());
        // OR:implies 经由生效(read:all 蕴含 read → read 支过)
        let read_all_policy = Policy::new([("mgr".to_owned(), vec![Permission::WidgetReadAll])]);
        assert!(read_all_policy
            .require_any(&member(&["mgr"]), check(&[], &either))
            .is_ok());
    }
}

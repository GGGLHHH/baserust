//! 授权(AuthZ)—— **归 app**。idm 只给身份事实(token 里的 roles),"role/scope 能干什么"全在这。
//!
//! 三份真相,各归其位:
//! - **权限词表**(有哪些 `Perm`)= 本文件的封闭枚举,拼错=编译错;
//! - **role→权限映射** = `seed.toml` 的 `[[roles]].permissions`(唯一真相),启动期载进 [`Policy`];
//! - **user→role** = idm 库 → JWT claim(运行期事实,不进文件)。
//!
//! 判定全在 app 进程内存完成:token 带 roles,[`Policy`] 把 roles 展开成权限,**绝不查 idm 库**
//! —— 契合"app 进程只 decode JWT"的拓扑。`scope` 是 per-token 子集(只收窄、不放大)。
//!
//! 这里是授权的**核心**(词表 + 判定),纯 Rust。从请求里取 token scope、组闸中间件、
//! `/permissions/me` 端点、`Perm`/`RoleName` 的 OpenAPI schema 归 HTTP 适配 `infra::authz`。

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::kernel::error::AppError;
use idm::AuthUser;

/// 权限词表的**唯一真相**(封闭集)。handler 用变体 `Perm::WidgetWrite`,拼错=编译错。
/// wire 串(TOML / JWT scope)经 `rename` 映射;未知串 → 反序列化失败 → 启动期挡住(fail-fast)。
/// 加权限 = 加一个变体 + `rename`,别处不动。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum RoleName {
    #[serde(rename = "superadmin")]
    Superadmin,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
}

impl RoleName {
    /// 全部变体(seed / 目录 / round-trip 测试用)。
    /// 加变体必补这里 —— 同 `Perm::ALL`,**漏了没有任何东西会发现**(数组字面量,不编译失败;
    /// round-trip 测试遍历的就是它)。`as_str()` 的穷尽 match 会逼你回到本 impl,但补 `ALL` 靠自觉。
    pub const ALL: [RoleName; 3] = [RoleName::Superadmin, RoleName::Admin, RoleName::User];

    /// wire 串(== serde `rename`;单一来源,`role_name_wire_matches` 测试钉死不漂移)。
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "superadmin",
            RoleName::Admin => "admin",
            RoleName::User => "user",
        }
    }

    /// 人读显示名(seed idm.roles.display_name)。
    pub fn display_name(&self) -> &'static str {
        match self {
            RoleName::Superadmin => "超级管理员",
            RoleName::Admin => "管理员",
            RoleName::User => "普通用户",
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
}

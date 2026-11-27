//! users(后台用户管理)的**领域模型**:读模型、命令(含校验规则)、排序字段、列表过滤条件。
//! 纯 Rust;身份权威在 idm(领域库),`display_name`/`avatar_url` 是跨 schema 富化字段(只展示,
//! 不作过滤/排序键)。请求/响应 JSON 与 query 形状在 `adapters::http::dto`。

use garde::Validate;
use idm::UserSortBy;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ports::UserSearchSort;
use crate::kernel::authorization::RoleName;
use crate::kernel::sort_order::SortOrder;

/// 后台用户读模型:身份(idm.users)+ 角色(idm)+ 富化的资料(app.profiles;缺/分进程降级 → None)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUserView {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: OffsetDateTime,
    /// idm 角色名(闭集;闭集外的存量角色被 `RoleName::parse_lossy` 跳过)。
    pub roles: Vec<RoleName>,
    /// 富化:app.profiles 的显示名(悬空/分进程 → None)。
    pub display_name: Option<String>,
    /// 富化:相对头像端点路径(悬空/分进程 → None)。
    pub avatar_url: Option<String>,
}

/// 角色目录项(admin 分配角色的候选集)。`name`=机器码(唯一稳定),`display_name`=展示名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    pub name: RoleName,
    pub display_name: String,
}

impl TryFrom<idm::Role> for Role {
    /// Err = 不在闭集的原始角色名(调用方决定跳过/告警,不 panic)。
    type Error = String;
    fn try_from(role: idm::Role) -> Result<Self, String> {
        let name = role.name.parse().map_err(|_| role.name)?;
        Ok(Self {
            id: role.id,
            name,
            display_name: role.display_name,
        })
    }
}

/// 建号命令(原子含角色)。`password` 复用注册的长度口径(`length(min=3)`)。
#[derive(Debug, Clone, Validate)]
pub struct CreateUser {
    #[garde(length(min = 1, max = 100))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
    #[garde(length(min = 3))]
    pub password: String,
    /// 角色 id(空 = 不授角色);未知 id → Validation。
    #[garde(skip)]
    pub roles: Vec<Uuid>,
}

/// 改身份命令(全量)。`email=None` 即清空(替换 email 会重置 email_verified,idm 语义)。
#[derive(Debug, Clone, Validate)]
pub struct UpdateUser {
    #[garde(length(min = 1, max = 100))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
}

/// 全量设角色命令(原子替换)。传角色 id;未知 id → Validation。
#[derive(Debug, Clone)]
pub struct SetRoles {
    pub roles: Vec<Uuid>,
}

/// 管理员重置密码命令(无需旧密码)。
#[derive(Debug, Clone, Validate)]
pub struct ResetPassword {
    #[garde(length(min = 3))]
    pub new_password: String,
}

/// 排序字段(白名单)。只排 primary-schema(idm.users)自己的列;`DisplayName` 仅投影路支持。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UserSortField {
    #[default]
    CreatedAt,
    Username,
    Email,
    /// 仅投影路(search 索引)支持;回退路(无 search 后端)在 `list()` 以 Validation 拦截。
    DisplayName,
}

impl UserSortField {
    /// 映射到 idm 直查的排序键(回退路专用)。
    ///
    /// # Panics
    ///
    /// `DisplayName` 没有 idm 对应列,传它即调用方漏了 `list()` 的 422 前置校验(实现 bug),panic。
    #[must_use]
    pub fn to_idm(self) -> UserSortBy {
        match self {
            UserSortField::CreatedAt => UserSortBy::CreatedAt,
            UserSortField::Username => UserSortBy::Username,
            UserSortField::Email => UserSortBy::Email,
            UserSortField::DisplayName => {
                unreachable!("display_name 排序仅投影路;回退路已在 list() 以 422 拦截")
            }
        }
    }

    /// 一一映射到投影侧排序键(投影路专用)。
    #[must_use]
    pub fn to_search(self) -> UserSearchSort {
        match self {
            UserSortField::CreatedAt => UserSearchSort::CreatedAt,
            UserSortField::Username => UserSearchSort::Username,
            UserSortField::Email => UserSearchSort::Email,
            UserSortField::DisplayName => UserSearchSort::DisplayName,
        }
    }
}

/// 列表过滤 + 排序条件。类目过滤范式:正选 `role` + 反选 `role_not`(角色是代码闭集 [`RoleName`])。
#[derive(Debug, Clone, Default)]
pub struct ListUsers {
    /// 用户名模糊(ILIKE 子串)。
    pub username: Option<String>,
    /// 用户名 + 显示名模糊搜索(仅投影/search 后端支持;无后端 → Validation)。
    pub query: Option<String>,
    /// 正选:含任一角色。
    pub role: Vec<RoleName>,
    /// 反选:不含任一角色。
    pub role_not: Vec<RoleName>,
    pub created_from: Option<OffsetDateTime>,
    pub created_to: Option<OffsetDateTime>,
    pub sort_by: UserSortField,
    pub order: SortOrder,
}

impl ListUsers {
    /// 正选角色名(wire 串)。喂给按角色**名**过滤的 idm / 投影(role name 是稳定机器键)。
    #[must_use]
    pub fn roles_any(&self) -> Vec<String> {
        self.role.iter().map(|r| r.as_str().to_owned()).collect()
    }

    /// 反选角色名(wire 串)。
    #[must_use]
    pub fn roles_none(&self) -> Vec<String> {
        self.role_not
            .iter()
            .map(|r| r.as_str().to_owned())
            .collect()
    }

    /// 是否默认排序(created_at desc)—— keyset 恒按 id 序,只有默认排序能配 cursor。
    #[must_use]
    pub fn is_default_sort(&self) -> bool {
        matches!(self.sort_by, UserSortField::CreatedAt) && matches!(self.order, SortOrder::Desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_filter_maps_enum_to_names() {
        let filter = ListUsers {
            role: vec![RoleName::Admin, RoleName::User],
            role_not: vec![RoleName::Superadmin],
            ..Default::default()
        };
        assert_eq!(
            filter.roles_any(),
            vec!["admin".to_string(), "user".to_string()]
        );
        assert_eq!(filter.roles_none(), vec!["superadmin".to_string()]);
        assert!(ListUsers::default().roles_any().is_empty());
        assert!(ListUsers::default().is_default_sort());
    }
}

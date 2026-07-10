//! users(后台用户管理)对外 DTO + 过滤/排序 query 类型。
//! 入参 `Deserialize + ToSchema + Validate`(校验在 app 边界);出参 `Serialize + ToSchema`。
//! 身份权威在 idm；`display_name`/`avatar_url` 是跨 schema 富化字段(只展示,不作过滤/排序键)。

use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::infra::authz::RoleName;
use crate::infra::sort::SortOrder;

/// 后台用户视图:身份(idm.users)+ 角色(idm)+ 富化的资料(app.profiles;缺/分进程降级 → null)。
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserView {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// idm 角色名(全量;闭集,生成前端 union)。
    pub roles: Vec<RoleName>,
    /// 富化:app.profiles 的显示名(悬空/分进程 → null)。
    pub display_name: Option<String>,
    /// 富化:相对 preview 路径(悬空/分进程 → null)。
    pub avatar_url: Option<String>,
}

/// 角色目录项(admin 分配角色的候选集;`GET /roles` 返回)。
/// `name`=机器码(唯一稳定,JWT/权限引用),`display_name`=展示名(UI,可改)。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RoleView {
    pub id: Uuid,
    /// 机器码(闭集,生成前端 union)。
    pub name: RoleName,
    pub display_name: String,
}

impl TryFrom<idm::Role> for RoleView {
    /// Err = 不在闭集的原始角色名(调用方决定跳过/告警,不 panic)。
    type Error = String;
    fn try_from(r: idm::Role) -> Result<Self, String> {
        let name = r.name.parse().map_err(|_| r.name)?;
        Ok(Self {
            id: r.id,
            name,
            display_name: r.display_name,
        })
    }
}

/// 建号(原子含角色)。`password` 复用 `RegisterRequest` 的长度口径(auth/types.rs `length(min=3)`)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateUserRequest {
    #[garde(length(min = 1, max = 100))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
    #[garde(length(min = 3))]
    pub password: String,
    /// 角色 id(空 = 不授角色);未知 id → 422。
    #[garde(skip)]
    pub roles: Vec<Uuid>,
}

/// 改身份(PUT 全量)。`email=None` 即清空(替换 email 会重置 email_verified,idm 语义)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateUserRequest {
    #[garde(length(min = 1, max = 100))]
    pub username: String,
    #[garde(inner(email))]
    pub email: Option<String>,
}

/// 全量设角色(原子替换)。传角色 id;未知 id → 422。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetRolesRequest {
    #[garde(skip)]
    pub roles: Vec<Uuid>,
}

/// 管理员重置密码(无需旧密码)。
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ResetPasswordRequest {
    #[garde(length(min = 3))]
    pub new_password: String,
}

/// 排序字段(白名单,防注入)。只排 primary-schema(idm.users)自己的列。
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserSortField {
    #[default]
    CreatedAt,
    Username,
    Email,
    /// 仅投影路(search 索引)支持;回退路(无 search 后端)在 `list()` 以 422 拦截。
    DisplayName,
}

impl UserSortField {
    pub fn to_idm(self) -> idm::UserSortBy {
        match self {
            UserSortField::CreatedAt => idm::UserSortBy::CreatedAt,
            UserSortField::Username => idm::UserSortBy::Username,
            UserSortField::Email => idm::UserSortBy::Email,
            UserSortField::DisplayName => {
                unreachable!("display_name 排序仅投影路;回退路已在 list() 以 422 拦截")
            }
        }
    }

    /// 一一映射到投影侧排序键(投影路专用)。
    pub fn to_search(self) -> crate::features::users::port::UserSearchSort {
        use crate::features::users::port::UserSearchSort;
        match self {
            UserSortField::CreatedAt => UserSearchSort::CreatedAt,
            UserSortField::Username => UserSearchSort::Username,
            UserSortField::Email => UserSearchSort::Email,
            UserSortField::DisplayName => UserSearchSort::DisplayName,
        }
    }
}

/// 列表过滤 query(扁平)。`#[serde(default)]`:缺字段回落默认,不 400。
/// 类目过滤范式:正选 `role`(数组)+ 反选 `role_not`(数组)。角色是代码闭集 [`RoleName`],
/// OpenAPI 数组按 `style=form, explode=true` 走**重复 key**(`?role=admin&role=user`);
/// 靠 `axum_extra::extract::Query`(serde_html_form)把重复 key 解进 `Vec`。
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct ListUsersFilter {
    /// 用户名模糊(ILIKE 子串)。
    pub username: Option<String>,
    /// 用户名 + 显示名模糊搜索(仅投影/search 后端支持;无后端 → 422)。
    pub q: Option<String>,
    /// 正选:含任一角色(重复 key,如 `?role=admin&role=user`)。
    #[param(style = Form, explode)]
    pub role: Vec<RoleName>,
    /// 反选:不含任一角色。
    #[param(style = Form, explode)]
    pub role_not: Vec<RoleName>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_to: Option<OffsetDateTime>,
    pub sort_by: UserSortField,
    pub order: SortOrder,
}

impl ListUsersFilter {
    /// 正选角色名(wire 串)。喂给按角色**名**过滤的 idm / 投影(role name 是稳定机器键)。
    pub fn roles_any(&self) -> Vec<String> {
        self.role.iter().map(|r| r.as_str().to_owned()).collect()
    }

    /// 反选角色名(wire 串)。
    pub fn roles_none(&self) -> Vec<String> {
        self.role_not
            .iter()
            .map(|r| r.as_str().to_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_filter_maps_enum_to_names() {
        let f = ListUsersFilter {
            role: vec![RoleName::Admin, RoleName::User],
            role_not: vec![RoleName::Superadmin],
            ..Default::default()
        };
        assert_eq!(f.roles_any(), vec!["admin".to_string(), "user".to_string()]);
        assert_eq!(f.roles_none(), vec!["superadmin".to_string()]);
        assert!(ListUsersFilter::default().roles_any().is_empty());
    }
}

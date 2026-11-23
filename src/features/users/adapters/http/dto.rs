//! users 的 **HTTP 线格式**:请求/响应 JSON、列表 query,与领域模型(`model`)互转。
//! 入参 `Deserialize + ToSchema`(校验规则是领域不变量,在 `model` 的命令上、由 service 执行);
//! 出参 `Serialize + ToSchema`。类型名即 OpenAPI schema 名(对前端的契约)。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::features::users::model;
use crate::infra::authz::RoleNameSchema;
use crate::infra::http::sort::SortOrder;
use crate::kernel::authz::RoleName;

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
    #[schema(value_type = Vec<RoleNameSchema>)]
    pub roles: Vec<RoleName>,
    /// 富化:app.profiles 的显示名(悬空/分进程 → null)。
    pub display_name: Option<String>,
    /// 富化:相对头像端点路径(悬空/分进程 → null)。
    pub avatar_url: Option<String>,
}

impl From<model::AdminUserView> for AdminUserView {
    fn from(v: model::AdminUserView) -> Self {
        Self {
            id: v.id,
            username: v.username,
            email: v.email,
            email_verified: v.email_verified,
            created_at: v.created_at,
            roles: v.roles,
            display_name: v.display_name,
            avatar_url: v.avatar_url,
        }
    }
}

/// 角色目录项(admin 分配角色的候选集;`GET /roles` 返回)。
/// `name`=机器码(唯一稳定,JWT/权限引用),`display_name`=展示名(UI,可改)。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RoleView {
    pub id: Uuid,
    /// 机器码(闭集,生成前端 union)。
    #[schema(value_type = RoleNameSchema)]
    pub name: RoleName,
    pub display_name: String,
}

impl From<model::Role> for RoleView {
    fn from(r: model::Role) -> Self {
        Self {
            id: r.id,
            name: r.name,
            display_name: r.display_name,
        }
    }
}

/// 建号(原子含角色)。username 1..=100、email 合法、password ≥3(领域校验)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    /// 角色 id(空 = 不授角色);未知 id → 422。
    pub roles: Vec<Uuid>,
}

impl From<CreateUserRequest> for model::CreateUser {
    fn from(r: CreateUserRequest) -> Self {
        Self {
            username: r.username,
            email: r.email,
            password: r.password,
            roles: r.roles,
        }
    }
}

/// 改身份(PUT 全量)。`email=None` 即清空(替换 email 会重置 email_verified,idm 语义)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub username: String,
    pub email: Option<String>,
}

impl From<UpdateUserRequest> for model::UpdateUser {
    fn from(r: UpdateUserRequest) -> Self {
        Self {
            username: r.username,
            email: r.email,
        }
    }
}

/// 全量设角色(原子替换)。传角色 id;未知 id → 422。
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRolesRequest {
    pub roles: Vec<Uuid>,
}

impl From<SetRolesRequest> for model::SetRoles {
    fn from(r: SetRolesRequest) -> Self {
        Self { roles: r.roles }
    }
}

/// 管理员重置密码(无需旧密码)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

impl From<ResetPasswordRequest> for model::ResetPassword {
    fn from(r: ResetPasswordRequest) -> Self {
        Self {
            new_password: r.new_password,
        }
    }
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

impl From<UserSortField> for model::UserSortField {
    fn from(f: UserSortField) -> Self {
        match f {
            UserSortField::CreatedAt => Self::CreatedAt,
            UserSortField::Username => Self::Username,
            UserSortField::Email => Self::Email,
            UserSortField::DisplayName => Self::DisplayName,
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
    #[param(style = Form, explode, value_type = Vec<RoleNameSchema>)]
    pub role: Vec<RoleName>,
    /// 反选:不含任一角色。
    #[param(style = Form, explode, value_type = Vec<RoleNameSchema>)]
    pub role_not: Vec<RoleName>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_to: Option<OffsetDateTime>,
    pub sort_by: UserSortField,
    pub order: SortOrder,
}

impl From<ListUsersFilter> for model::ListUsers {
    fn from(f: ListUsersFilter) -> Self {
        Self {
            username: f.username,
            q: f.q,
            role: f.role,
            role_not: f.role_not,
            created_from: f.created_from,
            created_to: f.created_to,
            sort_by: f.sort_by.into(),
            order: f.order.into(),
        }
    }
}

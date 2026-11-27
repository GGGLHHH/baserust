//! tenants 的 **HTTP 线格式**:请求 / 响应 JSON、列表 query,与领域模型(`model`)互转。
//! 类型名即 OpenAPI schema 名(对前端的契约)。闭集(租户状态 / 成员状态 / 角色名)经标记类型生成前端 union。

use idm::RoleScope;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::features::tenants::model::{self, MemberStatus, TenantStatus};
use crate::kernel::authorization::RoleName;

crate::closed_enum_to_schema!(TenantStatusSchema => TenantStatus, TenantStatus::ALL, "租户状态闭集");
crate::closed_enum_to_schema!(MemberStatusSchema => MemberStatus, MemberStatus::ALL, "成员状态闭集");

/// 成员关系上能授的角色 = [`RoleName`] 里作用域为租户的那些(admin、user)。只是 OpenAPI 名字不同的同一个
/// 核心类型:schema 名 `TenantRoleName`,取值从 `RoleName::ALL` 按 `scope()` 过滤(加角色自动跟上),
/// 生成的前端 union 里不会出现平台角色(superadmin)。服务端仍会把平台角色拒成 422(兜底)。
pub type TenantRoleName = RoleName;

/// [`TenantRoleNameSchema`] 的取值:`RoleName::ALL` 里作用域为租户的那些。
fn tenant_roles() -> Vec<RoleName> {
    RoleName::ALL
        .into_iter()
        .filter(|r| r.scope() == RoleScope::Tenant)
        .collect()
}

crate::closed_enum_to_schema!(
    TenantRoleNameSchema => TenantRoleName,
    tenant_roles(),
    "租户角色闭集(成员关系上能授的角色;平台角色不在内)"
);

/// 租户。`slug` 建后不可改、删除后也不复用。
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantView {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    #[schema(value_type = TenantStatusSchema)]
    pub status: TenantStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<model::TenantView> for TenantView {
    fn from(tenant: model::TenantView) -> Self {
        Self {
            id: tenant.id,
            slug: tenant.slug,
            name: tenant.name,
            status: tenant.status,
            created_at: tenant.created_at,
            updated_at: tenant.updated_at,
        }
    }
}

/// 建租户。slug:1-63 个小写字母 / 数字 / 连字符,不以连字符开头或结尾,全局唯一(含已删的);name 1..=100。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    pub slug: String,
    pub name: String,
}

impl From<CreateTenantRequest> for model::CreateTenant {
    fn from(request: CreateTenantRequest) -> Self {
        Self {
            slug: request.slug,
            name: request.name,
        }
    }
}

/// 改租户(PUT 全量:名称 + 状态;slug 不可改)。`status = suspended` 即停用(立即吊销该租户的会话)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    pub name: String,
    #[schema(value_type = TenantStatusSchema)]
    pub status: TenantStatus,
}

impl From<UpdateTenantRequest> for model::UpdateTenant {
    fn from(request: UpdateTenantRequest) -> Self {
        Self {
            name: request.name,
            status: request.status,
        }
    }
}

/// 租户成员:账号 + 该租户里的租户角色 / 成员状态 + 富化的资料(缺 → null)。
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberView {
    /// 账号 id(user id)。
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    /// 富化:显示名(缺 → null)。
    pub display_name: Option<String>,
    /// 富化:相对头像端点路径(缺 → null)。
    pub avatar_url: Option<String>,
    /// 该租户里的租户角色(闭集)。
    #[schema(value_type = Vec<TenantRoleNameSchema>)]
    pub roles: Vec<RoleName>,
    #[schema(value_type = MemberStatusSchema)]
    pub status: MemberStatus,
    /// 该账号持有任一平台角色(superadmin / 平台管理员)。这样的成员只有持 `platform:roles` 的人能改角色 / 移出
    /// (防接管,否则 403);前端据此隐藏按钮。
    pub holds_platform_role: bool,
}

impl From<model::MemberView> for MemberView {
    fn from(member: model::MemberView) -> Self {
        Self {
            id: member.id,
            username: member.username,
            email: member.email,
            display_name: member.display_name,
            avatar_url: member.avatar_url,
            roles: member.roles,
            status: member.status,
            holds_platform_role: member.holds_platform_role,
        }
    }
}

/// 按**完整用户名**把已有账号加进本租户(精确匹配;查不到 → 404 `account_not_found`)。
/// `roles` 只能是租户角色(平台角色 → 422)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddMemberRequest {
    pub username: String,
    #[schema(value_type = Vec<TenantRoleNameSchema>)]
    pub roles: Vec<RoleName>,
}

impl From<AddMemberRequest> for model::AddMember {
    fn from(request: AddMemberRequest) -> Self {
        Self {
            username: request.username,
            roles: request.roles,
        }
    }
}

/// 全量设成员的租户角色(原子替换;只能是租户角色,平台角色 → 422)。
#[derive(Debug, Deserialize, ToSchema)]
pub struct MemberRolesRequest {
    #[schema(value_type = Vec<TenantRoleNameSchema>)]
    pub roles: Vec<RoleName>,
}

/// 成员列表过滤 query。`#[serde(default)]`:缺字段回落默认,不 400。
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(default)]
#[into_params(parameter_in = Query)]
pub struct ListMembersFilter {
    /// 用户名 + 显示名模糊搜索(仅接了 search 投影后端时可用;未接 → 422)。
    #[serde(rename = "q")]
    pub query: Option<String>,
}

impl From<ListMembersFilter> for model::ListMembers {
    fn from(filter: ListMembersFilter) -> Self {
        Self {
            query: filter.query,
        }
    }
}

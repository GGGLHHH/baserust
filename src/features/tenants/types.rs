//! 租户类型。**闭集枚举而非裸 String** —— 照 closed-enums skill:
//! 有限已知取值必须是枚举,否则前端生成的 union 会漂移成 string。

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 租户状态。DB 侧有 `tenants_status_ck` check 约束双保险。
/// **只 `Deserialize`,没有 `Serialize`/`ToSchema`**:spec §4.9 的 `GET /auth/tenants`
/// 返回 `{id, name, display_name, role, active}`,不带 status,`Membership` 也不带它 ——
/// `Serialize`/`ToSchema` 目前没有消费方。`Deserialize` 是挣来的:spec §9 的
/// `seed.toml` 要解析 `status = "active"`。等真有端点要序列化它再挣回来。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
}

impl TenantStatus {
    /// DB 裸值。
    ///
    /// **没有配套的 `parse_db`** —— P1 从不把 status 读回来:`memberships` 的过滤
    /// (`status = 'active'`)写在 SQL 里,应用侧拿不到也不需要这一列。
    /// 等真有端点要展示租户状态时再加,那时它才不是死代码。
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// **租户级**角色。与平台级的 `infra::authz::RoleName` 是两回事 ——
/// 平台角色骑在租户边界之上,租户角色关在租户边界之内。见 spec §4.5。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Admin,
    Member,
}

impl TenantRole {
    /// DB 裸值(`tenant_members.role` 列 + API 响应)。**不带 `tn:` 前缀。**
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// JWT claim 里的 wire 串。**必须与 `RoleName::TenantAdmin.as_str()` 逐字相等** ——
    /// 这是等式不是巧合(spec §4.5):TenantRoleRepo push 它,Policy 按它查权限。
    /// P2 接线时会有测试钉住这条等式。
    pub fn wire(self) -> &'static str {
        match self {
            Self::Admin => "tn:admin",
            Self::Member => "tn:member",
        }
    }

    /// 从 DB 裸值解析。未知值 → None(fail-closed)。
    pub fn parse_db(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// 一条**有效**成员资格(已过滤停用/软删租户,见 `TenantRepo::memberships` 契约)。
/// 带上 name/display_name 是因为 P2 的 `GET /auth/tenants` 要它们 —— 三张表同 schema,join 合法。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub role: TenantRole,
}

// 刻意**没有** `Tenant` 实体 struct:P1 没有任何方法返回一整个租户
// (`upsert_tenant` 收散参,`memberships` 返回 `Membership`)。
// 等 P2 的 `GET /auth/tenants` 或租户管理端点真要它时再加。

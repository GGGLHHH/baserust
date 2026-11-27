//! tenants 的**领域模型**:租户读模型、成员读模型、命令(含校验规则)、闭集状态。
//! 纯 Rust;请求 / 响应 JSON 形状在主 crate 的 `adapters::http::dto`。

use std::str::FromStr;

use garde::Validate;
use idm::Tenant;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::kernel::authorization::RoleName;

/// 租户状态(闭集)。`Suspended` = 停用:成员登录 / 切换 / refresh 都进不去(idm 判定)。
/// wire 串与 idm 库里存的文本一致(`active` / `suspended`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TenantStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "suspended")]
    Suspended,
}

impl TenantStatus {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [TenantStatus; 2] = [TenantStatus::Active, TenantStatus::Suspended];

    /// wire 串(== serde rename,也是 idm 库里存的文本)。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
        }
    }
}

impl FromStr for TenantStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == value)
            .ok_or_else(|| format!("未知租户状态: {value}"))
    }
}

impl From<idm::TenantStatus> for TenantStatus {
    fn from(status: idm::TenantStatus) -> Self {
        match status {
            idm::TenantStatus::Active => TenantStatus::Active,
            idm::TenantStatus::Suspended => TenantStatus::Suspended,
        }
    }
}

impl From<TenantStatus> for idm::TenantStatus {
    fn from(status: TenantStatus) -> Self {
        match status {
            TenantStatus::Active => idm::TenantStatus::Active,
            TenantStatus::Suspended => idm::TenantStatus::Suspended,
        }
    }
}

/// 成员状态(闭集)。`Inactive` = 停用成员:关系和角色保留,但不算有效成员。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
}

impl MemberStatus {
    /// 全部变体(FromStr 查表 / wire round-trip 测试用)。加变体必补这里。
    pub const ALL: [MemberStatus; 2] = [MemberStatus::Active, MemberStatus::Inactive];

    /// wire 串(== serde rename,也是 idm 库里存的文本)。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MemberStatus::Active => "active",
            MemberStatus::Inactive => "inactive",
        }
    }
}

impl FromStr for MemberStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == value)
            .ok_or_else(|| format!("未知成员状态: {value}"))
    }
}

impl From<idm::MemberStatus> for MemberStatus {
    fn from(status: idm::MemberStatus) -> Self {
        match status {
            idm::MemberStatus::Active => MemberStatus::Active,
            idm::MemberStatus::Inactive => MemberStatus::Inactive,
        }
    }
}

/// 租户读模型(idm.tenants 存活行)。`slug` 建后不可改、删除后也不复用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantView {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: TenantStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl From<Tenant> for TenantView {
    fn from(tenant: Tenant) -> Self {
        Self {
            id: tenant.id,
            slug: tenant.slug,
            name: tenant.name,
            status: tenant.status.into(),
            created_at: tenant.created_at,
            updated_at: tenant.updated_at,
        }
    }
}

/// slug 上限(DNS label 长度,留给以后按子域名识别租户)。
pub const SLUG_MAX: usize = 63;

/// slug 规则:1..=63 个小写字母 / 数字 / 连字符,不以连字符开头或结尾。
fn valid_slug(value: &str, _: &()) -> garde::Result {
    let ok = !value.is_empty()
        && value.len() <= SLUG_MAX
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(garde::Error::new(
            "slug must be 1-63 lowercase letters, digits or hyphens, not starting or ending with a hyphen",
        ))
    }
}

/// 建租户命令。
#[derive(Debug, Clone, Validate)]
pub struct CreateTenant {
    #[garde(custom(valid_slug))]
    pub slug: String,
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}

/// 改租户命令(PUT 全量:名称 + 状态;slug 不可改,不在表示里)。
#[derive(Debug, Clone, Validate)]
pub struct UpdateTenant {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
    #[garde(skip)]
    pub status: TenantStatus,
}

/// 成员读模型:账号(idm,全局)+ 该租户里的成员关系(租户角色 / 状态)+ 富化的资料(缺 → None)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    /// 账号 id(user id)。
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// 该租户里的**租户角色**(闭集;闭集外的存量角色名被 `RoleName::parse_lossy` 跳过)。
    pub roles: Vec<RoleName>,
    pub status: MemberStatus,
    /// 该账号持有任一**平台角色**(superadmin / 平台管理员 / 闭集外的平台角色名,fail-closed,看未过滤原始名)。
    /// 持平台角色的成员只有 `platform:roles` 能改角色 / 移出(防接管);前端据此隐藏按钮。
    pub holds_platform_role: bool,
}

/// 按用户名把**已有账号**加进租户。用户名精确匹配(不做模糊、邮箱不算),查不到 → `AccountNotFound`。
#[derive(Debug, Clone, Validate)]
pub struct AddMember {
    #[garde(length(min = 1, max = 100))]
    pub username: String,
    /// 租户角色(平台角色 → 422)。
    #[garde(skip)]
    pub roles: Vec<RoleName>,
}

/// 成员列表过滤。`q` = 用户名 / 显示名模糊搜索(仅投影 / search 后端支持;无后端 → 422)。
#[derive(Debug, Clone, Default)]
pub struct ListMembers {
    pub query: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trips() {
        for status in TenantStatus::ALL {
            let wire = serde_json::to_value(status).unwrap();
            assert_eq!(wire.as_str(), Some(status.as_str()));
            assert_eq!(status.as_str().parse::<TenantStatus>().unwrap(), status);
            let idm: idm::TenantStatus = status.into();
            assert_eq!(idm.as_str(), status.as_str(), "与 idm 存的文本一致");
            assert_eq!(TenantStatus::from(idm), status);
        }
        for status in MemberStatus::ALL {
            let wire = serde_json::to_value(status).unwrap();
            assert_eq!(wire.as_str(), Some(status.as_str()));
            assert_eq!(status.as_str().parse::<MemberStatus>().unwrap(), status);
        }
        assert!("deleted".parse::<TenantStatus>().is_err());
    }

    #[test]
    fn slug_rules() {
        let ok = |slug: &str| {
            CreateTenant {
                slug: slug.into(),
                name: "x".into(),
            }
            .validate()
            .is_ok()
        };
        for good in ["acme", "a", "acme-2", "0a"] {
            assert!(ok(good), "{good}");
        }
        let long = "a".repeat(SLUG_MAX + 1);
        for bad in ["", "Acme", "a b", "-a", "a-", "a_b", "ä", long.as_str()] {
            assert!(!ok(bad), "{bad}");
        }
    }
}

/// [`crate::features::tenants::TenantAdminService::resolve_add_member`] 的结果:要加进来的账号与它要拿的租户角色。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMember {
    pub user_id: Uuid,
    pub role_ids: Vec<Uuid>,
}

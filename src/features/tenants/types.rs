//! 租户类型。**闭集枚举而非裸 String** —— 照 closed-enums skill:
//! 有限已知取值必须是枚举,否则前端生成的 union 会漂移成 string。
//!
//! 枚举↔DB 裸值的互转靠 `#[derive(sqlx::Type)]` + 每变体 `#[sqlx(rename)]`(照
//! `auth_audit/types.rs` 的既有范式)—— sqlx 直接 Encode/Decode,`.bind(role)` 即可,
//! 不用手写 as_db/parse_db,坏值自动经 sqlx 的 decode 错误 fail-closed。

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// 租户状态。DB 侧有 `tenants_status_ck` check 约束双保险。
///
/// **只 `Deserialize`,没有 `Serialize`/`ToSchema`**:spec §4.9 的 `GET /auth/tenants`
/// 返回 `{id, name, display_name, role, is_active}`,不带 status,`Membership` 也不带它 ——
/// 那两个派生目前没有消费方。`Deserialize` 是挣来的:spec §9 的 `seed.toml` 要解析
/// `status = "active"`。等真有端点要序列化它再挣回来。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text")]
pub enum TenantStatus {
    #[sqlx(rename = "active")]
    Active,
    #[sqlx(rename = "suspended")]
    Suspended,
}

/// **租户级**角色。与平台级的 `infra::authz::RoleName` 是两回事 ——
/// 平台角色骑在租户边界之上,租户角色关在租户边界之内。见 spec §4.5。
///
/// serde/sqlx 的串都是 DB 裸值(`admin`/`member`),与 `tenant_members_role_ck` 一致;
/// JWT claim 里那个带前缀的串走 [`TenantRole::claim`],**刻意不叫 `wire()`** ——
/// 本仓 `Perm::wire()` 的既有语义是「与 serde 输出逐字相等」(还有测试钉住),
/// 而这里的 claim 串(`tn:admin`)恰恰**不**等于 serde 输出,同名会误导读者。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text")]
pub enum TenantRole {
    #[sqlx(rename = "admin")]
    Admin,
    #[sqlx(rename = "member")]
    Member,
}

impl TenantRole {
    /// JWT claim 里的串。**必须与 `RoleName::TenantAdmin.as_str()` 逐字相等** ——
    /// 这是等式不是巧合(spec §4.5):TenantRoleRepo push 它,Policy 按它查权限。
    ///
    /// ⚠️ **P1 里这条等式钉不住**:等式的另一端 `RoleName::TenantAdmin` 此刻还不存在
    /// (P2 才加),本方法也零调用方 —— 一个拼写错误会静默到 P2 接线才炸。留着它是因为
    /// P2 一定要用、且它是 spec §4.5 的一部分;**但别指望这行 rustdoc 提醒谁** ——
    /// 该等式的强制在 spec §4.5 的 checklist 里(那是 P2 实施者会逐条过的清单)。
    pub fn claim(self) -> &'static str {
        match self {
            Self::Admin => "tn:admin",
            Self::Member => "tn:member",
        }
    }
}

/// 一条**有效**成员资格(已过滤停用/软删租户,见 `TenantRepo::memberships` 契约)。
///
/// `is_active` = 「这条是不是该用户当前激活的租户」。它由 `memberships`/`membership`
/// 一次 LEFT JOIN `user_active_tenant` 算出,**不是**单独查一次拼出来的 —— 那样两次读
/// 非同一快照,并发 set_active 时铸币路径可能读到不一致的组合。
///
/// 「active 未设」与「active 指向一个已失效(停用/软删/已退出)的租户」两种情况**刻意坍缩**成
/// 同一个结果:没有任何一条 `is_active = true`。spec §4.1 的回退逻辑对两者的处理本就相同
/// (都退到 `.first()`),不需要区分。
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Membership {
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub role: TenantRole,
    pub is_active: bool,
}

// 刻意**没有** `Tenant` 实体 struct:P1 没有任何方法返回一整个租户
// (`upsert_tenant` 收散参,`memberships` 返回 `Membership`)。
// 等 P2 的 `GET /auth/tenants` 或租户管理端点真要它时再加。

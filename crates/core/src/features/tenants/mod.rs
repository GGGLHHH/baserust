//! 租户与成员管理的**核心**:平台管理员管租户(建 / 改名 / 停用)和任意租户的成员,租户管理员管本租户的成员
//! (spec §4.5)。身份权威在 idm(领域库):租户 / 成员 / 会话直接用 idm 的仓储端口(同 users 用 idm 的账号端口);
//! 成员列表的检索投影、资料富化是跨模块能力,走本模块自己的窄端口(实现在组合根 `app/adapters/`)。
//! HTTP 适配器在主 crate。

pub mod model;
pub mod ports;
pub mod static_member_profiles;
mod tenant_admin_service;

pub use model::{
    AddMember, CreateTenant, ListMembers, MemberStatus, MemberView, ResolvedMember, TenantStatus,
    TenantView, UpdateTenant,
};
pub use ports::{
    MemberProfile, MemberProfiles, MemberSearchIndex, MemberSearchPage, MemberSearchRow,
};
pub use static_member_profiles::StaticMemberProfiles;
pub use tenant_admin_service::TenantAdminService;

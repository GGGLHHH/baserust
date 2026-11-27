//! 租户与成员管理模块 —— 身份原语在 idm 领域库,本模块编排(spec §4.5 / §4.6):
//! - **平台级**(`tenants:admin`,平台角色 platform_admin / superadmin):`/api/v1/admin/platform/tenants*` —— 建 / 改名 / 停用租户、
//!   管理任意租户的成员(给新租户指定第一个管理员)。
//! - **租户级**(`members:read` / `members:admin`,当前租户的租户角色):`/api/v1/admin/auth/members*` —— 本租户的
//!   成员列表、按用户名把已有账号加进来、设租户角色、移出。租户只从 token 来(`CurrentTenant`)。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里按名重新导出(不用 glob,见 CLAUDE.md「代码风格」);本 crate 只放适配器。

pub use baserust_core::features::tenants::{
    model, ports, static_member_profiles, AddMember, CreateTenant, ListMembers, MemberProfile,
    MemberProfiles, MemberSearchIndex, MemberSearchPage, MemberSearchRow, MemberStatus, MemberView,
    ResolvedMember, StaticMemberProfiles, TenantAdminService, TenantStatus, TenantView,
    UpdateTenant,
};

pub mod adapters;

pub use adapters::http::{members_router, platform_router};

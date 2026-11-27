//! **防接管闸**的组合根胶水(2026-11-26 角色补充):对一个账号动手前,看它**现有**的平台角色。
//!
//! 判定本身在 `Policy::require_platform_role_authority`(目标持平台角色 → 操作者要 `platform:roles`);这里只负责
//! 取目标的**未过滤原始**平台角色名(`user_roles` 原样,不经 `RoleName` 闭集过滤 —— 闭集外脏数据不能让闸失明,
//! 见 `UserAdminService::raw_role_names`)。放组合根:资料(profile)、租户成员(tenants)的 handler 都要用,
//! 而它们与账号模块(users)彼此零 import —— 跨模块只经 `AppState`。
//!
//! 只在挂了 idm 的进程上有意义(账号目录在 idm);调用它的端点(`/admin/auth/*`、`/admin/platform/*`)都归 idm 进程。

use idm::AuthUser;
use uuid::Uuid;

use crate::app::app_state::AppState;
use crate::kernel::app_error::AppError;
use crate::kernel::authorization::Permission;

impl AppState {
    /// 目标账号持有任一平台角色(superadmin / platform_admin / 闭集外的平台角色名)→ 操作者须持 `platform:roles`,否则 403。
    /// 账号不存在 / 已删 → 没有平台角色,放行(端点自己的 404 / 业务逻辑照旧)。
    pub async fn guard_platform_account(
        &self,
        actor: &AuthUser,
        scope: &[Permission],
        target: Uuid,
    ) -> Result<(), AppError> {
        let roles = match self.user_admin.raw_role_names(target).await {
            Ok(roles) => roles,
            Err(AppError::NotFound) => return Ok(()),
            Err(other) => return Err(other),
        };
        self.policy
            .require_platform_role_authority(actor, scope, &roles)
    }
}

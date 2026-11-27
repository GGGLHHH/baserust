//! tenants 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)。

pub mod dto;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::app_state::AppState;

/// 平台级租户管理:admin 组下 nest `/platform`(组闸 = 后台准入;端点内再 gate `tenants:admin`)。
pub fn platform_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_tenants, routes::create_tenant))
        .routes(routes!(routes::get_tenant, routes::update_tenant))
        .routes(routes!(routes::list_tenant_members))
        .routes(routes!(
            routes::put_tenant_member,
            routes::remove_tenant_member
        ))
}

/// 租户级成员管理:admin 组下 nest `/auth`(和账号管理同前缀,归 idm 进程;端点内 gate `members:*`)。
pub fn members_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_members, routes::add_member))
        .routes(routes!(routes::set_member_roles))
        .routes(routes!(routes::remove_member))
}

//! 后台用户管理模块 —— 薄 HTTP 壳套 idm 身份原语,读侧富化 app.profiles(强一致,零事件)。
//! 结构同 `auth`(HTTP 边界)+ 富化端口同 `profile`。全挂 admin 组、gate `users:admin`(superadmin 专属)。

mod port;
mod routes;
mod service;
mod types;

pub use port::{
    ProfileBrief, ProfileDirectory, StaticProfileDirectory, UserSearchFilter, UserSearchIndex,
    UserSearchPage, UserSearchRow, UserSearchSort,
};
pub use service::UserAdminService;
pub use types::{
    AdminUserView, CreateUserRequest, ListUsersFilter, ResetPasswordRequest, SetRolesRequest,
    UpdateUserRequest, UserSortField,
};

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// admin 组(组闸「admin:login」由 composition root 上;端点内再 gate「users:admin」)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::list_users, routes::create_user))
        .routes(routes!(
            routes::get_user,
            routes::update_user,
            routes::delete_user
        ))
        .routes(routes!(routes::set_user_roles))
        .routes(routes!(routes::reset_user_password))
}

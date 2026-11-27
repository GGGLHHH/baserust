//! 后台用户管理的**核心**:领域模型、端口、用例 + 内存替身。HTTP 适配器在主 crate。

pub mod model;
pub mod ports;
pub mod static_profile_directory;
mod user_admin_service;

pub use model::{AdminUserView, ListUsers, Role, UserSortField};
pub use ports::{
    ProfileBrief, ProfileDirectory, UserSearchFilter, UserSearchIndex, UserSearchPage,
    UserSearchRow, UserSearchSort,
};
pub use static_profile_directory::StaticProfileDirectory;
pub use user_admin_service::UserAdminService;

//! 后台用户管理的**核心**:领域模型、端口、用例 + 内存替身。HTTP 适配器在主 crate。

pub mod memory;
pub mod model;
pub mod ports;
mod service;

pub use memory::StaticProfileDirectory;
pub use model::{AdminUserView, ListUsers, Role, UserSortField};
pub use ports::{
    ProfileBrief, ProfileDirectory, UserSearchFilter, UserSearchIndex, UserSearchPage,
    UserSearchRow, UserSearchSort,
};
pub use service::UserAdminService;

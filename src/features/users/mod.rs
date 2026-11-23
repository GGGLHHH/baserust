//! 后台用户管理模块 —— 身份原语在 idm 领域库,本模块编排 + 读侧富化 app.profiles(强一致,零事件)。
//! 全挂 admin 组、gate `users:admin`(superadmin 专属)。
//!
//! **核心**(模块根目录;不依赖框架、数据库、HTTP):`model`(读模型/命令/排序/过滤)、
//! `ports`(富化目录、检索投影)、`service`(用例)。
//! **适配器**(`adapters/`):`http`(handler + DTO)、`memory`(富化目录替身)。

pub mod adapters;
pub mod model;
pub mod ports;
mod service;

pub use adapters::http::admin_router;
pub use adapters::memory::StaticProfileDirectory;
pub use model::{AdminUserView, ListUsers, Role, UserSortField};
pub use ports::{
    ProfileBrief, ProfileDirectory, UserSearchFilter, UserSearchIndex, UserSearchPage,
    UserSearchRow, UserSearchSort,
};
pub use service::UserAdminService;

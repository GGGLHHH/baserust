//! 用户资料模块:显示名 / 电话 / 头像(头像经 content,富化为相对 preview 路径)。
//! 分层照 widget;头像跨模块经 `AvatarProbe` 端口(适配在 app/adapters)。

mod port;
mod repo;
mod routes;
mod service;
mod types;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

pub use port::{AvatarInfo, AvatarProbe, StaticAvatarProbe};
pub use repo::{
    AppOutboxRecord, InMemoryAppOutbox, InMemoryProfileRepo, PgAppOutbox, PgProfileRepo,
    ProfileFields, ProfileRepo,
};
pub use service::ProfileService;
pub use types::{AvatarForm, Profile, ProfileResponse, PutProfileRequest};

/// 本模块路由 + OpenAPI,挂到主 router(/api/v1 由 nest 加)。
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::get_my_profile))
        .routes(routes!(routes::get_profile, routes::put_profile))
        .routes(routes!(routes::get_user_avatar))
}

/// 后台资料管理(admin 组;路径在 /users/{id} 下,与 users::admin_router 并挂)。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::get_user_profile, routes::set_user_profile))
        .routes(routes!(routes::set_user_avatar))
}

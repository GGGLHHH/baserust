//! auth 的 HTTP 适配器:路由挂载 + handler(`routes`)+ 线格式(`dto`)+ 鉴权中间件。

pub mod dto;
pub mod middleware;
mod routes;

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

/// public 组(无闸):注册/登录/刷新/登出。
pub fn public_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::register))
        .routes(routes!(routes::login))
        .routes(routes!(routes::refresh))
        .routes(routes!(routes::logout))
}

/// frontend 组(闸:登录):当前用户资料/改密/全登出/我的租户/切换租户。
pub fn me_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(routes::logout_all))
        .routes(routes!(
            routes::get_me,
            routes::update_me,
            routes::delete_me
        ))
        .routes(routes!(routes::change_password))
        .routes(routes!(routes::list_my_tenants))
        .routes(routes!(routes::switch_tenant))
}

/// admin 组闸内:当前管理员。
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_get_me))
}

/// admin 组闸外:后台登录(public 语义 —— 未认证请求闸挡不了,验密后 handler 自查 admin:login)。
pub fn admin_login_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(routes::admin_login))
}

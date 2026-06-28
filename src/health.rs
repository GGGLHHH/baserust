//! 健康检查:**liveness**(进程活着)与 **readiness**(依赖就绪)分离 —— k8s/编排靠 readyz 判断何时放流量。

use axum::extract::State;
use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(livez))
        .routes(routes!(readyz))
        .routes(routes!(health))
}

/// 存活探针:进程活着即 ok,**不查依赖**(给 k8s livenessProbe;失败会被重启)。
#[utoipa::path(get, path = "/livez", tag = "health", responses((status = 200, body = str)))]
async fn livez() -> &'static str {
    "ok"
}

/// 兼容别名 = livez,保留早期 `/health` 引用不破。
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, body = str)))]
async fn health() -> &'static str {
    "ok"
}

/// 就绪探针(给 k8s readinessProbe):DB 模式 ping `SELECT 1`,不通 → 503;内存模式无外部依赖,恒就绪。
/// 失败只让流量绕开本实例(不重启),与 livez 分工不同。
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "health",
    responses((status = 200, description = "就绪"), (status = 503, description = "依赖未就绪"))
)]
async fn readyz(State(state): State<AppState>) -> StatusCode {
    let Some(pool) = &state.db_pool else {
        return StatusCode::OK; // 内存模式:无外部依赖
    };
    match sqlx::query("select 1").execute(pool).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            tracing::warn!("readyz: 数据库 ping 失败: {e}");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

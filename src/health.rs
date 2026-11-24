//! 健康检查:**liveness**(进程活着)与 **readiness**(依赖就绪)分离 —— 编排靠 readyz 判断何时放流量。

use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(livez))
        .routes(routes!(readyz))
        .routes(routes!(health))
}

/// 存活探针:进程活着即 ok,**不查依赖**(给 livenessProbe;失败会被重启)。
#[utoipa::path(get, path = "/livez", tag = "health", responses((status = 200, body = str)))]
async fn livez() -> &'static str {
    "ok"
}

/// 兼容别名 = livez,保留早期 `/health` 引用不破。
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, body = str)))]
async fn health() -> &'static str {
    "ok"
}

/// 就绪报告:整体状态 + 每项依赖的检查结果。
#[derive(Serialize, ToSchema)]
pub struct ReadinessReport {
    /// `ok`:全部依赖可用;`unavailable`:至少一项不可用(此时 HTTP 503)。
    pub status: String,
    /// 每项依赖(`db_app` / `db_idm` / `db_content` / `db_search` / `nats`;内存模式为空)。
    pub checks: BTreeMap<String, ReadinessCheck>,
}

/// 单项依赖检查结果。
#[derive(Serialize, ToSchema)]
pub struct ReadinessCheck {
    pub ok: bool,
    /// 检查耗时(毫秒)。
    pub latency_ms: u64,
    /// 失败原因(成功时省略)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 就绪探针:并发检查本进程的全部依赖(各 schema 连接池 `select 1`、NATS 连接状态,每项 2s 超时),
/// 任一项不可用 → 503。失败只让流量绕开本实例(不重启),与 livez 分工不同。
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "health",
    responses(
        (status = 200, description = "全部依赖可用", body = ReadinessReport),
        (status = 503, description = "至少一项依赖不可用", body = ReadinessReport)
    )
)]
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<ReadinessReport>) {
    let results = state.probes.check().await;
    let all_ok = results.iter().all(|r| r.ok);
    for r in results.iter().filter(|r| !r.ok) {
        tracing::warn!(check = %r.name, error = ?r.error, "readyz: 依赖不可用");
    }
    let checks = results
        .into_iter()
        .map(|r| {
            (
                r.name,
                ReadinessCheck {
                    ok: r.ok,
                    latency_ms: r.latency_ms,
                    error: r.error,
                },
            )
        })
        .collect();
    let (code, status) = if all_ok {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    (
        code,
        Json(ReadinessReport {
            status: status.to_owned(),
            checks,
        }),
    )
}

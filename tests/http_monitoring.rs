//! 后台系统监控的**黑盒 HTTP 验收测试**:鉴权、报告形状、请求统计,以及分进程拓扑下 app 汇总 idm。
//!
//! 监控数据是进程全局的(同一测试二进制里的测试共享),断言只用"至少"/"包含",不卡精确计数。
//!
//! covers: GET /api/v1/admin/monitoring
//! covers: GET /api/v1/admin/monitoring/history
//! covers: GET /api/v1/admin/monitoring/logs
//! covers: POST /api/v1/public/client-errors

mod http_support;

use std::sync::Arc;
use uuid::Uuid;

use baserust::app::monitoring::MonitoringSetup;
use baserust::app::Mount;
use baserust::infra::config::Config;
use baserust::infra::monitor::histogram::Histogram;
use baserust::infra::monitor::store::{
    minute_start, LogEntry, MemoryOpsStore, MinuteRecord, OpsStore, PeriodTotals, RouteTotals,
    Service, Severity,
};
use http_support::{expect, expect_json, mint, TestServer, ADMIN, PASSWORD, SUPERADMIN};
use reqwest::StatusCode;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

const MONITORING: &str = "/api/v1/admin/monitoring";

/// 监控报告里的一行按路由统计。
#[derive(Debug)]
struct RouteStat {
    method: String,
    route: String,
    requests: u64,
}

fn routes(instance: &Value) -> Vec<RouteStat> {
    instance["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| RouteStat {
            method: row["method"].as_str().unwrap().to_owned(),
            route: row["route"].as_str().unwrap().to_owned(),
            requests: row["requests"].as_u64().unwrap(),
        })
        .collect()
}

/// 只有 `ops:read`(superadmin 独占)能看:未登录 401、租户 admin 403、平台管理员(有 users:admin)也 403。
#[tokio::test]
async fn monitoring_requires_ops_read() {
    let server = TestServer::start().await;
    expect(
        server.anonymous().get(MONITORING).await,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let admin = server.login(ADMIN, PASSWORD).await;
    expect(admin.get(MONITORING).await, StatusCode::FORBIDDEN).await;
    expect(
        platform_admin(&server).get(MONITORING).await,
        StatusCode::FORBIDDEN,
    )
    .await;
}

/// 平台管理员令牌(平台上下文,平台角色 platform_admin)。
fn platform_admin(server: &TestServer) -> http_support::Client {
    server.bearer(&mint(
        Uuid::now_v7(),
        "pa",
        &["platform_admin"],
        None,
        &[],
        vec![],
    ))
}

/// 单进程:一个 combined 实例;请求按路由模板计数,未匹配的路径归 `unmatched`,
/// 监控接口自己的轮询不计入。
#[tokio::test]
async fn single_process_report_counts_requests_by_route() {
    let server = TestServer::start().await;
    let superadmin = server.login(SUPERADMIN, PASSWORD).await;
    for _ in 0..3 {
        expect(
            superadmin.get("/api/v1/frontend/widgets/stats").await,
            StatusCode::OK,
        )
        .await;
    }
    expect(superadmin.get("/no/such/path").await, StatusCode::NOT_FOUND).await;
    expect(superadmin.get(MONITORING).await, StatusCode::OK).await;

    let report = expect_json(superadmin.get(MONITORING).await, StatusCode::OK).await;
    let instances = report["instances"].as_array().unwrap();
    assert_eq!(instances.len(), 1, "{report}");
    let me = &instances[0];
    assert_eq!(me["role"], "combined");
    assert_eq!(me["reachable"], true);
    assert_eq!(me["checks"], serde_json::json!([]), "内存模式无外部依赖");
    assert_eq!(me["sample_interval_secs"], 15);
    assert!(me["traffic"]["requests"].as_u64().unwrap() >= 4, "{me}");
    assert!(me["traffic"]["errors_4xx"].as_u64().unwrap() >= 1, "{me}");

    let route_stats = routes(me);
    let stats = route_stats
        .iter()
        .find(|r| r.method == "GET" && r.route == "/api/v1/frontend/widgets/stats")
        .unwrap_or_else(|| panic!("缺 widgets/stats: {route_stats:?}"));
    assert!(stats.requests >= 3, "{route_stats:?}");
    assert!(
        route_stats.iter().any(|r| r.route == "unmatched"),
        "{route_stats:?}"
    );
    assert!(
        route_stats.iter().all(|r| r.route != MONITORING),
        "监控轮询不计入: {route_stats:?}"
    );
    assert!(
        route_stats.iter().all(|r| !r.route.contains("/no/such")),
        "未匹配路径不能原样成为一行: {route_stats:?}"
    );
}

/// 分进程:app 经 `IDM_INTERNAL_URL` 拉 idm 的内部端点,两份报告并进同一个响应。
#[tokio::test]
async fn app_aggregates_idm_instance() {
    let idm = TestServer::start_mounted(Mount::Idm, |_| {}).await;
    // idm 进程上没有 admin 监控接口,只有内部端点
    expect(idm.anonymous().get(MONITORING).await, StatusCode::NOT_FOUND).await;
    let internal = expect_json(
        idm.anonymous().get("/internal/monitoring").await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(internal["role"], "idm");

    let config = Config {
        idm_internal_url: Some(idm.base.clone()),
        ..Config::default()
    };
    let app = TestServer::start_with(|state| {
        state.monitoring = MonitoringSetup::new(&config, Mount::App)
    })
    .await;
    let superadmin = app.login(SUPERADMIN, PASSWORD).await;
    let report = expect_json(superadmin.get(MONITORING).await, StatusCode::OK).await;
    let roles: Vec<&str> = report["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["app", "idm"], "{report}");
    assert_eq!(report["instances"][1]["reachable"], true, "{report}");
}

/// idm 拉不到:页面照常出,只把那个实例标成不可达(原因是概括性的,不带原始错误)。
#[tokio::test]
async fn unreachable_idm_is_reported_not_fatal() {
    let config = Config {
        // 保留端口 9(discard),没人监听 → 连接失败
        idm_internal_url: Some("http://127.0.0.1:9".to_owned()),
        ..Config::default()
    };
    let app = TestServer::start_with(|state| {
        state.monitoring = MonitoringSetup::new(&config, Mount::App)
    })
    .await;
    let superadmin = app.login(SUPERADMIN, PASSWORD).await;
    let report = expect_json(superadmin.get(MONITORING).await, StatusCode::OK).await;
    let idm = &report["instances"][1];
    assert_eq!(idm["role"], "idm", "{report}");
    assert_eq!(idm["reachable"], false, "{report}");
    assert!(
        idm["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{report}"
    );
    assert_eq!(report["instances"][0]["reachable"], true);
}

const HISTORY: &str = "/api/v1/admin/monitoring/history";
const LOGS: &str = "/api/v1/admin/monitoring/logs";

fn minute(instance: &str, at: OffsetDateTime, requests: u64, errors_5xx: u64) -> MinuteRecord {
    let mut latency = Histogram::default();
    for _ in 0..requests {
        latency.record(12.0);
    }
    MinuteRecord {
        instance: instance.to_owned(),
        bucket: at,
        totals: PeriodTotals {
            requests,
            errors_5xx,
            latency,
            ..Default::default()
        },
        routes: vec![RouteTotals {
            method: "GET".into(),
            route: "/api/v1/frontend/widgets".into(),
            requests,
            errors_5xx,
            latency,
            ..Default::default()
        }],
        db_operations: vec![],
    }
}

fn log(severity: Severity, body: &str, request_id: Option<&str>, ago: Duration) -> LogEntry {
    LogEntry {
        timestamp: OffsetDateTime::now_utc() - ago,
        instance: "combined".into(),
        service: if body.contains("projector") {
            Service::Idm
        } else {
            Service::App
        },
        severity,
        target: "baserust::test".into(),
        body: body.into(),
        request_id: request_id.map(str::to_owned),
        method: None,
        route: None,
        status: None,
        duration_ms: None,
        attributes: Default::default(),
    }
}

async fn server_with(store: Arc<MemoryOpsStore>) -> TestServer {
    TestServer::start_with(|state| {
        state.monitoring = MonitoringSetup::default().with_store(store);
    })
    .await
}

/// 历史与日志同样只给 ops:read。
#[tokio::test]
async fn history_and_logs_require_ops_read() {
    let server = TestServer::start().await;
    let admin = server.login(ADMIN, PASSWORD).await;
    let platform_admin_client = platform_admin(&server);
    for path in [HISTORY, LOGS] {
        expect(server.anonymous().get(path).await, StatusCode::UNAUTHORIZED).await;
        expect(admin.get(path).await, StatusCode::FORBIDDEN).await;
        expect(platform_admin_client.get(path).await, StatusCode::FORBIDDEN).await;
    }
}

/// 历史:按范围重新分桶(24h = 5 分钟一点),合计与接口明细来自存储;内存存储标 persistent=false。
#[tokio::test]
async fn history_aggregates_stored_minutes() {
    let store = Arc::new(MemoryOpsStore::new());
    let base = minute_start(OffsetDateTime::now_utc()) - Duration::minutes(20);
    for minute_offset in 0..10 {
        store
            .record_minute(&minute(
                "combined",
                base + Duration::minutes(minute_offset),
                3,
                u64::from(minute_offset == 4),
            ))
            .await
            .unwrap();
    }
    let server = server_with(store).await;
    let superadmin = server.login(SUPERADMIN, PASSWORD).await;

    let history = expect_json(superadmin.get(HISTORY).await, StatusCode::OK).await;
    assert_eq!(history["range"], "24h", "默认 24 小时");
    assert_eq!(history["step_secs"], 300);
    assert_eq!(history["persistent"], false);
    let me = &history["instances"][0];
    assert_eq!(me["role"], "combined");
    assert_eq!(me["traffic"]["requests"], 30);
    assert_eq!(me["traffic"]["errors_5xx"], 1);
    let sum: u64 = me["points"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["requests"].as_u64().unwrap())
        .sum();
    assert_eq!(sum, 30, "各点相加 = 合计");
    assert_eq!(me["routes"][0]["requests"], 30);

    let history = expect_json(
        superadmin.get(&format!("{HISTORY}?range=7d")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(history["step_secs"], 1800);
    expect(
        superadmin.get(&format!("{HISTORY}?range=2d")).await,
        StatusCode::BAD_REQUEST,
    )
    .await;
}

/// 日志:时间倒序、级别 / 关键字 / 请求 id 过滤、offset 分页带总数;参数越界 422。
#[tokio::test]
async fn logs_filter_and_paginate() {
    let store = Arc::new(MemoryOpsStore::new());
    store
        .insert_logs(&[
            log(
                Severity::Warn,
                "慢请求:GET /a",
                Some("req-1"),
                Duration::minutes(3),
            ),
            log(
                Severity::Error,
                "数据库连接失败",
                Some("req-2"),
                Duration::minutes(2),
            ),
            log(Severity::Warn, "projector 重试", None, Duration::minutes(1)),
        ])
        .await
        .unwrap();
    let server = server_with(store).await;
    let superadmin = server.login(SUPERADMIN, PASSWORD).await;

    let logs = expect_json(superadmin.get(LOGS).await, StatusCode::OK).await;
    assert_eq!(logs["page_info"]["total"], 3);
    let bodies: Vec<&str> = logs["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["body"].as_str().unwrap())
        .collect();
    assert_eq!(
        bodies,
        ["projector 重试", "数据库连接失败", "慢请求:GET /a"],
        "新的在前"
    );

    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?level=ERROR")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 1);
    assert_eq!(logs["items"][0]["severity"], "ERROR");

    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?request_id=req-1")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["items"][0]["request_id"], "req-1");

    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?q=PROJECTOR")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 1, "关键字不区分大小写");

    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?service=idm")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 1);
    assert_eq!(logs["items"][0]["service"], "idm");
    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?service=app")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 2);

    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?page=2&size=2")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["items"].as_array().unwrap().len(), 1);
    assert_eq!(logs["page_info"]["total_pages"], 2);

    expect(
        superadmin.get(&format!("{LOGS}?size=0")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
    expect(
        superadmin.get(&format!("{LOGS}?size=500")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
}

const CLIENT_ERRORS: &str = "/api/v1/public/client-errors";

/// 前端错误上报:免登录可报,进日志库归「web」;页面地址去掉 query;条数越界 422,kind 不认识 400。
#[tokio::test]
async fn client_errors_land_in_logs_as_web() {
    let store = Arc::new(MemoryOpsStore::new());
    let server = server_with(store).await;
    let body = serde_json::json!({
        "errors": [{
            "kind": "render",
            "message": "Cannot read properties of undefined (reading 'name')",
            "stack": "TypeError: ...\n    at UserRow (users.tsx:12:7)",
            "page": "/admin/users?token=secret",
            "release": "test-build"
        }]
    });
    expect(
        server.anonymous().post_json(CLIENT_ERRORS, &body).await,
        StatusCode::NO_CONTENT,
    )
    .await;

    let superadmin = server.login(SUPERADMIN, PASSWORD).await;
    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?service=web")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 1);
    let item = &logs["items"][0];
    assert_eq!(item["service"], "web");
    assert_eq!(item["severity"], "ERROR");
    assert_eq!(item["route"], "/admin/users", "query 去掉了");
    assert_eq!(item["attributes"]["kind"], "render");
    assert_eq!(item["attributes"]["release"], "test-build");
    assert!(item["body"].as_str().unwrap().contains("reading 'name'"));
    let logs = expect_json(
        superadmin.get(&format!("{LOGS}?service=app")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(logs["page_info"]["total"], 0, "前端错误不混进 app");

    let one = serde_json::json!({"kind": "error", "message": "boom"});
    for count in [0, 11] {
        let batch = serde_json::json!({ "errors": vec![one.clone(); count] });
        expect(
            server.anonymous().post_json(CLIENT_ERRORS, &batch).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
    expect(
        server
            .anonymous()
            .post_json(
                CLIENT_ERRORS,
                &serde_json::json!({"errors": [{"kind": "nope", "message": "x"}]}),
            )
            .await,
        StatusCode::BAD_REQUEST,
    )
    .await;
    // 请求体超过 64 KB:和别的接口一样回 400(统一错误体),不进日志
    expect(
        server.anonymous()
            .post_json(
                CLIENT_ERRORS,
                &serde_json::json!({"errors": [{"kind": "error", "message": "x".repeat(70 * 1024)}]}),
            )
            .await,
        StatusCode::BAD_REQUEST,
    )
    .await;
}

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

use baserust::app::monitoring::MonitoringSetup;
use baserust::app::Mount;
use baserust::infra::config::Config;
use baserust::infra::monitor::hist::Hist;
use baserust::infra::monitor::store::{
    minute_start, LogEntry, MemoryOpsStore, MinuteRecord, OpsStore, PeriodTotals, RouteTotals,
    Service, Severity,
};
use http_support::{expect, expect_json, TestServer, ADMIN, PASSWORD, SUPERADMIN};
use reqwest::StatusCode;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

const MON: &str = "/api/v1/admin/monitoring";

fn routes(instance: &Value) -> Vec<(String, String, u64)> {
    instance["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["method"].as_str().unwrap().to_owned(),
                r["route"].as_str().unwrap().to_owned(),
                r["requests"].as_u64().unwrap(),
            )
        })
        .collect()
}

/// 只有 `users:admin` 能看:未登录 401、没有 users:admin 的 admin 403。
#[tokio::test]
async fn monitoring_requires_users_admin() {
    let s = TestServer::start().await;
    expect(s.anon().get(MON).await, StatusCode::UNAUTHORIZED).await;
    let admin = s.login(ADMIN, PASSWORD).await;
    expect(admin.get(MON).await, StatusCode::FORBIDDEN).await;
}

/// 单进程:一个 combined 实例;请求按路由模板计数,未匹配的路径归 `unmatched`,
/// 监控接口自己的轮询不计入。
#[tokio::test]
async fn single_process_report_counts_requests_by_route() {
    let s = TestServer::start().await;
    let sa = s.login(SUPERADMIN, PASSWORD).await;
    for _ in 0..3 {
        expect(sa.get("/api/v1/public/widgets/stats").await, StatusCode::OK).await;
    }
    expect(sa.get("/no/such/path").await, StatusCode::NOT_FOUND).await;
    expect(sa.get(MON).await, StatusCode::OK).await;

    let v = expect_json(sa.get(MON).await, StatusCode::OK).await;
    let instances = v["instances"].as_array().unwrap();
    assert_eq!(instances.len(), 1, "{v}");
    let me = &instances[0];
    assert_eq!(me["role"], "combined");
    assert_eq!(me["reachable"], true);
    assert_eq!(me["checks"], serde_json::json!([]), "内存模式无外部依赖");
    assert_eq!(me["sample_interval_secs"], 15);
    assert!(me["traffic"]["requests"].as_u64().unwrap() >= 4, "{me}");
    assert!(me["traffic"]["errors_4xx"].as_u64().unwrap() >= 1, "{me}");

    let rs = routes(me);
    let stats = rs
        .iter()
        .find(|(m, r, _)| m == "GET" && r == "/api/v1/public/widgets/stats")
        .unwrap_or_else(|| panic!("缺 widgets/stats: {rs:?}"));
    assert!(stats.2 >= 3, "{rs:?}");
    assert!(rs.iter().any(|(_, r, _)| r == "unmatched"), "{rs:?}");
    assert!(
        rs.iter().all(|(_, r, _)| r != MON),
        "监控轮询不计入: {rs:?}"
    );
    assert!(
        rs.iter().all(|(_, r, _)| !r.contains("/no/such")),
        "未匹配路径不能原样成为一行: {rs:?}"
    );
}

/// 分进程:app 经 `IDM_INTERNAL_URL` 拉 idm 的内部端点,两份报告并进同一个响应。
#[tokio::test]
async fn app_aggregates_idm_instance() {
    let idm = TestServer::start_mounted(Mount::Idm, |_| {}).await;
    // idm 进程上没有 admin 监控接口,只有内部端点
    expect(idm.anon().get(MON).await, StatusCode::NOT_FOUND).await;
    let internal = expect_json(idm.anon().get("/internal/monitoring").await, StatusCode::OK).await;
    assert_eq!(internal["role"], "idm");

    let config = Config {
        idm_internal_url: Some(idm.base.clone()),
        ..Config::default()
    };
    let app =
        TestServer::start_with(|st| st.monitoring = MonitoringSetup::new(&config, Mount::App))
            .await;
    let sa = app.login(SUPERADMIN, PASSWORD).await;
    let v = expect_json(sa.get(MON).await, StatusCode::OK).await;
    let roles: Vec<&str> = v["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["app", "idm"], "{v}");
    assert_eq!(v["instances"][1]["reachable"], true, "{v}");
}

/// idm 拉不到:页面照常出,只把那个实例标成不可达(原因是概括性的,不带原始错误)。
#[tokio::test]
async fn unreachable_idm_is_reported_not_fatal() {
    let config = Config {
        // 保留端口 9(discard),没人监听 → 连接失败
        idm_internal_url: Some("http://127.0.0.1:9".to_owned()),
        ..Config::default()
    };
    let app =
        TestServer::start_with(|st| st.monitoring = MonitoringSetup::new(&config, Mount::App))
            .await;
    let sa = app.login(SUPERADMIN, PASSWORD).await;
    let v = expect_json(sa.get(MON).await, StatusCode::OK).await;
    let idm = &v["instances"][1];
    assert_eq!(idm["role"], "idm", "{v}");
    assert_eq!(idm["reachable"], false, "{v}");
    assert!(idm["error"].as_str().is_some_and(|e| !e.is_empty()), "{v}");
    assert_eq!(v["instances"][0]["reachable"], true);
}

const HISTORY: &str = "/api/v1/admin/monitoring/history";
const LOGS: &str = "/api/v1/admin/monitoring/logs";

fn minute(instance: &str, at: OffsetDateTime, requests: u64, errors_5xx: u64) -> MinuteRecord {
    let mut latency = Hist::default();
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
        db_ops: vec![],
    }
}

fn log(severity: Severity, body: &str, request_id: Option<&str>, ago: Duration) -> LogEntry {
    LogEntry {
        ts: OffsetDateTime::now_utc() - ago,
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
    TestServer::start_with(|st| {
        st.monitoring = MonitoringSetup::default().with_store(store);
    })
    .await
}

/// 历史与日志同样只给 users:admin。
#[tokio::test]
async fn history_and_logs_require_users_admin() {
    let s = TestServer::start().await;
    let admin = s.login(ADMIN, PASSWORD).await;
    for path in [HISTORY, LOGS] {
        expect(s.anon().get(path).await, StatusCode::UNAUTHORIZED).await;
        expect(admin.get(path).await, StatusCode::FORBIDDEN).await;
    }
}

/// 历史:按范围重新分桶(24h = 5 分钟一点),合计与接口明细来自存储;内存存储标 persistent=false。
#[tokio::test]
async fn history_aggregates_stored_minutes() {
    let store = Arc::new(MemoryOpsStore::new());
    let base = minute_start(OffsetDateTime::now_utc()) - Duration::minutes(20);
    for k in 0..10 {
        store
            .record_minute(&minute(
                "combined",
                base + Duration::minutes(k),
                3,
                u64::from(k == 4),
            ))
            .await
            .unwrap();
    }
    let s = server_with(store).await;
    let sa = s.login(SUPERADMIN, PASSWORD).await;

    let v = expect_json(sa.get(HISTORY).await, StatusCode::OK).await;
    assert_eq!(v["range"], "24h", "默认 24 小时");
    assert_eq!(v["step_secs"], 300);
    assert_eq!(v["persistent"], false);
    let me = &v["instances"][0];
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

    let v = expect_json(sa.get(&format!("{HISTORY}?range=7d")).await, StatusCode::OK).await;
    assert_eq!(v["step_secs"], 1800);
    expect(
        sa.get(&format!("{HISTORY}?range=2d")).await,
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
    let s = server_with(store).await;
    let sa = s.login(SUPERADMIN, PASSWORD).await;

    let v = expect_json(sa.get(LOGS).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 3);
    let bodies: Vec<&str> = v["items"]
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

    let v = expect_json(sa.get(&format!("{LOGS}?level=ERROR")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1);
    assert_eq!(v["items"][0]["severity"], "ERROR");

    let v = expect_json(
        sa.get(&format!("{LOGS}?request_id=req-1")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["items"][0]["request_id"], "req-1");

    let v = expect_json(sa.get(&format!("{LOGS}?q=PROJECTOR")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1, "关键字不区分大小写");

    let v = expect_json(sa.get(&format!("{LOGS}?service=idm")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1);
    assert_eq!(v["items"][0]["service"], "idm");
    let v = expect_json(sa.get(&format!("{LOGS}?service=app")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 2);

    let v = expect_json(
        sa.get(&format!("{LOGS}?page=2&size=2")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(v["page_info"]["total_pages"], 2);

    expect(
        sa.get(&format!("{LOGS}?size=0")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
    expect(
        sa.get(&format!("{LOGS}?size=500")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
}

const CLIENT_ERRORS: &str = "/api/v1/public/client-errors";

/// 前端错误上报:免登录可报,进日志库归「web」;页面地址去掉 query;条数越界 422,kind 不认识 400。
#[tokio::test]
async fn client_errors_land_in_logs_as_web() {
    let store = Arc::new(MemoryOpsStore::new());
    let s = server_with(store).await;
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
        s.anon().post_json(CLIENT_ERRORS, &body).await,
        StatusCode::NO_CONTENT,
    )
    .await;

    let sa = s.login(SUPERADMIN, PASSWORD).await;
    let v = expect_json(sa.get(&format!("{LOGS}?service=web")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1);
    let item = &v["items"][0];
    assert_eq!(item["service"], "web");
    assert_eq!(item["severity"], "ERROR");
    assert_eq!(item["route"], "/admin/users", "query 去掉了");
    assert_eq!(item["attributes"]["kind"], "render");
    assert_eq!(item["attributes"]["release"], "test-build");
    assert!(item["body"].as_str().unwrap().contains("reading 'name'"));
    let v = expect_json(sa.get(&format!("{LOGS}?service=app")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 0, "前端错误不混进 app");

    let one = serde_json::json!({"kind": "error", "message": "boom"});
    for n in [0, 11] {
        let batch = serde_json::json!({ "errors": vec![one.clone(); n] });
        expect(
            s.anon().post_json(CLIENT_ERRORS, &batch).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
    expect(
        s.anon()
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
        s.anon()
            .post_json(
                CLIENT_ERRORS,
                &serde_json::json!({"errors": [{"kind": "error", "message": "x".repeat(70 * 1024)}]}),
            )
            .await,
        StatusCode::BAD_REQUEST,
    )
    .await;
}

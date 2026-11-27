//! 认证审计(auth_audit)的**黑盒 HTTP 验收测试**:全局审计流 / 仪表盘统计 / SSE 实时推送 / 单用户历史。
//! 测试体不 import 任何 web 框架类型(换底座只换 `http_support::serve`)。与 `auth_audit_api.rs`(axum oneshot)
//! 覆盖同一组场景并补强(过滤 / 分页 / 统计口径 / SSE 帧)。
//!
//! 造数据口径:内存模式没有 projector(生产里它从 JetStream 投影落库再发 SSE),所以经**端口**造数据 ——
//! `server.auth_events`(`AuthEventRepo::insert`)写行、`server.auth_bus.publish` 推帧,再经 HTTP 断言。
//!
//! 授权口径(seed 策略):`/api/v1/admin` 组闸要后台准入(租户 `admin:login` 或任一平台级权限),
//! 四个端点内再 gate `audit:read`(superadmin 独占;平台管理员有 users:admin 也不行)。
//!
//! covers: GET /api/v1/admin/auth/auth-events
//! covers: GET /api/v1/admin/auth/auth-events/stats
//! covers: GET /api/v1/admin/auth/auth-events/stream
//! covers: GET /api/v1/admin/auth/users/{id}/auth-events

mod http_support;

use baserust::features::auth_audit::model::to_row;
use baserust::features::auth_audit::{AuthEventRepo, NewAuthEvent};
use baserust::kernel::authorization::Permission;
use http_support::{
    expect, expect_error, expect_json, mint, next_sse_event, user_token, Client, TestServer, ADMIN,
    DEFAULT_TENANT, PASSWORD, SUPERADMIN,
};
use reqwest::StatusCode;
use serde_json::Value;
use std::fmt::Display;
use std::net::IpAddr;
use std::slice;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, Time, UtcOffset};
use uuid::Uuid;

const EVENTS: &str = "/api/v1/admin/auth/auth-events";
const STATS: &str = "/api/v1/admin/auth/auth-events/stats";
const STREAM: &str = "/api/v1/admin/auth/auth-events/stream";

fn user_events(id: impl Display) -> String {
    format!("/api/v1/admin/auth/users/{id}/auth-events")
}

// ───────────────────────────── 帮手 ─────────────────────────────

/// 满权 superadmin 令牌会话(无 scope 收窄)。
fn superadmin(server: &TestServer) -> Client {
    server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![],
    ))
}

/// 一条默认事件:前台密码登录成功、当前时刻、无用户 / 无 IP。各测试按需改字段。
fn event(sequence: i64) -> NewAuthEvent {
    NewAuthEvent {
        id: Uuid::now_v7(),
        event_type: "auth.login_succeeded".into(),
        occurred_at: OffsetDateTime::now_utc(),
        channel: "public".into(),
        auth_method: "password".into(),
        user_id: None,
        identifier_attempted: None,
        session_id: None,
        actor: None,
        outcome: "success".into(),
        failure_reason: None,
        ip: None,
        forwarded_chain: None,
        user_agent: None,
        request_id: None,
        tenant_id: None,
        event_sequence: sequence,
    }
}

/// 失败事件(登录失败 + 原因)。
fn failed(sequence: i64, reason: &str) -> NewAuthEvent {
    NewAuthEvent {
        event_type: "auth.login_failed".into(),
        outcome: "failure".into(),
        failure_reason: Some(reason.into()),
        ..event(sequence)
    }
}

/// 经仓储端口落库(= 生产里 projector 的写入)。
async fn seed(server: &TestServer, events: &[NewAuthEvent]) {
    for auth_event in events {
        assert!(
            server.auth_events.insert(auth_event).await.unwrap(),
            "seq {} 应真插入",
            auth_event.event_sequence
        );
    }
}

/// `count` 个严格递增的 v7 id(列表按 id DESC 排序,测试据此推期望顺序)。
fn ascending_ids(count: usize) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = (0..count).map(|_| Uuid::now_v7()).collect();
    ids.sort();
    ids
}

/// UTC 整点(镜像服务端小时桶)。
fn floor_hour(timestamp: OffsetDateTime) -> OffsetDateTime {
    let utc = timestamp.to_offset(UtcOffset::UTC);
    utc.replace_time(Time::from_hms(utc.hour(), 0, 0).unwrap())
}

/// RFC3339 → query 值(`+` 必须转义,否则被解成空格)。
fn query_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp.format(&Rfc3339).unwrap().replace('+', "%2B")
}

fn parse_ts(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        value
            .as_str()
            .unwrap_or_else(|| panic!("不是时间串: {value}")),
        &Rfc3339,
    )
    .unwrap()
}

fn items(page: &Value) -> &[Value] {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("应有 items 数组: {page}"))
}

/// 列表里各行的 id(按响应顺序)。
fn ids(page: &Value) -> Vec<String> {
    items(page)
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_owned())
        .collect()
}

fn id_strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

/// 列表里各行某字段(字符串)的值。
fn field(page: &Value, key: &str) -> Vec<String> {
    items(page)
        .iter()
        .map(|e| e[key].as_str().unwrap_or("").to_owned())
        .collect()
}

fn approx(value: &Value, want: f64) {
    let got = value
        .as_f64()
        .unwrap_or_else(|| panic!("不是数字: {value}"));
    assert!((got - want).abs() < 1e-9, "期望 {want},实际 {got}");
}

/// 从 SSE 帧取 `event:` 名与 `data:` JSON。
fn parse_frame(frame: &str) -> (String, Value) {
    let mut name = String::new();
    let mut data = String::new();
    for line in frame.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            name = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data.push_str(rest.trim_start());
        }
    }
    let json =
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("data 不是 JSON({e}): {frame}"));
    (name, json)
}

// ───────────────────────────── 鉴权 / 授权 ─────────────────────────────

/// 四个端点都在 admin 组闸后:无凭据 → 401 + 统一错误体。
#[tokio::test]
async fn all_endpoints_require_login_401() {
    let server = TestServer::start().await;
    let anonymous = server.anonymous();
    for path in [
        EVENTS.to_owned(),
        STATS.to_owned(),
        STREAM.to_owned(),
        user_events(Uuid::now_v7()),
    ] {
        expect_error(
            anonymous.get(&path).await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }
}

/// 权限矩阵:普通用户(无 admin:login)被组闸挡 403;admin 能进后台但无 audit:read → 403;
/// 平台管理员(users:admin / tenants:admin 都有,但 audit:read 是 superadmin 独占)→ 403;
/// 降权令牌(scope 不含 audit:read / 一个后台准入权限都不含)即便 role 是 superadmin 也 403。
#[tokio::test]
async fn all_endpoints_forbid_without_audit_read_403() {
    let server = TestServer::start().await;
    let user = server.bearer(&user_token().0);
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    let platform_admin = server.bearer(&mint(
        Uuid::now_v7(),
        "pa",
        &["platform_admin"],
        None,
        &[],
        vec![],
    ));
    let superadmin_id = Uuid::now_v7();
    let scoped_no_audit_read = server.bearer(&mint(
        superadmin_id,
        SUPERADMIN,
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![Permission::AdminLogin, Permission::UsersAdmin],
    ));
    let scoped_no_admin_entry = server.bearer(&mint(
        superadmin_id,
        SUPERADMIN,
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![Permission::WidgetRead],
    ));
    for path in [
        EVENTS.to_owned(),
        STATS.to_owned(),
        STREAM.to_owned(),
        user_events(Uuid::now_v7()),
    ] {
        for (who, client) in [
            ("user", &user),
            ("admin", &admin),
            ("平台管理员", &platform_admin),
            ("scope 缺 audit:read", &scoped_no_audit_read),
            ("scope 无后台准入", &scoped_no_admin_entry),
        ] {
            let response = client.get(&path).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{who} 访问 {path} 应 403"
            );
            expect_error(response, StatusCode::FORBIDDEN, "forbidden").await;
        }
    }
}

/// superadmin:cookie 会话(后台登录)与 scope 只含 audit:read 的降权令牌都能读
/// (audit:read 是平台级权限,本身就是后台准入)。
#[tokio::test]
async fn superadmin_cookie_session_and_exact_scope_can_read() {
    let server = TestServer::start().await;
    let cookie = server.login_admin(SUPERADMIN, PASSWORD).await;
    let scoped = server.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &["superadmin"],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        vec![Permission::AuditRead],
    ));
    seed(&server, &[event(1)]).await;
    for client in [&cookie, &scoped] {
        let page = expect_json(client.get(EVENTS).await, StatusCode::OK).await;
        assert_eq!(items(&page).len(), 1, "{page}");
        expect(client.get(STATS).await, StatusCode::OK).await;
        expect(
            client.get(&user_events(Uuid::now_v7())).await,
            StatusCode::OK,
        )
        .await;
    }
}

// ───────────────────────────── GET /auth-events:形状 / 分页 ─────────────────────────────

/// 空库 → 200 空页(offset 模式,total 0);落一行后读回的行形状与写入一致(含富化列恒 null)。
#[tokio::test]
async fn list_returns_row_shape() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let page = expect_json(superadmin_client.get(EVENTS).await, StatusCode::OK).await;
    assert!(items(&page).is_empty(), "{page}");
    assert_eq!(page["page_info"]["mode"], "offset");
    assert_eq!(page["page_info"]["total"], 0);

    let user_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let auth_event = NewAuthEvent {
        event_type: "auth.admin_access_denied".into(),
        channel: "admin".into(),
        user_id: Some(user_id),
        identifier_attempted: Some("someone@x.test".into()),
        session_id: Some(session_id),
        actor: Some("someone".into()),
        outcome: "failure".into(),
        failure_reason: Some("no_admin_perm".into()),
        ip: Some("203.0.113.7".parse().unwrap()),
        user_agent: Some("curl/8".into()),
        forwarded_chain: Some("203.0.113.7".into()),
        request_id: Some("req-1".into()),
        ..event(1)
    };
    seed(&server, slice::from_ref(&auth_event)).await;

    let page = expect_json(superadmin_client.get(EVENTS).await, StatusCode::OK).await;
    assert_eq!(page["page_info"]["total"], 1);
    let row = &items(&page)[0];
    assert_eq!(row["id"], auth_event.id.to_string());
    assert_eq!(row["event_type"], "auth.admin_access_denied");
    assert_eq!(parse_ts(&row["occurred_at"]), auth_event.occurred_at);
    assert_eq!(row["channel"], "admin");
    assert_eq!(row["user_id"], user_id.to_string());
    assert_eq!(row["identifier_attempted"], "someone@x.test");
    assert_eq!(row["session_id"], session_id.to_string());
    assert_eq!(row["actor"], "someone");
    assert_eq!(row["outcome"], "failure");
    assert_eq!(row["failure_reason"], "no_admin_perm");
    assert_eq!(row["ip"], "203.0.113.7");
    assert_eq!(row["user_agent"], "curl/8");
    for key in ["country", "city", "os", "browser"] {
        assert_eq!(
            row.get(key),
            Some(&Value::Null),
            "富化列 {key} 应存在且为 null: {row}"
        );
    }
    // 写模型内部字段不外泄。
    for key in ["auth_method", "forwarded_chain", "request_id", "event_seq"] {
        assert!(row.get(key).is_none(), "{key} 不应出现在读模型里: {row}");
    }
}

/// 同 event_seq 重投(projector 至少一次投递)只落一行。
#[tokio::test]
async fn duplicate_event_seq_is_listed_once() {
    let server = TestServer::start().await;
    seed(&server, &[event(7)]).await;
    assert!(
        !server.auth_events.insert(&event(7)).await.unwrap(),
        "同 seq 重投应被幂等吞掉"
    );
    let page = expect_json(superadmin(&server).get(EVENTS).await, StatusCode::OK).await;
    assert_eq!(items(&page).len(), 1, "{page}");
}

/// 按 id(v7)倒序;offset 分页:total / total_pages / 越界空页 / with_total=false 不算总数。
#[tokio::test]
async fn list_newest_first_with_offset_pagination() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let ids_ascending = ascending_ids(5);
    let events: Vec<_> = ids_ascending
        .iter()
        .enumerate()
        .map(|(i, id)| NewAuthEvent {
            id: *id,
            ..event(i as i64 + 1)
        })
        .collect();
    seed(&server, &events).await;
    let newest_first: Vec<String> = id_strings(&ids_ascending).into_iter().rev().collect();

    let page = expect_json(superadmin_client.get(EVENTS).await, StatusCode::OK).await;
    assert_eq!(ids(&page), newest_first, "应按 id DESC(新的在前)");

    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?page=1&size=2"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&page), newest_first[0..2]);
    assert_eq!(page["page_info"]["mode"], "offset");
    assert_eq!(page["page_info"]["page"], 1);
    assert_eq!(page["page_info"]["size"], 2);
    assert_eq!(page["page_info"]["total"], 5);
    assert_eq!(page["page_info"]["total_pages"], 3);

    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?page=3&size=2"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&page), newest_first[4..5]);

    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?page=4&size=2"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(items(&page).is_empty(), "越界页应为空: {page}");
    assert_eq!(page["page_info"]["total"], 5);

    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?page=1&size=2&with_total=false"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(items(&page).len(), 2);
    assert_eq!(
        page["page_info"]["total"],
        Value::Null,
        "with_total=false 不算总数: {page}"
    );
}

/// cursor 模式:空 cursor= 为首页,沿 next_cursor 走完全部,末页 has_more=false 且无 next_cursor。
#[tokio::test]
async fn list_cursor_pagination_walks_all_pages() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let ids_ascending = ascending_ids(5);
    let events: Vec<_> = ids_ascending
        .iter()
        .enumerate()
        .map(|(i, id)| NewAuthEvent {
            id: *id,
            ..event(i as i64 + 1)
        })
        .collect();
    seed(&server, &events).await;
    let newest_first: Vec<String> = id_strings(&ids_ascending).into_iter().rev().collect();

    let mut seen = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;
    loop {
        let page = expect_json(
            superadmin_client
                .get(&format!("{EVENTS}?cursor={cursor}&size=2"))
                .await,
            StatusCode::OK,
        )
        .await;
        pages += 1;
        assert_eq!(page["page_info"]["mode"], "cursor", "{page}");
        assert_eq!(page["page_info"]["limit"], 2);
        seen.extend(ids(&page));
        if page["page_info"]["has_more"] == true {
            cursor = page["page_info"]["next_cursor"]
                .as_str()
                .expect("has_more 时应给 next_cursor")
                .to_owned();
        } else {
            assert_eq!(
                page["page_info"]["next_cursor"],
                Value::Null,
                "末页不应有 next_cursor: {page}"
            );
            break;
        }
        assert!(pages < 10, "cursor 翻页不收敛");
    }
    assert_eq!(pages, 3);
    assert_eq!(seen, newest_first, "cursor 翻页应不重不漏、保持倒序");
}

/// 分页参数错误:page 与 cursor 同传 → 422 validation;坏 cursor → 400 bad_request;size 越界 clamp 到 [1,100]。
#[tokio::test]
async fn list_pagination_param_errors() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    for query in ["page=1&cursor=", "page=2&cursor=abc"] {
        expect_error(
            superadmin_client.get(&format!("{EVENTS}?{query}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        superadmin_client
            .get(&format!("{EVENTS}?cursor=!!!not-a-cursor"))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin_client.get(&format!("{EVENTS}?page=abc")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;

    let page = expect_json(
        superadmin_client.get(&format!("{EVENTS}?size=1000")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        page["page_info"]["size"], 100,
        "size 上限 clamp 到 100: {page}"
    );
    let page = expect_json(
        superadmin_client.get(&format!("{EVENTS}?size=0")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(page["page_info"]["size"], 1, "size 下限 clamp 到 1: {page}");
}

// ───────────────────────────── GET /auth-events:过滤 ─────────────────────────────

/// event_type / outcome 过滤,单用与组合(AND)。
#[tokio::test]
async fn list_filters_by_event_type_and_outcome() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let ok = event(1);
    let bad = failed(2, "bad_password");
    let refreshed = NewAuthEvent {
        event_type: "auth.refreshed".into(),
        ..event(3)
    };
    let denied = NewAuthEvent {
        event_type: "auth.admin_access_denied".into(),
        outcome: "failure".into(),
        failure_reason: Some("no_admin_perm".into()),
        channel: "admin".into(),
        ..event(4)
    };
    seed(
        &server,
        &[ok.clone(), bad.clone(), refreshed.clone(), denied.clone()],
    )
    .await;

    let sorted = |mut values: Vec<String>| {
        values.sort();
        values
    };
    let get_ids = |query: &'static str| {
        let superadmin_client = superadmin_client.clone();
        async move {
            sorted(ids(&expect_json(
                superadmin_client.get(&format!("{EVENTS}?{query}")).await,
                StatusCode::OK,
            )
            .await))
        }
    };

    assert_eq!(
        get_ids("event_type=auth.login_failed").await,
        vec![bad.id.to_string()]
    );
    assert_eq!(
        get_ids("event_type=auth.refreshed").await,
        vec![refreshed.id.to_string()]
    );
    assert_eq!(
        get_ids("outcome=failure").await,
        sorted(vec![bad.id.to_string(), denied.id.to_string()])
    );
    assert_eq!(
        get_ids("outcome=success").await,
        sorted(vec![ok.id.to_string(), refreshed.id.to_string()])
    );
    assert_eq!(
        get_ids("event_type=auth.admin_access_denied&outcome=failure").await,
        vec![denied.id.to_string()]
    );
    assert!(
        get_ids("event_type=auth.refreshed&outcome=failure")
            .await
            .is_empty(),
        "组合过滤是 AND"
    );
    // 闭集里合法但无数据的类型 → 200 空(不是 400)。
    assert!(get_ids("event_type=auth.account_deleted").await.is_empty());
}

/// 闭集外的 event_type / outcome → 400 bad_request(而非静默空结果)。
#[tokio::test]
async fn list_unknown_enum_filter_is_400() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    for query in [
        "event_type=login_failed",
        "event_type=auth.nope",
        "outcome=maybe",
        "outcome=SUCCESS",
    ] {
        expect_error(
            superadmin_client.get(&format!("{EVENTS}?{query}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

/// q 联合模糊搜:actor / identifier_attempted / ip 文本子串,大小写不敏感;空白 q = 不搜。
#[tokio::test]
async fn list_q_searches_actor_identifier_and_ip() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let alice = NewAuthEvent {
        actor: Some("alice".into()),
        ip: Some("10.1.1.1".parse().unwrap()),
        ..event(10)
    };
    let bob = NewAuthEvent {
        actor: Some("bob".into()),
        identifier_attempted: Some("Bob@Example.com".into()),
        ip: Some("10.2.2.2".parse().unwrap()),
        ..failed(11, "bad_password")
    };
    seed(&server, &[alice, bob]).await;

    let actors = |query: &'static str| {
        let superadmin_client = superadmin_client.clone();
        async move {
            let mut names = field(
                &expect_json(
                    superadmin_client.get(&format!("{EVENTS}?q={query}")).await,
                    StatusCode::OK,
                )
                .await,
                "actor",
            );
            names.sort();
            names
        }
    };
    assert_eq!(actors("alic").await, vec!["alice"], "actor 子串");
    assert_eq!(actors("ALIC").await, vec!["alice"], "大小写不敏感");
    assert_eq!(actors("10.2").await, vec!["bob"], "ip 子串");
    assert_eq!(
        actors("example.COM").await,
        vec!["bob"],
        "identifier_attempted 子串,大小写不敏感"
    );
    assert_eq!(actors("10.").await, vec!["alice", "bob"]);
    assert!(actors("carol").await.is_empty());
    assert_eq!(
        actors("%20%20").await,
        vec!["alice", "bob"],
        "空白 q 视同不搜"
    );
    // q 与其它过滤 AND 组合。
    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?q=10.&outcome=failure"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(field(&page, "actor"), vec!["bob"]);
}

/// ip 精确过滤(不是子串);非法 ip → 400 bad_request。
#[tokio::test]
async fn list_ip_exact_filter() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let exact_match = NewAuthEvent {
        ip: Some("10.0.0.1".parse().unwrap()),
        ..event(1)
    };
    let prefix_sibling = NewAuthEvent {
        ip: Some("10.0.0.10".parse().unwrap()),
        ..event(2)
    };
    let ipv6 = NewAuthEvent {
        ip: Some("2001:db8::1".parse().unwrap()),
        ..event(3)
    };
    let none = event(4);
    seed(
        &server,
        &[exact_match.clone(), prefix_sibling, ipv6.clone(), none],
    )
    .await;

    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?ip=10.0.0.1"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        ids(&page),
        vec![exact_match.id.to_string()],
        "精确匹配,不应命中 10.0.0.10"
    );
    // IPv6 规范化比较:展开写法也命中。
    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?ip=2001:0db8:0:0:0:0:0:0001"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&page), vec![ipv6.id.to_string()]);
    assert_eq!(items(&page)[0]["ip"], "2001:db8::1");
    let page = expect_json(
        superadmin_client
            .get(&format!("{EVENTS}?ip=10.9.9.9"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(items(&page).is_empty());

    for bad in ["10.0.0", "not-an-ip", "10.0.0.256"] {
        expect_error(
            superadmin_client.get(&format!("{EVENTS}?ip={bad}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

/// 时间范围:[from, to) —— from 含、to 不含;单边也可;非法时间 → 400 bad_request。
#[tokio::test]
async fn list_time_range_from_inclusive_to_exclusive() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let base = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    let at = |sequence: i64, occurred_at: OffsetDateTime| NewAuthEvent {
        occurred_at,
        ..event(sequence)
    };
    let before = at(1, base - Duration::seconds(1));
    let on_from = at(2, base);
    let mid = at(3, base + Duration::minutes(30));
    let on_to = at(4, base + Duration::hours(1));
    seed(
        &server,
        &[before.clone(), on_from.clone(), mid.clone(), on_to.clone()],
    )
    .await;

    let ranged = |query: String| {
        let superadmin_client = superadmin_client.clone();
        async move {
            let mut event_ids = ids(&expect_json(
                superadmin_client.get(&format!("{EVENTS}?{query}")).await,
                StatusCode::OK,
            )
            .await);
            event_ids.sort();
            event_ids
        }
    };
    let sorted = |events: &[&NewAuthEvent]| {
        let mut event_ids: Vec<String> = events.iter().map(|e| e.id.to_string()).collect();
        event_ids.sort();
        event_ids
    };

    let from = query_timestamp(base);
    let to = query_timestamp(base + Duration::hours(1));
    assert_eq!(
        ranged(format!("from={from}&to={to}")).await,
        sorted(&[&on_from, &mid])
    );
    assert_eq!(
        ranged(format!("from={from}")).await,
        sorted(&[&on_from, &mid, &on_to])
    );
    assert_eq!(
        ranged(format!("to={to}")).await,
        sorted(&[&before, &on_from, &mid])
    );
    // 带非 UTC 偏移的同一时刻,结果不变。
    let offset = UtcOffset::from_hms(8, 0, 0).unwrap();
    assert_eq!(
        ranged(format!(
            "from={}&to={}",
            query_timestamp(base.to_offset(offset)),
            query_timestamp((base + Duration::hours(1)).to_offset(offset))
        ))
        .await,
        sorted(&[&on_from, &mid])
    );

    for bad in [
        "from=yesterday",
        "to=2026-13-01T00:00:00Z",
        "from=2026-11-01",
    ] {
        expect_error(
            superadmin_client.get(&format!("{EVENTS}?{bad}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

// ───────────────────────────── GET /users/{id}/auth-events ─────────────────────────────

/// 单用户历史只含该用户的行(不泄露别人的 / 匿名失败行);过滤与分页照常生效;
/// 不存在的用户 → 200 空页(过滤结果,不是 404)。
#[tokio::test]
async fn user_auth_events_only_returns_that_users_rows() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let alice = Uuid::now_v7();
    let bob = Uuid::now_v7();
    let alice_login = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        ..event(1)
    };
    let alice_logout = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        event_type: "auth.logged_out".into(),
        ..event(2)
    };
    let alice_failure = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        ..failed(3, "bad_password")
    };
    let bob_login = NewAuthEvent {
        user_id: Some(bob),
        actor: Some("bob".into()),
        ..event(4)
    };
    let anonymous_failure = NewAuthEvent {
        identifier_attempted: Some("alice".into()),
        ..failed(5, "unknown_user")
    };
    seed(
        &server,
        &[
            alice_login,
            alice_logout.clone(),
            alice_failure.clone(),
            bob_login.clone(),
            anonymous_failure,
        ],
    )
    .await;

    let page = expect_json(
        superadmin_client.get(&user_events(alice)).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(items(&page).len(), 3, "{page}");
    assert!(
        items(&page)
            .iter()
            .all(|e| e["user_id"] == alice.to_string()),
        "只应有 alice 的行: {page}"
    );
    assert_eq!(page["page_info"]["total"], 3);

    let page = expect_json(
        superadmin_client.get(&user_events(bob)).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&page), vec![bob_login.id.to_string()]);

    // 过滤在单用户范围内生效。
    let page = expect_json(
        superadmin_client
            .get(&format!(
                "{}?event_type=auth.logged_out",
                user_events(alice)
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&page), vec![alice_logout.id.to_string()]);
    let page = expect_json(
        superadmin_client
            .get(&format!("{}?outcome=failure", user_events(alice)))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        ids(&page),
        vec![alice_failure.id.to_string()],
        "匿名失败行(identifier=alice)不属于 alice"
    );
    // q 不能把范围扩到别的用户。
    let page = expect_json(
        superadmin_client
            .get(&format!("{}?q=bob", user_events(alice)))
            .await,
        StatusCode::OK,
    )
    .await;
    assert!(items(&page).is_empty(), "q 不应越出单用户范围: {page}");

    // 分页。
    let page = expect_json(
        superadmin_client
            .get(&format!("{}?page=2&size=2", user_events(alice)))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(items(&page).len(), 1);
    assert_eq!(page["page_info"]["total"], 3);
    assert_eq!(page["page_info"]["total_pages"], 2);

    // 没有任何事件的用户 → 200 空页。
    let page = expect_json(
        superadmin_client.get(&user_events(Uuid::now_v7())).await,
        StatusCode::OK,
    )
    .await;
    assert!(items(&page).is_empty());
    assert_eq!(page["page_info"]["total"], 0);
}

/// 路径 id 不是 UUID → 400 bad_request;查询参数错误与全局列表同口径。
#[tokio::test]
async fn user_auth_events_param_errors() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    expect_error(
        superadmin_client.get(&user_events("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        superadmin_client.get(&user_events(123)).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let path = user_events(Uuid::now_v7());
    expect_error(
        superadmin_client
            .get(&format!("{path}?page=1&cursor="))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        superadmin_client
            .get(&format!("{path}?event_type=auth.bogus"))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── GET /auth-events/stats ─────────────────────────────

/// 显式区间 [from, to) 的全部聚合:小时桶(两端整点含、零填充)、reasons / types / top_ips、KPI 与环比。
#[tokio::test]
async fn stats_aggregates_explicit_window() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let hour0 = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    let hour1 = hour0 + Duration::hours(1);
    let hour2 = hour0 + Duration::hours(2);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    let success = NewAuthEvent {
        occurred_at: hour0 + Duration::minutes(5),
        ip: Some(ip1),
        ..event(1)
    };
    let failure1 = NewAuthEvent {
        occurred_at: hour0 + Duration::minutes(10),
        ip: Some(ip1),
        ..failed(2, "bad_password")
    };
    let failure2 = NewAuthEvent {
        occurred_at: hour1 + Duration::minutes(5),
        ip: Some(ip2),
        ..failed(3, "unknown_user")
    };
    let failure3 = NewAuthEvent {
        occurred_at: hour1 + Duration::minutes(6),
        ip: Some(ip2),
        event_type: "auth.admin_access_denied".into(),
        channel: "admin".into(),
        ..failed(4, "no_admin_perm")
    };
    // 正好在 to 上:不计入(to 不含)。
    let on_to = NewAuthEvent {
        occurred_at: hour2,
        ip: Some("10.0.0.3".parse().unwrap()),
        ..event(5)
    };
    // 上一个等长窗口 [hour0-2h, hour0) 的 1 条失败,喂环比分母。
    let previous = NewAuthEvent {
        occurred_at: hour0 - Duration::minutes(30),
        ..failed(6, "bad_password")
    };
    seed(
        &server,
        &[success, failure1, failure2, failure3, on_to, previous],
    )
    .await;

    let stats = expect_json(
        superadmin_client
            .get(&format!(
                "{STATS}?from={}&to={}",
                query_timestamp(hour0),
                query_timestamp(hour2)
            ))
            .await,
        StatusCode::OK,
    )
    .await;

    // activity:hour0 / hour1 / hour2 三个桶(generate_series 两端含),hour2 桶为 0(on_to 被排除)。
    let activity = stats["activity"].as_array().unwrap();
    let buckets: Vec<(OffsetDateTime, i64, i64)> = activity
        .iter()
        .map(|bucket| {
            (
                parse_ts(&bucket["t"]),
                bucket["success"].as_i64().unwrap(),
                bucket["failure"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        buckets,
        vec![(hour0, 1, 1), (hour1, 0, 2), (hour2, 0, 0)],
        "{stats}"
    );

    // reasons:失败原因计数(同计数的顺序不定,按集合比)。
    let mut reasons: Vec<(String, i64)> = stats["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reason| {
            (
                reason["key"].as_str().unwrap().to_owned(),
                reason["count"].as_i64().unwrap(),
            )
        })
        .collect();
    reasons.sort();
    assert_eq!(
        reasons,
        vec![
            ("bad_password".to_owned(), 1),
            ("no_admin_perm".to_owned(), 1),
            ("unknown_user".to_owned(), 1)
        ]
    );

    // types:按计数降序,login_failed(2)在首。
    let types = stats["types"].as_array().unwrap();
    assert_eq!(types[0]["key"], "auth.login_failed");
    assert_eq!(types[0]["count"], 2);
    let mut rest: Vec<(String, i64)> = types[1..]
        .iter()
        .map(|type_count| {
            (
                type_count["key"].as_str().unwrap().to_owned(),
                type_count["count"].as_i64().unwrap(),
            )
        })
        .collect();
    rest.sort();
    assert_eq!(
        rest,
        vec![
            ("auth.admin_access_denied".to_owned(), 1),
            ("auth.login_succeeded".to_owned(), 1)
        ]
    );

    // top_ips:按失败数降序(10.0.0.3 在区间外不出现)。
    let top: Vec<(String, i64, i64)> = stats["top_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|ip_stat| {
            (
                ip_stat["ip"].as_str().unwrap().to_owned(),
                ip_stat["failures"].as_i64().unwrap(),
                ip_stat["total"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        top,
        vec![("10.0.0.2".to_owned(), 2, 2), ("10.0.0.1".to_owned(), 1, 2)]
    );

    // KPI:当前 4 条 / 3 失败 / 2 个 IP;上窗 1 条 / 1 失败。
    let kpi = &stats["kpi"];
    assert_eq!(kpi["total_events"], 4);
    assert_eq!(kpi["failed_count"], 3);
    assert_eq!(kpi["unique_ips"], 2);
    approx(&kpi["success_rate"], 0.25);
    approx(&kpi["total_delta"], 3.0); // (4-1)/1
    approx(&kpi["failed_delta"], 2.0); // (3-1)/1
}

/// 缺省区间 = 最近 24h:25 个小时桶;24h 外的事件只进环比分母。
#[tokio::test]
async fn stats_default_window_is_last_24h() {
    let server = TestServer::start().await;
    let now = OffsetDateTime::now_utc();
    seed(
        &server,
        &[
            NewAuthEvent {
                occurred_at: now - Duration::hours(1),
                ..event(1)
            },
            NewAuthEvent {
                occurred_at: now - Duration::hours(25),
                ..failed(2, "bad_password")
            },
            NewAuthEvent {
                occurred_at: now - Duration::hours(60),
                ..event(3)
            },
        ],
    )
    .await;
    let stats = expect_json(superadmin(&server).get(STATS).await, StatusCode::OK).await;
    let activity = stats["activity"].as_array().unwrap();
    assert_eq!(
        activity.len(),
        25,
        "floor(now-24h)..=floor(now) 共 25 个小时桶"
    );
    assert!(
        activity.iter().all(|b| parse_ts(&b["t"]).minute() == 0),
        "桶对齐整点"
    );
    let success_total: i64 = activity
        .iter()
        .map(|b| b["success"].as_i64().unwrap())
        .sum();
    assert_eq!(success_total, 1);
    let kpi = &stats["kpi"];
    assert_eq!(kpi["total_events"], 1);
    assert_eq!(kpi["failed_count"], 0);
    approx(&kpi["success_rate"], 1.0);
    approx(&kpi["total_delta"], 0.0); // (1-1)/1
    approx(&kpi["failed_delta"], -1.0); // (0-1)/1
}

/// 空窗口:各维度为空数组、KPI 为 0,success_rate 记 1.0,环比无基数记 0.0(不出 NaN/∞)。
#[tokio::test]
async fn stats_empty_window_defaults() {
    let server = TestServer::start().await;
    let window_start = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(5);
    let stats = expect_json(
        superadmin(&server)
            .get(&format!(
                "{STATS}?from={}&to={}",
                query_timestamp(window_start),
                query_timestamp(window_start + Duration::hours(2))
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let activity = stats["activity"].as_array().unwrap();
    assert_eq!(activity.len(), 3);
    assert!(activity
        .iter()
        .all(|b| b["success"] == 0 && b["failure"] == 0));
    for key in ["reasons", "types", "top_ips"] {
        assert_eq!(
            stats[key],
            serde_json::json!([]),
            "{key} 应为空数组: {stats}"
        );
    }
    let kpi = &stats["kpi"];
    assert_eq!(kpi["total_events"], 0);
    assert_eq!(kpi["failed_count"], 0);
    assert_eq!(kpi["unique_ips"], 0);
    approx(&kpi["success_rate"], 1.0);
    approx(&kpi["total_delta"], 0.0);
    approx(&kpi["failed_delta"], 0.0);
}

/// from >= to 不报错,退化成 [to-1h, to) 的 1 小时窗口。
#[tokio::test]
async fn stats_inverted_window_degrades_to_one_hour() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    let base_hour = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    seed(
        &server,
        &[
            NewAuthEvent {
                occurred_at: base_hour + Duration::minutes(30),
                ..event(1)
            },
            NewAuthEvent {
                occurred_at: base_hour + Duration::minutes(90),
                ..failed(2, "bad_password")
            },
        ],
    )
    .await;
    let to = base_hour + Duration::hours(2);
    for from in [to, to + Duration::hours(3)] {
        let stats = expect_json(
            superadmin_client
                .get(&format!(
                    "{STATS}?from={}&to={}",
                    query_timestamp(from),
                    query_timestamp(to)
                ))
                .await,
            StatusCode::OK,
        )
        .await;
        let bucket_starts: Vec<OffsetDateTime> = stats["activity"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| parse_ts(&b["t"]))
            .collect();
        assert_eq!(
            bucket_starts,
            vec![base_hour + Duration::hours(1), to],
            "{stats}"
        );
        assert_eq!(
            stats["kpi"]["total_events"], 1,
            "只含 [to-1h, to) 内的那条: {stats}"
        );
        assert_eq!(stats["kpi"]["failed_count"], 1);
    }
}

/// 区间上限 clamp 到 92 天(防巨量小时桶):from 被抬到 to-92d。
#[tokio::test]
async fn stats_window_clamped_to_92_days() {
    let server = TestServer::start().await;
    let to = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(1);
    seed(
        &server,
        &[
            NewAuthEvent {
                occurred_at: to - Duration::days(91),
                ..event(1)
            },
            NewAuthEvent {
                occurred_at: to - Duration::days(100),
                ..event(2)
            },
        ],
    )
    .await;
    let stats = expect_json(
        superadmin(&server)
            .get(&format!(
                "{STATS}?from={}&to={}",
                query_timestamp(to - Duration::days(200)),
                query_timestamp(to)
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let activity = stats["activity"].as_array().unwrap();
    assert_eq!(activity.len(), 92 * 24 + 1, "92 天的小时桶(两端含)");
    assert_eq!(parse_ts(&activity[0]["t"]), to - Duration::days(92));
    assert_eq!(stats["kpi"]["total_events"], 1, "100 天前的那条被 clamp 掉");
}

/// 半小时制时区的区间(+05:30):桶仍对齐 UTC 整点,事件照样落桶(不全零)。
#[tokio::test]
async fn stats_fractional_offset_buckets_align_to_utc_hour() {
    let server = TestServer::start().await;
    let hour = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(3);
    seed(
        &server,
        &[NewAuthEvent {
            occurred_at: hour + Duration::minutes(5),
            ..event(1)
        }],
    )
    .await;
    let offset = UtcOffset::from_hms(5, 30, 0).unwrap();
    let from = (hour - Duration::minutes(30)).to_offset(offset);
    let to = (hour + Duration::hours(1)).to_offset(offset);
    let stats = expect_json(
        superadmin(&server)
            .get(&format!(
                "{STATS}?from={}&to={}",
                query_timestamp(from),
                query_timestamp(to)
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let activity = stats["activity"].as_array().unwrap();
    assert!(
        activity.iter().all(|b| parse_ts(&b["t"]).minute() == 0),
        "桶必须对齐整点: {stats}"
    );
    let success_total: i64 = activity
        .iter()
        .map(|b| b["success"].as_i64().unwrap())
        .sum();
    assert_eq!(success_total, 1, "{stats}");
    assert_eq!(stats["kpi"]["total_events"], 1);
}

/// top_ips 最多 6 个,按失败数降序。
#[tokio::test]
async fn stats_top_ips_capped_at_six() {
    let server = TestServer::start().await;
    let window_start = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(4);
    let mut events = Vec::new();
    let mut sequence = 0;
    for i in 1..=8u8 {
        for _ in 0..i {
            sequence += 1;
            events.push(NewAuthEvent {
                occurred_at: window_start + Duration::minutes(i64::from(i)),
                ip: Some(format!("10.0.1.{i}").parse().unwrap()),
                ..failed(sequence, "bad_password")
            });
        }
    }
    seed(&server, &events).await;
    let stats = expect_json(
        superadmin(&server)
            .get(&format!(
                "{STATS}?from={}&to={}",
                query_timestamp(window_start),
                query_timestamp(window_start + Duration::hours(1))
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let top: Vec<(String, i64)> = stats["top_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|ip_stat| {
            (
                ip_stat["ip"].as_str().unwrap().to_owned(),
                ip_stat["failures"].as_i64().unwrap(),
            )
        })
        .collect();
    let want: Vec<(String, i64)> = (3..=8).rev().map(|i| (format!("10.0.1.{i}"), i)).collect();
    assert_eq!(top, want);
    assert_eq!(
        stats["kpi"]["unique_ips"], 8,
        "unique_ips 不受 top 截断影响"
    );
    assert_eq!(stats["kpi"]["total_events"], 36);
}

/// 非法时间参数 → 400 bad_request。
#[tokio::test]
async fn stats_invalid_time_is_400() {
    let server = TestServer::start().await;
    let superadmin_client = superadmin(&server);
    for query in ["from=now", "to=2026-11-23", "from=2026-11-23T25:00:00Z"] {
        expect_error(
            superadmin_client.get(&format!("{STATS}?{query}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

// ───────────────────────────── GET /auth-events/stream(SSE) ─────────────────────────────

/// 开流 → 发布 → 收到 `event: auth_event` 帧,data 是 AuthEventRow JSON;多帧按发布顺序到达。
#[tokio::test]
async fn sse_pushes_auth_event_frames() {
    let server = TestServer::start().await;
    let superadmin_client = server.login_admin(SUPERADMIN, PASSWORD).await; // 浏览器式 cookie 会话(EventSource 的真实用法)
    let response = superadmin_client.get(STREAM).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"),
        "{:?}",
        response.headers()
    );
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    let user_id = Uuid::now_v7();
    let first = NewAuthEvent {
        user_id: Some(user_id),
        actor: Some("alice".into()),
        channel: "admin".into(),
        ip: Some("198.51.100.9".parse().unwrap()),
        user_agent: Some("ua/1".into()),
        ..failed(1, "bad_password")
    };
    let second = NewAuthEvent {
        event_type: "auth.logged_out".into(),
        ..event(2)
    };
    server.auth_bus.publish(to_row(&first).unwrap());
    server.auth_bus.publish(to_row(&second).unwrap());

    let (name, data) = parse_frame(&next_sse_event(&mut stream, &mut buffer).await);
    assert_eq!(name, "auth_event");
    assert_eq!(data["id"], first.id.to_string());
    assert_eq!(data["event_type"], "auth.login_failed");
    assert_eq!(parse_ts(&data["occurred_at"]), first.occurred_at);
    assert_eq!(data["channel"], "admin");
    assert_eq!(data["user_id"], user_id.to_string());
    assert_eq!(data["actor"], "alice");
    assert_eq!(data["outcome"], "failure");
    assert_eq!(data["failure_reason"], "bad_password");
    assert_eq!(data["ip"], "198.51.100.9");
    assert_eq!(data["user_agent"], "ua/1");
    for key in [
        "identifier_attempted",
        "session_id",
        "country",
        "city",
        "os",
        "browser",
    ] {
        assert_eq!(
            data.get(key),
            Some(&Value::Null),
            "{key} 应存在且为 null: {data}"
        );
    }

    let (name, data) = parse_frame(&next_sse_event(&mut stream, &mut buffer).await);
    assert_eq!(name, "auth_event");
    assert_eq!(data["id"], second.id.to_string(), "按发布顺序到达");
    assert_eq!(data["event_type"], "auth.logged_out");
    assert_eq!(data["outcome"], "success");
    assert_eq!(data["failure_reason"], Value::Null);
}

/// best-effort 无回放:订阅前发布的事件收不到;同时在线的多个订阅者各自收到(广播)。
#[tokio::test]
async fn sse_no_replay_and_broadcasts_to_all_subscribers() {
    let server = TestServer::start().await;
    let early = event(1);
    server.auth_bus.publish(to_row(&early).unwrap()); // 此时无订阅者

    let first_response = superadmin(&server).get(STREAM).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    let second_response = superadmin(&server).get(STREAM).await;
    assert_eq!(second_response.status(), StatusCode::OK);
    let (mut first_stream, mut second_stream) = (
        first_response.bytes_stream(),
        second_response.bytes_stream(),
    );
    let (mut first_buffer, mut second_buffer) = (String::new(), String::new());

    let live = failed(2, "unknown_user");
    server.auth_bus.publish(to_row(&live).unwrap());
    for (stream, buffer) in [
        (&mut first_stream, &mut first_buffer),
        (&mut second_stream, &mut second_buffer),
    ] {
        let (name, data) = parse_frame(&next_sse_event(stream, buffer).await);
        assert_eq!(name, "auth_event");
        assert_eq!(data["id"], live.id.to_string(), "订阅前的事件不应回放");
        assert_eq!(data["failure_reason"], "unknown_user");
    }
}

// ───────────────────────────── 后端未接线 ─────────────────────────────

/// 审计后端未接线(非 idm 进程 / 无 search 库)→ 404 not_found;授权闸仍在前(无 audit:read 照样 403)。
#[tokio::test]
async fn no_audit_backend_is_404_after_authz() {
    let server = TestServer::start_with(|state| state.auth_audit = None).await;
    let superadmin_client = superadmin(&server);
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    for path in [
        EVENTS.to_owned(),
        STATS.to_owned(),
        user_events(Uuid::now_v7()),
    ] {
        expect_error(
            superadmin_client.get(&path).await,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
        expect_error(admin.get(&path).await, StatusCode::FORBIDDEN, "forbidden").await;
    }
}

/// SSE 总线未接线(没有 projector 发布者)→ 404 not_found;授权闸仍在前。
#[tokio::test]
async fn no_event_bus_stream_is_404_after_authz() {
    let server = TestServer::start_with(|state| state.auth_events_bus = None).await;
    expect_error(
        superadmin(&server).get(STREAM).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let admin = server.login_admin(ADMIN, PASSWORD).await;
    expect_error(admin.get(STREAM).await, StatusCode::FORBIDDEN, "forbidden").await;
    // 列表 / 统计不依赖总线,照常可用。
    expect(superadmin(&server).get(EVENTS).await, StatusCode::OK).await;
}

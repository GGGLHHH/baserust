//! 认证审计(auth_audit)的**黑盒 HTTP 验收测试**:全局审计流 / 仪表盘统计 / SSE 实时推送 / 单用户历史。
//! 测试体不 import 任何 web 框架类型(换底座只换 `http_support::serve`)。与 `auth_audit_api.rs`(axum oneshot)
//! 覆盖同一组场景并补强(过滤 / 分页 / 统计口径 / SSE 帧)。
//!
//! 造数据口径:内存模式没有 projector(生产里它从 JetStream 投影落库再发 SSE),所以经**端口**造数据 ——
//! `s.auth_events`(`AuthEventRepo::insert`)写行、`s.auth_bus.publish` 推帧,再经 HTTP 断言。
//!
//! 授权口径(seed 策略):`/api/v1/admin` 组闸要 `admin:login`(admin + superadmin 皆持),
//! 四个端点内再 gate `users:admin`(仅 superadmin)。
//!
//! covers: GET /api/v1/admin/auth/auth-events
//! covers: GET /api/v1/admin/auth/auth-events/stats
//! covers: GET /api/v1/admin/auth/auth-events/stream
//! covers: GET /api/v1/admin/auth/users/{id}/auth-events

mod http_support;

use baserust::features::auth_audit::model::to_row;
use baserust::features::auth_audit::{AuthEventRepo, NewAuthEvent};
use baserust::kernel::authz::Perm;
use http_support::{
    expect, expect_error, expect_json, mint, next_sse_event, user_token, Client, TestServer, ADMIN,
    PASSWORD, SUPERADMIN,
};
use reqwest::StatusCode;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, Time, UtcOffset};
use uuid::Uuid;

const EV: &str = "/api/v1/admin/auth/auth-events";
const STATS: &str = "/api/v1/admin/auth/auth-events/stats";
const STREAM: &str = "/api/v1/admin/auth/auth-events/stream";

fn user_events(id: impl std::fmt::Display) -> String {
    format!("/api/v1/admin/auth/users/{id}/auth-events")
}

// ───────────────────────────── 帮手 ─────────────────────────────

/// 满权 superadmin 令牌会话(无 scope 收窄)。
fn superadmin(s: &TestServer) -> Client {
    s.bearer(&mint(Uuid::now_v7(), SUPERADMIN, &["superadmin"], vec![]))
}

/// 一条默认事件:前台密码登录成功、当前时刻、无用户 / 无 IP。各测试按需改字段。
fn ev(seq: i64) -> NewAuthEvent {
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
        event_seq: seq,
    }
}

/// 失败事件(登录失败 + 原因)。
fn failed(seq: i64, reason: &str) -> NewAuthEvent {
    NewAuthEvent {
        event_type: "auth.login_failed".into(),
        outcome: "failure".into(),
        failure_reason: Some(reason.into()),
        ..ev(seq)
    }
}

/// 经仓储端口落库(= 生产里 projector 的写入)。
async fn seed(s: &TestServer, events: &[NewAuthEvent]) {
    for e in events {
        assert!(
            s.auth_events.insert(e).await.unwrap(),
            "seq {} 应真插入",
            e.event_seq
        );
    }
}

/// n 个严格递增的 v7 id(列表按 id DESC 排序,测试据此推期望顺序)。
fn ascending_ids(n: usize) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = (0..n).map(|_| Uuid::now_v7()).collect();
    ids.sort();
    ids
}

/// UTC 整点(镜像服务端小时桶)。
fn floor_hour(t: OffsetDateTime) -> OffsetDateTime {
    let t = t.to_offset(UtcOffset::UTC);
    t.replace_time(Time::from_hms(t.hour(), 0, 0).unwrap())
}

/// RFC3339 → query 值(`+` 必须转义,否则被解成空格)。
fn q_ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap().replace('+', "%2B")
}

fn parse_ts(v: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        v.as_str().unwrap_or_else(|| panic!("不是时间串: {v}")),
        &Rfc3339,
    )
    .unwrap()
}

fn items(v: &Value) -> &Vec<Value> {
    v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("应有 items 数组: {v}"))
}

/// 列表里各行的 id(按响应顺序)。
fn ids(v: &Value) -> Vec<String> {
    items(v)
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_owned())
        .collect()
}

fn id_strs(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

/// 列表里各行某字段(字符串)的值。
fn field(v: &Value, key: &str) -> Vec<String> {
    items(v)
        .iter()
        .map(|e| e[key].as_str().unwrap_or("").to_owned())
        .collect()
}

fn approx(v: &Value, want: f64) {
    let got = v.as_f64().unwrap_or_else(|| panic!("不是数字: {v}"));
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
    let s = TestServer::start().await;
    let anon = s.anon();
    for path in [
        EV.to_owned(),
        STATS.to_owned(),
        STREAM.to_owned(),
        user_events(Uuid::now_v7()),
    ] {
        expect_error(
            anon.get(&path).await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }
}

/// 权限矩阵:普通用户(无 admin:login)被组闸挡 403;admin 能进后台但无 users:admin → 403;
/// 降权令牌(scope 不含 users:admin / 不含 admin:login)即便 role 是 superadmin 也 403。
#[tokio::test]
async fn all_endpoints_forbid_without_users_admin_403() {
    let s = TestServer::start().await;
    let user = s.bearer(&user_token().0);
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    let sa = Uuid::now_v7();
    let scoped_no_users_admin = s.bearer(&mint(
        sa,
        SUPERADMIN,
        &["superadmin"],
        vec![Perm::AdminLogin],
    ));
    let scoped_no_admin_login = s.bearer(&mint(
        sa,
        SUPERADMIN,
        &["superadmin"],
        vec![Perm::UsersAdmin],
    ));
    for path in [
        EV.to_owned(),
        STATS.to_owned(),
        STREAM.to_owned(),
        user_events(Uuid::now_v7()),
    ] {
        for (who, c) in [
            ("user", &user),
            ("admin", &admin),
            ("scope 缺 users:admin", &scoped_no_users_admin),
            ("scope 缺 admin:login", &scoped_no_admin_login),
        ] {
            let resp = c.get(&path).await;
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{who} 访问 {path} 应 403"
            );
            expect_error(resp, StatusCode::FORBIDDEN, "forbidden").await;
        }
    }
}

/// superadmin:cookie 会话(后台登录)与 scope 恰含 admin:login + users:admin 的降权令牌都能读。
#[tokio::test]
async fn superadmin_cookie_session_and_exact_scope_can_read() {
    let s = TestServer::start().await;
    let cookie = s.login_admin(SUPERADMIN, PASSWORD).await;
    let scoped = s.bearer(&mint(
        Uuid::now_v7(),
        SUPERADMIN,
        &["superadmin"],
        vec![Perm::AdminLogin, Perm::UsersAdmin],
    ));
    seed(&s, &[ev(1)]).await;
    for c in [&cookie, &scoped] {
        let v = expect_json(c.get(EV).await, StatusCode::OK).await;
        assert_eq!(items(&v).len(), 1, "{v}");
        expect(c.get(STATS).await, StatusCode::OK).await;
        expect(c.get(&user_events(Uuid::now_v7())).await, StatusCode::OK).await;
    }
}

// ───────────────────────────── GET /auth-events:形状 / 分页 ─────────────────────────────

/// 空库 → 200 空页(offset 模式,total 0);落一行后读回的行形状与写入一致(含富化列恒 null)。
#[tokio::test]
async fn list_returns_row_shape() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let v = expect_json(sa.get(EV).await, StatusCode::OK).await;
    assert!(items(&v).is_empty(), "{v}");
    assert_eq!(v["page_info"]["mode"], "offset");
    assert_eq!(v["page_info"]["total"], 0);

    let uid = Uuid::now_v7();
    let sid = Uuid::now_v7();
    let e = NewAuthEvent {
        event_type: "auth.admin_access_denied".into(),
        channel: "admin".into(),
        user_id: Some(uid),
        identifier_attempted: Some("someone@x.test".into()),
        session_id: Some(sid),
        actor: Some("someone".into()),
        outcome: "failure".into(),
        failure_reason: Some("no_admin_perm".into()),
        ip: Some("203.0.113.7".parse().unwrap()),
        user_agent: Some("curl/8".into()),
        forwarded_chain: Some("203.0.113.7".into()),
        request_id: Some("req-1".into()),
        ..ev(1)
    };
    seed(&s, std::slice::from_ref(&e)).await;

    let v = expect_json(sa.get(EV).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["total"], 1);
    let row = &items(&v)[0];
    assert_eq!(row["id"], e.id.to_string());
    assert_eq!(row["event_type"], "auth.admin_access_denied");
    assert_eq!(parse_ts(&row["occurred_at"]), e.occurred_at);
    assert_eq!(row["channel"], "admin");
    assert_eq!(row["user_id"], uid.to_string());
    assert_eq!(row["identifier_attempted"], "someone@x.test");
    assert_eq!(row["session_id"], sid.to_string());
    assert_eq!(row["actor"], "someone");
    assert_eq!(row["outcome"], "failure");
    assert_eq!(row["failure_reason"], "no_admin_perm");
    assert_eq!(row["ip"], "203.0.113.7");
    assert_eq!(row["user_agent"], "curl/8");
    for k in ["country", "city", "os", "browser"] {
        assert_eq!(
            row.get(k),
            Some(&Value::Null),
            "富化列 {k} 应存在且为 null: {row}"
        );
    }
    // 写模型内部字段不外泄。
    for k in ["auth_method", "forwarded_chain", "request_id", "event_seq"] {
        assert!(row.get(k).is_none(), "{k} 不应出现在读模型里: {row}");
    }
}

/// 同 event_seq 重投(projector 至少一次投递)只落一行。
#[tokio::test]
async fn duplicate_event_seq_is_listed_once() {
    let s = TestServer::start().await;
    seed(&s, &[ev(7)]).await;
    assert!(
        !s.auth_events.insert(&ev(7)).await.unwrap(),
        "同 seq 重投应被幂等吞掉"
    );
    let v = expect_json(superadmin(&s).get(EV).await, StatusCode::OK).await;
    assert_eq!(items(&v).len(), 1, "{v}");
}

/// 按 id(v7)倒序;offset 分页:total / total_pages / 越界空页 / with_total=false 不算总数。
#[tokio::test]
async fn list_newest_first_with_offset_pagination() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let ids_asc = ascending_ids(5);
    let events: Vec<_> = ids_asc
        .iter()
        .enumerate()
        .map(|(i, id)| NewAuthEvent {
            id: *id,
            ..ev(i as i64 + 1)
        })
        .collect();
    seed(&s, &events).await;
    let newest_first: Vec<String> = id_strs(&ids_asc).into_iter().rev().collect();

    let v = expect_json(sa.get(EV).await, StatusCode::OK).await;
    assert_eq!(ids(&v), newest_first, "应按 id DESC(新的在前)");

    let v = expect_json(sa.get(&format!("{EV}?page=1&size=2")).await, StatusCode::OK).await;
    assert_eq!(ids(&v), newest_first[0..2]);
    assert_eq!(v["page_info"]["mode"], "offset");
    assert_eq!(v["page_info"]["page"], 1);
    assert_eq!(v["page_info"]["size"], 2);
    assert_eq!(v["page_info"]["total"], 5);
    assert_eq!(v["page_info"]["total_pages"], 3);

    let v = expect_json(sa.get(&format!("{EV}?page=3&size=2")).await, StatusCode::OK).await;
    assert_eq!(ids(&v), newest_first[4..5]);

    let v = expect_json(sa.get(&format!("{EV}?page=4&size=2")).await, StatusCode::OK).await;
    assert!(items(&v).is_empty(), "越界页应为空: {v}");
    assert_eq!(v["page_info"]["total"], 5);

    let v = expect_json(
        sa.get(&format!("{EV}?page=1&size=2&with_total=false"))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(items(&v).len(), 2);
    assert_eq!(
        v["page_info"]["total"],
        Value::Null,
        "with_total=false 不算总数: {v}"
    );
}

/// cursor 模式:空 cursor= 为首页,沿 next_cursor 走完全部,末页 has_more=false 且无 next_cursor。
#[tokio::test]
async fn list_cursor_pagination_walks_all_pages() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let ids_asc = ascending_ids(5);
    let events: Vec<_> = ids_asc
        .iter()
        .enumerate()
        .map(|(i, id)| NewAuthEvent {
            id: *id,
            ..ev(i as i64 + 1)
        })
        .collect();
    seed(&s, &events).await;
    let newest_first: Vec<String> = id_strs(&ids_asc).into_iter().rev().collect();

    let mut seen = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;
    loop {
        let v = expect_json(
            sa.get(&format!("{EV}?cursor={cursor}&size=2")).await,
            StatusCode::OK,
        )
        .await;
        pages += 1;
        assert_eq!(v["page_info"]["mode"], "cursor", "{v}");
        assert_eq!(v["page_info"]["limit"], 2);
        seen.extend(ids(&v));
        if v["page_info"]["has_more"] == true {
            cursor = v["page_info"]["next_cursor"]
                .as_str()
                .expect("has_more 时应给 next_cursor")
                .to_owned();
        } else {
            assert_eq!(
                v["page_info"]["next_cursor"],
                Value::Null,
                "末页不应有 next_cursor: {v}"
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
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    for q in ["page=1&cursor=", "page=2&cursor=abc"] {
        expect_error(
            sa.get(&format!("{EV}?{q}")).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
        )
        .await;
    }
    expect_error(
        sa.get(&format!("{EV}?cursor=!!!not-a-cursor")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.get(&format!("{EV}?page=abc")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;

    let v = expect_json(sa.get(&format!("{EV}?size=1000")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["size"], 100, "size 上限 clamp 到 100: {v}");
    let v = expect_json(sa.get(&format!("{EV}?size=0")).await, StatusCode::OK).await;
    assert_eq!(v["page_info"]["size"], 1, "size 下限 clamp 到 1: {v}");
}

// ───────────────────────────── GET /auth-events:过滤 ─────────────────────────────

/// event_type / outcome 过滤,单用与组合(AND)。
#[tokio::test]
async fn list_filters_by_event_type_and_outcome() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let ok = ev(1);
    let bad = failed(2, "bad_password");
    let refreshed = NewAuthEvent {
        event_type: "auth.refreshed".into(),
        ..ev(3)
    };
    let denied = NewAuthEvent {
        event_type: "auth.admin_access_denied".into(),
        outcome: "failure".into(),
        failure_reason: Some("no_admin_perm".into()),
        channel: "admin".into(),
        ..ev(4)
    };
    seed(
        &s,
        &[ok.clone(), bad.clone(), refreshed.clone(), denied.clone()],
    )
    .await;

    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let get_ids = |q: &'static str| {
        let sa = sa.clone();
        async move {
            sorted(ids(&expect_json(
                sa.get(&format!("{EV}?{q}")).await,
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
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    for q in [
        "event_type=login_failed",
        "event_type=auth.nope",
        "outcome=maybe",
        "outcome=SUCCESS",
    ] {
        expect_error(
            sa.get(&format!("{EV}?{q}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

/// q 联合模糊搜:actor / identifier_attempted / ip 文本子串,大小写不敏感;空白 q = 不搜。
#[tokio::test]
async fn list_q_searches_actor_identifier_and_ip() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let alice = NewAuthEvent {
        actor: Some("alice".into()),
        ip: Some("10.1.1.1".parse().unwrap()),
        ..ev(10)
    };
    let bob = NewAuthEvent {
        actor: Some("bob".into()),
        identifier_attempted: Some("Bob@Example.com".into()),
        ip: Some("10.2.2.2".parse().unwrap()),
        ..failed(11, "bad_password")
    };
    seed(&s, &[alice, bob]).await;

    let actors = |q: &'static str| {
        let sa = sa.clone();
        async move {
            let mut a = field(
                &expect_json(sa.get(&format!("{EV}?q={q}")).await, StatusCode::OK).await,
                "actor",
            );
            a.sort();
            a
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
    let v = expect_json(
        sa.get(&format!("{EV}?q=10.&outcome=failure")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(field(&v, "actor"), vec!["bob"]);
}

/// ip 精确过滤(不是子串);非法 ip → 400 bad_request。
#[tokio::test]
async fn list_ip_exact_filter() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let a = NewAuthEvent {
        ip: Some("10.0.0.1".parse().unwrap()),
        ..ev(1)
    };
    let b = NewAuthEvent {
        ip: Some("10.0.0.10".parse().unwrap()),
        ..ev(2)
    };
    let v6 = NewAuthEvent {
        ip: Some("2001:db8::1".parse().unwrap()),
        ..ev(3)
    };
    let none = ev(4);
    seed(&s, &[a.clone(), b, v6.clone(), none]).await;

    let v = expect_json(sa.get(&format!("{EV}?ip=10.0.0.1")).await, StatusCode::OK).await;
    assert_eq!(
        ids(&v),
        vec![a.id.to_string()],
        "精确匹配,不应命中 10.0.0.10"
    );
    // IPv6 规范化比较:展开写法也命中。
    let v = expect_json(
        sa.get(&format!("{EV}?ip=2001:0db8:0:0:0:0:0:0001")).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&v), vec![v6.id.to_string()]);
    assert_eq!(items(&v)[0]["ip"], "2001:db8::1");
    let v = expect_json(sa.get(&format!("{EV}?ip=10.9.9.9")).await, StatusCode::OK).await;
    assert!(items(&v).is_empty());

    for bad in ["10.0.0", "not-an-ip", "10.0.0.256"] {
        expect_error(
            sa.get(&format!("{EV}?ip={bad}")).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        )
        .await;
    }
}

/// 时间范围:[from, to) —— from 含、to 不含;单边也可;非法时间 → 400 bad_request。
#[tokio::test]
async fn list_time_range_from_inclusive_to_exclusive() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let base = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    let at = |seq: i64, t: OffsetDateTime| NewAuthEvent {
        occurred_at: t,
        ..ev(seq)
    };
    let before = at(1, base - Duration::seconds(1));
    let on_from = at(2, base);
    let mid = at(3, base + Duration::minutes(30));
    let on_to = at(4, base + Duration::hours(1));
    seed(
        &s,
        &[before.clone(), on_from.clone(), mid.clone(), on_to.clone()],
    )
    .await;

    let ranged = |q: String| {
        let sa = sa.clone();
        async move {
            let mut v = ids(&expect_json(sa.get(&format!("{EV}?{q}")).await, StatusCode::OK).await);
            v.sort();
            v
        }
    };
    let sorted = |ids: &[&NewAuthEvent]| {
        let mut v: Vec<String> = ids.iter().map(|e| e.id.to_string()).collect();
        v.sort();
        v
    };

    let from = q_ts(base);
    let to = q_ts(base + Duration::hours(1));
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
    let off = UtcOffset::from_hms(8, 0, 0).unwrap();
    assert_eq!(
        ranged(format!(
            "from={}&to={}",
            q_ts(base.to_offset(off)),
            q_ts((base + Duration::hours(1)).to_offset(off))
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
            sa.get(&format!("{EV}?{bad}")).await,
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
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let alice = Uuid::now_v7();
    let bob = Uuid::now_v7();
    let a1 = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        ..ev(1)
    };
    let a2 = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        event_type: "auth.logged_out".into(),
        ..ev(2)
    };
    let a3 = NewAuthEvent {
        user_id: Some(alice),
        actor: Some("alice".into()),
        ..failed(3, "bad_password")
    };
    let b1 = NewAuthEvent {
        user_id: Some(bob),
        actor: Some("bob".into()),
        ..ev(4)
    };
    let anon = NewAuthEvent {
        identifier_attempted: Some("alice".into()),
        ..failed(5, "unknown_user")
    };
    seed(&s, &[a1, a2.clone(), a3.clone(), b1.clone(), anon]).await;

    let v = expect_json(sa.get(&user_events(alice)).await, StatusCode::OK).await;
    assert_eq!(items(&v).len(), 3, "{v}");
    assert!(
        items(&v).iter().all(|e| e["user_id"] == alice.to_string()),
        "只应有 alice 的行: {v}"
    );
    assert_eq!(v["page_info"]["total"], 3);

    let v = expect_json(sa.get(&user_events(bob)).await, StatusCode::OK).await;
    assert_eq!(ids(&v), vec![b1.id.to_string()]);

    // 过滤在单用户范围内生效。
    let v = expect_json(
        sa.get(&format!(
            "{}?event_type=auth.logged_out",
            user_events(alice)
        ))
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(ids(&v), vec![a2.id.to_string()]);
    let v = expect_json(
        sa.get(&format!("{}?outcome=failure", user_events(alice)))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        ids(&v),
        vec![a3.id.to_string()],
        "匿名失败行(identifier=alice)不属于 alice"
    );
    // q 不能把范围扩到别的用户。
    let v = expect_json(
        sa.get(&format!("{}?q=bob", user_events(alice))).await,
        StatusCode::OK,
    )
    .await;
    assert!(items(&v).is_empty(), "q 不应越出单用户范围: {v}");

    // 分页。
    let v = expect_json(
        sa.get(&format!("{}?page=2&size=2", user_events(alice)))
            .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(items(&v).len(), 1);
    assert_eq!(v["page_info"]["total"], 3);
    assert_eq!(v["page_info"]["total_pages"], 2);

    // 没有任何事件的用户 → 200 空页。
    let v = expect_json(sa.get(&user_events(Uuid::now_v7())).await, StatusCode::OK).await;
    assert!(items(&v).is_empty());
    assert_eq!(v["page_info"]["total"], 0);
}

/// 路径 id 不是 UUID → 400 bad_request;查询参数错误与全局列表同口径。
#[tokio::test]
async fn user_auth_events_param_errors() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    expect_error(
        sa.get(&user_events("not-a-uuid")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    expect_error(
        sa.get(&user_events(123)).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
    let p = user_events(Uuid::now_v7());
    expect_error(
        sa.get(&format!("{p}?page=1&cursor=")).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation",
    )
    .await;
    expect_error(
        sa.get(&format!("{p}?event_type=auth.bogus")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await;
}

// ───────────────────────────── GET /auth-events/stats ─────────────────────────────

/// 显式区间 [from, to) 的全部聚合:小时桶(两端整点含、零填充)、reasons / types / top_ips、KPI 与环比。
#[tokio::test]
async fn stats_aggregates_explicit_window() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let h0 = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    let h1 = h0 + Duration::hours(1);
    let h2 = h0 + Duration::hours(2);
    let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    let s1 = NewAuthEvent {
        occurred_at: h0 + Duration::minutes(5),
        ip: Some(ip1),
        ..ev(1)
    };
    let f1 = NewAuthEvent {
        occurred_at: h0 + Duration::minutes(10),
        ip: Some(ip1),
        ..failed(2, "bad_password")
    };
    let f2 = NewAuthEvent {
        occurred_at: h1 + Duration::minutes(5),
        ip: Some(ip2),
        ..failed(3, "unknown_user")
    };
    let f3 = NewAuthEvent {
        occurred_at: h1 + Duration::minutes(6),
        ip: Some(ip2),
        event_type: "auth.admin_access_denied".into(),
        channel: "admin".into(),
        ..failed(4, "no_admin_perm")
    };
    // 正好在 to 上:不计入(to 不含)。
    let on_to = NewAuthEvent {
        occurred_at: h2,
        ip: Some("10.0.0.3".parse().unwrap()),
        ..ev(5)
    };
    // 上一个等长窗口 [h0-2h, h0) 的 1 条失败,喂环比分母。
    let prev = NewAuthEvent {
        occurred_at: h0 - Duration::minutes(30),
        ..failed(6, "bad_password")
    };
    seed(&s, &[s1, f1, f2, f3, on_to, prev]).await;

    let v = expect_json(
        sa.get(&format!("{STATS}?from={}&to={}", q_ts(h0), q_ts(h2)))
            .await,
        StatusCode::OK,
    )
    .await;

    // activity:h0 / h1 / h2 三个桶(generate_series 两端含),h2 桶为 0(on_to 被排除)。
    let act = v["activity"].as_array().unwrap();
    let buckets: Vec<(OffsetDateTime, i64, i64)> = act
        .iter()
        .map(|b| {
            (
                parse_ts(&b["t"]),
                b["success"].as_i64().unwrap(),
                b["failure"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(buckets, vec![(h0, 1, 1), (h1, 0, 2), (h2, 0, 0)], "{v}");

    // reasons:失败原因计数(同计数的顺序不定,按集合比)。
    let mut reasons: Vec<(String, i64)> = v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["key"].as_str().unwrap().to_owned(),
                r["count"].as_i64().unwrap(),
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
    let types = v["types"].as_array().unwrap();
    assert_eq!(types[0]["key"], "auth.login_failed");
    assert_eq!(types[0]["count"], 2);
    let mut rest: Vec<(String, i64)> = types[1..]
        .iter()
        .map(|t| {
            (
                t["key"].as_str().unwrap().to_owned(),
                t["count"].as_i64().unwrap(),
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
    let top: Vec<(String, i64, i64)> = v["top_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["ip"].as_str().unwrap().to_owned(),
                i["failures"].as_i64().unwrap(),
                i["total"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        top,
        vec![("10.0.0.2".to_owned(), 2, 2), ("10.0.0.1".to_owned(), 1, 2)]
    );

    // KPI:当前 4 条 / 3 失败 / 2 个 IP;上窗 1 条 / 1 失败。
    let kpi = &v["kpi"];
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
    let s = TestServer::start().await;
    let now = OffsetDateTime::now_utc();
    seed(
        &s,
        &[
            NewAuthEvent {
                occurred_at: now - Duration::hours(1),
                ..ev(1)
            },
            NewAuthEvent {
                occurred_at: now - Duration::hours(25),
                ..failed(2, "bad_password")
            },
            NewAuthEvent {
                occurred_at: now - Duration::hours(60),
                ..ev(3)
            },
        ],
    )
    .await;
    let v = expect_json(superadmin(&s).get(STATS).await, StatusCode::OK).await;
    let act = v["activity"].as_array().unwrap();
    assert_eq!(act.len(), 25, "floor(now-24h)..=floor(now) 共 25 个小时桶");
    assert!(
        act.iter().all(|b| parse_ts(&b["t"]).minute() == 0),
        "桶对齐整点"
    );
    assert_eq!(
        act.iter()
            .map(|b| b["success"].as_i64().unwrap())
            .sum::<i64>(),
        1
    );
    let kpi = &v["kpi"];
    assert_eq!(kpi["total_events"], 1);
    assert_eq!(kpi["failed_count"], 0);
    approx(&kpi["success_rate"], 1.0);
    approx(&kpi["total_delta"], 0.0); // (1-1)/1
    approx(&kpi["failed_delta"], -1.0); // (0-1)/1
}

/// 空窗口:各维度为空数组、KPI 为 0,success_rate 记 1.0,环比无基数记 0.0(不出 NaN/∞)。
#[tokio::test]
async fn stats_empty_window_defaults() {
    let s = TestServer::start().await;
    let h0 = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(5);
    let v = expect_json(
        superadmin(&s)
            .get(&format!(
                "{STATS}?from={}&to={}",
                q_ts(h0),
                q_ts(h0 + Duration::hours(2))
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let act = v["activity"].as_array().unwrap();
    assert_eq!(act.len(), 3);
    assert!(act.iter().all(|b| b["success"] == 0 && b["failure"] == 0));
    for k in ["reasons", "types", "top_ips"] {
        assert_eq!(v[k], serde_json::json!([]), "{k} 应为空数组: {v}");
    }
    let kpi = &v["kpi"];
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
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    let h0 = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(10);
    seed(
        &s,
        &[
            NewAuthEvent {
                occurred_at: h0 + Duration::minutes(30),
                ..ev(1)
            },
            NewAuthEvent {
                occurred_at: h0 + Duration::minutes(90),
                ..failed(2, "bad_password")
            },
        ],
    )
    .await;
    let to = h0 + Duration::hours(2);
    for from in [to, to + Duration::hours(3)] {
        let v = expect_json(
            sa.get(&format!("{STATS}?from={}&to={}", q_ts(from), q_ts(to)))
                .await,
            StatusCode::OK,
        )
        .await;
        let ts: Vec<OffsetDateTime> = v["activity"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| parse_ts(&b["t"]))
            .collect();
        assert_eq!(ts, vec![h0 + Duration::hours(1), to], "{v}");
        assert_eq!(
            v["kpi"]["total_events"], 1,
            "只含 [to-1h, to) 内的那条: {v}"
        );
        assert_eq!(v["kpi"]["failed_count"], 1);
    }
}

/// 区间上限 clamp 到 92 天(防巨量小时桶):from 被抬到 to-92d。
#[tokio::test]
async fn stats_window_clamped_to_92_days() {
    let s = TestServer::start().await;
    let to = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(1);
    seed(
        &s,
        &[
            NewAuthEvent {
                occurred_at: to - Duration::days(91),
                ..ev(1)
            },
            NewAuthEvent {
                occurred_at: to - Duration::days(100),
                ..ev(2)
            },
        ],
    )
    .await;
    let v = expect_json(
        superadmin(&s)
            .get(&format!(
                "{STATS}?from={}&to={}",
                q_ts(to - Duration::days(200)),
                q_ts(to)
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let act = v["activity"].as_array().unwrap();
    assert_eq!(act.len(), 92 * 24 + 1, "92 天的小时桶(两端含)");
    assert_eq!(parse_ts(&act[0]["t"]), to - Duration::days(92));
    assert_eq!(v["kpi"]["total_events"], 1, "100 天前的那条被 clamp 掉");
}

/// 半小时制时区的区间(+05:30):桶仍对齐 UTC 整点,事件照样落桶(不全零)。
#[tokio::test]
async fn stats_fractional_offset_buckets_align_to_utc_hour() {
    let s = TestServer::start().await;
    let h = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(3);
    seed(
        &s,
        &[NewAuthEvent {
            occurred_at: h + Duration::minutes(5),
            ..ev(1)
        }],
    )
    .await;
    let off = UtcOffset::from_hms(5, 30, 0).unwrap();
    let from = (h - Duration::minutes(30)).to_offset(off);
    let to = (h + Duration::hours(1)).to_offset(off);
    let v = expect_json(
        superadmin(&s)
            .get(&format!("{STATS}?from={}&to={}", q_ts(from), q_ts(to)))
            .await,
        StatusCode::OK,
    )
    .await;
    let act = v["activity"].as_array().unwrap();
    assert!(
        act.iter().all(|b| parse_ts(&b["t"]).minute() == 0),
        "桶必须对齐整点: {v}"
    );
    assert_eq!(
        act.iter()
            .map(|b| b["success"].as_i64().unwrap())
            .sum::<i64>(),
        1,
        "{v}"
    );
    assert_eq!(v["kpi"]["total_events"], 1);
}

/// top_ips 最多 6 个,按失败数降序。
#[tokio::test]
async fn stats_top_ips_capped_at_six() {
    let s = TestServer::start().await;
    let h0 = floor_hour(OffsetDateTime::now_utc()) - Duration::hours(4);
    let mut events = Vec::new();
    let mut seq = 0;
    for i in 1..=8u8 {
        for _ in 0..i {
            seq += 1;
            events.push(NewAuthEvent {
                occurred_at: h0 + Duration::minutes(i64::from(i)),
                ip: Some(format!("10.0.1.{i}").parse().unwrap()),
                ..failed(seq, "bad_password")
            });
        }
    }
    seed(&s, &events).await;
    let v = expect_json(
        superadmin(&s)
            .get(&format!(
                "{STATS}?from={}&to={}",
                q_ts(h0),
                q_ts(h0 + Duration::hours(1))
            ))
            .await,
        StatusCode::OK,
    )
    .await;
    let top: Vec<(String, i64)> = v["top_ips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["ip"].as_str().unwrap().to_owned(),
                i["failures"].as_i64().unwrap(),
            )
        })
        .collect();
    let want: Vec<(String, i64)> = (3..=8).rev().map(|i| (format!("10.0.1.{i}"), i)).collect();
    assert_eq!(top, want);
    assert_eq!(v["kpi"]["unique_ips"], 8, "unique_ips 不受 top 截断影响");
    assert_eq!(v["kpi"]["total_events"], 36);
}

/// 非法时间参数 → 400 bad_request。
#[tokio::test]
async fn stats_invalid_time_is_400() {
    let s = TestServer::start().await;
    let sa = superadmin(&s);
    for q in ["from=now", "to=2026-11-23", "from=2026-11-23T25:00:00Z"] {
        expect_error(
            sa.get(&format!("{STATS}?{q}")).await,
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
    let s = TestServer::start().await;
    let sa = s.login_admin(SUPERADMIN, PASSWORD).await; // 浏览器式 cookie 会话(EventSource 的真实用法)
    let resp = sa.get(STREAM).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"),
        "{:?}",
        resp.headers()
    );
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    let uid = Uuid::now_v7();
    let first = NewAuthEvent {
        user_id: Some(uid),
        actor: Some("alice".into()),
        channel: "admin".into(),
        ip: Some("198.51.100.9".parse().unwrap()),
        user_agent: Some("ua/1".into()),
        ..failed(1, "bad_password")
    };
    let second = NewAuthEvent {
        event_type: "auth.logged_out".into(),
        ..ev(2)
    };
    s.auth_bus.publish(to_row(&first).unwrap());
    s.auth_bus.publish(to_row(&second).unwrap());

    let (name, data) = parse_frame(&next_sse_event(&mut stream, &mut buf).await);
    assert_eq!(name, "auth_event");
    assert_eq!(data["id"], first.id.to_string());
    assert_eq!(data["event_type"], "auth.login_failed");
    assert_eq!(parse_ts(&data["occurred_at"]), first.occurred_at);
    assert_eq!(data["channel"], "admin");
    assert_eq!(data["user_id"], uid.to_string());
    assert_eq!(data["actor"], "alice");
    assert_eq!(data["outcome"], "failure");
    assert_eq!(data["failure_reason"], "bad_password");
    assert_eq!(data["ip"], "198.51.100.9");
    assert_eq!(data["user_agent"], "ua/1");
    for k in [
        "identifier_attempted",
        "session_id",
        "country",
        "city",
        "os",
        "browser",
    ] {
        assert_eq!(
            data.get(k),
            Some(&Value::Null),
            "{k} 应存在且为 null: {data}"
        );
    }

    let (name, data) = parse_frame(&next_sse_event(&mut stream, &mut buf).await);
    assert_eq!(name, "auth_event");
    assert_eq!(data["id"], second.id.to_string(), "按发布顺序到达");
    assert_eq!(data["event_type"], "auth.logged_out");
    assert_eq!(data["outcome"], "success");
    assert_eq!(data["failure_reason"], Value::Null);
}

/// best-effort 无回放:订阅前发布的事件收不到;同时在线的多个订阅者各自收到(广播)。
#[tokio::test]
async fn sse_no_replay_and_broadcasts_to_all_subscribers() {
    let s = TestServer::start().await;
    let early = ev(1);
    s.auth_bus.publish(to_row(&early).unwrap()); // 此时无订阅者

    let a = superadmin(&s).get(STREAM).await;
    assert_eq!(a.status(), StatusCode::OK);
    let b = superadmin(&s).get(STREAM).await;
    assert_eq!(b.status(), StatusCode::OK);
    let (mut sa, mut sb) = (a.bytes_stream(), b.bytes_stream());
    let (mut ba, mut bb) = (String::new(), String::new());

    let live = failed(2, "unknown_user");
    s.auth_bus.publish(to_row(&live).unwrap());
    for (stream, buf) in [(&mut sa, &mut ba), (&mut sb, &mut bb)] {
        let (name, data) = parse_frame(&next_sse_event(stream, buf).await);
        assert_eq!(name, "auth_event");
        assert_eq!(data["id"], live.id.to_string(), "订阅前的事件不应回放");
        assert_eq!(data["failure_reason"], "unknown_user");
    }
}

// ───────────────────────────── 后端未接线 ─────────────────────────────

/// 审计后端未接线(非 idm 进程 / 无 search 库)→ 404 not_found;授权闸仍在前(无 users:admin 照样 403)。
#[tokio::test]
async fn no_audit_backend_is_404_after_authz() {
    let s = TestServer::start_with(|st| st.auth_audit = None).await;
    let sa = superadmin(&s);
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    for path in [EV.to_owned(), STATS.to_owned(), user_events(Uuid::now_v7())] {
        expect_error(sa.get(&path).await, StatusCode::NOT_FOUND, "not_found").await;
        expect_error(admin.get(&path).await, StatusCode::FORBIDDEN, "forbidden").await;
    }
}

/// SSE 总线未接线(没有 projector 发布者)→ 404 not_found;授权闸仍在前。
#[tokio::test]
async fn no_event_bus_stream_is_404_after_authz() {
    let s = TestServer::start_with(|st| st.auth_events_bus = None).await;
    expect_error(
        superadmin(&s).get(STREAM).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
    let admin = s.login_admin(ADMIN, PASSWORD).await;
    expect_error(admin.get(STREAM).await, StatusCode::FORBIDDEN, "forbidden").await;
    // 列表 / 统计不依赖总线,照常可用。
    expect(superadmin(&s).get(EV).await, StatusCode::OK).await;
}

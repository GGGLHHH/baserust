//! AuthEventRepo 契约一致性:**同一批断言对 InMemoryAuthEventRepo 与 PgAuthEventRepo 各跑一遍**
//! (镜像 widget/profile/search 的 conformance),钉死两实现的 parity —— 幂等插入、过滤(用户 / 类型 /
//! 结果 / 联合模糊搜 / IP / 时间窗)、id 倒序、offset 与 keyset 分页、保留期删除、仪表盘统计。
//! PG 入口还会把**同一批数据**在内存实现上再算一遍统计,断言两边 `stats` 完全相等(内存实现是
//! 手写聚合、PG 是五条 SQL,口径最容易悄悄分叉)。
//!
//! 内存入口:默认 `cargo test` 就跑。
//! PG 入口:`cargo test --features pg-conformance --test auth_event_repo_conformance`(`just test-pg` 挂了本文件)。
//! **连 search role**(`auth_event` 表在 search 库,跨运行共享)—— 每次运行用随机的远古时间窗(1990 年代)、
//! 随机 event_seq / user_id / 搜索标记 / IP,与别的运行和真实数据互不干扰;结束时删掉本次造的行。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use baserust::features::auth_audit::{
    AuthEventQuery, AuthEventRepo, AuthEventType, AuthOutcome, AuthStats, NewAuthEvent,
};
use baserust::kernel::pagination::{Page, PageInfo, PageParams};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 一次运行的测试数据。
struct Fixture {
    /// 统计窗口起点(整点)。窗口 = [t, t+3h)。
    t: OffsetDateTime,
    uid: Uuid,
    uid2: Uuid,
    tag: String,
    ip_a: IpAddr,
    ip_b: IpAddr,
    /// 按 id 递增序:[e_old, e1, e2, e3, e4, e5]。
    events: Vec<NewAuthEvent>,
}

fn fixture() -> Fixture {
    let n = Uuid::now_v7().as_u128();
    // 1990-01-01 起随机 0..~11 年的整点,作本次运行专属的远古时间窗。
    let t = OffsetDateTime::from_unix_timestamp(631_152_000).unwrap()
        + Duration::hours((n % 100_000) as i64);
    let seq0 = (n % (i64::MAX as u128 / 2)) as i64;
    let tag = format!("cf{:x}", n % 0xffff_ffff);
    let ip_a = IpAddr::V4(Ipv4Addr::new(10, (n >> 8) as u8, (n >> 16) as u8, 1));
    let ip_b = IpAddr::V4(Ipv4Addr::new(10, (n >> 8) as u8, (n >> 16) as u8, 2));
    let uid = Uuid::now_v7();
    let uid2 = Uuid::now_v7();
    let mut seq = seq0;
    let mut ev = |event_type: &str,
                  channel: &str,
                  at: OffsetDateTime,
                  user: Option<Uuid>,
                  outcome: &str,
                  reason: Option<&str>,
                  ip: IpAddr,
                  actor: Option<String>,
                  ident: Option<String>| {
        seq += 1;
        NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: event_type.to_owned(),
            occurred_at: at,
            channel: channel.to_owned(),
            auth_method: "password".to_owned(),
            user_id: user,
            identifier_attempted: ident,
            session_id: None,
            actor,
            outcome: outcome.to_owned(),
            failure_reason: reason.map(str::to_owned),
            ip: Some(ip),
            forwarded_chain: None,
            user_agent: Some("conformance".to_owned()),
            request_id: None,
            event_seq: seq,
        }
    };
    let m = Duration::minutes;
    let events = vec![
        // 窗口外(一天前):保留期删除用
        ev(
            "auth.logged_out",
            "public",
            t - Duration::days(1),
            Some(uid),
            "success",
            None,
            ip_a,
            None,
            None,
        ),
        ev(
            "auth.login_succeeded",
            "public",
            t + m(10),
            Some(uid),
            "success",
            None,
            ip_a,
            Some(format!("alice-{tag}")),
            None,
        ),
        ev(
            "auth.login_failed",
            "public",
            t + m(20),
            Some(uid),
            "failure",
            Some("bad_password"),
            ip_b,
            None,
            Some(format!("alice-{tag}")),
        ),
        ev(
            "auth.login_failed",
            "admin",
            t + m(70),
            None,
            "failure",
            Some("unknown_user"),
            ip_b,
            None,
            Some(format!("ghost-{tag}")),
        ),
        ev(
            "auth.admin_access_denied",
            "admin",
            t + m(80),
            Some(uid2),
            "failure",
            Some("no_admin_perm"),
            ip_a,
            Some(format!("bob-{tag}")),
            None,
        ),
        ev(
            "auth.refreshed",
            "public",
            t + m(150),
            Some(uid),
            "success",
            None,
            ip_a,
            None,
            None,
        ),
    ];
    Fixture {
        t,
        uid,
        uid2,
        tag,
        ip_a,
        ip_b,
        events,
    }
}

fn ids(page: &Page<baserust::features::auth_audit::AuthEventRow>) -> Vec<Uuid> {
    page.items.iter().map(|r| r.id).collect()
}

fn total<T>(p: &Page<T>) -> Option<u64> {
    match p.page_info {
        PageInfo::Offset { total, .. } => total,
        PageInfo::Cursor { .. } => panic!("应是 offset 页"),
    }
}

fn next_after<T>(p: &Page<T>) -> Option<Uuid> {
    match p.page_info {
        PageInfo::Cursor { next_after, .. } => next_after,
        PageInfo::Offset { .. } => panic!("应是 cursor 页"),
    }
}

fn offset(size: u64) -> PageParams {
    PageParams::Offset {
        page: 1,
        size,
        with_total: true,
    }
}

/// 契约唯一真相源。返回窗口统计(PG 入口拿它与内存实现比对)。
async fn auth_event_contract(repo: &dyn AuthEventRepo, fx: &Fixture) -> AuthStats {
    let e = &fx.events;
    let id = |i: usize| e[i].id;

    // ── 1. 插入 + 幂等(同 event_seq 重投 → false,不重复) ──
    for ev in e {
        assert!(repo.insert(ev).await.unwrap(), "首次插入应为 true");
    }
    assert!(
        !repo.insert(&e[1]).await.unwrap(),
        "同 event_seq 重投应被幂等吞掉"
    );

    // ── 2. 按用户列:id 倒序 + total ──
    let q = AuthEventQuery {
        user_id: Some(fx.uid),
        ..Default::default()
    };
    let p = repo.list(&q, offset(10)).await.unwrap();
    assert_eq!(
        ids(&p),
        vec![id(5), id(2), id(1), id(0)],
        "user 过滤 + id(v7,生成序)倒序"
    );
    assert_eq!(total(&p), Some(4));

    // ── 3. 类型过滤 ──
    let q = AuthEventQuery {
        user_id: Some(fx.uid),
        event_type: Some(AuthEventType::LoginFailed),
        ..Default::default()
    };
    assert_eq!(ids(&repo.list(&q, offset(10)).await.unwrap()), vec![id(2)]);

    // ── 4. 结果 + 联合模糊搜(大小写不敏感)+ 时间窗 ──
    let q = AuthEventQuery {
        outcome: Some(AuthOutcome::Failure),
        q: Some(fx.tag.to_uppercase()),
        from: Some(fx.t),
        to: Some(fx.t + Duration::hours(3)),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&q, offset(10)).await.unwrap()),
        vec![id(4), id(3), id(2)]
    );

    // ── 5. IP 精确过滤(限定在本次窗口内) ──
    let q = AuthEventQuery {
        ip: Some(fx.ip_b),
        from: Some(fx.t),
        to: Some(fx.t + Duration::hours(3)),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&q, offset(10)).await.unwrap()),
        vec![id(3), id(2)]
    );

    // ── 6. keyset 分页(按 id 倒序翻,末页无 next) ──
    let q = AuthEventQuery {
        q: Some(fx.tag.clone()),
        ..Default::default()
    };
    let p1 = repo
        .list(
            &q,
            PageParams::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(ids(&p1), vec![id(4), id(3)]);
    let next = next_after(&p1).expect("还有下一页");
    let p2 = repo
        .list(
            &q,
            PageParams::Cursor {
                after: Some(next),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(ids(&p2), vec![id(2), id(1)]);
    assert_eq!(next_after(&p2), None, "末页不应有 next");

    // ── 7. 仪表盘统计 [t, t+3h) ──
    let stats = repo.stats(fx.t, fx.t + Duration::hours(3)).await.unwrap();
    let buckets: Vec<(i64, i64)> = stats
        .activity
        .iter()
        .map(|b| (b.success, b.failure))
        .collect();
    assert_eq!(
        buckets,
        vec![(1, 1), (0, 2), (1, 0), (0, 0)],
        "小时桶零填充、两端含"
    );
    assert_eq!(stats.activity[0].t, fx.t);
    let types: HashMap<String, i64> = stats
        .types
        .iter()
        .map(|c| (c.key.as_str().to_owned(), c.count))
        .collect();
    assert_eq!(
        types,
        HashMap::from([
            ("auth.login_failed".to_owned(), 2),
            ("auth.login_succeeded".to_owned(), 1),
            ("auth.admin_access_denied".to_owned(), 1),
            ("auth.refreshed".to_owned(), 1),
        ])
    );
    let reasons: HashMap<String, i64> = stats
        .reasons
        .iter()
        .map(|c| (c.key.as_str().to_owned(), c.count))
        .collect();
    assert_eq!(
        reasons,
        HashMap::from([
            ("bad_password".to_owned(), 1),
            ("unknown_user".to_owned(), 1),
            ("no_admin_perm".to_owned(), 1),
        ])
    );
    let ips: Vec<(String, i64, i64)> = stats
        .top_ips
        .iter()
        .map(|s| (s.ip.clone(), s.failures, s.total))
        .collect();
    assert_eq!(
        ips,
        vec![(fx.ip_b.to_string(), 2, 2), (fx.ip_a.to_string(), 1, 3)],
        "失败多的 IP 在前"
    );
    assert_eq!(stats.kpi.total_events, 5);
    assert_eq!(stats.kpi.failed_count, 3);
    assert_eq!(stats.kpi.unique_ips, 2);
    assert_eq!(stats.kpi.total_delta, 0.0, "上个等长窗口为 0 → 记 0.0");

    // ── 8. 保留期删除:删 occurred_at < t 的行(本次的 e_old;共享库里更早的残留也可能一起删) ──
    let deleted = repo.delete_older_than(fx.t).await.unwrap();
    assert!(deleted >= 1, "至少删掉 e_old");
    let q = AuthEventQuery {
        user_id: Some(fx.uid),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&q, offset(10)).await.unwrap()),
        vec![id(5), id(2), id(1)]
    );
    let q = AuthEventQuery {
        user_id: Some(fx.uid2),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&q, offset(10)).await.unwrap()),
        vec![id(4)],
        "窗口内的行不受影响"
    );

    // 清场:本次的行都在 t+1 天之前(1990 年代),真实数据不会这么老
    repo.delete_older_than(fx.t + Duration::days(1))
        .await
        .unwrap();
    stats
}

#[tokio::test]
async fn memory_satisfies_auth_event_contract() {
    let repo = baserust::features::auth_audit::InMemoryAuthEventRepo::new();
    auth_event_contract(&repo, &fixture()).await;
}

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::*;
    use baserust::features::auth_audit::{InMemoryAuthEventRepo, PgAuthEventRepo};

    /// 统计里 `ORDER BY count DESC` 的并列顺序未定义 → 比对前按 (count 降序, key) 归一。
    fn normalized(mut s: AuthStats) -> AuthStats {
        s.types.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.key.as_str().cmp(b.key.as_str()))
        });
        s.reasons.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.key.as_str().cmp(b.key.as_str()))
        });
        s
    }

    async fn connect() -> sqlx::PgPool {
        let url = std::env::var("SEARCH_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://search:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let pool = sqlx::PgPool::connect(&url).await.expect(
            "连 search role 失败(先 `just up` + `just migrate-search` + `just pg-test-grant`)",
        );
        sqlx::migrate!("migrations/search")
            .run(&pool)
            .await
            .expect("跑 migrations/search 失败(幂等,应可重复跑)");
        pool
    }

    #[tokio::test]
    async fn pg_satisfies_auth_event_contract_and_matches_memory_stats() {
        let fx = fixture();
        let pg = PgAuthEventRepo::new(connect().await);
        let pg_stats = auth_event_contract(&pg, &fx).await;
        let mem_stats = auth_event_contract(&InMemoryAuthEventRepo::new(), &fx).await;
        assert_eq!(
            normalized(pg_stats),
            normalized(mem_stats),
            "内存与 PG 的统计口径应完全一致"
        );
    }
}

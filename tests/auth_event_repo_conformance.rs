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

use baserust::features::auth_audit::{AuthEventRow, InMemoryAuthEventRepo};
use baserust::kernel::time_range::TimeRange;
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
    user_id: Uuid,
    other_user_id: Uuid,
    tag: String,
    ip_a: IpAddr,
    ip_b: IpAddr,
    /// e1 / e5 所在的租户(其余事件没有租户)。
    tenant: Uuid,
    /// 按 id 递增序:[e_old, e1, e2, e3, e4, e5]。
    events: Vec<NewAuthEvent>,
}

fn fixture() -> Fixture {
    let random_bits = Uuid::now_v7().as_u128();
    // 1990-01-01 起随机 0..~11 年的整点,作本次运行专属的远古时间窗。
    let window_start = OffsetDateTime::from_unix_timestamp(631_152_000).unwrap()
        + Duration::hours((random_bits % 100_000) as i64);
    let initial_sequence = (random_bits % (i64::MAX as u128 / 2)) as i64;
    let tag = format!("cf{:x}", random_bits % 0xffff_ffff);
    let ip_a = IpAddr::V4(Ipv4Addr::new(
        10,
        (random_bits >> 8) as u8,
        (random_bits >> 16) as u8,
        1,
    ));
    let ip_b = IpAddr::V4(Ipv4Addr::new(
        10,
        (random_bits >> 8) as u8,
        (random_bits >> 16) as u8,
        2,
    ));
    let user_id = Uuid::now_v7();
    let other_user_id = Uuid::now_v7();
    let mut sequence = initial_sequence;
    let mut event = |event_type: &str,
                     channel: &str,
                     at: OffsetDateTime,
                     user: Option<Uuid>,
                     outcome: &str,
                     reason: Option<&str>,
                     ip: IpAddr,
                     actor: Option<String>,
                     identifier: Option<String>| {
        sequence += 1;
        NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: event_type.to_owned(),
            occurred_at: at,
            channel: channel.to_owned(),
            auth_method: "password".to_owned(),
            user_id: user,
            identifier_attempted: identifier,
            session_id: None,
            actor,
            outcome: outcome.to_owned(),
            failure_reason: reason.map(str::to_owned),
            ip: Some(ip),
            forwarded_chain: None,
            user_agent: Some("conformance".to_owned()),
            request_id: None,
            tenant_id: None,
            event_sequence: sequence,
        }
    };
    let minutes = Duration::minutes;
    let mut events = vec![
        // 窗口外(一天前):保留期删除用
        event(
            "auth.logged_out",
            "public",
            window_start - Duration::days(1),
            Some(user_id),
            "success",
            None,
            ip_a,
            None,
            None,
        ),
        event(
            "auth.login_succeeded",
            "public",
            window_start + minutes(10),
            Some(user_id),
            "success",
            None,
            ip_a,
            Some(format!("alice-{tag}")),
            None,
        ),
        event(
            "auth.login_failed",
            "public",
            window_start + minutes(20),
            Some(user_id),
            "failure",
            Some("bad_password"),
            ip_b,
            None,
            Some(format!("alice-{tag}")),
        ),
        event(
            "auth.login_failed",
            "admin",
            window_start + minutes(70),
            None,
            "failure",
            Some("unknown_user"),
            ip_b,
            None,
            Some(format!("ghost-{tag}")),
        ),
        event(
            "auth.admin_access_denied",
            "admin",
            window_start + minutes(80),
            Some(other_user_id),
            "failure",
            Some("no_admin_perm"),
            ip_a,
            Some(format!("bob-{tag}")),
            None,
        ),
        event(
            "auth.refreshed",
            "public",
            window_start + minutes(150),
            Some(user_id),
            "success",
            None,
            ip_a,
            None,
            None,
        ),
    ];
    // 多租户:进了租户的事件记 tenant_id(e1 登录进租户、e5 刷新同一会话);登录失败等没有租户。
    let tenant = Uuid::now_v7();
    events[1].tenant_id = Some(tenant);
    events[5].tenant_id = Some(tenant);
    Fixture {
        t: window_start,
        user_id,
        other_user_id,
        tag,
        ip_a,
        ip_b,
        tenant,
        events,
    }
}

fn ids(page: &Page<AuthEventRow>) -> Vec<Uuid> {
    page.items.iter().map(|r| r.id).collect()
}

fn total<T>(page: &Page<T>) -> Option<u64> {
    match page.page_info {
        PageInfo::Offset { total, .. } => total,
        PageInfo::Cursor { .. } => panic!("应是 offset 页"),
    }
}

fn next_after<T>(page: &Page<T>) -> Option<Uuid> {
    match page.page_info {
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

/// 多租户(spec §4.4 / §6.1):auth_event 记下事件所在的租户(读回来原样),没有租户的事件为 `None`。
/// `page` = 按 `fixture.user_id` 列出的那一页(e5 / e2 / e1 / e0)。
fn auth_event_records_tenant(page: &Page<AuthEventRow>, fixture: &Fixture) {
    let by_id: HashMap<Uuid, Option<Uuid>> =
        page.items.iter().map(|r| (r.id, r.tenant_id)).collect();
    let events = &fixture.events;
    assert_eq!(
        by_id[&events[1].id],
        Some(fixture.tenant),
        "登录进租户的事件记租户"
    );
    assert_eq!(by_id[&events[5].id], Some(fixture.tenant));
    assert_eq!(by_id[&events[2].id], None, "登录失败没有租户");
    assert_eq!(by_id[&events[0].id], None);
}

/// 契约唯一真相源。返回窗口统计(PG 入口拿它与内存实现比对)。
async fn auth_event_contract(repo: &dyn AuthEventRepo, fixture: &Fixture) -> AuthStats {
    let events = &fixture.events;
    let id = |i: usize| events[i].id;

    // ── 1. 插入 + 幂等(同 event_seq 重投 → false,不重复) ──
    for event in events {
        assert!(repo.insert(event).await.unwrap(), "首次插入应为 true");
    }
    assert!(
        !repo.insert(&events[1]).await.unwrap(),
        "同 event_seq 重投应被幂等吞掉"
    );

    // ── 2. 按用户列:id 倒序 + total ──
    let query = AuthEventQuery {
        user_id: Some(fixture.user_id),
        ..Default::default()
    };
    let page = repo.list(&query, offset(10)).await.unwrap();
    assert_eq!(
        ids(&page),
        vec![id(5), id(2), id(1), id(0)],
        "user 过滤 + id(v7,生成序)倒序"
    );
    assert_eq!(total(&page), Some(4));
    auth_event_records_tenant(&page, fixture);

    // ── 3. 类型过滤 ──
    let query = AuthEventQuery {
        user_id: Some(fixture.user_id),
        event_type: Some(AuthEventType::LoginFailed),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&query, offset(10)).await.unwrap()),
        vec![id(2)]
    );

    // ── 4. 结果 + 联合模糊搜(大小写不敏感)+ 时间窗 ──
    let query = AuthEventQuery {
        outcome: Some(AuthOutcome::Failure),
        query: Some(fixture.tag.to_uppercase()),
        from: Some(fixture.t),
        to: Some(fixture.t + Duration::hours(3)),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&query, offset(10)).await.unwrap()),
        vec![id(4), id(3), id(2)]
    );

    // ── 5. IP 精确过滤(限定在本次窗口内) ──
    let query = AuthEventQuery {
        ip: Some(fixture.ip_b),
        from: Some(fixture.t),
        to: Some(fixture.t + Duration::hours(3)),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&query, offset(10)).await.unwrap()),
        vec![id(3), id(2)]
    );

    // ── 6. keyset 分页(按 id 倒序翻,末页无 next) ──
    let query = AuthEventQuery {
        query: Some(fixture.tag.clone()),
        ..Default::default()
    };
    let first_page = repo
        .list(
            &query,
            PageParams::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(ids(&first_page), vec![id(4), id(3)]);
    let next = next_after(&first_page).expect("还有下一页");
    let second_page = repo
        .list(
            &query,
            PageParams::Cursor {
                after: Some(next),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(ids(&second_page), vec![id(2), id(1)]);
    assert_eq!(next_after(&second_page), None, "末页不应有 next");

    // ── 7. 仪表盘统计 [t, t+3h) ──
    let stats = repo
        .stats(TimeRange {
            from: fixture.t,
            to: fixture.t + Duration::hours(3),
        })
        .await
        .unwrap();
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
    assert_eq!(stats.activity[0].bucket_start, fixture.t);
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
        vec![
            (fixture.ip_b.to_string(), 2, 2),
            (fixture.ip_a.to_string(), 1, 3)
        ],
        "失败多的 IP 在前"
    );
    assert_eq!(stats.kpi.total_events, 5);
    assert_eq!(stats.kpi.failed_count, 3);
    assert_eq!(stats.kpi.unique_ips, 2);
    assert_eq!(stats.kpi.total_delta, 0.0, "上个等长窗口为 0 → 记 0.0");

    // ── 8. 保留期删除:删 occurred_at < t 的行(本次的 e_old;共享库里更早的残留也可能一起删) ──
    let deleted = repo.delete_older_than(fixture.t).await.unwrap();
    assert!(deleted >= 1, "至少删掉 e_old");
    let query = AuthEventQuery {
        user_id: Some(fixture.user_id),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&query, offset(10)).await.unwrap()),
        vec![id(5), id(2), id(1)]
    );
    let query = AuthEventQuery {
        user_id: Some(fixture.other_user_id),
        ..Default::default()
    };
    assert_eq!(
        ids(&repo.list(&query, offset(10)).await.unwrap()),
        vec![id(4)],
        "窗口内的行不受影响"
    );

    // 清场:本次的行都在 t+1 天之前(1990 年代),真实数据不会这么老
    repo.delete_older_than(fixture.t + Duration::days(1))
        .await
        .unwrap();
    stats
}

#[tokio::test]
async fn memory_satisfies_auth_event_contract() {
    let repo = InMemoryAuthEventRepo::new();
    auth_event_contract(&repo, &fixture()).await;
}

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::*;
    use baserust::features::auth_audit::{InMemoryAuthEventRepo, PgAuthEventRepo};
    use sqlx::PgPool;
    use std::env;

    /// 统计里 `ORDER BY count DESC` 的并列顺序未定义 → 比对前按 (count 降序, key) 归一。
    fn normalized(mut stats: AuthStats) -> AuthStats {
        stats.types.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.key.as_str().cmp(b.key.as_str()))
        });
        stats.reasons.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.key.as_str().cmp(b.key.as_str()))
        });
        stats
    }

    /// 迁移用 owner(`SEARCH_OWNER_DATABASE_URL`,幂等),契约跑在 **system 账号**上
    /// (`SEARCH_SYSTEM_DATABASE_URL`:auth_event 是平台级表,读写都只走 search_system 池 —— 和生产一样)。
    async fn connect() -> PgPool {
        let owner_url = env::var("SEARCH_OWNER_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://search_owner:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let owner = PgPool::connect(&owner_url).await.expect(
            "连 search_owner 失败(先 `just up` + `just db-ensure-roles` + `just migrate-search`)",
        );
        sqlx::migrate!("migrations/search")
            .run(&owner)
            .await
            .expect("跑 migrations/search 失败(幂等,应可重复跑)");
        owner.close().await;
        let url = env::var("SEARCH_SYSTEM_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://search_system:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        PgPool::connect(&url)
            .await
            .expect("连 search_system 账号失败(先 `just up` + `just db-ensure-roles`)")
    }

    #[tokio::test]
    async fn pg_satisfies_auth_event_contract_and_matches_memory_stats() {
        let fixture = fixture();
        let pg = PgAuthEventRepo::new(connect().await);
        let pg_stats = auth_event_contract(&pg, &fixture).await;
        let memory_stats = auth_event_contract(&InMemoryAuthEventRepo::new(), &fixture).await;
        assert_eq!(
            normalized(pg_stats),
            normalized(memory_stats),
            "内存与 PG 的统计口径应完全一致"
        );
    }
}

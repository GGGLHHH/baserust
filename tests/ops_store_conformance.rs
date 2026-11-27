//! OpsStore 契约一致性:同一批断言对 `MemoryOpsStore` 与 `PgOpsStore` 各跑一遍,钉死两实现的口径
//! (分钟写入 → 分钟 / 小时两层读、接口与数据库明细合计、日志过滤与分页、保留期清理)。
//!
//! 内存入口:默认 `cargo test` 就跑。
//! PG 入口:`cargo test --features pg-conformance --test ops_store_conformance`,连 ops role
//! (`OPS_DATABASE_URL`,默认 `postgres://ops:pwd@localhost:5821/baserust`;先 `just db-ensure-roles`)。
//! 测试开头自己跑一遍 `migrations/ops`(幂等),新库也能直接跑。
//! 每次运行用随机的实例名和 1990 年代的随机时间窗,与真实数据、别的运行互不干扰;结束时删掉本次造的行。

use baserust::infra::monitor::histogram::Histogram;
use baserust::infra::monitor::store::{
    hour_start, DbOperationTotals, LogEntry, LogPage, LogQuery, MemoryOpsStore, MinuteRecord,
    OpsStore, PeriodTotals, RouteTotals, SeriesRow, Service, Severity, Tier,
};
use baserust::kernel::time_range::TimeRange;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct Fixture {
    instance: String,
    /// 整点。数据落在 [hour, hour+2h)。
    hour: OffsetDateTime,
    tag: String,
}

fn fixture() -> Fixture {
    let seed = Uuid::now_v7().as_u128();
    let start = OffsetDateTime::from_unix_timestamp(631_152_000).unwrap()
        + Duration::hours((seed % 90_000) as i64);
    Fixture {
        instance: format!("t{:x}", seed % 0xffff_ffff),
        hour: hour_start(start),
        tag: format!("tag{:x}", (seed >> 32) % 0xffff_ffff),
    }
}

fn histogram_of(count: u64, ms: f64) -> Histogram {
    let mut histogram = Histogram::default();
    for _ in 0..count {
        histogram.record(ms);
    }
    histogram
}

fn minute_record(fixture: &Fixture, minute: i64, requests: u64, pool_in_use: u64) -> MinuteRecord {
    MinuteRecord {
        instance: fixture.instance.clone(),
        bucket: fixture.hour + Duration::minutes(minute),
        totals: PeriodTotals {
            requests,
            errors_5xx: 1,
            latency: histogram_of(requests, 8.0),
            db_calls: 2,
            db_latency: histogram_of(2, 3.0),
            pool_in_use_max: pool_in_use,
            pool_max: 10,
            rss_bytes_max: Some(1000 + pool_in_use),
            cpu_percent_max: Some(pool_in_use as f64),
            ..Default::default()
        },
        routes: vec![RouteTotals {
            method: "GET".into(),
            route: "/x".into(),
            requests,
            errors_5xx: 1,
            latency: histogram_of(requests, 8.0),
            ..Default::default()
        }],
        db_operations: vec![DbOperationTotals {
            operation: "pg.x.list".into(),
            latency: histogram_of(2, 3.0),
        }],
    }
}

fn log(
    fixture: &Fixture,
    minute: i64,
    severity: Severity,
    body: &str,
    request_id: Option<&str>,
) -> LogEntry {
    LogEntry {
        timestamp: fixture.hour + Duration::minutes(minute),
        instance: fixture.instance.clone(),
        service: if request_id == Some("r2") {
            Service::Idm
        } else {
            Service::App
        },
        severity,
        target: "conformance".into(),
        body: format!("{} {body}", fixture.tag),
        request_id: request_id.map(str::to_owned),
        method: Some("GET".into()),
        route: Some("/x".into()),
        status: Some(500),
        duration_ms: Some(12.5),
        attributes: serde_json::json!({ "k": "v" }).as_object().unwrap().clone(),
    }
}

async fn contract(store: &dyn OpsStore, fixture: &Fixture) {
    // 小时 0 的第 0、1 分钟 + 小时 1 的第 0 分钟
    store
        .record_minute(&minute_record(fixture, 0, 4, 3))
        .await
        .unwrap();
    store
        .record_minute(&minute_record(fixture, 1, 6, 7))
        .await
        .unwrap();
    store
        .record_minute(&minute_record(fixture, 60, 5, 2))
        .await
        .unwrap();
    let to = fixture.hour + Duration::hours(2);
    let range = TimeRange {
        from: fixture.hour,
        to,
    };
    let mine = |rows: Vec<SeriesRow>| {
        rows.into_iter()
            .filter(|r| r.instance == fixture.instance)
            .collect::<Vec<_>>()
    };

    let minutes = mine(store.series(Tier::Minute, range).await.unwrap());
    assert_eq!(minutes.len(), 3);
    assert_eq!(minutes[1].totals.requests, 6);
    assert_eq!(
        minutes[1].totals.latency,
        histogram_of(6, 8.0),
        "直方图原样存取"
    );
    assert_eq!(minutes[0].totals.rss_bytes_max, Some(1003));

    let hours = mine(store.series(Tier::Hour, range).await.unwrap());
    assert_eq!(hours.len(), 2, "两个小时");
    let first_hour = &hours[0].totals;
    assert_eq!(first_hour.requests, 10, "小时 = 分钟相加");
    assert_eq!(first_hour.errors_5xx, 2);
    assert_eq!(first_hour.latency, histogram_of(10, 8.0), "直方图逐桶相加");
    assert_eq!(first_hour.db_calls, 4);
    assert_eq!(first_hour.pool_in_use_max, 7, "读数取最大");
    assert_eq!(first_hour.cpu_percent_max, Some(7.0));

    let routes: Vec<_> = store
        .route_totals(range)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.instance == fixture.instance)
        .collect();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].totals.requests, 15);
    assert_eq!(routes[0].totals.errors_5xx, 3);
    let databases: Vec<_> = store
        .db_operation_totals(range)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.instance == fixture.instance)
        .collect();
    assert_eq!(databases[0].totals.latency.total(), 6);

    // 日志
    store
        .insert_logs(&[
            log(fixture, 1, Severity::Warn, "first", Some("r1")),
            log(fixture, 2, Severity::Error, "second_100%", Some("r2")),
            log(fixture, 3, Severity::Warn, "third", None),
        ])
        .await
        .unwrap();
    let base = LogQuery {
        instance: Some(fixture.instance.clone()),
        page: 1,
        size: 10,
        ..Default::default()
    };
    let LogPage { logs: items, total } = store.logs(&base).await.unwrap();
    assert_eq!(total, 3);
    assert!(items[0].entry.body.ends_with("third"), "时间倒序");
    assert_eq!(items[2].entry.attributes["k"], "v");
    assert_eq!(items[1].entry.status, Some(500));

    let errors = LogQuery {
        min_severity: Some(Severity::Error),
        ..base.clone()
    };
    assert_eq!(store.logs(&errors).await.unwrap().total, 1);
    let warn_up = LogQuery {
        min_severity: Some(Severity::Warn),
        ..base.clone()
    };
    assert_eq!(store.logs(&warn_up).await.unwrap().total, 3);
    let idm_only = LogQuery {
        service: Some(Service::Idm),
        ..base.clone()
    };
    let LogPage { logs: items, total } = store.logs(&idm_only).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(items[0].entry.service, Service::Idm, "service 原样存取");
    let by_request_id = LogQuery {
        request_id: Some("r1".into()),
        ..base.clone()
    };
    assert_eq!(store.logs(&by_request_id).await.unwrap().total, 1);
    let by_query = LogQuery {
        query: Some("SECOND_100%".into()),
        ..base.clone()
    };
    assert_eq!(
        store.logs(&by_query).await.unwrap().total,
        1,
        "LIKE 元字符按字面匹配、不区分大小写"
    );
    let literal = LogQuery {
        query: Some("_10".into()),
        ..base.clone()
    };
    assert_eq!(store.logs(&literal).await.unwrap().total, 1);
    let window = LogQuery {
        from: Some(fixture.hour + Duration::minutes(2)),
        to: Some(fixture.hour + Duration::minutes(3)),
        ..base.clone()
    };
    assert_eq!(store.logs(&window).await.unwrap().total, 1, "[from, to)");
    let page2 = LogQuery {
        page: 2,
        size: 2,
        ..base.clone()
    };
    let LogPage { logs: items, total } = store.logs(&page2).await.unwrap();
    assert_eq!((items.len(), total), (1, 3));

    // 保留期:1990 年代的数据全都过期
    let purged = store.purge(OffsetDateTime::now_utc()).await.unwrap();
    assert!(purged.minutes >= 3 && purged.logs >= 3, "{purged:?}");
    assert!(mine(store.series(Tier::Minute, range).await.unwrap()).is_empty());
    assert_eq!(store.logs(&base).await.unwrap().total, 0);
}

#[tokio::test]
async fn memory_store_conforms() {
    let store = MemoryOpsStore::new();
    contract(&store, &fixture()).await;
}

#[cfg(feature = "pg-conformance")]
mod pg {
    use super::*;
    use baserust::infra::monitor::pg_ops_store::PgOpsStore;
    use sqlx::PgPool;
    use std::env;

    #[tokio::test]
    async fn pg_store_conforms() {
        let url = env::var("OPS_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://ops:pwd@localhost:5821/baserust?sslmode=disable".into()
        });
        let pool = PgPool::connect(&url)
            .await
            .expect("连 ops 库(先 just db-ensure-roles)");
        sqlx::migrate!("migrations/ops")
            .run(&pool)
            .await
            .expect("跑 migrations/ops 失败(幂等,应可重复跑)");
        let fixture = fixture();
        contract(&PgOpsStore::new(pool.clone()), &fixture).await;
        // 兜底清理(正常已被 purge 删掉;小时表 / 明细表的 1990 年数据也一并清)
        for sql in [
            "delete from metric_minute where instance = $1",
            "delete from metric_hour where instance = $1",
            "delete from route_hour where instance = $1",
            "delete from db_op_hour where instance = $1",
            "delete from log_record where instance = $1",
        ] {
            sqlx::query(sql)
                .bind(&fixture.instance)
                .execute(&pool)
                .await
                .unwrap();
        }
    }
}

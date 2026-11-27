//! auth_audit 仓储端口的**内存适配器**(默认实现 + 测试替身)。与 PG 的过滤/排序/统计口径 parity。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime, Time, UtcOffset};

use crate::features::auth_audit::auth_event_repo::AuthEventRepo;
use crate::features::auth_audit::model::{
    AuthEventQuery, AuthEventRow, AuthEventType, AuthKpi, AuthStats, FailureReason, IpStat,
    NewAuthEvent, ReasonCount, StatBucket, TypeCount,
};
use crate::kernel::app_error::AppError;
use crate::kernel::pagination::{OffsetPosition, Page, PageParams};
use crate::kernel::time_range::TimeRange;

/// 认证事件仓储的内存实现(脚手架默认 / 测试替身)。只追加,保留期 job 删旧行。
#[derive(Default)]
pub struct InMemoryAuthEventRepo {
    rows: Mutex<Vec<NewAuthEvent>>,
}

impl InMemoryAuthEventRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 测试辅助:当前落库条数。
    ///
    /// # Panics
    ///
    /// 内部锁中毒(别的线程持锁时 panic)时 panic。
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.lock().expect("锁未中毒").len()
    }

    /// 还没有任何落库行。
    ///
    /// # Panics
    ///
    /// 内部锁中毒(别的线程持锁时 panic)时 panic。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.lock().expect("锁未中毒").is_empty()
    }
}

/// 按小时取整(镜像 SQL `date_trunc('hour', ...)`)。
///
/// **先归一到 UTC 再截断**:截断是"抹掉分秒",结果取决于 `timestamp` 自己带的时区偏移。而 `?from`/`?to`
/// 经 rfc3339 反序列化会**保留客户端给的偏移**(`+05:30`),事件的 `occurred_at` 却恒是 UTC ——
/// 不归一就会一边落在 `:30`、一边落在 `:00`,桶与事件永不相等(半小时制时区整条 activity 全零)。
/// PG 侧 `date_trunc('hour', $1::timestamptz)` 在(UTC 的)会话时区里截断,与此同口径。
pub(crate) fn floor_hour(timestamp: OffsetDateTime) -> OffsetDateTime {
    let timestamp = timestamp.to_offset(UtcOffset::UTC);
    timestamp.replace_time(Time::from_hms(timestamp.hour(), 0, 0).expect("hour 0-23 恒合法"))
}

/// 某行是否命中列表过滤(与 PG 的 `apply_filters` 同口径)。`needle` = 联合模糊搜的针(已 trim + 小写,
/// 空串已滤掉),与 pg 的 ILIKE 子串同口径(parity)。
fn matches_query(event: &NewAuthEvent, query: &AuthEventQuery, needle: Option<&str>) -> bool {
    let contains_needle = |needle: &str| {
        let has = |value: Option<&str>| value.is_some_and(|v| v.to_lowercase().contains(needle));
        has(event.actor.as_deref())
            || has(event.identifier_attempted.as_deref())
            || event
                .ip
                .is_some_and(|ip| ip.to_string().to_lowercase().contains(needle))
    };
    query.user_id.is_none_or(|u| event.user_id == Some(u))
        && query
            .event_type
            .is_none_or(|t| event.event_type == t.as_str())
        && query.outcome.is_none_or(|o| event.outcome == o.as_str())
        && needle.is_none_or(contains_needle)
        && query.ip.is_none_or(|ip| event.ip == Some(ip))
        && query.from.is_none_or(|from| event.occurred_at >= from)
        && query.to.is_none_or(|to| event.occurred_at < to)
}

/// 单个 IP 的计数累加器(`stats` 的 top_ips 用)。
#[derive(Default)]
struct IpTally {
    total: i64,
    failures: i64,
}

#[async_trait]
impl AuthEventRepo for InMemoryAuthEventRepo {
    async fn insert(&self, event: &NewAuthEvent) -> Result<bool, AppError> {
        let mut rows = self.rows.lock().expect("锁未中毒");
        if rows
            .iter()
            .any(|r| r.event_sequence == event.event_sequence)
        {
            return Ok(false); // 幂等:重投不重复、不再发布
        }
        rows.push(event.clone());
        Ok(true)
    }

    async fn list(
        &self,
        query: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        let rows = self.rows.lock().expect("锁未中毒");
        let needle: Option<String> = query
            .query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let mut items: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| matches_query(r, query, needle.as_deref()))
            .collect();
        items.sort_by(|a, b| b.id.cmp(&a.id)); // id v7 DESC
        let out: Vec<AuthEventRow> = items
            .iter()
            .map(|event| {
                AuthEventRow::try_from(*event).expect("闭集串恒合法(仅由本仓 emit/投影校验后写入)")
            })
            .collect();
        match page {
            PageParams::Offset {
                page,
                size,
                with_total,
            } => {
                let total = if with_total {
                    Some(out.len() as u64)
                } else {
                    None
                };
                let start = ((page.saturating_sub(1)) * size) as usize;
                let slice = out.into_iter().skip(start).take(size as usize).collect();
                Ok(Page::new_with_offset(
                    slice,
                    OffsetPosition { page, size },
                    total,
                ))
            }
            PageParams::Cursor { after, limit } => {
                // keyset 恒按 id DESC(v7 id 即创建序倒序);id < after 配 ORDER BY id DESC(parity 于 PG)。
                let mut rows: Vec<AuthEventRow> = out
                    .into_iter()
                    .filter(|r| after.is_none_or(|a| r.id < a))
                    .take(limit as usize + 1)
                    .collect();
                let has_more = rows.len() as u64 > limit;
                let next = if has_more {
                    rows.truncate(limit as usize);
                    rows.last().map(|r| r.id)
                } else {
                    None
                };
                Ok(Page::new_with_cursor(rows, limit, next))
            }
        }
    }

    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let mut rows = self.rows.lock().expect("锁未中毒");
        let before = rows.len();
        rows.retain(|r| r.occurred_at >= cutoff);
        Ok((before - rows.len()) as u64)
    }

    /// 单测用直白聚合(非 SQL);语义镜像 `PgAuthEventRepo::stats` 的五条查询。
    async fn stats(&self, range: TimeRange) -> Result<AuthStats, AppError> {
        let TimeRange { from, to } = range;
        let rows = self.rows.lock().expect("锁未中毒");
        let in_range: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| r.occurred_at >= from && r.occurred_at < to)
            .collect();

        // activity:小时桶零填充,区间同 SQL 的 generate_series(两端含)。
        let mut activity = Vec::new();
        let mut hour = floor_hour(from);
        let end = floor_hour(to);
        while hour <= end {
            let (success, failure) = in_range
                .iter()
                .filter(|r| floor_hour(r.occurred_at) == hour)
                .fold(
                    (0i64, 0i64),
                    |(success_count, failure_count), event| match event.outcome.as_str() {
                        "success" => (success_count + 1, failure_count),
                        "failure" => (success_count, failure_count + 1),
                        _ => (success_count, failure_count),
                    },
                );
            activity.push(StatBucket {
                bucket_start: hour,
                success,
                failure,
            });
            hour += Duration::hours(1);
        }

        let mut reason_counts: HashMap<FailureReason, i64> = HashMap::new();
        let failures = in_range.iter().filter(|r| r.outcome == "failure");
        for event in failures {
            if let Some(reason) = &event.failure_reason {
                let key: FailureReason = reason
                    .parse()
                    .expect("failure_reason 恒为 FailureReason 已知取值(仅由本仓 emit 写入)");
                *reason_counts.entry(key).or_insert(0) += 1;
            }
        }
        let mut reasons: Vec<ReasonCount> = reason_counts
            .into_iter()
            .map(|(key, count)| ReasonCount { key, count })
            .collect();
        reasons.sort_by(|a, b| b.count.cmp(&a.count));

        let mut type_counts: HashMap<AuthEventType, i64> = HashMap::new();
        for event in in_range.iter() {
            let key: AuthEventType = event
                .event_type
                .parse()
                .expect("event_type 恒为 AuthEventType 已知取值(仅由本仓 emit 写入)");
            *type_counts.entry(key).or_insert(0) += 1;
        }
        let mut types: Vec<TypeCount> = type_counts
            .into_iter()
            .map(|(key, count)| TypeCount { key, count })
            .collect();
        types.sort_by(|a, b| b.count.cmp(&a.count));

        let mut ip_stats: HashMap<String, IpTally> = HashMap::new();
        for event in in_range.iter() {
            if let Some(ip) = event.ip {
                let tally = ip_stats.entry(ip.to_string()).or_default();
                tally.total += 1;
                if event.outcome == "failure" {
                    tally.failures += 1;
                }
            }
        }
        let mut top_ips: Vec<IpStat> = ip_stats
            .into_iter()
            .map(|(ip, tally)| IpStat {
                ip,
                failures: tally.failures,
                total: tally.total,
            })
            .collect();
        top_ips.sort_by(|a, b| b.failures.cmp(&a.failures).then(b.total.cmp(&a.total)));
        top_ips.truncate(6);

        let total = in_range.len() as i64;
        let failed = in_range.iter().filter(|r| r.outcome == "failure").count() as i64;
        let distinct_ips: HashSet<IpAddr> = in_range.iter().filter_map(|r| r.ip).collect();
        let unique_ips = distinct_ips.len() as i64;
        let success_rate = if total > 0 {
            (total - failed) as f64 / total as f64
        } else {
            1.0
        };

        // 环比:上个等长窗口 [previous_from, from),语义镜像 `PgAuthEventRepo::stats`。
        let previous_from = from - (to - from);
        let previous_in_range: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| r.occurred_at >= previous_from && r.occurred_at < from)
            .collect();
        let previous_total = previous_in_range.len() as i64;
        let previous_failed = previous_in_range
            .iter()
            .filter(|r| r.outcome == "failure")
            .count() as i64;
        let total_delta = if previous_total > 0 {
            (total - previous_total) as f64 / previous_total as f64
        } else {
            0.0
        };
        let failed_delta = if previous_failed > 0 {
            (failed - previous_failed) as f64 / previous_failed as f64
        } else {
            0.0
        };

        Ok(AuthStats {
            activity,
            reasons,
            types,
            top_ips,
            kpi: AuthKpi {
                total_events: total,
                failed_count: failed,
                unique_ips,
                success_rate,
                total_delta,
                failed_delta,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::pagination::PageParams;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn new_event(sequence: i64, user: Option<Uuid>) -> NewAuthEvent {
        NewAuthEvent {
            id: Uuid::now_v7(),
            event_type: "auth.login_succeeded".into(),
            occurred_at: OffsetDateTime::now_utc(),
            channel: "public".into(),
            auth_method: "password".into(),
            user_id: user,
            identifier_attempted: None,
            session_id: Some(Uuid::now_v7()),
            actor: user.map(|u| u.to_string()),
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

    #[tokio::test]
    async fn insert_is_idempotent_and_list_filters_by_user() {
        let repo = InMemoryAuthEventRepo::new();
        let alice = Uuid::now_v7();
        repo.insert(&new_event(1, Some(alice))).await.unwrap();
        repo.insert(&new_event(1, Some(alice))).await.unwrap(); // 同 seq 重投 → 无第二行
        repo.insert(&new_event(2, Some(Uuid::now_v7())))
            .await
            .unwrap();

        let query = AuthEventQuery {
            user_id: Some(alice),
            ..Default::default()
        };
        let page = repo
            .list(
                &query,
                PageParams::Offset {
                    page: 1,
                    size: 20,
                    with_total: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            page.items.len(),
            1,
            "同 seq 去重 + 按 user 过滤只剩 alice 一行"
        );
    }

    #[tokio::test]
    async fn delete_older_than_removes_only_stale_rows() {
        let repo = InMemoryAuthEventRepo::new();
        let now = OffsetDateTime::now_utc();

        let mut stale = new_event(1, Some(Uuid::now_v7()));
        stale.occurred_at = now - time::Duration::days(91);
        let recent = new_event(2, Some(Uuid::now_v7()));

        repo.insert(&stale).await.unwrap();
        repo.insert(&recent).await.unwrap();

        let deleted = repo
            .delete_older_than(now - time::Duration::days(90))
            .await
            .unwrap();
        assert_eq!(deleted, 1, "只应删掉 91 天前那条");
        assert_eq!(repo.len(), 1, "剩下的应只有近期那条");
    }

    #[tokio::test]
    async fn stats_aggregates_activity_reasons_and_kpi() {
        let repo = InMemoryAuthEventRepo::new();
        let hour0 = floor_hour(OffsetDateTime::now_utc());
        let hour1 = hour0 + time::Duration::hours(1);

        let mut success_event = new_event(1, Some(Uuid::now_v7()));
        success_event.occurred_at = hour0 + time::Duration::minutes(5);
        success_event.ip = Some("10.0.0.1".parse().unwrap());

        let mut bad_password_event = new_event(2, Some(Uuid::now_v7()));
        bad_password_event.occurred_at = hour0 + time::Duration::minutes(10);
        bad_password_event.outcome = "failure".into();
        bad_password_event.failure_reason = Some("bad_password".into());
        bad_password_event.ip = Some("10.0.0.1".parse().unwrap());

        let mut unknown_user_event = new_event(3, Some(Uuid::now_v7()));
        unknown_user_event.occurred_at = hour1 + time::Duration::minutes(5);
        unknown_user_event.outcome = "failure".into();
        unknown_user_event.failure_reason = Some("unknown_user".into());
        unknown_user_event.ip = Some("10.0.0.2".parse().unwrap());

        // 落在上一个等长窗口([previous_from, hour0))的一条失败事件,用来喂环比分母(否则
        // previous_total/previous_failed 恒 0,delta 分支测不到)。
        let mut previous_window_event = new_event(4, Some(Uuid::now_v7()));
        previous_window_event.occurred_at = hour0 - time::Duration::minutes(30);
        previous_window_event.outcome = "failure".into();
        previous_window_event.failure_reason = Some("bad_password".into());

        for event in [
            &success_event,
            &bad_password_event,
            &unknown_user_event,
            &previous_window_event,
        ] {
            repo.insert(event).await.unwrap();
        }

        // 上界取 hour1+1h(整点),覆盖 hour1 的事件,同时零填充出一个空的第 3 桶。
        let stats = repo
            .stats(TimeRange {
                from: hour0,
                to: hour1 + time::Duration::hours(1),
            })
            .await
            .unwrap();

        assert_eq!(stats.activity.len(), 3, "hour0/hour1/hour2 三个零填充桶");
        let bucket0 = stats
            .activity
            .iter()
            .find(|b| b.bucket_start == hour0)
            .unwrap();
        assert_eq!((bucket0.success, bucket0.failure), (1, 1));
        let bucket1 = stats
            .activity
            .iter()
            .find(|b| b.bucket_start == hour1)
            .unwrap();
        assert_eq!((bucket1.success, bucket1.failure), (0, 1));

        assert_eq!(stats.reasons.len(), 2);
        assert!(stats
            .reasons
            .iter()
            .any(|r| r.key == FailureReason::BadPassword && r.count == 1));
        assert!(stats
            .reasons
            .iter()
            .any(|r| r.key == FailureReason::UnknownUser && r.count == 1));

        assert_eq!(stats.types.len(), 1, "三条都是 auth.login_succeeded");
        assert_eq!(stats.types[0].count, 3);

        assert_eq!(stats.top_ips.len(), 2);
        let ip1 = stats.top_ips.iter().find(|i| i.ip == "10.0.0.1").unwrap();
        assert_eq!((ip1.total, ip1.failures), (2, 1));

        assert_eq!(stats.kpi.total_events, 3);
        assert_eq!(stats.kpi.failed_count, 2);
        assert_eq!(stats.kpi.unique_ips, 2);
        assert!(
            (stats.kpi.success_rate - (1.0 / 3.0)).abs() < 1e-9,
            "1 成功 / 3 总数"
        );
        // 上个窗口(previous_window_event)1 条、1 条失败;当前窗口 3 条、2 条失败。
        assert!((stats.kpi.total_delta - 2.0).abs() < 1e-9, "(3-1)/1 = 2.0");
        assert!((stats.kpi.failed_delta - 1.0).abs() < 1e-9, "(2-1)/1 = 1.0");
    }

    /// **半小时制时区的窗口不能把 activity 打成全零**。`?from`/`?to` 经 rfc3339 反序列化会保留
    /// 客户端偏移(`+05:30`),而 `occurred_at` 恒 UTC:截断若在各自偏移里做,桶落 `:30`、事件落
    /// `:00`,`floor_hour(occurred_at) == hour` 永不成立 —— kpi 有数、activity 全零。
    /// PG 的 `date_trunc` 在 UTC 会话时区截断,不受偏移影响,故这也是内存↔PG 的口径分叉。
    #[tokio::test]
    async fn stats_buckets_align_to_utc_hour_for_fractional_offset_bounds() {
        let repo = InMemoryAuthEventRepo::new();
        let hour = floor_hour(OffsetDateTime::now_utc());
        let mut event = new_event(1, Some(Uuid::now_v7()));
        event.occurred_at = hour + time::Duration::minutes(5);
        repo.insert(&event).await.unwrap();

        // 同样的时刻,换成客户端的 +05:30 表示(仅偏移不同,instant 不变)。
        let offset = time::UtcOffset::from_hms(5, 30, 0).unwrap();
        let from = (hour - time::Duration::minutes(30)).to_offset(offset);
        let to = (hour + time::Duration::hours(1)).to_offset(offset);
        let stats = repo.stats(TimeRange { from, to }).await.unwrap();

        assert!(
            stats.activity.iter().all(|b| b.bucket_start.minute() == 0),
            "桶必须对齐整点(而非跟着 from 的 :30 偏移走): {:?}",
            stats
                .activity
                .iter()
                .map(|b| b.bucket_start)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            stats.activity.iter().map(|b| b.success).sum::<i64>(),
            1,
            "事件必须落进某个桶;全零 = 桶与事件因偏移错位对不上"
        );
    }
}

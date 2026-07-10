use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use time::{OffsetDateTime, Time};

use super::super::types::{
    AuthEventQuery, AuthEventRow, AuthEventType, AuthKpi, AuthStats, FailureReason, IpStat,
    NewAuthEvent, ReasonCount, StatBucket, TypeCount,
};
use super::AuthEventRepo;
use crate::infra::error::AppError;
use crate::infra::pagination::{Page, PageParams};

#[derive(Default)]
pub struct InMemoryAuthEventRepo {
    rows: Mutex<Vec<NewAuthEvent>>,
}
impl InMemoryAuthEventRepo {
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
        }
    }
    /// 测试辅助:当前落库条数。
    pub fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.lock().unwrap().is_empty()
    }
}

/// 按小时取整(镜像 SQL `date_trunc('hour', ...)`);projector 发布行也复用这份 to_row。
pub(crate) fn floor_hour(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_time(Time::from_hms(t.hour(), 0, 0).expect("hour 0-23 恒合法"))
}

pub(crate) fn to_row(e: &NewAuthEvent) -> AuthEventRow {
    AuthEventRow {
        id: e.id,
        // event_type 只由本仓 auth::emit 写入,恒是 AuthEventType 的合法串(pg 侧走 sqlx::Type
        // 的 Decode 走不到这里;这里 parse 失败 = 数据异常,炸出来而非静默吞掉,见 types.rs 头注)。
        event_type: e
            .event_type
            .parse()
            .expect("event_type 恒为 AuthEventType 已知取值(仅由本仓 emit 写入)"),
        occurred_at: e.occurred_at,
        // channel/outcome/failure_reason:同 event_type,恒为本仓 emit 产出的合法串,见 types.rs 头注。
        channel: e
            .channel
            .parse()
            .expect("channel 恒为 AuthChannel 已知取值(仅由本仓 emit 写入)"),
        user_id: e.user_id,
        identifier_attempted: e.identifier_attempted.clone(),
        session_id: e.session_id,
        actor: e.actor.clone(),
        outcome: e
            .outcome
            .parse()
            .expect("outcome 恒为 AuthOutcome 已知取值(仅由本仓 emit 写入)"),
        failure_reason: e.failure_reason.as_deref().map(|r| {
            r.parse()
                .expect("failure_reason 恒为 FailureReason 已知取值(仅由本仓 emit 写入)")
        }),
        ip: e.ip.map(|i| i.to_string()),
        user_agent: e.user_agent.clone(),
        country: None,
        city: None,
        os: None,
        browser: None,
    }
}

#[async_trait]
impl AuthEventRepo for InMemoryAuthEventRepo {
    async fn insert(&self, ev: &NewAuthEvent) -> Result<(), AppError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.event_seq == ev.event_seq) {
            return Ok(()); // 幂等
        }
        rows.push(ev.clone());
        Ok(())
    }

    async fn list(
        &self,
        f: &AuthEventQuery,
        page: PageParams,
    ) -> Result<Page<AuthEventRow>, AppError> {
        let rows = self.rows.lock().unwrap();
        let mut items: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| f.user_id.is_none_or(|u| r.user_id == Some(u)))
            .filter(|r| f.event_type.is_none_or(|t| r.event_type == t.as_str()))
            .filter(|r| f.outcome.is_none_or(|o| r.outcome == o.as_str()))
            .collect();
        items.sort_by(|a, b| b.id.cmp(&a.id)); // id v7 DESC
        let out: Vec<AuthEventRow> = items.iter().map(|e| to_row(e)).collect();
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
                Ok(Page::offset(slice, page, size, total))
            }
            PageParams::Cursor { limit, .. } => {
                let slice: Vec<_> = out.into_iter().take(limit as usize).collect();
                Ok(Page::cursor(slice, limit, None))
            }
        }
    }

    async fn delete_older_than(&self, cutoff: OffsetDateTime) -> Result<u64, AppError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| r.occurred_at >= cutoff);
        Ok((before - rows.len()) as u64)
    }

    /// 单测用直白聚合(非 SQL);语义镜像 `PgAuthEventRepo::stats` 的五条查询。
    async fn stats(&self, from: OffsetDateTime, to: OffsetDateTime) -> Result<AuthStats, AppError> {
        let rows = self.rows.lock().unwrap();
        let in_range: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| r.occurred_at >= from && r.occurred_at < to)
            .collect();

        // activity:小时桶零填充,区间同 SQL 的 generate_series(两端含)。
        let mut activity = Vec::new();
        let mut t = floor_hour(from);
        let end = floor_hour(to);
        while t <= end {
            let (success, failure) = in_range
                .iter()
                .filter(|r| floor_hour(r.occurred_at) == t)
                .fold((0i64, 0i64), |(s, f), r| match r.outcome.as_str() {
                    "success" => (s + 1, f),
                    "failure" => (s, f + 1),
                    _ => (s, f),
                });
            activity.push(StatBucket {
                t,
                success,
                failure,
            });
            t += time::Duration::hours(1);
        }

        let mut reason_counts: HashMap<FailureReason, i64> = HashMap::new();
        for r in in_range.iter().filter(|r| r.outcome == "failure") {
            if let Some(reason) = &r.failure_reason {
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
        for r in in_range.iter() {
            let key: AuthEventType = r
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

        let mut ip_stats: HashMap<String, (i64, i64)> = HashMap::new(); // ip -> (total, failures)
        for r in in_range.iter() {
            if let Some(ip) = r.ip {
                let entry = ip_stats.entry(ip.to_string()).or_insert((0, 0));
                entry.0 += 1;
                if r.outcome == "failure" {
                    entry.1 += 1;
                }
            }
        }
        let mut top_ips: Vec<IpStat> = ip_stats
            .into_iter()
            .map(|(ip, (total, failures))| IpStat {
                ip,
                failures,
                total,
            })
            .collect();
        top_ips.sort_by(|a, b| b.failures.cmp(&a.failures).then(b.total.cmp(&a.total)));
        top_ips.truncate(6);

        let total = in_range.len() as i64;
        let failed = in_range.iter().filter(|r| r.outcome == "failure").count() as i64;
        let unique_ips = in_range
            .iter()
            .filter_map(|r| r.ip)
            .collect::<HashSet<_>>()
            .len() as i64;
        let success_rate = if total > 0 {
            (total - failed) as f64 / total as f64
        } else {
            1.0
        };

        // 环比:上个等长窗口 [prev_from, from),语义镜像 `PgAuthEventRepo::stats`。
        let prev_from = from - (to - from);
        let prev_in_range: Vec<&NewAuthEvent> = rows
            .iter()
            .filter(|r| r.occurred_at >= prev_from && r.occurred_at < from)
            .collect();
        let prev_total = prev_in_range.len() as i64;
        let prev_failed = prev_in_range
            .iter()
            .filter(|r| r.outcome == "failure")
            .count() as i64;
        let total_delta = if prev_total > 0 {
            (total - prev_total) as f64 / prev_total as f64
        } else {
            0.0
        };
        let failed_delta = if prev_failed > 0 {
            (failed - prev_failed) as f64 / prev_failed as f64
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
    use crate::infra::pagination::PageParams;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn ev(seq: i64, user: Option<Uuid>) -> NewAuthEvent {
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
            event_seq: seq,
        }
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_list_filters_by_user() {
        let repo = InMemoryAuthEventRepo::new();
        let alice = Uuid::now_v7();
        repo.insert(&ev(1, Some(alice))).await.unwrap();
        repo.insert(&ev(1, Some(alice))).await.unwrap(); // 同 seq 重投 → 无第二行
        repo.insert(&ev(2, Some(Uuid::now_v7()))).await.unwrap();

        let q = AuthEventQuery {
            user_id: Some(alice),
            ..Default::default()
        };
        let page = repo
            .list(
                &q,
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

        let mut stale = ev(1, Some(Uuid::now_v7()));
        stale.occurred_at = now - time::Duration::days(91);
        let recent = ev(2, Some(Uuid::now_v7()));

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

        let mut success_ev = ev(1, Some(Uuid::now_v7()));
        success_ev.occurred_at = hour0 + time::Duration::minutes(5);
        success_ev.ip = Some("10.0.0.1".parse().unwrap());

        let mut bad_password_ev = ev(2, Some(Uuid::now_v7()));
        bad_password_ev.occurred_at = hour0 + time::Duration::minutes(10);
        bad_password_ev.outcome = "failure".into();
        bad_password_ev.failure_reason = Some("bad_password".into());
        bad_password_ev.ip = Some("10.0.0.1".parse().unwrap());

        let mut unknown_user_ev = ev(3, Some(Uuid::now_v7()));
        unknown_user_ev.occurred_at = hour1 + time::Duration::minutes(5);
        unknown_user_ev.outcome = "failure".into();
        unknown_user_ev.failure_reason = Some("unknown_user".into());
        unknown_user_ev.ip = Some("10.0.0.2".parse().unwrap());

        // 落在上一个等长窗口([prev_from, hour0))的一条失败事件,用来喂环比分母(否则
        // prev_total/prev_failed 恒 0,delta 分支测不到)。
        let mut prev_window_ev = ev(4, Some(Uuid::now_v7()));
        prev_window_ev.occurred_at = hour0 - time::Duration::minutes(30);
        prev_window_ev.outcome = "failure".into();
        prev_window_ev.failure_reason = Some("bad_password".into());

        for e in [
            &success_ev,
            &bad_password_ev,
            &unknown_user_ev,
            &prev_window_ev,
        ] {
            repo.insert(e).await.unwrap();
        }

        // 上界取 hour1+1h(整点),覆盖 hour1 的事件,同时零填充出一个空的第 3 桶。
        let stats = repo
            .stats(hour0, hour1 + time::Duration::hours(1))
            .await
            .unwrap();

        assert_eq!(stats.activity.len(), 3, "hour0/hour1/hour2 三个零填充桶");
        let bucket0 = stats.activity.iter().find(|b| b.t == hour0).unwrap();
        assert_eq!((bucket0.success, bucket0.failure), (1, 1));
        let bucket1 = stats.activity.iter().find(|b| b.t == hour1).unwrap();
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
        // 上个窗口(prev_window_ev)1 条、1 条失败;当前窗口 3 条、2 条失败。
        assert!((stats.kpi.total_delta - 2.0).abs() < 1e-9, "(3-1)/1 = 2.0");
        assert!((stats.kpi.failed_delta - 1.0).abs() < 1e-9, "(2-1)/1 = 1.0");
    }
}

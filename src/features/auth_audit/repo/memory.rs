use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::super::types::{AuthEventQuery, AuthEventRow, NewAuthEvent};
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

fn to_row(e: &NewAuthEvent) -> AuthEventRow {
    AuthEventRow {
        id: e.id,
        event_type: e.event_type.clone(),
        occurred_at: e.occurred_at,
        channel: e.channel.clone(),
        user_id: e.user_id,
        identifier_attempted: e.identifier_attempted.clone(),
        session_id: e.session_id,
        outcome: e.outcome.clone(),
        failure_reason: e.failure_reason.clone(),
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
            .filter(|r| f.event_type.as_ref().is_none_or(|t| &r.event_type == t))
            .filter(|r| f.outcome.as_ref().is_none_or(|o| &r.outcome == o))
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
}

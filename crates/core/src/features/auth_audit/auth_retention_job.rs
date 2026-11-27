//! auth_event 90 天保留:周期 DELETE occurred_at < now()-90d。审计 append-only,靠删旧控量。

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::time as tokio_time;

use super::auth_event_repo::AuthEventRepo;

const RETENTION_DAYS: i64 = 90;

/// 认证审计保留期后台任务:每 6 小时删一次超过 90 天的 auth_event 行。
pub struct AuthRetentionJob {
    repo: Arc<dyn AuthEventRepo>,
    interval: Duration,
}

impl AuthRetentionJob {
    pub fn new(repo: Arc<dyn AuthEventRepo>) -> Self {
        Self {
            repo,
            interval: Duration::from_secs(6 * 3600), // 每 6h 扫一次
        }
    }

    /// 后台循环:删过期行 → 睡 `interval` 或等 shutdown。`shutdown` 置位或发送端被丢弃都视为退出。
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            let cutoff = OffsetDateTime::now_utc() - time::Duration::days(RETENTION_DAYS);
            match self.repo.delete_older_than(cutoff).await {
                Ok(deleted) if deleted > 0 => tracing::info!(deleted, "auth_event 保留:删除过期行"),
                Ok(_) => {}
                Err(error) => tracing::warn!(error = %error, "auth_event 保留删除失败,下轮重试"),
            }
            tokio::select! {
                _ = tokio_time::sleep(self.interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

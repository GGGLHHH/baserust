//! 依赖探针:本进程持有的各 schema 连接池 + NATS 连接。`/readyz` 与后台监控页用它逐项检查依赖、
//! 读连接池占用(`app::monitoring`)。内存模式下为空(恒就绪)。

use std::time::{Duration, Instant};

use sqlx::PgPool;

/// 单项检查结果。
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub name: String,
    pub ok: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Clone, Default)]
pub struct Probes {
    pools: Vec<(&'static str, PgPool)>,
    nats: Option<async_nats::Client>,
}

/// 单项检查超时:依赖慢到这个程度,对放流量来说就等于挂了。
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

impl Probes {
    pub fn new(pools: Vec<(&'static str, PgPool)>, nats: Option<async_nats::Client>) -> Self {
        Self { pools, nats }
    }

    /// 并发检查全部依赖:每个连接池 `select 1`、NATS 连接状态。每项 2s 超时。
    pub async fn check(&self) -> Vec<ProbeResult> {
        let pools = self.pools.iter().map(|(name, pool)| async move {
            let started = Instant::now();
            let res =
                tokio::time::timeout(PROBE_TIMEOUT, sqlx::query("select 1").execute(pool)).await;
            let error = match res {
                Ok(Ok(_)) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("超时".to_owned()),
            };
            ProbeResult {
                name: format!("db_{name}"),
                ok: error.is_none(),
                latency_ms: started.elapsed().as_millis() as u64,
                error,
            }
        });
        let mut out = futures_util::future::join_all(pools).await;
        if let Some(client) = &self.nats {
            let state = client.connection_state();
            let ok = matches!(state, async_nats::connection::State::Connected);
            out.push(ProbeResult {
                name: "nats".to_owned(),
                ok,
                latency_ms: 0,
                error: (!ok).then(|| format!("{state:?}")),
            });
        }
        out
    }

    /// 各连接池当前占用(监控页 / 采样用)。
    pub fn pool_stats(&self) -> Vec<crate::infra::monitor::report::PoolStatus> {
        self.pools
            .iter()
            .map(|(name, pool)| {
                let size = pool.size();
                let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
                crate::infra::monitor::report::PoolStatus {
                    name: (*name).to_owned(),
                    size,
                    idle,
                    in_use: size.saturating_sub(idle),
                    max: pool.options().get_max_connections(),
                }
            })
            .collect()
    }

    /// 报连接池占用到 `/metrics`(开了 metrics 时由采样任务定时调用)。
    pub fn record_pool_metrics(&self) {
        use crate::infra::telemetry::{DB_POOL_CONNECTIONS, DB_POOL_MAX};
        for (name, pool) in &self.pools {
            let size = pool.size() as f64;
            let idle = pool.num_idle() as f64;
            let name = *name;
            metrics::gauge!(DB_POOL_CONNECTIONS, "pool" => name, "state" => "idle").set(idle);
            metrics::gauge!(DB_POOL_CONNECTIONS, "pool" => name, "state" => "in_use")
                .set(size - idle);
            metrics::gauge!(DB_POOL_MAX, "pool" => name)
                .set(pool.options().get_max_connections() as f64);
        }
    }
}

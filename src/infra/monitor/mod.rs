//! **进程内监控**:后台「系统监控」页的数据源(`GET /api/v1/admin/monitoring`)。不依赖任何外部组件。
//!
//! - **请求**:中间件 [`track_requests`] 按路由模板记请求数 / 4xx / 5xx / 延迟直方图;
//! - **数据库**:[`DbTimingLayer`](tracing layer)给仓储方法上的 `pg.*` span 计时;
//! - **后台任务**:outbox relay、projector、SSE 连接经 `infra::telemetry` 的埋点函数写进来;
//! - **进程**:内存 / CPU / 线程 / 文件句柄(`metrics-process` 的采集函数)。
//!
//! 全部是累计值。采样任务每 [`SAMPLE_INTERVAL`] 存一份**累计快照**,环形保留 [`RETENTION`];
//! 窗口统计 = 当前累计 − 最老快照,历史曲线 = 相邻快照之差。进程重启即清空(只做"现在怎么样",
//! 不做长期留存)。进程全局单例([`global`]):埋点处(中间件、tracing layer、后台循环)拿不到 AppState。
//!
//! 全项目的**锁中毒策略**(状态可丢弃 → 丢弃中毒状态、换新、清标记;绝不读中毒数据、不 panic)
//! 写在 [`lock_or_reset`] 上;保护可丢弃状态的 `Mutex` 都经它取锁。

mod db_timing_layer;
pub mod histogram;
pub mod logs;
#[allow(
    clippy::module_inception,
    reason = "指南要求叶子模块按主要条目 `Monitor` 命名,而非叶子模块 `monitor` 只放声明与 re-export"
)]
mod monitor;
pub mod pg_ops_store;
pub mod report;
pub mod store;

pub use self::db_timing_layer::DbTimingLayer;
pub use self::histogram::Histogram;
pub(crate) use self::monitor::lock_or_reset;
pub use self::monitor::{
    global, track_requests, ConsumerBacklog, InFlightGuard, Monitor, ProjectorOutcome,
    RequestOutcome, RETENTION, SAMPLE_INTERVAL, UNMATCHED_ROUTE,
};

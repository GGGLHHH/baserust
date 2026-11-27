//! 给仓储方法计时:仓储的每个 trait 方法都带 `#[tracing::instrument(name = "pg.<表>.<方法>")]`,
//! 这个 layer 在 span 建立时记下时刻、关闭时把耗时写进 [`super::Monitor`]。
//! 装配时配 `filter_fn` 只放行 `pg.*` span(见 `app::runtime::init_tracing`),与日志级别无关。

use std::time::Instant;

use tracing::{span, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// 数据库操作 span 的名字前缀。
pub const DB_SPAN_PREFIX: &str = "pg.";

/// 存在 span 扩展里的建立时刻。
struct StartedAt(Instant);

/// 数据库操作计时 layer:`pg.*` span 关闭时把耗时记进进程内监控。
pub struct DbTimingLayer;

impl DbTimingLayer {
    /// 只接 `pg.*` span 的过滤条件(per-layer filter 用)。
    #[must_use]
    pub fn wants(metadata: &Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name().starts_with(DB_SPAN_PREFIX)
    }
}

impl<S> Layer<S> for DbTimingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attributes: &span::Attributes<'_>,
        id: &span::Id,
        context: Context<'_, S>,
    ) {
        if !attributes.metadata().name().starts_with(DB_SPAN_PREFIX) {
            return;
        }
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(StartedAt(Instant::now()));
        }
    }

    fn on_close(&self, id: span::Id, context: Context<'_, S>) {
        let Some(span) = context.span(&id) else {
            return;
        };
        let started = span
            .extensions()
            .get::<StartedAt>()
            .map(|started_at| started_at.0);
        if let Some(started) = started {
            super::global().record_db(span.metadata().name(), started.elapsed());
        }
    }
}

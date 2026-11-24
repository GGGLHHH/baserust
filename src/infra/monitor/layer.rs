//! 给仓储方法计时:仓储的每个 trait 方法都带 `#[tracing::instrument(name = "pg.<表>.<方法>")]`,
//! 这个 layer 在 span 建立时记下时刻、关闭时把耗时写进 [`super::Monitor`]。
//! 装配时配 `filter_fn` 只放行 `pg.*` span(见 `app::runtime::init_tracing`),与日志级别无关。

use std::time::Instant;

use tracing::{span, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// 数据库操作 span 的名字前缀。
pub const DB_SPAN_PREFIX: &str = "pg.";

struct StartedAt(Instant);

pub struct DbTimingLayer;

impl DbTimingLayer {
    /// 只接 `pg.*` span 的过滤条件(per-layer filter 用)。
    pub fn wants(meta: &tracing::Metadata<'_>) -> bool {
        meta.is_span() && meta.name().starts_with(DB_SPAN_PREFIX)
    }
}

impl<S> Layer<S> for DbTimingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if !attrs.metadata().name().starts_with(DB_SPAN_PREFIX) {
            return;
        }
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(StartedAt(Instant::now()));
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let started = span.extensions().get::<StartedAt>().map(|s| s.0);
        if let Some(started) = started {
            super::global().record_db(span.metadata().name(), started.elapsed());
        }
    }
}

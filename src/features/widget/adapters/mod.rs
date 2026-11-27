//! widget 的**适配器**(外层):实现核心的端口(仓储 / 事件总线 / 用户目录的测试替身),
//! 或驱动核心(HTTP)。依赖只向内指:这里可以用核心的一切,核心不 import 这里。

pub mod bus;
pub mod http;
pub mod pg_widget_repo;

/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里按名重新导出。
pub use baserust_core::features::widget::{
    in_memory_widget_repo, memory_event_bus, static_user_directory,
};

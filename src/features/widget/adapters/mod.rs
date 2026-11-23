//! widget 的**适配器**(外层):实现核心的端口(仓储 / 事件总线 / 用户目录的测试替身),
//! 或驱动核心(HTTP)。依赖只向内指:这里可以用核心的一切,核心不 import 这里。

pub mod bus;
pub mod http;
/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里重新导出,路径不变。
pub use baserust_core::features::widget::memory;
pub mod postgres;

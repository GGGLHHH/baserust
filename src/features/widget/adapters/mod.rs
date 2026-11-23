//! widget 的**适配器**(外层):实现核心的端口(仓储 / 事件总线 / 用户目录的测试替身),
//! 或驱动核心(HTTP)。依赖只向内指:这里可以用核心的一切,核心不 import 这里。

pub mod bus;
pub mod http;
pub mod memory;
pub mod postgres;

//! users 的**适配器**(外层):HTTP(驱动侧)+ 富化目录的内存替身。身份写侧直接用 idm 领域库的
//! 端口与实现(组合根装配),跨模块端口的真实现(profile 富化 / search 投影)在 `app/adapters/`。

pub mod http;
/// 内存适配器是纯 Rust,住在核心 crate(核心单测要用它当假适配器);这里重新导出,路径不变。
pub use baserust_core::features::users::memory;

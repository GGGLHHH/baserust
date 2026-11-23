//! users 的**适配器**(外层):HTTP(驱动侧)+ 富化目录的内存替身。身份写侧直接用 idm 领域库的
//! 端口与实现(组合根装配),跨模块端口的真实现(profile 富化 / search 投影)在 `app/adapters/`。

pub mod http;
pub mod memory;

//! tenants 的**适配器**(外层):HTTP(驱动侧)+ 资料富化的内存替身。租户 / 成员 / 会话的写侧直接用 idm 领域库的
//! 端口与实现(组合根装配),跨模块端口的真实现(search 成员索引 / profile 富化)在 `app/adapters/`。

pub mod http;

/// 内存适配器是纯 Rust,住在核心 crate;这里按名重新导出。
pub use baserust_core::features::tenants::static_member_profiles;

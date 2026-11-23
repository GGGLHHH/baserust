//! 各业务模块的核心(模型 / 端口 / 用例 / 内存适配器)。content 与 auth 的核心在独立的领域库
//! (`content` / `idm`),主 crate 只有它们的 HTTP 适配器,故这里没有对应模块。

pub mod auth_audit;
pub mod profile;
pub mod search;
pub mod users;
pub mod widget;

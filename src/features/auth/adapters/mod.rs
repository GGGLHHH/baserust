//! auth 的**适配器**:
//! - `http`  认证端点、DTO、httponly cookie、鉴权中间件(驱动侧)
//! - `token` JWT 签发 / 校验 —— idm `TokenSigner` / `TokenVerifier` 端口的实现(被驱动侧)
//! - `emit`  认证审计事件 → idm 发件箱(被驱动侧)

pub mod emit;
pub mod http;
pub mod token;

//! auth 业务模块 —— **核心在 idm 领域库**(注册 / 登录 / 会话轮换 / 改密的用例与端口;零 HTTP)。
//! 本模块只有适配器:认证 HTTP 边界(端点 + DTO + 校验 + httponly cookie + 鉴权中间件)、
//! idm token 端口的 JWT 实现、审计事件发射。

pub mod adapters;

pub use adapters::http::dto::UserResponse;
pub use adapters::http::middleware::authenticate;
pub use adapters::http::{admin_login_router, admin_router, me_router, public_router};
pub use adapters::token::{AppTokenSigner, AppTokenVerifier, NoopSigner};

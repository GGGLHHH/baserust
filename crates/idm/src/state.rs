//! idm 的 HTTP state:router/middleware 的 `State<IdmState>`。持认证 service + cookie 标志。
//! app 单体 `nest` idm router 时构造它注入;idm 分进程入口也用它。

use crate::service::AuthService;

/// idm HTTP 层依赖容器。`Clone` 廉价(AuthService 内部全 Arc),axum 每请求 clone。
#[derive(Clone)]
pub struct IdmState {
    pub auth: AuthService,
    /// 认证 cookie 是否带 `Secure`(prod=true,仅 https 发送;dev http 必须 false)。
    pub cookie_secure: bool,
}

/// 鉴权中间件的依赖倒置端口:任何能提供 `AuthService` 的 state 都能挂 `authenticate`。
/// idm 的 `IdmState` 与 app 的 `AppState` 都 impl 它 —— app 中间件栈即可挂
/// `idm::authenticate::<AppState>`,authenticate 逻辑只此一份、两边共享。
pub trait HasAuth: Clone + Send + Sync + 'static {
    fn auth(&self) -> &AuthService;
}

impl HasAuth for IdmState {
    fn auth(&self) -> &AuthService {
        &self.auth
    }
}

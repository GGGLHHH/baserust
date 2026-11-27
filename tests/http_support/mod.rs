//! **黑盒 HTTP 验收测试**的公共件(`tests/http_*.rs` 用)。
//!
//! - 服务端:真实组合根 `AppState::try_new`(内存模式:不设任何 DB/NATS/S3 环境变量)+ 完整路由与中间件栈,
//!   绑 `127.0.0.1:0`。seed 建好 `superadmin` / `admin` / `user`(密码 `pwd`),不灌 mock 样本。
//! - 客户端:reqwest,**浏览器式会话**(cookie 存储:登录拿 httponly cookie,后续请求自动带上);
//!   也可用 Bearer 令牌(自铸降权令牌等场景)。
//! - **只有 [`serve`] 认识 web 框架**(现在是 axum)。换底座只换它,测试体原样当验收标准。
//!
//! 每个测试起独立服务(互不干扰);服务跑在测试自己的 tokio 运行时里,测试结束即停。

#![allow(
    dead_code,
    reason = "各 http_* 测试文件按需取用,单个测试 crate 里总有用不到的帮手"
)]

use baserust::app;
use bytes::Bytes;
use futures_util::Stream;
use reqwest::multipart::Form;
use reqwest::redirect;
use std::net::{SocketAddr, TcpListener};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::time;

use baserust::app::{AppState, Mount};
use baserust::features::auth::{AppTokenSigner, ScopedTenant};
use baserust::features::auth_audit::{AuthAuditService, AuthEventBus, InMemoryAuthEventRepo};
use baserust::infra::config::Config;
use baserust::kernel::authorization::Permission;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::Value;
use uuid::Uuid;

/// seed.toml 里的默认账号(密码都是 `pwd`)。都是默认租户的成员:superadmin(平台角色 superadmin +
/// 默认租户 admin)、admin(默认租户 admin)、user(默认租户 user)—— 登录即进默认租户。
pub const SUPERADMIN: &str = "superadmin";
/// 默认租户 admin 的账号名。
pub const ADMIN: &str = "admin";
/// 默认租户普通成员的账号名。
pub const USER: &str = "user";
/// seed 账号的公共密码。
pub const PASSWORD: &str = "pwd";

/// 默认租户(seed 的 `slug = "default"`,固定 id)。
pub const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

// ───────────────────────────── 唯一绑定框架的地方 ─────────────────────────────

/// 把 `state` 挂成完整应用(全部路由 + 中间件栈),在 `listener` 上开始服务。
/// **换 web 底座 = 换这个函数的实现**;签名(std TcpListener + AppState + Config)与框架无关。
fn serve(listener: TcpListener, state: AppState, config: &Config, mount: Mount) {
    let app = app::build_router(state, config, mount);
    listener.set_nonblocking(true).unwrap();
    let listener = TokioTcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
}

// ──────────────────────────────── 以下与框架无关 ────────────────────────────────

/// 测试配置:内存模式(零外部依赖)+ seed 账号 + **空** mock(干净起点)。
fn test_config() -> Config {
    Config {
        mock_file: Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/http_support/empty_mock.toml"
            )
            .to_owned(),
        ),
        ..Config::default()
    }
}

/// 一个跑起来的测试服务。
pub struct TestServer {
    /// 服务根地址,形如 `http://127.0.0.1:<端口>`。
    pub base: String,
    /// 认证审计读模型(内存)。生产里由 projector 从 JetStream 投影写入;黑盒测试直接经仓储造数据。
    pub auth_events: Arc<InMemoryAuthEventRepo>,
    /// 认证审计 SSE 总线(生产里 projector 落库后发布;测试直接发布)。
    pub auth_bus: AuthEventBus,
}

impl TestServer {
    /// 默认装配、单进程挂全部模块(`Mount::Both`)起服务。
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// 起服务前改装配(如换授权策略)。
    pub async fn start_with(customize: impl FnOnce(&mut AppState)) -> Self {
        Self::start_mounted(Mount::Both, customize).await
    }

    /// 换一份 mock 数据起服务(`tests/http_support/<file>`):演示租户 / 成员关系等经组合根的 mock 装进去,
    /// 测试体仍只走 HTTP。
    pub async fn start_with_mock(file: &str) -> Self {
        let config = Config {
            mock_file: Some(format!(
                "{}/tests/http_support/{file}",
                env!("CARGO_MANIFEST_DIR")
            )),
            ..test_config()
        };
        Self::start_config(config, Mount::Both, |_| {}).await
    }

    /// 按指定挂载范围起服务(默认 `Both` 单进程;分进程拓扑的场景用 `App` / `Idm`)。
    pub async fn start_mounted(mount: Mount, customize: impl FnOnce(&mut AppState)) -> Self {
        Self::start_config(test_config(), mount, customize).await
    }

    async fn start_config(
        config: Config,
        mount: Mount,
        customize: impl FnOnce(&mut AppState),
    ) -> Self {
        // 组合根装配或端口绑定失败都是测试环境问题,直接 panic。
        let mut state = AppState::try_new(&config, mount)
            .await
            .expect("内存模式装配")
            .state;
        // 内存模式不装审计后端(它读 search 库)→ 换内存实现,让审计端点也能黑盒覆盖。
        let auth_events = Arc::new(InMemoryAuthEventRepo::new());
        state.auth_audit = Some(AuthAuditService::new(auth_events.clone()));
        let auth_bus = AuthEventBus::new();
        state.auth_events_bus = Some(auth_bus.clone());
        customize(&mut state);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        serve(listener, state, &config, mount);
        Self {
            base: format!("http://{address}"),
            auth_events,
            auth_bus,
        }
    }

    /// 无凭据会话(带 cookie 存储:登录 / 注册后自动带 cookie)。
    pub fn anonymous(&self) -> Client {
        Client {
            base: self.base.clone(),
            http: reqwest::Client::builder()
                .no_proxy()
                .cookie_store(true)
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            bearer: None,
        }
    }

    /// 用 Bearer 令牌的会话(自铸令牌:降权 scope、任意主体)。
    pub fn bearer(&self, token: &str) -> Client {
        Client {
            bearer: Some(token.to_owned()),
            ..self.anonymous()
        }
    }

    /// 前台登录(`/public/auth/login`)→ 带 httponly cookie 的会话。seed 账号登录即进默认租户
    /// (token 带 `tenant_id` = [`DEFAULT_TENANT`] 和该租户里的角色)。
    ///
    /// # Panics
    ///
    /// 登录不是 200 时 panic(连同响应体)。
    pub async fn login(&self, identifier: &str, password: &str) -> Client {
        let client = self.anonymous();
        let response = client
            .post_json(
                "/api/v1/public/auth/login",
                &serde_json::json!({ "identifier": identifier, "password": password }),
            )
            .await;
        expect(response, StatusCode::OK).await;
        client
    }

    /// 后台登录(`/admin/auth/login`,要 `admin:login`)→ 带 cookie 的会话。
    ///
    /// # Panics
    ///
    /// 登录不是 200 时 panic(连同响应体)。
    pub async fn login_admin(&self, identifier: &str, password: &str) -> Client {
        let client = self.anonymous();
        let response = client
            .post_json(
                "/api/v1/admin/auth/login",
                &serde_json::json!({ "identifier": identifier, "password": password }),
            )
            .await;
        expect(response, StatusCode::OK).await;
        client
    }
}

/// 一个客户端会话。路径传 `/api/v1/...` 这样的绝对路径。
///
/// 发请求的便捷方法(`get` / `post_json` …)在网络层失败(连不上服务)时直接 panic:
/// 测试里这是环境故障,不是被测行为。
#[derive(Clone)]
pub struct Client {
    /// 服务根地址(同 [`TestServer::base`])。
    pub base: String,
    /// 底层 reqwest 客户端(带 cookie 存储、不跟随重定向)。
    pub http: reqwest::Client,
    /// 每个请求都带上的 Bearer 令牌(`None` = 只靠 cookie)。
    pub bearer: Option<String>,
}

impl Client {
    /// 任意请求(自己补 header / body);带上本会话的 Bearer(若有)。
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let builder = self.http.request(method, format!("{}{path}", self.base));
        match &self.bearer {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// 发 GET。
    pub async fn get(&self, path: &str) -> Response {
        self.request(Method::GET, path).send().await.unwrap()
    }

    /// 发无 body 的 DELETE。
    pub async fn delete(&self, path: &str) -> Response {
        self.request(Method::DELETE, path).send().await.unwrap()
    }

    /// 发无 body 的 POST。
    pub async fn post_empty(&self, path: &str) -> Response {
        self.request(Method::POST, path).send().await.unwrap()
    }

    /// 发 JSON body 的 POST。
    pub async fn post_json(&self, path: &str, body: &Value) -> Response {
        self.request(Method::POST, path)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    /// 发 JSON body 的 PUT。
    pub async fn put_json(&self, path: &str, body: &Value) -> Response {
        self.request(Method::PUT, path)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    /// 发 JSON body 的 DELETE。
    pub async fn delete_json(&self, path: &str, body: &Value) -> Response {
        self.request(Method::DELETE, path)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    /// 发 multipart 表单的 POST(上传)。
    pub async fn post_multipart(&self, path: &str, form: Form) -> Response {
        self.request(Method::POST, path)
            .multipart(form)
            .send()
            .await
            .unwrap()
    }
}

// ───────────────────────────── 断言帮手 ─────────────────────────────

/// 断言状态码,失败时把响应体一起打出来(黑盒排障全靠它)。返回 body 文本。
///
/// # Panics
///
/// 状态码不等于 `status` 时 panic。
pub async fn expect(response: Response, status: StatusCode) -> String {
    let got = response.status();
    let url = response.url().to_string();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(got, status, "{url} → {got},body: {body}");
    body
}

/// 断言状态码并解析 JSON body。
///
/// # Panics
///
/// 状态码不对或 body 不是 JSON 时 panic。
pub async fn expect_json(response: Response, status: StatusCode) -> Value {
    let body = expect(response, status).await;
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("body 不是 JSON({e}): {body}"))
}

/// 断言是**统一错误体** `{code, error}`(状态码 + 机器码)。
///
/// # Panics
///
/// 状态码、机器码不对或缺 `error` 文案时 panic。
pub async fn expect_error(response: Response, status: StatusCode, code: &str) {
    let body = expect_json(response, status).await;
    assert_eq!(body["code"], code, "错误机器码: {body}");
    assert!(
        body["error"].is_string(),
        "统一错误体要有 error 文案: {body}"
    );
}

/// 读 SSE 流直到凑满**一个完整事件**(以空行结尾),跳过心跳注释帧。真实网络上一帧可能被拆成
/// 多个 chunk,也可能和下一帧粘在一起 —— 不能假设"一次读 = 一帧"。
///
/// # Panics
///
/// 5s 内没凑满一个事件、流提前结束或读流出错时 panic。
pub async fn next_sse_event(
    stream: &mut (impl Stream<Item = reqwest::Result<Bytes>> + Unpin),
    buffer: &mut String,
) -> String {
    use futures_util::StreamExt;
    loop {
        if let Some(end) = buffer.find("\n\n") {
            let event = buffer[..end].to_owned();
            buffer.drain(..end + 2);
            if event
                .lines()
                .all(|line| line.starts_with(':') || line.is_empty())
            {
                continue; // 心跳
            }
            return event;
        }
        let chunk = time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("5s 内应收到 SSE 事件")
            .expect("流不应结束")
            .unwrap();
        buffer.push_str(str::from_utf8(&chunk).unwrap());
    }
}

// ───────────────────────────── 令牌 ─────────────────────────────

/// 自铸令牌(`dev()` 固定内嵌密钥对:服务端 verifier 照验)。
/// `platform_roles` = 平台角色(token `roles`);`tenant` = 当前租户(`None` = 平台上下文,租户级接口 403
/// `tenant_required`),`tenant_roles` = 该租户里的角色(没有租户时忽略);`scope` 空 = 不收窄。
///
/// # Panics
///
/// 签发失败(内嵌密钥坏了)时 panic。
pub fn mint(
    id: Uuid,
    username: &str,
    platform_roles: &[&str],
    tenant: Option<Uuid>,
    tenant_roles: &[&str],
    scope: Vec<Permission>,
) -> String {
    let owned =
        |roles: &[&str]| -> Vec<String> { roles.iter().map(|role| (*role).to_owned()).collect() };
    AppTokenSigner::new_with_development_key()
        .mint_scoped(
            id,
            username,
            owned(platform_roles),
            tenant.map(|id| ScopedTenant {
                id,
                roles: owned(tenant_roles),
            }),
            scope,
            900,
        )
        .unwrap()
}

/// 默认租户里、只有租户角色的令牌(最常用:普通成员 / 租户管理员)。
pub fn member_token(
    id: Uuid,
    username: &str,
    tenant_roles: &[&str],
    scope: Vec<Permission>,
) -> String {
    mint(id, username, &[], Some(DEFAULT_TENANT), tenant_roles, scope)
}

/// 平台管理员令牌:平台角色 superadmin + 默认租户 admin(= seed 里 superadmin 登录后的样子)。
pub fn superadmin_token(id: Uuid, scope: Vec<Permission>) -> String {
    mint(
        id,
        SUPERADMIN,
        &[SUPERADMIN],
        Some(DEFAULT_TENANT),
        &[ADMIN],
        scope,
    )
}

/// 一个新 `user` 主体的令牌(默认租户的 user)。返回 (token, user_id)。
pub fn user_token() -> (String, Uuid) {
    let id = Uuid::now_v7();
    (member_token(id, "user", &["user"], vec![]), id)
}

/// 收窄 scope 的 admin 令牌(默认租户的 admin;scope 只收窄不放大)。
pub fn admin_scoped(scope: Vec<Permission>) -> String {
    member_token(Uuid::nil(), "admin", &["admin"], scope)
}

//! **黑盒 HTTP 验收测试**的公共件(`tests/http_*.rs` 用)。
//!
//! - 服务端:真实组合根 `AppState::new`(内存模式:不设任何 DB/NATS/S3 环境变量)+ 完整路由与中间件栈,
//!   绑 `127.0.0.1:0`。seed 建好 `superadmin` / `admin` / `user`(密码 `pwd`),不灌 mock 样本。
//! - 客户端:reqwest,**浏览器式会话**(cookie 存储:登录拿 httponly cookie,后续请求自动带上);
//!   也可用 Bearer 令牌(自铸降权令牌等场景)。
//! - **只有 [`serve`] 认识 web 框架**(现在是 axum)。换底座只换它,测试体原样当验收标准。
//!
//! 每个测试起独立服务(互不干扰);服务跑在测试自己的 tokio 运行时里,测试结束即停。

#![allow(dead_code)] // 各 http_* 测试文件按需取用

use std::sync::Arc;

use baserust::app::{AppState, Mount};
use baserust::features::auth::AppTokenSigner;
use baserust::features::auth_audit::{AuthAuditService, AuthEventBus, InMemoryAuthEventRepo};
use baserust::infra::config::Config;
use baserust::kernel::authz::Perm;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::Value;
use uuid::Uuid;

/// seed.toml 里的默认账号(密码都是 `pwd`)。
pub const SUPERADMIN: &str = "superadmin";
pub const ADMIN: &str = "admin";
pub const USER: &str = "user";
pub const PASSWORD: &str = "pwd";

// ───────────────────────────── 唯一绑定框架的地方 ─────────────────────────────

/// 把 `state` 挂成完整应用(全部路由 + 中间件栈),在 `listener` 上开始服务。
/// **换 web 底座 = 换这个函数的实现**;签名(std TcpListener + AppState + Config)与框架无关。
fn serve(listener: std::net::TcpListener, state: AppState, config: &Config) {
    let app = baserust::app::build_router(state, config, Mount::Both);
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
}

// ──────────────────────────────── 以下与框架无关 ────────────────────────────────

/// 测试配置:内存模式(零外部依赖)+ seed 账号 + **空** mock(干净起点)。
pub fn test_config() -> Config {
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
    pub base: String,
    /// 认证审计读模型(内存)。生产里由 projector 从 JetStream 投影写入;黑盒测试直接经仓储造数据。
    pub auth_events: Arc<InMemoryAuthEventRepo>,
    /// 认证审计 SSE 总线(生产里 projector 落库后发布;测试直接发布)。
    pub auth_bus: AuthEventBus,
}

impl TestServer {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// 起服务前改装配(如换授权策略)。
    pub async fn start_with(customize: impl FnOnce(&mut AppState)) -> Self {
        let config = test_config();
        let (mut state, _background) = AppState::new(&config, Mount::Both)
            .await
            .expect("内存模式装配");
        // 内存模式不装审计后端(它读 search 库)→ 换内存实现,让审计端点也能黑盒覆盖。
        let auth_events = Arc::new(InMemoryAuthEventRepo::new());
        state.auth_audit = Some(AuthAuditService::new(auth_events.clone()));
        let auth_bus = AuthEventBus::new();
        state.auth_events_bus = Some(auth_bus.clone());
        customize(&mut state);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, state, &config);
        Self {
            base: format!("http://{addr}"),
            auth_events,
            auth_bus,
        }
    }

    /// 无凭据会话(带 cookie 存储:登录 / 注册后自动带 cookie)。
    pub fn anon(&self) -> Client {
        Client {
            base: self.base.clone(),
            http: reqwest::Client::builder()
                .no_proxy()
                .cookie_store(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            bearer: None,
        }
    }

    /// 用 Bearer 令牌的会话(自铸令牌:降权 scope、任意主体)。
    pub fn bearer(&self, token: &str) -> Client {
        Client {
            bearer: Some(token.to_owned()),
            ..self.anon()
        }
    }

    /// 前台登录(`/public/auth/login`)→ 带 httponly cookie 的会话。
    pub async fn login(&self, identifier: &str, password: &str) -> Client {
        let c = self.anon();
        let resp = c
            .post_json(
                "/api/v1/public/auth/login",
                &serde_json::json!({ "identifier": identifier, "password": password }),
            )
            .await;
        expect(resp, StatusCode::OK).await;
        c
    }

    /// 后台登录(`/admin/auth/login`,要 `admin:login`)→ 带 cookie 的会话。
    pub async fn login_admin(&self, identifier: &str, password: &str) -> Client {
        let c = self.anon();
        let resp = c
            .post_json(
                "/api/v1/admin/auth/login",
                &serde_json::json!({ "identifier": identifier, "password": password }),
            )
            .await;
        expect(resp, StatusCode::OK).await;
        c
    }
}

/// 一个客户端会话。路径传 `/api/v1/...` 这样的绝对路径。
#[derive(Clone)]
pub struct Client {
    pub base: String,
    pub http: reqwest::Client,
    pub bearer: Option<String>,
}

impl Client {
    /// 任意请求(自己补 header / body);带上本会话的 Bearer(若有)。
    pub fn req(&self, method: Method, path: &str) -> RequestBuilder {
        let r = self.http.request(method, format!("{}{path}", self.base));
        match &self.bearer {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    }

    pub async fn get(&self, path: &str) -> Response {
        self.req(Method::GET, path).send().await.unwrap()
    }

    pub async fn delete(&self, path: &str) -> Response {
        self.req(Method::DELETE, path).send().await.unwrap()
    }

    pub async fn post_empty(&self, path: &str) -> Response {
        self.req(Method::POST, path).send().await.unwrap()
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Response {
        self.req(Method::POST, path)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    pub async fn put_json(&self, path: &str, body: &Value) -> Response {
        self.req(Method::PUT, path).json(body).send().await.unwrap()
    }

    pub async fn delete_json(&self, path: &str, body: &Value) -> Response {
        self.req(Method::DELETE, path)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    pub async fn post_multipart(&self, path: &str, form: reqwest::multipart::Form) -> Response {
        self.req(Method::POST, path)
            .multipart(form)
            .send()
            .await
            .unwrap()
    }
}

// ───────────────────────────── 断言帮手 ─────────────────────────────

/// 断言状态码,失败时把响应体一起打出来(黑盒排障全靠它)。返回 body 文本。
pub async fn expect(resp: Response, status: StatusCode) -> String {
    let got = resp.status();
    let url = resp.url().to_string();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(got, status, "{url} → {got},body: {body}");
    body
}

/// 断言状态码并解析 JSON body。
pub async fn expect_json(resp: Response, status: StatusCode) -> Value {
    let body = expect(resp, status).await;
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("body 不是 JSON({e}): {body}"))
}

/// 断言是**统一错误体** `{code, error}`(状态码 + 机器码)。
pub async fn expect_error(resp: Response, status: StatusCode, code: &str) {
    let v = expect_json(resp, status).await;
    assert_eq!(v["code"], code, "错误机器码: {v}");
    assert!(v["error"].is_string(), "统一错误体要有 error 文案: {v}");
}

/// 读 SSE 流直到凑满**一个完整事件**(以空行结尾),跳过心跳注释帧。真实网络上一帧可能被拆成
/// 多个 chunk,也可能和下一帧粘在一起 —— 不能假设"一次读 = 一帧"。超时 5s。
pub async fn next_sse_event(
    stream: &mut (impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin),
    buf: &mut String,
) -> String {
    use futures_util::StreamExt;
    loop {
        if let Some(end) = buf.find("\n\n") {
            let event = buf[..end].to_owned();
            buf.drain(..end + 2);
            if event.lines().all(|l| l.starts_with(':') || l.is_empty()) {
                continue; // 心跳
            }
            return event;
        }
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("5s 内应收到 SSE 事件")
            .expect("流不应结束")
            .unwrap();
        buf.push_str(std::str::from_utf8(&chunk).unwrap());
    }
}

// ───────────────────────────── 令牌 ─────────────────────────────

/// 自铸令牌(`dev()` 固定内嵌密钥对:服务端 verifier 照验)。`scope` 空 = 不收窄。
pub fn mint(id: Uuid, username: &str, roles: &[&str], scope: Vec<Perm>) -> String {
    AppTokenSigner::dev()
        .mint_scoped(
            id,
            username,
            roles.iter().map(|r| (*r).to_owned()).collect(),
            scope,
            900,
        )
        .unwrap()
}

/// 一个新 `user` 主体的令牌。返回 (token, user_id)。
pub fn user_token() -> (String, Uuid) {
    let id = Uuid::now_v7();
    (mint(id, "user", &["user"], vec![]), id)
}

/// 收窄 scope 的 admin 令牌(scope 只收窄不放大)。
pub fn admin_scoped(scope: Vec<Perm>) -> String {
    mint(Uuid::nil(), "admin", &["admin"], scope)
}

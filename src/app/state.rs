use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use super::adapters::InProcessUserDirectory;
use super::router::Mount;
use crate::features::widget::{
    InMemoryWidgetRepo, PgWidgetRepo, UserDirectory, WidgetRepo, WidgetService,
};
use crate::infra::config::Config;
use idm::{
    Argon2Hasher, AuthService, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, PgRoleRepo,
    PgSessionRepo, PgUserRepo, RoleRepo, SessionRepo, UserRepo,
};

/// 数据库 schema(= role = 连接归属)。每个 schema 用自己的 role 连接。
///
/// **跨模块访问范式**:要读别的 schema,用 [`connect_for_schema`] 起对方 schema 的连接、
/// **走对方模块的 repo** 读 —— 严禁跨 schema join(idm/app 各自 role 的 search_path 物理上也挡着)。
/// 富化接口时按此装配:在 `new` 里起对方 schema 的连接、建对方 repo、注入本模块 service
/// (绝不在本模块的 SQL 里直接 `join 别的schema.表`)。
#[derive(Clone, Copy, Debug)]
pub enum Schema {
    App,
    Idm,
}

/// 应用级依赖容器。范式(替代 DI 框架):
/// - 用 axum 的 `State` 提取器注入到每个 handler。
/// - 字段是 service;service 内部持 `Arc<dyn Trait>` 仓储端口,启动时决定注入哪个实现。
/// - 廉价 `Clone`(字段都是 Arc),axum 每请求 clone 一份。
/// - 加业务模块 = 在这里加一个 service 字段 + 在 `new` 里装配它。
#[derive(Clone)]
pub struct AppState {
    pub widgets: WidgetService,
    pub auth: AuthService,
    /// readyz 就绪探针用:DB 模式持 pool(ping `SELECT 1`),内存模式为 `None`(恒就绪)。
    pub db_pool: Option<PgPool>,
    /// 认证 cookie 是否带 `Secure`(prod=true,仅 https 发送;dev http 必须 false 否则浏览器不发)。
    pub cookie_secure: bool,
}

impl AppState {
    /// 按 `mount` 只装配本进程真正用到的库:app 进程连 app DB(widget)、idm 进程连 idm DB(auth/me),
    /// 各自不连对方的库 —— 省掉闲置连接,也让 readyz 探针 ping 的是本进程主库。
    /// app 进程的鉴权中间件只 decode JWT(roles 在 claim 里),不查 idm 库,故 idm 用内存占位即可。
    pub async fn new(config: &Config, mount: Mount) -> anyhow::Result<Self> {
        let needs_app = matches!(mount, Mount::App | Mount::Both);
        let needs_idm = matches!(mount, Mount::Idm | Mount::Both);

        // widget(app schema):仅 app/both 进程需要。设了 APP_DB_HOST → PG,否则内存(脚手架默认)。
        let app_pool = if needs_app {
            connect_for_schema(config, Schema::App).await?
        } else {
            None
        };
        let widget_repo: Arc<dyn WidgetRepo> = match &app_pool {
            // pool.clone() 廉价(内部 Arc):一份给 repo,app_pool 留给 readyz 探针。
            Some(pool) => Arc::new(PgWidgetRepo::new(pool.clone())),
            None => {
                if needs_app {
                    tracing::warn!("未设 APP_DB_HOST,widget 仓储使用内存实现(脚手架默认)");
                }
                Arc::new(InMemoryWidgetRepo::new())
            }
        };

        // idm(idm schema):仅 idm/both 进程需要。设了 IDM_DB_HOST → PG(读 seed 的 superadmin 等),否则内存。
        let idm_pool = if needs_idm {
            connect_for_schema(config, Schema::Idm).await?
        } else {
            None
        };
        let (idm_users, idm_sessions, idm_roles): (
            Arc<dyn UserRepo>,
            Arc<dyn SessionRepo>,
            Arc<dyn RoleRepo>,
        ) = match &idm_pool {
            Some(pool) => (
                Arc::new(PgUserRepo::new(pool.clone())),
                Arc::new(PgSessionRepo::new(pool.clone())),
                Arc::new(PgRoleRepo::new(pool.clone())),
            ),
            None => {
                if needs_idm {
                    tracing::warn!("未设 IDM_DB_HOST,idm 仓储使用内存实现");
                }
                (
                    Arc::new(InMemoryUserRepo::new()),
                    Arc::new(InMemorySessionRepo::new()),
                    Arc::new(InMemoryRoleRepo::new()),
                )
            }
        };
        // 跨模块富化:widget 的 UserDirectory 端口由 app 注入 idm 的进程内适配器(复用 idm_users)。
        // 单体 Both 连真 idm 库;分进程 App 时 idm_users 是内存占位 → 富化降级为空(留待 HttpUserDirectory)。
        let user_directory: Arc<dyn UserDirectory> =
            Arc::new(InProcessUserDirectory::new(idm_users.clone()));

        let auth = AuthService::new(
            idm_users,
            idm_sessions,
            idm_roles,
            Arc::new(Argon2Hasher),
            &config.idm_jwt_secret,
            config.idm_access_ttl_secs,
            config.idm_refresh_ttl_secs,
        );

        Ok(Self {
            widgets: WidgetService::new(widget_repo, user_directory),
            auth,
            // readyz 探针 ping 本进程主库:app 进程→app 库,idm 进程→idm 库。
            db_pool: app_pool.or(idm_pool),
            cookie_secure: config.app_env.is_prod(),
        })
    }
}

/// 按 `schema` 起连接池(复用该 schema 自己的 role)。未配置对应 `*_DB_HOST` → `None`(走内存)。
///
/// **跨模块访问其他 schema 的唯一连接入口**:本进程主连接与未来的跨模块只读连接都经它,口径一致 ——
/// 拿到对方 schema 的连接后**只走对方模块的 repo** 读,绝不跨 schema join。
pub async fn connect_for_schema(config: &Config, schema: Schema) -> anyhow::Result<Option<PgPool>> {
    let url = match schema {
        Schema::App => config.app_database_url(),
        Schema::Idm => config.idm_database_url(),
    };
    match url {
        Some(url) => Ok(Some(connect_pool(&url).await?)),
        None => Ok(None),
    }
}

/// 连接 Postgres 并建连接池。范式:`PgPool` 自带连接池,无需 deadpool。
async fn connect_pool(url: &str) -> anyhow::Result<PgPool> {
    // 不在 app 启动时跑迁移:schema 变更由 sqlx-cli 显式执行(just migrate),是受控部署步骤,
    // 而非 app 启动副作用 —— 避免多实例并发抢迁移、回滚困难、启动期改 schema 等风险。
    PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .context("连接 Postgres 失败")
}

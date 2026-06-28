use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::features::idm::{
    Argon2Hasher, AuthService, InMemorySessionRepo, InMemoryUserRepo, PgSessionRepo, PgUserRepo,
    SessionRepo, UserRepo,
};
use crate::features::widget::{InMemoryWidgetRepo, PgWidgetRepo, WidgetRepo, WidgetService};
use crate::infra::config::Config;

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
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        // 可拔插实现:设了 APP_DB_HOST 用 app role 连 Postgres,否则走内存。
        // 镜像现有 Go 服务 AUTH_BACKEND=memory|db 的取舍:同一 trait,启动时二选一。
        let (widget_repo, db_pool): (Arc<dyn WidgetRepo>, Option<PgPool>) =
            match config.app_database_url() {
                Some(url) => {
                    let pool = connect_pool(&url).await?;
                    // pool.clone() 廉价(内部 Arc):一份给 repo,一份给 readyz 探针。
                    (Arc::new(PgWidgetRepo::new(pool.clone())), Some(pool))
                }
                None => {
                    tracing::warn!("未设 APP_DB_HOST,widget 仓储使用内存实现(脚手架默认)");
                    (Arc::new(InMemoryWidgetRepo::new()), None)
                }
            };

        // idm 仓储:设了 IDM_DB_HOST 用 idm role 连 Postgres(读 seed 的 superadmin 等),否则内存。
        let (idm_users, idm_sessions): (Arc<dyn UserRepo>, Arc<dyn SessionRepo>) =
            match config.idm_database_url() {
                Some(url) => {
                    let pool = connect_pool(&url).await?;
                    (
                        Arc::new(PgUserRepo::new(pool.clone())),
                        Arc::new(PgSessionRepo::new(pool)),
                    )
                }
                None => {
                    tracing::warn!("未设 IDM_DB_HOST,idm 仓储使用内存实现");
                    (
                        Arc::new(InMemoryUserRepo::new()),
                        Arc::new(InMemorySessionRepo::new()),
                    )
                }
            };
        let auth = AuthService::new(
            idm_users,
            idm_sessions,
            Arc::new(Argon2Hasher),
            &config.idm_jwt_secret,
            config.idm_access_ttl_secs,
            config.idm_refresh_ttl_secs,
        );

        Ok(Self {
            widgets: WidgetService::new(widget_repo),
            auth,
            db_pool,
            cookie_secure: config.app_env.is_prod(),
        })
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

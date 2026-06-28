use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

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
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        // 可拔插实现:设了 APP_DB_HOST 用 app role 连 Postgres,否则走内存。
        // 镜像现有 Go 服务 AUTH_BACKEND=memory|db 的取舍:同一 trait,启动时二选一。
        let widget_repo: Arc<dyn WidgetRepo> = match config.app_database_url() {
            Some(url) => {
                let pool = connect_pool(&url).await?;
                Arc::new(PgWidgetRepo::new(pool))
            }
            None => {
                tracing::warn!("未设 APP_DB_HOST,widget 仓储使用内存实现(脚手架默认)");
                Arc::new(InMemoryWidgetRepo::new())
            }
        };

        Ok(Self {
            widgets: WidgetService::new(widget_repo),
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

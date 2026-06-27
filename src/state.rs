use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::Config;
use crate::widget::{InMemoryWidgetRepo, PgWidgetRepo, WidgetRepo, WidgetService};

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
        // 可拔插实现:设了 DATABASE_URL 走 Postgres,否则走内存。
        // 镜像现有 Go 服务 AUTH_BACKEND=memory|db 的取舍:同一 trait,启动时二选一。
        let widget_repo: Arc<dyn WidgetRepo> = match &config.database_url {
            Some(url) => {
                let pool = connect_pool(url).await?;
                Arc::new(PgWidgetRepo::new(pool))
            }
            None => {
                tracing::warn!("未设 DATABASE_URL,widget 仓储使用内存实现(脚手架默认)");
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
    PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .context("连接 Postgres 失败")
}

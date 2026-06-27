use std::net::SocketAddr;

use anyhow::Context;
use figment::{providers::Env, Figment};
use serde::Deserialize;

/// 应用配置。范式:
/// - 字段缺省值用 serde `#[serde(default = ...)]`(替代 Go cleanenv 的 `env-default`)。
/// - 环境变量覆盖经 figment(变量名转小写匹配字段:`BIND_ADDR` -> `bind_addr`)。
/// - 加配置项 = 加字段 + 给默认值。需要 yaml 配置文件时再开 figment 的 yaml provider
///   (注意会传递依赖已废弃的 serde_yaml,见 docs)。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// 监听地址,环境变量 `BIND_ADDR`,默认 `0.0.0.0:8080`。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Postgres 连接串,环境变量 `DATABASE_URL`。
    /// 不设则 widget 仓储走内存实现(脚手架默认,无需数据库)。
    #[serde(default)]
    pub database_url: Option<String>,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("默认监听地址应合法")
}

impl Config {
    /// 从环境变量加载(main 里已先 load 过 .env)。
    pub fn load() -> anyhow::Result<Self> {
        Figment::new()
            .merge(Env::raw())
            .extract()
            .context("解析环境变量配置失败")
    }
}

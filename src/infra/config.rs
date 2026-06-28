use std::net::SocketAddr;

use anyhow::Context;
use figment::{providers::Env, Figment};
use serde::Deserialize;

/// 应用配置。范式:
/// - 字段缺省值用 serde `#[serde(default = ...)]`(替代 Go cleanenv 的 `env-default`)。
/// - 环境变量覆盖经 figment(变量名转小写匹配字段:`BIND_ADDR` -> `bind_addr`)。
/// - 加配置项 = 加字段 + 给默认值。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// 监听地址,环境变量 `BIND_ADDR`,默认 `0.0.0.0:8080`。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// app schema 的数据库连接,按 role 分字段(镜像 Go 的 `AppDBConfig`)。
    /// 用 app role 连接,靠 role 的 search_path 落到 app schema,代码/SQL 都不写 schema 前缀。
    /// `APP_DB_HOST` 的存在 = 启用 pg;不设 → widget 仓储走内存(脚手架默认,无需数据库)。
    #[serde(default)]
    pub app_db_host: Option<String>,
    #[serde(default = "default_db_port")]
    pub app_db_port: u16,
    #[serde(default = "default_db_database")]
    pub app_db_database: String,
    #[serde(default = "default_app_db_user")]
    pub app_db_user: String,
    #[serde(default = "default_db_password")]
    pub app_db_password: String,
    #[serde(default = "default_db_sslmode")]
    pub app_db_sslmode: String,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("默认监听地址应合法")
}
fn default_db_port() -> u16 {
    5432
}
fn default_db_database() -> String {
    "xchangeai".into()
}
fn default_app_db_user() -> String {
    "app".into()
}
fn default_db_password() -> String {
    "pwd".into()
}
fn default_db_sslmode() -> String {
    "disable".into()
}

impl Config {
    /// 从环境变量加载(main 里已先 load 过 .env)。
    pub fn load() -> anyhow::Result<Self> {
        Figment::new()
            .merge(Env::raw())
            .extract()
            .context("解析环境变量配置失败")
    }

    /// app schema 的连接串(role=app)。`None` = 没设 `APP_DB_HOST` → widget 走内存。
    /// 多 schema 时再加 `idm_database_url()` 等,各用自己的 role(此处只有 app 有业务)。
    pub fn app_database_url(&self) -> Option<String> {
        self.app_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                self.app_db_user,
                self.app_db_password,
                host,
                self.app_db_port,
                self.app_db_database,
                self.app_db_sslmode,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: Option<&str>) -> Config {
        Config {
            bind_addr: default_bind_addr(),
            app_db_host: host.map(Into::into),
            app_db_port: 6000,
            app_db_database: "db".into(),
            app_db_user: "app".into(),
            app_db_password: "pw".into(),
            app_db_sslmode: "require".into(),
        }
    }

    #[test]
    fn no_host_means_memory() {
        assert!(cfg(None).app_database_url().is_none());
    }

    #[test]
    fn url_built_from_role_fields() {
        assert_eq!(
            cfg(Some("h")).app_database_url().unwrap(),
            "postgres://app:pw@h:6000/db?sslmode=require"
        );
    }
}

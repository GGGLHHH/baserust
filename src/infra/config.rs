use std::net::SocketAddr;

use anyhow::Context;
use figment::{providers::Env, Figment};
use serde::Deserialize;

/// 运行环境。影响:日志格式(prod 走 JSON / 非 prod 走彩色)、是否暴露 /docs、CORS 策略。
/// 环境变量 `APP_ENV`(dev/staging/prod),缺省 dev。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Dev,
    Staging,
    Prod,
}

impl Profile {
    pub fn is_prod(self) -> bool {
        matches!(self, Profile::Prod)
    }

    /// 文档端点(/docs、/api-docs/*)只在**非 prod** 暴露 —— prod 收起以减少攻击面。
    pub fn expose_docs(self) -> bool {
        !self.is_prod()
    }
}

/// 应用配置。范式:
/// - 字段缺省值用 serde `#[serde(default = ...)]`(替代 Go cleanenv 的 `env-default`)。
/// - 环境变量覆盖经 figment(变量名转小写匹配字段:`BIND_ADDR` -> `bind_addr`)。
/// - 加配置项 = 加字段 + 给默认值(并在 `Default` impl 里同步)。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// 监听地址,环境变量 `BIND_ADDR`,默认 `0.0.0.0:8080`。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// 运行环境,`APP_ENV`(dev/staging/prod),默认 dev。决定日志格式 / 是否挂 /docs / CORS 策略。
    #[serde(default)]
    pub app_env: Profile,

    /// CORS 允许的源,`CORS_ALLOWED_ORIGINS`(逗号分隔)。**仅 prod 生效**:
    /// prod 用此白名单;dev/staging 走宽松策略(permissive),不读此项。
    #[serde(default)]
    pub cors_allowed_origins: String,

    /// 限流(按 IP)。**opt-in**:`RATE_LIMIT_ENABLED=true` 才启用(零配置静默启动默认关)。
    #[serde(default)]
    pub rate_limit_enabled: bool,
    /// 每 IP 每秒补充令牌数,`RATE_LIMIT_PER_SEC`,默认 10。
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: u32,
    /// 每 IP 突发上限,`RATE_LIMIT_BURST`,默认 20。
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,

    /// Prometheus metrics + `/metrics` 端点。**opt-in**:`METRICS_ENABLED=true` 才启用。
    #[serde(default)]
    pub metrics_enabled: bool,

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

    /// idm JWT 签名密钥(HS256),`IDM_JWT_SECRET`。脚手架给 dev 默认(静默启动),**生产必须覆盖**。
    #[serde(default = "default_jwt_secret")]
    pub idm_jwt_secret: String,
    /// access token 有效秒数,`IDM_ACCESS_TTL_SECS`,默认 900(15min)。
    #[serde(default = "default_access_ttl_secs")]
    pub idm_access_ttl_secs: i64,
    /// refresh token 有效秒数,`IDM_REFRESH_TTL_SECS`,默认 604800(7天)。
    #[serde(default = "default_refresh_ttl_secs")]
    pub idm_refresh_ttl_secs: i64,

    /// 进程内 seed:idm-mounting 进程启动时**幂等**写默认 role/账号(memory 与 PG 都适用)。
    /// `IDM_SEED_ON_START`(true/false)。**未设时默认 = 非 prod 才 seed**(dev 便利;prod 不自动建
    /// superadmin/pwd,要 seed 走显式 `seed` bin)。见 [`Config::seed_on_start`]。
    #[serde(default)]
    pub idm_seed_on_start: Option<bool>,

    /// idm schema 的数据库连接,按 role 分字段(role=idm,镜像 app_db_*)。
    /// `IDM_DB_HOST` 的存在 = idm 走 PG(读 seed 的 superadmin 等);不设 → idm 仓储走内存。
    #[serde(default)]
    pub idm_db_host: Option<String>,
    #[serde(default = "default_db_port")]
    pub idm_db_port: u16,
    #[serde(default = "default_db_database")]
    pub idm_db_database: String,
    #[serde(default = "default_idm_db_user")]
    pub idm_db_user: String,
    #[serde(default = "default_db_password")]
    pub idm_db_password: String,
    #[serde(default = "default_db_sslmode")]
    pub idm_db_sslmode: String,
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
fn default_rate_limit_per_sec() -> u32 {
    10
}
fn default_rate_limit_burst() -> u32 {
    20
}
fn default_jwt_secret() -> String {
    // dev 默认:零环境变量也能静默启动;生产**务必**用 IDM_JWT_SECRET 覆盖。
    "dev-insecure-secret-change-me-in-prod".into()
}
fn default_access_ttl_secs() -> i64 {
    900
}
fn default_refresh_ttl_secs() -> i64 {
    604_800
}
fn default_idm_db_user() -> String {
    "idm".into()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: default_bind_addr(),
            app_env: Profile::default(),
            cors_allowed_origins: String::new(),
            rate_limit_enabled: false,
            rate_limit_per_sec: default_rate_limit_per_sec(),
            rate_limit_burst: default_rate_limit_burst(),
            metrics_enabled: false,
            app_db_host: None,
            app_db_port: default_db_port(),
            app_db_database: default_db_database(),
            app_db_user: default_app_db_user(),
            app_db_password: default_db_password(),
            app_db_sslmode: default_db_sslmode(),
            idm_jwt_secret: default_jwt_secret(),
            idm_access_ttl_secs: default_access_ttl_secs(),
            idm_refresh_ttl_secs: default_refresh_ttl_secs(),
            idm_seed_on_start: None,
            idm_db_host: None,
            idm_db_port: default_db_port(),
            idm_db_database: default_db_database(),
            idm_db_user: default_idm_db_user(),
            idm_db_password: default_db_password(),
            idm_db_sslmode: default_db_sslmode(),
        }
    }
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

    /// idm schema 的连接串(role=idm)。`None` = 没设 `IDM_DB_HOST` → idm 走内存。
    pub fn idm_database_url(&self) -> Option<String> {
        self.idm_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                self.idm_db_user,
                self.idm_db_password,
                host,
                self.idm_db_port,
                self.idm_db_database,
                self.idm_db_sslmode,
            )
        })
    }

    /// 是否在进程内 seed idm 默认数据。未显式设 `IDM_SEED_ON_START` → **非 prod 才 seed**
    /// (dev/staging 便利;prod 不自动建 superadmin/pwd,避免启动期意外写库)。
    pub fn seed_on_start(&self) -> bool {
        self.idm_seed_on_start.unwrap_or(!self.app_env.is_prod())
    }

    /// prod CORS 白名单(解析逗号分隔、去空白、去空项)。
    pub fn cors_origins(&self) -> Vec<String> {
        self.cors_allowed_origins
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: Option<&str>) -> Config {
        Config {
            app_db_host: host.map(Into::into),
            app_db_port: 6000,
            app_db_database: "db".into(),
            app_db_user: "app".into(),
            app_db_password: "pw".into(),
            app_db_sslmode: "require".into(),
            ..Config::default()
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

    #[test]
    fn prod_only_hides_docs() {
        assert!(Profile::Dev.expose_docs());
        assert!(Profile::Staging.expose_docs());
        assert!(!Profile::Prod.expose_docs());
    }
}

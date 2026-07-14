use std::net::SocketAddr;

use anyhow::Context;
use figment::{providers::Env, Figment};
use serde::Deserialize;

/// 内嵌开发密钥对(keys/,**明文入库是刻意的**:零配置启动铁律)。prod 启动校验拒用(见 AppState::new)。
pub const DEV_JWT_PRIVATE_KEY_PEM: &str = include_str!("../../keys/dev-ed25519.pem");
pub const DEV_JWT_PUBLIC_KEY_PEM: &str = include_str!("../../keys/dev-ed25519.pub.pem");

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

    /// 信任的反向代理层数(nginx 等),`TRUSTED_PROXY_HOPS`,默认 1。
    /// `ClientContext` 解析真实客户端 IP 时,按此值从 X-Forwarded-For 右数第 (N+1) 跳取值(防伪造最左)。
    /// **直连暴露(前面没有反代)必须设 0**:否则客户端自造的单条 XFF 恰是"右数第 1 跳"而被当可信
    /// —— 审计 IP 与限流键(TrustedIpKeyExtractor)都会吃到伪造值。
    #[serde(default = "default_trusted_proxy_hops")]
    pub trusted_proxy_hops: usize,

    /// app 进程是否内嵌 idm,`IDM_EMBEDDED`,默认 true(开发单体 `Both`)。
    /// 生产设 `IDM_EMBEDDED=false` → 只挂 app,idm 走独立 `idm` bin(nginx 按前缀分流)。
    #[serde(default = "default_idm_embedded")]
    pub idm_embedded: bool,

    /// 日志过滤指令,`RUST_LOG`(tracing EnvFilter 语法)。未设 → 按环境缺省(prod=info、非 prod=debug),
    /// 见 [`Config::log_filter`]。
    #[serde(default)]
    pub rust_log: Option<String>,
    /// 文件日志路径,`LOG_FILE`。设了才写文件(dev 观察用,每次启动 truncate);
    /// 容器/生产不设 → 只 stdout,由 docker/k8s 收集。
    #[serde(default)]
    pub log_file: Option<String>,

    /// seed 数据文件路径,`SEED_FILE`。未设 → 编译期嵌入的 `seed.toml`。
    #[serde(default)]
    pub seed_file: Option<String>,
    /// mock 样本数据文件路径,`MOCK_FILE`。未设 → 编译期嵌入的 `mock.toml`。
    #[serde(default)]
    pub mock_file: Option<String>,

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

    /// access token 有效秒数,`IDM_ACCESS_TTL_SECS`,默认 900(15min)。
    #[serde(default = "default_access_ttl_secs")]
    pub idm_access_ttl_secs: i64,
    /// refresh token 有效秒数,`IDM_REFRESH_TTL_SECS`,默认 604800(7天)。
    #[serde(default = "default_refresh_ttl_secs")]
    pub idm_refresh_ttl_secs: i64,

    /// JWT 签发私钥 PEM(Ed25519)。默认内嵌 dev 私钥;生产 idm 进程经 JWT_PRIVATE_KEY_FILE 覆盖。
    #[serde(default = "default_jwt_private_key_pem")]
    pub jwt_private_key_pem: String,
    /// JWT 验签公钥 PEM。默认内嵌 dev 公钥;生产两进程都经 JWT_PUBLIC_KEY_FILE 覆盖。
    #[serde(default = "default_jwt_public_key_pem")]
    pub jwt_public_key_pem: String,
    /// 设了则读该文件覆盖 jwt_private_key_pem(镜像 SEED_FILE 范式;env 里放路径不放多行 PEM)。
    #[serde(default)]
    pub jwt_private_key_file: Option<String>,
    #[serde(default)]
    pub jwt_public_key_file: Option<String>,

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

    /// content schema 的数据库连接,按 role 分字段(role=content,镜像 app_db_*/idm_db_*)。
    /// `CONTENT_DB_HOST` 的存在 = content 仓储走 PG;不设 → content 走内存(脚手架默认,字节走内存 backend)。
    #[serde(default)]
    pub content_db_host: Option<String>,
    #[serde(default = "default_db_port")]
    pub content_db_port: u16,
    #[serde(default = "default_db_database")]
    pub content_db_database: String,
    #[serde(default = "default_content_db_user")]
    pub content_db_user: String,
    #[serde(default = "default_db_password")]
    pub content_db_password: String,
    #[serde(default = "default_db_sslmode")]
    pub content_db_sslmode: String,

    /// search schema 的数据库连接,按 role 分字段(role=search,镜像 content_db_*)。
    /// `SEARCH_DB_HOST` 的存在 = 启用投影读模型(projector 写 + P4 list 读);不设 → 无投影(P4 list 回退)。
    #[serde(default)]
    pub search_db_host: Option<String>,
    #[serde(default = "default_db_port")]
    pub search_db_port: u16,
    #[serde(default = "default_db_database")]
    pub search_db_database: String,
    #[serde(default = "default_search_db_user")]
    pub search_db_user: String,
    #[serde(default = "default_db_password")]
    pub search_db_password: String,
    #[serde(default = "default_db_sslmode")]
    pub search_db_sslmode: String,

    /// NATS 地址,`NATS_URL`(如 `nats://localhost:2224`,本地 compose 主机端口)—— widget 事件总线选择链的**最高优先**:
    /// 设了 → NatsEventBus(多实例默认);没设但有 app pool → PgEventBus(LISTEN/NOTIFY 退路);
    /// 都没有 → 内存(单实例,最终 fallback)。装配在组合根 `AppState::new`。
    #[serde(default)]
    pub nats_url: Option<String>,

    /// S3/minio 对象存储 —— content 模块的字节后端(元数据进 PG,字节进 S3)。
    /// **presence = use S3**:设了 `S3_ENDPOINT` → content 用 minio/S3 backend;不设 → 内存 backend
    /// (脚手架默认,零外部依赖)。其余字段镜像 db 的「全有默认」约定。
    #[serde(default)]
    pub s3_endpoint: Option<String>,
    /// 桶名,`S3_BUCKET`,默认 `content`(compose 的 minio-init 建同名桶)。
    #[serde(default = "default_s3_bucket")]
    pub s3_bucket: String,
    /// 静态访问密钥,`S3_ACCESS_KEY`(minio 默认 minio)。
    #[serde(default = "default_s3_access_key")]
    pub s3_access_key: String,
    /// 静态密钥,`S3_SECRET_KEY`(minio 默认 minio12345)。
    #[serde(default = "default_s3_secret_key")]
    pub s3_secret_key: String,
    /// 区域,`S3_REGION`,默认 `us-east-1`(minio 不校验,但 SDK 需一个值)。
    #[serde(default = "default_s3_region")]
    pub s3_region: String,
    /// presign URL 形态,`S3_PRESIGN_RELATIVE`,默认 false。
    /// false = 绝对 URL(host 来自 `S3_ENDPOINT`,浏览器直连 minio;dev/单域名)。
    /// true = 相对 URL(仅 path+query,浏览器经反代 nginx→minio;prod 边缘 TLS 拓扑,只开 80、零域名配置)。
    /// true 时 `S3_ENDPOINT` 应指内网(如 `http://minio:9000`),nginx 把 `/<bucket>/` 的 Host 固定回它。
    #[serde(default)]
    pub s3_presign_relative: bool,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("默认监听地址应合法")
}
fn default_db_port() -> u16 {
    5432
}
fn default_db_database() -> String {
    "baserust".into()
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
fn default_idm_embedded() -> bool {
    true
}
fn default_trusted_proxy_hops() -> usize {
    1
}
fn default_rate_limit_burst() -> u32 {
    20
}
fn default_access_ttl_secs() -> i64 {
    900
}
fn default_refresh_ttl_secs() -> i64 {
    604_800
}
fn default_jwt_private_key_pem() -> String {
    DEV_JWT_PRIVATE_KEY_PEM.into()
}
fn default_jwt_public_key_pem() -> String {
    DEV_JWT_PUBLIC_KEY_PEM.into()
}
fn default_idm_db_user() -> String {
    "idm".into()
}
fn default_content_db_user() -> String {
    "content".into()
}
fn default_search_db_user() -> String {
    "search".into()
}
fn default_s3_bucket() -> String {
    "content".into()
}
fn default_s3_access_key() -> String {
    "minio".into()
}
fn default_s3_secret_key() -> String {
    "minio12345".into()
}
fn default_s3_region() -> String {
    "us-east-1".into()
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
            trusted_proxy_hops: default_trusted_proxy_hops(),
            idm_embedded: default_idm_embedded(),
            rust_log: None,
            log_file: None,
            seed_file: None,
            mock_file: None,
            app_db_host: None,
            app_db_port: default_db_port(),
            app_db_database: default_db_database(),
            app_db_user: default_app_db_user(),
            app_db_password: default_db_password(),
            app_db_sslmode: default_db_sslmode(),
            idm_access_ttl_secs: default_access_ttl_secs(),
            idm_refresh_ttl_secs: default_refresh_ttl_secs(),
            jwt_private_key_pem: default_jwt_private_key_pem(),
            jwt_public_key_pem: default_jwt_public_key_pem(),
            jwt_private_key_file: None,
            jwt_public_key_file: None,
            idm_seed_on_start: None,
            idm_db_host: None,
            idm_db_port: default_db_port(),
            idm_db_database: default_db_database(),
            idm_db_user: default_idm_db_user(),
            idm_db_password: default_db_password(),
            idm_db_sslmode: default_db_sslmode(),
            content_db_host: None,
            content_db_port: default_db_port(),
            content_db_database: default_db_database(),
            content_db_user: default_content_db_user(),
            content_db_password: default_db_password(),
            content_db_sslmode: default_db_sslmode(),
            search_db_host: None,
            search_db_port: default_db_port(),
            search_db_database: default_db_database(),
            search_db_user: default_search_db_user(),
            search_db_password: default_db_password(),
            search_db_sslmode: default_db_sslmode(),
            nats_url: None,
            s3_endpoint: None,
            s3_bucket: default_s3_bucket(),
            s3_access_key: default_s3_access_key(),
            s3_secret_key: default_s3_secret_key(),
            s3_region: default_s3_region(),
            s3_presign_relative: false,
        }
    }
}

/// 百分号编码连接串里的 user/password/database。生成的密码(如 `openssl rand -base64`)常含
/// `/ + @ ? #` 等 URL 保留字符,直接插值进 `postgres://user:pass@host/db` 会破坏 authority 解析
/// (`/` 提前结束 authority),或让形如 `%XX` 的子串被 sqlx 误 percent-decode 成别的密码 —— 都表现为
/// opaque 的启动期连接失败。这里只保留 RFC3986 unreserved 字符,其余全编码;sqlx 连接时 percent-decode
/// 还原,过度编码(把 unreserved 也编码)无害。host 不编码(避免破坏 IPv6 `[::1]` 的方括号/冒号)。
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

impl Config {
    /// 从环境变量加载(调用方先 load 过 .env)。**全部环境变量的读取/默认值收口在本文件**:
    /// 加变量 = 加字段(figment 变量名转小写匹配),别在别处 `std::env::var`。
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg: Config = Figment::new()
            .merge(Env::raw())
            .extract()
            .context("解析环境变量配置失败")?;
        apply_jwt_key_file_overrides(&mut cfg)?;
        Ok(cfg)
    }

    /// app schema 的连接串(role=app)。`None` = 没设 `APP_DB_HOST` → widget 走内存。
    pub fn app_database_url(&self) -> Option<String> {
        self.app_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                enc(&self.app_db_user),
                enc(&self.app_db_password),
                host,
                self.app_db_port,
                enc(&self.app_db_database),
                self.app_db_sslmode,
            )
        })
    }

    /// idm schema 的连接串(role=idm)。`None` = 没设 `IDM_DB_HOST` → idm 走内存。
    pub fn idm_database_url(&self) -> Option<String> {
        self.idm_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                enc(&self.idm_db_user),
                enc(&self.idm_db_password),
                host,
                self.idm_db_port,
                enc(&self.idm_db_database),
                self.idm_db_sslmode,
            )
        })
    }

    /// content schema 的连接串(role=content)。`None` = 没设 `CONTENT_DB_HOST` → content 走内存。
    pub fn content_database_url(&self) -> Option<String> {
        self.content_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                enc(&self.content_db_user),
                enc(&self.content_db_password),
                host,
                self.content_db_port,
                enc(&self.content_db_database),
                self.content_db_sslmode,
            )
        })
    }

    /// search schema 的连接串(role=search)。`None` = 没设 `SEARCH_DB_HOST` → 无投影 backend。
    pub fn search_database_url(&self) -> Option<String> {
        self.search_db_host.as_ref().map(|host| {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                enc(&self.search_db_user),
                enc(&self.search_db_password),
                host,
                self.search_db_port,
                enc(&self.search_db_database),
                self.search_db_sslmode,
            )
        })
    }

    /// 是否在进程内 seed idm 默认账号(+ demo 数据)。未显式设 `IDM_SEED_ON_START` 时:
    /// - **非 prod** → true(dev/staging 用嵌入的默认账号便利);
    /// - **prod** → 仅当提供了 `SEED_FILE`(= 运维显式给了真账号/密码文件)才 true。
    ///
    /// 容器/prod 无 `just`/`cargo`,只有二进制 —— seed 必须在启动时跑;prod 挂 `SEED_FILE`
    /// (真密码,非仓库里的 `pwd` 弱默认)即在 idm 进程启动幂等建号。没给 SEED_FILE → 不 seed,
    /// 绝不用嵌入默认在 prod 建 superadmin/pwd(这才是原「避免启动期意外写库」真正针对的)。
    /// 幂等:账号已存在则跳过(`seed::apply`),重启不冲掉运维轮换过的密码。
    pub fn seed_on_start(&self) -> bool {
        self.idm_seed_on_start
            .unwrap_or(!self.app_env.is_prod() || self.seed_file.is_some())
    }

    /// 日志过滤指令:`RUST_LOG` 优先;未设按环境缺省(prod=info、非 prod=debug)。
    pub fn log_filter(&self) -> &str {
        // sqlx::query=warn:压掉 sqlx 每条 SQL 的 info/debug 刷屏,只留慢查询 WARN + 错误。
        // 要看 SQL 调试:显式设 RUST_LOG(如 `RUST_LOG=debug,sqlx::query=debug`)覆盖本默认。
        self.rust_log
            .as_deref()
            .unwrap_or(if self.app_env.is_prod() {
                "info,sqlx::query=warn"
            } else {
                "debug,sqlx::query=warn"
            })
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

/// `JWT_*_KEY_FILE` 覆盖:设了则读文件内容覆盖对应 PEM 字段(镜像 SEED_FILE 范式)。抽成独立函数以便单测,
/// 不依赖 figment/环境变量。
fn apply_jwt_key_file_overrides(cfg: &mut Config) -> anyhow::Result<()> {
    if let Some(p) = &cfg.jwt_private_key_file {
        cfg.jwt_private_key_pem = std::fs::read_to_string(p)
            .with_context(|| format!("读 JWT_PRIVATE_KEY_FILE {p} 失败"))?;
    }
    if let Some(p) = &cfg.jwt_public_key_file {
        cfg.jwt_public_key_pem = std::fs::read_to_string(p)
            .with_context(|| format!("读 JWT_PUBLIC_KEY_FILE {p} 失败"))?;
    }
    Ok(())
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
    fn url_percent_encodes_reserved_userinfo() {
        // 生成的密码常含 URL 保留字符;原样插值会在 '/' 处截断 authority → 连接失败。
        // 编码后 sqlx 的 URL 解析器应能正确解析(且 password 里不再有裸 '/')。
        let mut c = cfg(Some("h"));
        c.app_db_password = "p/w@x?y#z ".into();
        let url = c.app_database_url().unwrap();
        assert!(!url.contains("p/w"), "保留字符必须被编码: {url}");
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .expect("编码后的连接串必须可解析");
    }

    #[test]
    fn log_filter_prefers_rust_log_then_env_default() {
        let mut c = Config::default();
        assert_eq!(c.log_filter(), "debug,sqlx::query=warn");
        c.app_env = Profile::Prod;
        assert_eq!(c.log_filter(), "info,sqlx::query=warn");
        c.rust_log = Some("warn".into());
        assert_eq!(c.log_filter(), "warn");
    }

    #[test]
    fn prod_only_hides_docs() {
        assert!(Profile::Dev.expose_docs());
        assert!(Profile::Staging.expose_docs());
        assert!(!Profile::Prod.expose_docs());
    }

    /// JWT_*_KEY_FILE 覆盖:设了文件则读内容覆盖 PEM 字段;未设保持内嵌默认。
    #[test]
    fn jwt_key_file_overrides_pem_fields() {
        let dir = std::env::temp_dir().join("jwt-key-override-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.pub.pem");
        std::fs::write(
            &p,
            "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        let mut cfg = Config::default();
        assert_eq!(
            cfg.jwt_public_key_pem, DEV_JWT_PUBLIC_KEY_PEM,
            "默认应是内嵌 dev"
        );
        cfg.jwt_public_key_file = Some(p.to_string_lossy().into_owned());
        apply_jwt_key_file_overrides(&mut cfg).unwrap();
        assert!(cfg.jwt_public_key_pem.contains("fake"), "应被文件内容覆盖");
        // 指向不存在的文件 → 报错带路径
        cfg.jwt_private_key_file = Some("/no/such/key.pem".to_owned());
        assert!(apply_jwt_key_file_overrides(&mut cfg).is_err());
    }

    #[test]
    fn seed_on_start_prod_needs_seed_file() {
        let seeds = |env: Profile, seed_file: Option<&str>, explicit: Option<bool>| {
            Config {
                app_env: env,
                seed_file: seed_file.map(Into::into),
                idm_seed_on_start: explicit,
                ..Config::default()
            }
            .seed_on_start()
        };
        // 非 prod:恒开(嵌入默认账号便利)。
        assert!(seeds(Profile::Dev, None, None));
        // prod 无 SEED_FILE:关(绝不用嵌入的 pwd 弱默认建超管)。
        assert!(!seeds(Profile::Prod, None, None));
        // prod + SEED_FILE(运维给了真账号/密码):开(启动幂等建号,容器无外部命令)。
        assert!(seeds(Profile::Prod, Some("seed.prod.toml"), None));
        // 显式 IDM_SEED_ON_START 永远优先(prod 无 SEED_FILE 也能强开,反之强关)。
        assert!(seeds(Profile::Prod, None, Some(true)));
        assert!(!seeds(Profile::Prod, Some("seed.prod.toml"), Some(false)));
    }
}

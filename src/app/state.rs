use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use super::adapters::{
    ContentAvatarProbe, IdmOutboxSource, InProcessProfileDirectory, InProcessUserDirectory,
    SearchIndexAdapter,
};
use super::router::Mount;
use crate::features::auth::{AppTokenSigner, AppTokenVerifier, NoopSigner};
use crate::features::auth_audit::{
    projector::AuthEventProjector, AuthEventBus, AuthEventRepo, AuthRetentionJob, PgAuthEventRepo,
};
use crate::features::profile::{
    AvatarProbe, InMemoryProfileRepo, PgAppOutbox, PgProfileRepo, ProfileRepo, ProfileService,
};
use crate::features::search::{projector::Projector, PgSearchIndexRepo, SearchIndexRepo};
use crate::features::users::{self, UserAdminService, UserSearchIndex};
use crate::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, NatsEventBus, PgEventBus, PgWidgetRepo,
    UserDirectory, WidgetRepo, WidgetService,
};
use crate::infra::authz::Policy;
use crate::infra::config::Config;
use crate::infra::jetstream::JetStreamPublisher;
use crate::infra::objectstore::S3ObjectStore;
use crate::infra::outbox::{EventPublisher, OutboxRelay, OutboxSource};
use content::{
    ContentRepo, ContentService, InMemoryContentRepo, InMemoryObjectRepo, InMemoryObjectStore,
    ObjectRepo, ObjectStore, PgContentRepo, PgObjectRepo,
};
use idm::{
    Argon2Hasher, AuthService, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, OutboxRepo,
    PgOutboxRepo, PgRoleRepo, PgSessionRepo, PgUserRepo, RoleRepo, SessionRepo, UserRepo,
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
    Content,
    Search,
}

/// 应用级依赖容器。范式(替代 DI 框架):
/// - 用 axum 的 `State` 提取器注入到每个 handler。
/// - 字段是 service;service 内部持 `Arc<dyn Trait>` 仓储端口,启动时决定注入哪个实现。
/// - 廉价 `Clone`(字段都是 Arc),axum 每请求 clone 一份。
/// - 加业务模块 = 在这里加一个 service 字段 + 在 `new` 里装配它。
#[derive(Clone)]
pub struct AppState {
    pub widgets: WidgetService,
    /// 用户资料(app schema;头像经 content 富化,适配器见 app/adapters)。
    pub profiles: ProfileService,
    /// widget 变更事件总线(SSE 订阅端点用;service 持同一实例发布)。
    pub widget_events: Arc<dyn EventBus>,
    /// content 内容/对象存储服务(领域来自 content 库;app 注入仓储 + minio/内存 ObjectStore)。
    pub contents: ContentService,
    pub auth: AuthService,
    /// 后台用户管理(idm 身份原语 + app.profiles 富化)。仅 needs_idm 进程装真实现。
    pub user_admin: UserAdminService,
    /// readyz 就绪探针用:DB 模式持 pool(ping `SELECT 1`),内存模式为 `None`(恒就绪)。
    pub db_pool: Option<PgPool>,
    /// 认证 cookie 是否带 `Secure`(prod=true,仅 https 发送;dev http 必须 false 否则浏览器不发)。
    pub cookie_secure: bool,
    /// **授权策略(归 app)**:role→权限,从 `seed.toml` 派生的内存只读 `Policy`。handler 经
    /// `state.policy.require(_scoped)` gate 端点。**不查 idm 库**(roles 在 token 里)。
    pub policy: Arc<Policy>,
    /// JWT 验证半边(公钥)。所有进程持有 —— authenticate 中间件验签/取 scope。
    pub token_verifier: Arc<AppTokenVerifier>,
    /// JWT 签发半边(私钥)。**仅 needs_idm 进程 Some**;`Mount::App` = None(app 被攻破铸不出 token)。
    pub token_signer: Option<Arc<AppTokenSigner>>,
    /// idm.outbox 写句柄(仅 needs_idm 进程 Some):auth handler 发审计事件用(fire-and-forget)。
    pub idm_outbox: Option<Arc<dyn idm::OutboxRepo>>,
    /// auth_event 读句柄(admin 查询端点用)。仅 needs_idm + 配了 search pool 时 Some。
    pub auth_events: Option<Arc<dyn AuthEventRepo>>,
    /// auth_event 实时推送总线(`/admin/auth/auth-events/stream` SSE 用;projector 持同一实例发布)。
    /// 仅当 `auth_projector` 真装起来(needs_idm && NATS_URL && search pool)时 Some ——
    /// 唯一发布者没装,总线就不该对外暴露(否则 SSE 200 挂着永不推送,见 `AuthEventBus` 头注)。
    pub auth_events_bus: Option<AuthEventBus>,
}

/// 组合根装的后台任务(随 `run` 的优雅退出而停)。P1 outbox relay + P3 search projector,
/// 都是"装了就 spawn、没装就跳过"的可选后台循环 —— 打包一份返回,省得 `new` 签名越加越长。
pub struct BackgroundTasks {
    pub relays: Vec<OutboxRelay>,
    pub projector: Option<Projector>,
    pub auth_projector: Option<AuthEventProjector>,
    pub auth_retention: Option<AuthRetentionJob>,
}

impl AppState {
    /// 按 `mount` 只装配本进程真正用到的库:app 进程连 app DB(widget)、idm 进程连 idm DB(auth/me),
    /// 各自不连对方的库 —— 省掉闲置连接,也让 readyz 探针 ping 的是本进程主库。
    /// app 进程的鉴权中间件只 decode JWT(roles 在 claim 里),不查 idm 库,故 idm 用内存占位即可。
    pub async fn new(config: &Config, mount: Mount) -> anyhow::Result<(Self, BackgroundTasks)> {
        let needs_app = matches!(mount, Mount::App | Mount::Both);
        let needs_idm = matches!(mount, Mount::Idm | Mount::Both);

        // prod fail-fast(**先于连库**:钥错比 DB 错更该早报,也守"安全不变量最前"):内嵌 dev 密钥
        // 只准开发用 —— 公钥全进程校验,私钥只在真持有它的进程(needs_idm)校验。
        if config.app_env.is_prod() {
            anyhow::ensure!(
                config.jwt_public_key_pem != crate::infra::config::DEV_JWT_PUBLIC_KEY_PEM,
                "prod 禁用内嵌 dev JWT 公钥:设 JWT_PUBLIC_KEY_FILE"
            );
            if needs_idm {
                anyhow::ensure!(
                    config.jwt_private_key_pem != crate::infra::config::DEV_JWT_PRIVATE_KEY_PEM,
                    "prod 禁用内嵌 dev JWT 私钥:设 JWT_PRIVATE_KEY_FILE"
                );
            }
        }

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

        // 事件总线(SSE 范式)—— IoC 选择链:NATS_URL → NATS(多实例默认);
        // 无则有 app pool → PG LISTEN/NOTIFY(已有 PG 不加组件的退路);都无 → 内存(单实例兜底)。
        let widget_events: Arc<dyn EventBus> = match (&config.nats_url, &app_pool) {
            (Some(url), _) if needs_app => Arc::new(NatsEventBus::connect(url).await?),
            (_, Some(pool)) => Arc::new(PgEventBus::new(pool.clone())),
            _ => {
                if needs_app {
                    tracing::warn!("未设 NATS_URL 且无 app pool,事件总线使用内存实现(单实例)");
                }
                Arc::new(MemoryEventBus::new())
            }
        };

        // content(content schema):app 进程的模块(与 widget 同进程)。设了 CONTENT_DB_HOST → PG,否则内存。
        // 字节后端独立于库:设了 S3_ENDPOINT → minio/S3(S3ObjectStore),否则进程内 InMemoryObjectStore。
        let content_pool = if needs_app {
            connect_for_schema(config, Schema::Content).await?
        } else {
            None
        };
        let content_repo: Arc<dyn ContentRepo> = match &content_pool {
            Some(pool) => Arc::new(PgContentRepo::new(pool.clone())),
            None => {
                if needs_app {
                    tracing::warn!("未设 CONTENT_DB_HOST,content 仓储使用内存实现(脚手架默认)");
                }
                Arc::new(InMemoryContentRepo::new())
            }
        };
        let object_repo: Arc<dyn ObjectRepo> = match &content_pool {
            Some(pool) => Arc::new(PgObjectRepo::new(pool.clone())),
            None => Arc::new(InMemoryObjectRepo::new()),
        };
        let (object_store, backend_name): (Arc<dyn ObjectStore>, String) = match &config.s3_endpoint
        {
            Some(endpoint) => {
                let store = S3ObjectStore::new(
                    endpoint,
                    &config.s3_region,
                    &config.s3_bucket,
                    &config.s3_access_key,
                    &config.s3_secret_key,
                    config.s3_presign_relative,
                )
                .await;
                (Arc::new(store), "minio".to_owned())
            }
            None => {
                if needs_app {
                    tracing::warn!("未设 S3_ENDPOINT,content 字节后端使用内存实现(脚手架默认)");
                }
                (Arc::new(InMemoryObjectStore::new()), "memory".to_owned())
            }
        };
        let contents = ContentService::new(content_repo, object_repo, object_store, backend_name);

        // profile(app schema):可拔插仓储同 widget(复用 app_pool);头像探测经进程内 content 适配器。
        let profile_repo: Arc<dyn ProfileRepo> = match &app_pool {
            Some(pool) => Arc::new(PgProfileRepo::new(pool.clone())),
            None => Arc::new(InMemoryProfileRepo::new()),
        };
        let avatar_probe: Arc<dyn AvatarProbe> =
            Arc::new(ContentAvatarProbe::new(contents.clone()));
        let profiles = ProfileService::new(profile_repo.clone(), avatar_probe);

        // idm(idm schema):仅 idm/both 进程需要。设了 IDM_DB_HOST → PG(读 seed 的 superadmin 等),否则内存。
        let idm_pool = if needs_idm {
            connect_for_schema(config, Schema::Idm).await?
        } else {
            None
        };
        // search(search schema,读模型归 idm 侧):仅 needs_idm 进程需要,只喂 projector(不进 AppState 字段)。
        let search_pool = if needs_idm {
            connect_for_schema(config, Schema::Search).await?
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
                // user 与 role repo **共享** RoleStore —— 否则 create_with_roles/set_roles 的授予对
                // roles_for_user/list 不可见(PG 侧靠共表天然一致,内存侧需显式 sharing_with)。
                let mem_users = InMemoryUserRepo::new();
                let mem_roles = InMemoryRoleRepo::sharing_with(&mem_users);
                (
                    Arc::new(mem_users) as Arc<dyn UserRepo>,
                    Arc::new(InMemorySessionRepo::new()),
                    Arc::new(mem_roles) as Arc<dyn RoleRepo>,
                )
            }
        };
        // seed.toml 是 idm 默认数据 + **app 授权策略**两份真相的载体,**load 一次**:
        let seed = super::seed::SeedData::load(config.seed_file.as_deref())?;
        seed.assert_permission_catalog()?; // 启动期不变量:seed 权限词表 == 代码 Perm 闭集(多/漏即拒启动)

        // 授权策略(归 app),**可拔插**(同 widget):设了 APP_DB_HOST → 读 app schema 的 role_permissions 表
        // (role→权限可运行时改);否则从 seed.toml 派生内存 Policy。dev(seed_on_start)先幂等灌表。
        // 注:prod 分进程 Idm 时 needs_app=false、app_pool=None → 走内存(idm 进程只 gate /me,够用)。
        let policy = Arc::new(match &app_pool {
            Some(pool) => {
                if needs_app && config.seed_on_start() {
                    super::policy_repo::seed_authz(pool, &seed).await?;
                }
                super::policy_repo::load_policy(pool).await?
            }
            None => seed.policy(),
        });
        policy.assert_roles_covered(seed.granted_roles())?; // 启动期不变量:账号引用的 role 都得有策略条目

        // 进程内 seed:idm-mounting 进程 + 开启时(默认非 prod),幂等写默认 role/账号(复用 &seed)。
        // memory 与 PG 都生效 —— dev 内存模式也能有 superadmin/admin/user 登录。prod 默认不跑,走显式 `seed` bin。
        if needs_idm && config.seed_on_start() {
            super::seed::apply(
                idm_users.as_ref(),
                idm_roles.as_ref(),
                &Argon2Hasher,
                &seed,
                Some("system".to_owned()),
            )
            .await?;
        }

        // mock 样本数据(dev/demo 专用):owner(username)经 idm 解析 → 幂等写 app widget/profile 仓储。
        // 需 app+idm 同进程(才能解析 owner)+ seed 开启 → 即 dev `Both`;prod 分进程不跑(无 demo 数据污染)。
        // 跟在 idm seed 之后:此时 admin/user 已存在,owner 才解析得到。
        if needs_app && needs_idm && config.seed_on_start() {
            let mock = super::mock::MockData::load(config.mock_file.as_deref())?;
            super::mock::apply(
                widget_repo.as_ref(),
                profile_repo.as_ref(),
                idm_users.as_ref(),
                &mock,
            )
            .await?;
        }

        // 跨模块富化:widget 的 UserDirectory 端口由 app 注入 idm 的进程内适配器(复用 idm_users)。
        // 单体 Both 连真 idm 库;分进程 App 时 idm_users 是内存占位 → 富化降级为空(留待 HttpUserDirectory)。
        let user_directory: Arc<dyn UserDirectory> =
            Arc::new(InProcessUserDirectory::new(idm_users.clone()));

        // 非对称 JWT:验证半边人人有,签发半边只进 idm 进程(分进程最小权限)。dev/prod 钥校验见函数首。
        let token_verifier = Arc::new(
            AppTokenVerifier::from_pem(&config.jwt_public_key_pem).context("JWT 公钥装配失败")?,
        );
        let token_signer = if needs_idm {
            Some(Arc::new(
                AppTokenSigner::from_pem(&config.jwt_private_key_pem)
                    .context("JWT 私钥装配失败")?,
            ))
        } else {
            None
        };
        // app 进程注入 NoopSigner:签发路径本不可达(auth 路由不挂),真被调到就炸(wiring bug)。
        let signer_port: Arc<dyn idm::TokenSigner> = match &token_signer {
            Some(s) => s.clone(),
            None => Arc::new(NoopSigner),
        };
        // 后台用户管理:富化端口**恒**包 profile_repo —— 单体(内存/PG)profile_repo 有数据 → 富化;
        // 分进程 idm(needs_app=false)profile_repo 是空内存占位 → 批量查空 → display_name/avatar 自然降级 null。
        // (勿按 app_pool 的 Some/None 选:内存 Both 也 None 但 profile_repo 有数据,那样会误降级。)
        // idm repos 被 AuthService::builder move 走 —— user_admin 先 clone(Arc,廉价)。
        let profile_directory: Arc<dyn users::ProfileDirectory> =
            Arc::new(InProcessProfileDirectory::new(profile_repo.clone()));
        // 配了 search pool(SEARCH_DB_HOST + needs_idm)→ list 读投影(q/display_name 搜/排);
        // 否则 None → list 回退 idm 直查 + q/display_name-sort 422。读侧独立建 PgSearchIndexRepo(与
        // build_projector 的写侧各持 pool.clone(),廉价 Arc,读写解耦、不共享实例)。
        let user_search: Option<Arc<dyn UserSearchIndex>> = search_pool.as_ref().map(|pool| {
            let repo: Arc<dyn SearchIndexRepo> = Arc::new(PgSearchIndexRepo::new(pool.clone()));
            Arc::new(SearchIndexAdapter::new(repo)) as Arc<dyn UserSearchIndex>
        });
        let user_admin = UserAdminService::new(
            idm_users.clone(),
            idm_roles.clone(),
            idm_sessions.clone(),
            Arc::new(Argon2Hasher),
            profile_directory,
            user_search,
        );

        let auth = AuthService::builder(idm_users, idm_sessions, idm_roles)
            .hasher(Arc::new(Argon2Hasher))
            .signer(signer_port)
            .verifier(token_verifier.clone())
            .access_ttl_secs(config.idm_access_ttl_secs)
            .refresh_ttl_secs(config.idm_refresh_ttl_secs)
            .build();

        let outbox_relays = build_outbox_relays(
            config,
            needs_idm,
            needs_app,
            idm_pool.as_ref(),
            app_pool.as_ref(),
        )
        .await?;
        let projector = build_projector(config, needs_idm, search_pool.as_ref()).await?;

        // auth 审计:写句柄(idm.outbox,handler 发事件用)+ 读句柄(auth_event,admin 查询用)+
        // projector(消费投影)+ 保留 job,都在 `db_pool: app_pool.or(idm_pool)` **移动 idm_pool 之前**
        // 用 `.as_ref()` 建好(镜像上面 search_pool/user_search 的写法)。
        let idm_outbox: Option<Arc<dyn idm::OutboxRepo>> = idm_pool
            .as_ref()
            .map(|p| Arc::new(PgOutboxRepo::new(p.clone())) as Arc<dyn idm::OutboxRepo>);
        let auth_events: Option<Arc<dyn AuthEventRepo>> = search_pool
            .as_ref()
            .map(|p| Arc::new(PgAuthEventRepo::new(p.clone())) as Arc<dyn AuthEventRepo>);
        // SSE 总线:唯一发布者是下面的 auth_projector,只有它真装起来了总线才该对外暴露 ——
        // 否则 needs_idm 但 nats/search 未配时,`/stream` 会 200 挂着却永不推送(sibling 端点已 404)。
        // 装配顺序在 `db_pool` 移动 idm_pool 之前 —— 之后还要 `.clone()` 一份塞进 projector。
        let bus = needs_idm.then(AuthEventBus::new);
        let auth_projector =
            build_auth_event_projector(config, needs_idm, search_pool.as_ref(), bus.clone())
                .await?;
        let auth_events_bus = if auth_projector.is_some() { bus } else { None };
        let auth_retention = search_pool.as_ref().map(|p| {
            AuthRetentionJob::new(
                Arc::new(PgAuthEventRepo::new(p.clone())) as Arc<dyn AuthEventRepo>
            )
        });

        Ok((
            Self {
                widgets: WidgetService::new(widget_repo, user_directory, widget_events.clone()),
                profiles,
                widget_events,
                contents,
                auth,
                user_admin,
                // readyz 探针 ping 本进程主库:app 进程→app 库,idm 进程→idm 库。
                db_pool: app_pool.or(idm_pool),
                cookie_secure: config.app_env.is_prod(),
                policy,
                token_verifier,
                token_signer,
                idm_outbox,
                auth_events,
                auth_events_bus,
            },
            BackgroundTasks {
                relays: outbox_relays,
                projector,
                auth_projector,
                auth_retention,
            },
        ))
    }
}

/// 装配 outbox relay(JetStream 交付腿)。规则:设了 `NATS_URL` 且本进程持有对应 schema 的 pg pool
/// 才起该 schema 的 relay —— idm relay 归 needs_idm 进程、app relay 归 needs_app 进程(单体 Both 两个都起)。
/// 无 nats(脚手架默认)→ 空 Vec,不外发事件(P4 的 list 走回退)。nats 设了但连不上 → fail-fast(同 NatsEventBus)。
async fn build_outbox_relays(
    config: &Config,
    needs_idm: bool,
    needs_app: bool,
    idm_pool: Option<&PgPool>,
    app_pool: Option<&PgPool>,
) -> anyhow::Result<Vec<OutboxRelay>> {
    use std::time::Duration;
    let Some(nats_url) = config.nats_url.as_deref() else {
        return Ok(Vec::new());
    };
    let idm_src = if needs_idm { idm_pool } else { None };
    let app_src = if needs_app { app_pool } else { None };
    if idm_src.is_none() && app_src.is_none() {
        return Ok(Vec::new()); // nats 设了但本进程无相关 schema pool → 无可 relay
    }
    // 与 NatsEventBus::connect 同哲学:nats 挂着起不来。
    let publisher: Arc<dyn EventPublisher> = Arc::new(JetStreamPublisher::connect(nats_url).await?);
    // poll_interval/batch:P1 纯轮询的合理默认;P2 叠 NOTIFY 降延迟。
    let poll_interval = Duration::from_secs(1);
    let batch = 128;
    let mut relays = Vec::new();
    if let Some(pool) = idm_src {
        let repo: Arc<dyn OutboxRepo> = Arc::new(PgOutboxRepo::new(pool.clone()));
        let source: Arc<dyn OutboxSource> = Arc::new(IdmOutboxSource::new(repo));
        relays.push(OutboxRelay::new(
            source,
            publisher.clone(),
            poll_interval,
            batch,
        ));
    }
    if let Some(pool) = app_src {
        let source: Arc<dyn OutboxSource> = Arc::new(PgAppOutbox::new(pool.clone()));
        relays.push(OutboxRelay::new(
            source,
            publisher.clone(),
            poll_interval,
            batch,
        ));
    }
    tracing::info!("装配 {} 个 outbox relay(JetStream 交付)", relays.len());
    Ok(relays)
}

/// 装配 projector:needs_idm 进程 + NATS_URL + search pool 三者齐才起(它连 nats consume + 写 search)。
/// 否则 None(无投影;P4 list 回退)。durable name 固定 "admin_user_projector"。
async fn build_projector(
    config: &Config,
    needs_idm: bool,
    search_pool: Option<&PgPool>,
) -> anyhow::Result<Option<Projector>> {
    let (Some(nats_url), Some(pool)) = (
        config.nats_url.as_deref().filter(|_| needs_idm),
        search_pool,
    ) else {
        return Ok(None);
    };
    let repo: Arc<dyn SearchIndexRepo> = Arc::new(PgSearchIndexRepo::new(pool.clone()));
    Ok(Some(
        Projector::connect(nats_url, repo, "admin_user_projector").await?,
    ))
}

/// 装配 auth_event 投影器:needs_idm + NATS_URL + search pool 三者齐才起。镜像 `build_projector`;
/// 独立 durable name "auth_event_projector",消费 `events.idm.auth.>`(见 `AuthEventProjector::connect`)。
/// `bus`:落库成功后发布给 SSE 订阅者,转发给 `AuthEventProjector::connect`。
async fn build_auth_event_projector(
    config: &Config,
    needs_idm: bool,
    search_pool: Option<&PgPool>,
    bus: Option<AuthEventBus>,
) -> anyhow::Result<Option<AuthEventProjector>> {
    let (Some(nats_url), Some(pool)) = (
        config.nats_url.as_deref().filter(|_| needs_idm),
        search_pool,
    ) else {
        return Ok(None);
    };
    let repo: Arc<dyn AuthEventRepo> = Arc::new(PgAuthEventRepo::new(pool.clone()));
    Ok(Some(
        AuthEventProjector::connect(nats_url, repo, "auth_event_projector", bus).await?,
    ))
}

/// 按 `schema` 起连接池(复用该 schema 自己的 role)。未配置对应 `*_DB_HOST` → `None`(走内存)。
///
/// **跨模块访问其他 schema 的唯一连接入口**:本进程主连接与未来的跨模块只读连接都经它,口径一致 ——
/// 拿到对方 schema 的连接后**只走对方模块的 repo** 读,绝不跨 schema join。
pub async fn connect_for_schema(config: &Config, schema: Schema) -> anyhow::Result<Option<PgPool>> {
    let url = match schema {
        Schema::App => config.app_database_url(),
        Schema::Idm => config.idm_database_url(),
        Schema::Content => config.content_database_url(),
        Schema::Search => config.search_database_url(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::config::Profile;

    /// prod + 内嵌 dev 密钥 → 启动拒(公钥全进程;私钥仅 needs_idm)。
    #[tokio::test]
    async fn prod_rejects_embedded_dev_jwt_keys() {
        let cfg = Config {
            app_env: Profile::Prod,
            ..Config::default()
        };
        // AppState 无 Debug(含 trait object 字段),手动 match 而非 expect_err/unwrap_err。
        let err = match AppState::new(&cfg, Mount::Both).await {
            Ok((_, _)) => panic!("prod+dev 钥应拒启动"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("JWT"), "{err}");
    }
}

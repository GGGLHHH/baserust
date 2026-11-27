//! 组合根的装配:`AppState`(应用级依赖容器)+ 后台任务 + 各 schema 的连接池入口。
//! 按挂载范围与配置在启动时决定每个端口注入哪个实现(内存 / PG / NATS …)。

use std::sync::Arc;

use anyhow::Context;
use async_nats::ConnectOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use time::Duration;

use crate::app::adapters::{
    ContentAvatarProbe, IdmOutboxSource, InProcessProfileDirectory, InProcessUserDirectory,
    MemberSearchAdapter, SearchIndexAdapter,
};
use crate::app::monitoring::MonitoringSetup;
use crate::app::probes::{ProbePool, Probes};
use crate::app::router::Mount;
use crate::app::seed::{self, IdmSeedRepos, SeedData};
use crate::app::{avatar_repair, mock_data, policy_repo};
use crate::features::auth::{AppTokenSigner, AppTokenVerifier, NoopSigner};
use crate::features::auth_audit::adapters::auth_event_projector::AuthEventProjector;
use crate::features::auth_audit::{
    AuthAuditService, AuthEventBus, AuthEventRepo, AuthRetentionJob, PgAuthEventRepo,
};
use crate::features::profile::{
    AvatarProbe, InMemoryProfileRepo, PgAppOutbox, PgProfileRepo, ProfileRepo, ProfileService,
};
use crate::features::search::projector::Projector;
use crate::features::search::{PgSearchIndexRepo, SearchIndexRepo};
use crate::features::tenants::{MemberProfiles, MemberSearchIndex, TenantAdminService};
use crate::features::users::{ProfileDirectory, UserAdminService, UserSearchIndex};
use crate::features::widget::{
    EventBus, InMemoryWidgetRepo, MemoryEventBus, NatsEventBus, PgEventBus, PgWidgetRepo,
    UserDirectory, WidgetRepo, WidgetService,
};
use crate::infra::config::{
    Config, DEVELOPMENT_JWT_PRIVATE_KEY_PEM, DEVELOPMENT_JWT_PUBLIC_KEY_PEM,
};
use crate::infra::jet_stream_publisher::{DurableConsumer, JetStreamPublisher};
use crate::infra::monitor::pg_ops_store::PgOpsStore;
use crate::infra::monitor::store::{MemoryOpsStore, OpsStore};
use crate::infra::outbox::{EventPublisher, OutboxRelay, OutboxSource};
use crate::infra::s3_object_store::{PresignUrlStyle, S3ObjectStore, S3Settings};
use crate::kernel::authorization::Policy;
use content::{
    ContentRepo, ContentService, InMemoryContentRepo, InMemoryObjectRepo, InMemoryObjectStore,
    ObjectRepo, ObjectStore, PgContentRepo, PgObjectRepo,
};
use idm::{
    Argon2Hasher, AuthService, InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo,
    InMemoryTenantRepo, InMemoryUserRepo, MemberRepo, OutboxRepo, PgMemberRepo, PgOutboxRepo,
    PgRoleRepo, PgSessionRepo, PgTenantRepo, PgUserRepo, RoleRepo, SessionRepo, TenantRepo,
    TokenSigner, UserRepo,
};

/// 数据库 schema(= 运行时 role = 连接归属)。每个 schema 用自己的 role 连接。
///
/// app / content / search 拆成三个账号(spec §4.4):`<schema>_owner` 跑迁移、拥有表(运行时不用);
/// `<schema>` 运行时(只有 DML、NOBYPASSRLS,[`connect_for_schema`]);`<schema>_system`
/// BYPASSRLS(后台任务,[`connect_system_for_schema`])。idm / ops 不拆。
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
    /// 运维数据(后台监控的历史指标与日志)。
    Ops,
}

/// 本应用用的认证服务:四个 idm 仓储端口都在启动时按配置二选一(内存 / PG),所以填 `Arc<dyn …>`
/// (idm 给 `Arc<T>` 做了端口转发实现)。依据同 [`AppState`] 文档里的「Generics versus `dyn Trait`」。
pub type AppAuthService =
    AuthService<Arc<dyn UserRepo>, Arc<dyn SessionRepo>, Arc<dyn RoleRepo>, Arc<dyn MemberRepo>>;

/// 本应用用的内容服务:仓储(内存 / PG)和字节后端(内存 / S3)都在启动时按配置二选一,填 `Arc<dyn …>`;
/// 端口全是 `Arc`,`Clone` 廉价,直接放进 [`AppState`]。
pub type AppContentService =
    ContentService<Arc<dyn ContentRepo>, Arc<dyn ObjectRepo>, Arc<dyn ObjectStore>>;

/// 应用级依赖容器。范式(替代 DI 框架):
/// - 用 axum 的 `State` 提取器注入到每个 handler。
/// - 字段是 service;service 内部持 `Arc<dyn Trait>` 仓储端口,启动时决定注入哪个实现。
/// - 廉价 `Clone`(字段都是 Arc),axum 每请求 clone 一份。
/// - 加业务模块 = 在这里加一个 service 字段 + 在 `try_new` 里装配它。
///
/// 端口用 `Arc<dyn Port>` 共享,依据风格指南「Avoid `Rc` and `Arc`」的例外(借用结构会
/// *unreasonably complex*):axum 的 `State` 与 `tokio::spawn` 都要求 `'static`,同一实例被多个用例 /
/// 后台任务共享;「Generics versus `dyn Trait`」只约束库,这里是应用代码,且实现要在启动时按配置二选一。
#[derive(Clone)]
pub struct AppState {
    /// widget 用例(app schema;创建者经 idm 富化)。
    pub widgets: WidgetService,
    /// 用户资料(app schema;头像经 content 富化,适配器见 app/adapters)。
    pub profiles: ProfileService,
    /// widget 变更事件总线(SSE 订阅端点用;service 持同一实例发布)。
    pub widget_events: Arc<dyn EventBus>,
    /// content 内容/对象存储服务(领域来自 content 库;app 注入仓储 + minio/内存 ObjectStore)。
    pub contents: AppContentService,
    /// 认证(idm:登录 / 刷新 / 会话 / 切换租户)。仅 needs_idm 进程连真 idm 库。
    /// `AuthService` 不 `Clone`,共享一个实例(`Arc`,理由同上)。
    pub auth: Arc<AppAuthService>,
    /// 后台用户管理(idm 身份原语 + app.profiles 富化)。仅 needs_idm 进程装真实现。
    pub user_admin: UserAdminService,
    /// 租户 / 成员管理(idm 租户、成员、会话原语 + search 成员索引 + app.profiles 富化)。仅 needs_idm 进程挂路由。
    pub tenant_admin: TenantAdminService,
    /// 依赖探针(`/readyz` 逐项检查 + 连接池指标):本进程持有的各 schema 连接池 + NATS 连接。
    /// 内存模式为空(恒就绪)。测试里直接 `Default::default()`。
    pub probes: Probes,
    /// 后台监控页:本进程的角色(app / idm / 合体)+ 要汇总的远端 idm(分进程拓扑)。测试里 `Default::default()`。
    pub monitoring: MonitoringSetup,
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
    pub idm_outbox: Option<Arc<dyn OutboxRepo>>,
    /// auth_event 读句柄(admin 查询端点用)。仅 needs_idm + 配了 search pool 时 Some。
    pub auth_audit: Option<AuthAuditService>,
    /// auth_event 实时推送总线(`/admin/auth/auth-events/stream` SSE 用;projector 持同一实例发布)。
    /// 仅当 `auth_projector` 真装起来(needs_idm && NATS_URL && search pool)时 Some ——
    /// 唯一发布者没装,总线就不该对外暴露(否则 SSE 200 挂着永不推送,见 `AuthEventBus` 头注)。
    pub auth_events_bus: Option<AuthEventBus>,
    /// **system 连接池**(BYPASSRLS 账号 `<schema>_system`,spec §4.4):后台任务(投影器、保留期清理、
    /// rebuild、seed / mock)和平台级跨租户读用它;请求路径一律走运行时账号的池 + `infra::pg::tenant_transaction`。
    /// app / content 归 needs_app 进程、search 归 needs_idm 进程,各自要设了对应 `*_DB_HOST`;内存模式为 None。
    pub app_system_pool: Option<PgPool>,
    /// content 的 system 连接池(见 [`Self::app_system_pool`])。
    pub content_system_pool: Option<PgPool>,
    /// search 的 system 连接池(见 [`Self::app_system_pool`])。
    pub search_system_pool: Option<PgPool>,
}

/// idm 仓储五件套,`AppState::try_new` 按有无 idm 库二选一装配。
struct IdmRepos {
    users: Arc<dyn UserRepo>,
    sessions: Arc<dyn SessionRepo>,
    roles: Arc<dyn RoleRepo>,
    members: Arc<dyn MemberRepo>,
    tenants: Arc<dyn TenantRepo>,
}

/// [`AppState::try_new`] 的产物:装配好的共享状态 + 待启动的后台任务。
pub struct AssembledApp {
    pub state: AppState,
    pub background_tasks: BackgroundTasks,
}

/// 组合根装的后台任务(随 `run` 的优雅退出而停)。P1 outbox relay + P3 search projector,
/// 都是"装了就 spawn、没装就跳过"的可选后台循环 —— 打包一份返回,省得 `try_new` 签名越加越长。
pub struct BackgroundTasks {
    /// 各 schema 的 outbox relay(发 JetStream)。
    pub relays: Vec<OutboxRelay>,
    /// search 读模型投影器(账号目录 + 租户成员索引)。
    pub projector: Option<Projector>,
    /// auth_event 投影器(登录日志)。
    pub auth_projector: Option<AuthEventProjector>,
    /// auth_event 保留期清理。
    pub auth_retention: Option<AuthRetentionJob>,
}

impl AppState {
    /// 按 `mount` 只装配本进程真正用到的库:app 进程连 app DB(widget)、idm 进程连 idm DB(auth/me),
    /// 各自不连对方的库 —— 省掉闲置连接,也让 readyz 探针 ping 的是本进程主库。
    /// app 进程的鉴权中间件只 decode JWT(roles 在 claim 里),不查 idm 库,故 idm 用内存占位即可。
    pub async fn try_new(config: &Config, mount: Mount) -> anyhow::Result<AssembledApp> {
        let needs_app = matches!(mount, Mount::App | Mount::Both);
        let needs_idm = matches!(mount, Mount::Idm | Mount::Both);

        // prod fail-fast(**先于连库**:钥错比 DB 错更该早报,也守"安全不变量最前"):内嵌 dev 密钥
        // 只准开发用 —— 公钥全进程校验,私钥只在真持有它的进程(needs_idm)校验。
        if config.app_environment.is_production() {
            anyhow::ensure!(
                config.jwt_public_key_pem != DEVELOPMENT_JWT_PUBLIC_KEY_PEM,
                "prod 禁用内嵌 dev JWT 公钥:设 JWT_PUBLIC_KEY_FILE"
            );
            if needs_idm {
                anyhow::ensure!(
                    config.jwt_private_key_pem != DEVELOPMENT_JWT_PRIVATE_KEY_PEM,
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
            // 运行时账号(非 owner、NOBYPASSRLS)+ 每个方法自己的租户事务。
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
            (Some(url), _) if needs_app => Arc::new(NatsEventBus::try_new(url).await?),
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
        // system 池(BYPASSRLS):与运行时池同 host/库,账号不同;只在本进程持有该 schema 时连。
        let app_system_pool = if needs_app {
            connect_system_for_schema(config, Schema::App).await?
        } else {
            None
        };
        let content_system_pool = if needs_app {
            connect_system_for_schema(config, Schema::Content).await?
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
                let store = S3ObjectStore::new(S3Settings {
                    endpoint,
                    region: &config.s3_region,
                    bucket: &config.s3_bucket,
                    access_key: &config.s3_access_key,
                    secret_key: &config.s3_secret_key,
                    presign_url_style: if config.s3_presign_relative {
                        PresignUrlStyle::Relative
                    } else {
                        PresignUrlStyle::Absolute
                    },
                })
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
        let contents =
            AppContentService::new(content_repo, object_repo, object_store, backend_name);

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
        // search(search schema,读模型归 idm 侧):仅 needs_idm 进程需要。运行时池只给请求路径读成员索引
        // (租户事务 + RLS);投影器 / 保留期 / 认证审计(平台级)用 system 池。
        let search_pool = if needs_idm {
            connect_for_schema(config, Schema::Search).await?
        } else {
            None
        };
        let search_system_pool = if needs_idm {
            connect_system_for_schema(config, Schema::Search).await?
        } else {
            None
        };
        let IdmRepos {
            users: idm_users,
            sessions: idm_sessions,
            roles: idm_roles,
            members: idm_members,
            tenants: idm_tenants,
        } = match &idm_pool {
            Some(pool) => IdmRepos {
                users: Arc::new(PgUserRepo::new(pool.clone())),
                sessions: Arc::new(PgSessionRepo::new(pool.clone())),
                roles: Arc::new(PgRoleRepo::new(pool.clone())),
                members: Arc::new(PgMemberRepo::new(pool.clone())),
                tenants: Arc::new(PgTenantRepo::new(pool.clone())),
            },
            None => {
                if needs_idm {
                    tracing::warn!("未设 IDM_DB_HOST,idm 仓储使用内存实现");
                }
                // user 与 role repo **共享** RoleStore —— 否则 create_with_roles/set_roles 的授予对
                // roles_for_user/list 不可见(PG 侧靠共表天然一致,内存侧需显式 new_shared_with)。
                let memory_users = InMemoryUserRepo::new();
                // 成员 / 会话仓储同理共享租户存储(登录选租户、会话的租户外键校验看同一批租户)。
                let memory_roles = InMemoryRoleRepo::new_shared_with(&memory_users);
                let memory_sessions = InMemorySessionRepo::new_shared_with(&memory_users);
                let memory_members = InMemoryMemberRepo::new_shared_with(&memory_users);
                let memory_tenants = InMemoryTenantRepo::new_shared_with(&memory_users);
                IdmRepos {
                    users: Arc::new(memory_users),
                    sessions: Arc::new(memory_sessions),
                    roles: Arc::new(memory_roles),
                    members: Arc::new(memory_members),
                    tenants: Arc::new(memory_tenants),
                }
            }
        };
        // seed.toml 载**租户 + 账号**;角色/权限/role→权限默认是代码闭集(kernel::authorization::{RoleName, Permission})。
        let seed_data = SeedData::try_new(config.seed_file.as_deref())?;

        // 授权策略(归 app),**可拔插**(同 widget):设了 APP_DB_HOST → 读 app schema 的 role_permissions 表
        // (role→权限可运行时改);否则从 seed.toml 派生内存 Policy。
        // 注:prod 分进程 Idm 时 needs_app=false、app_pool=None → 走内存(idm 进程只 gate /me,够用)。
        //
        // **词表幂等同步不门控 seed_on_start**:prod+dev 只要连了 app 库就在启动跑 seed_authorization。
        // 它把 `Permission` 代码闭集投影进 permissions/role_permissions,ON CONFLICT 只增补、不覆盖
        // 运行期改动(admin 后台编辑安全)、无密钥非敏感 —— 加权限变体重启即自动进表,无需迁移/手工 seed。
        // 与账号+密码 seed(下方 seed_on_start 门控,prod 不自动建超管)刻意解耦:那个才是"避免启动期意外写库"的对象。
        // **启动时载入一次**,运行期只读;跨作用域的 role_permissions 行在载入时 WARN 并忽略(spec §6.1)。
        let policy = Arc::new(match &app_pool {
            Some(pool) => {
                if needs_app {
                    policy_repo::seed_authorization(pool, &seed_data).await?;
                }
                policy_repo::load_policy(pool).await?
            }
            None => seed_data.policy(),
        });
        // 旧头像修复(幂等,见 app::avatar_repair):profiles 引用的、还在默认租户里的头像 content 转成个人内容。
        // 与 seed_authorization 同理不门控 seed_on_start —— prod 升级后第一次启动就要修好,否则旧头像全部显示不出来。
        // 要 app 池(读 profiles)+ content system 池(BYPASSRLS 改 content 各表);内存模式没有旧数据,跳过。
        if needs_app {
            if let (Some(app), Some(content_system)) = (&app_pool, &content_system_pool) {
                avatar_repair::repair_legacy_avatars(avatar_repair::AvatarRepairPools {
                    app,
                    content_system,
                })
                .await?;
            }
        }
        // 启动期不变量:账号引用的 role(平台 + 租户)都得有策略条目
        policy.assert_roles_covered(seed_data.granted_roles().iter().map(String::as_str))?;
        let idm_seed_repos = IdmSeedRepos {
            users: idm_users.as_ref(),
            roles: idm_roles.as_ref(),
            tenants: idm_tenants.as_ref(),
            members: idm_members.as_ref(),
        };

        // 启动期不变量(不受 seed_on_start 控制):持 superadmin 的存活账号最多一个。改动前能经接口授出,存量库里
        // 可能已有多个,而现在接口撤不掉 —— 拒绝启动并指向清理办法。先于 seed:报错信息直接说清理,不被 seed 的冲突掩盖。
        if needs_idm {
            seed::ensure_single_superadmin(idm_users.as_ref()).await?;
        }

        // 进程内 seed:idm-mounting 进程 + 开启时,幂等写默认 role/账号(复用 &seed)。
        // memory 与 PG 都生效 —— dev 内存模式也有 superadmin/admin/user 登录。
        // 门控见 `Config::seed_on_start`:非 prod 默认开(嵌入弱默认账号);prod 仅当挂了 `SEED_FILE`
        // (真密码)才开 —— 容器无 `just`/`cargo`,靠此在启动幂等建号,不再依赖外部 seed bin。
        if needs_idm && config.seed_on_start() {
            let seed_report =
                seed::apply(idm_seed_repos, &Argon2Hasher, &seed_data, Some("system")).await?;
            // 账号的初始 profile(app schema)。**额外要 needs_app**:纯 idm 进程的 profile_repo 是
            // 内存占位,写进去静默丢、重启蒸发(同 router.rs 不给纯 idm 进程挂后台资料端点的理由)。
            // 分进程拓扑下没有初始 profile 也不阻断 —— `/profiles/me` 未建时回空资料,用户 PUT 即建。
            if needs_app {
                seed::apply_profiles(
                    profile_repo.as_ref(),
                    idm_users.as_ref(),
                    &seed_data,
                    &seed_report,
                    Some("system".to_owned()),
                )
                .await?;
            }
        }

        // mock 样本数据(dev/demo 专用):owner(username)经 idm 解析 → 幂等写 app widget/profile 仓储。
        // 需 app+idm 同进程(才能解析 owner)+ seed 开启 + **非 prod**。
        // 跟在 idm seed 之后:此时 admin/user 已存在,owner 才解析得到。
        //
        if should_apply_mock(config, needs_app, needs_idm) {
            let mock_data = mock_data::MockData::try_new(config.mock_file.as_deref())?;
            // mock 是后台写入(spec §4.4:seed / mock 用 _system 账号);仓储照样按租户写、照样走租户事务。
            let mock_widgets: Arc<dyn WidgetRepo> = match &app_system_pool {
                Some(system_pool) => Arc::new(PgWidgetRepo::new(system_pool.clone())),
                None => widget_repo.clone(),
            };
            mock_data::apply(
                mock_widgets.as_ref(),
                profile_repo.as_ref(),
                idm_seed_repos,
                &Argon2Hasher,
                &mock_data,
            )
            .await?;
        }

        // 跨模块富化:widget 的 UserDirectory 端口由 app 注入 idm 的进程内适配器(复用 idm_users)。
        // 单体 Both 连真 idm 库;分进程 App 时 idm_users 是内存占位 → 富化降级为空(留待 HttpUserDirectory)。
        let user_directory: Arc<dyn UserDirectory> =
            Arc::new(InProcessUserDirectory::new(idm_users.clone()));

        // 非对称 JWT:验证半边人人有,签发半边只进 idm 进程(分进程最小权限)。dev/prod 钥校验见函数首。
        let token_verifier = Arc::new(
            AppTokenVerifier::try_new(&config.jwt_public_key_pem).context("JWT 公钥装配失败")?,
        );
        let token_signer = if needs_idm {
            Some(Arc::new(
                AppTokenSigner::try_new(&config.jwt_private_key_pem).context("JWT 私钥装配失败")?,
            ))
        } else {
            None
        };
        // app 进程注入 NoopSigner:签发路径本不可达(auth 路由不挂),真被调到就炸(wiring bug)。
        let signer_port: Arc<dyn TokenSigner> = match &token_signer {
            Some(signer) => signer.clone(),
            None => Arc::new(NoopSigner),
        };
        // 后台用户管理:富化端口**恒**包 profile_repo —— 单体(内存/PG)profile_repo 有数据 → 富化;
        // 分进程 idm(needs_app=false)profile_repo 是空内存占位 → 批量查空 → display_name/avatar 自然降级 null。
        // (勿按 app_pool 的 Some/None 选:内存 Both 也 None 但 profile_repo 有数据,那样会误降级。)
        // idm repos 被 AuthService::builder move 走 —— user_admin 先 clone(Arc,廉价)。
        let profile_directory: Arc<dyn ProfileDirectory> =
            Arc::new(InProcessProfileDirectory::new(profile_repo.clone()));
        // 配了 search pool(SEARCH_DB_HOST + needs_idm)→ 平台账号列表读全局账号目录 account_index
        // (q/display_name 搜/排);否则 None → list 回退 idm 直查 + q/display_name-sort 422。读侧用**运行时池**
        // (account_index 不开 RLS,运行时账号只有 SELECT);写侧(build_projector)用 system 池,各建各的 PgSearchIndexRepo。
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
        // 租户 / 成员管理:成员列表读 search 的租户成员索引(**运行时池**:repo 的 query 每次在租户事务里查,RLS 兜底);
        // 没接 search → None → 回退 idm 直查(q 422)。资料富化同 user_admin(恒包 profile_repo)。
        let member_search: Option<Arc<dyn MemberSearchIndex>> = search_pool.as_ref().map(|pool| {
            let repo: Arc<dyn SearchIndexRepo> = Arc::new(PgSearchIndexRepo::new(pool.clone()));
            Arc::new(MemberSearchAdapter::new(repo)) as Arc<dyn MemberSearchIndex>
        });
        let tenant_admin = TenantAdminService::new(
            idm_tenants.clone(),
            idm_members.clone(),
            idm_users.clone(),
            idm_roles.clone(),
            idm_sessions.clone(),
            Arc::new(InProcessProfileDirectory::new(profile_repo.clone()))
                as Arc<dyn MemberProfiles>,
            member_search,
        );

        // 成员仓储必填:登录进最近用过的租户、refresh 校验成员关系、切换租户、注册加入默认租户。
        let auth = AppAuthService::builder(idm_users, idm_sessions, idm_roles, idm_members)
            .hasher(Argon2Hasher)
            .signer(signer_port)
            .verifier(token_verifier.clone())
            .access_ttl(Duration::seconds(config.idm_access_ttl_seconds))
            .refresh_ttl(Duration::seconds(config.idm_refresh_ttl_seconds))
            .build();

        let outbox_relays = build_outbox_relays(
            config,
            needs_idm,
            needs_app,
            idm_pool.as_ref(),
            // 后台任务一律走 system 池(spec §4.4)。它和运行时池同由 APP_DB_HOST 决定,有 app 池就有它。
            app_system_pool.as_ref(),
        )
        .await?;
        let projector = build_projector(config, needs_idm, search_system_pool.as_ref()).await?;

        // auth 审计:写句柄(idm.outbox,handler 发事件用)+ 读句柄(auth_event,admin 查询用)+
        // projector(消费投影)+ 保留 job,都在下方组装 `probes` 之前
        // 用 `.as_ref()` 建好(镜像上面 search_pool/user_search 的写法)。
        let idm_outbox: Option<Arc<dyn OutboxRepo>> = idm_pool
            .as_ref()
            .map(|p| Arc::new(PgOutboxRepo::new(p.clone())) as Arc<dyn OutboxRepo>);
        // auth_event 是平台级表(spec §6.1:只给平台管理员看,含无租户的行):读写都走 search 的 system 池。
        let auth_audit = search_system_pool.as_ref().map(|pool| {
            AuthAuditService::new(
                Arc::new(PgAuthEventRepo::new(pool.clone())) as Arc<dyn AuthEventRepo>
            )
        });
        // SSE 总线:唯一发布者是下面的 auth_projector,只有它真装起来了总线才该对外暴露 ——
        // 否则 needs_idm 但 nats/search 未配时,`/stream` 会 200 挂着却永不推送(sibling 端点已 404)。
        // 装配顺序在组装 `probes` 之前 —— 之后还要 `.clone()` 一份塞进 projector。
        let bus = needs_idm.then(AuthEventBus::new);
        let auth_projector =
            build_auth_event_projector(config, needs_idm, search_system_pool.as_ref(), bus.clone())
                .await?;
        let auth_events_bus = if auth_projector.is_some() { bus } else { None };
        let auth_retention = search_system_pool.as_ref().map(|pool| {
            AuthRetentionJob::new(
                Arc::new(PgAuthEventRepo::new(pool.clone())) as Arc<dyn AuthEventRepo>
            )
        });

        // 依赖探针:本进程实际连着的每个 schema 连接池 + 一条专用 NATS 连接(只看连接状态,不收发)。
        let probe_nats = match &config.nats_url {
            Some(url) => Some(
                ConnectOptions::new()
                    .name("baserust-probe")
                    .connect(url)
                    .await
                    .context("连接 NATS(就绪探针)失败")?,
            ),
            None => None,
        };
        // ops(运维数据:监控历史与日志):各进程都连;不设 OPS_DB_HOST → 内存(只留最近一段)。
        let ops_pool = connect_for_schema(config, Schema::Ops).await?;
        let ops_store: Arc<dyn OpsStore> = match &ops_pool {
            Some(pool) => Arc::new(PgOpsStore::new(pool.clone())),
            None => Arc::new(MemoryOpsStore::new()),
        };
        let probe_pools: Vec<ProbePool> = [
            ("app", &app_pool),
            ("idm", &idm_pool),
            ("content", &content_pool),
            ("search", &search_pool),
            ("ops", &ops_pool),
        ]
        .into_iter()
        .filter_map(|(name, pool)| pool.clone().map(|pool| ProbePool { name, pool }))
        .collect();
        let probes = Probes::new(probe_pools, probe_nats);

        Ok(AssembledApp {
            state: Self {
                widgets: WidgetService::new(widget_repo, user_directory, widget_events.clone()),
                profiles,
                widget_events,
                contents,
                auth: Arc::new(auth),
                user_admin,
                tenant_admin,
                probes,
                monitoring: MonitoringSetup::new(config, mount).with_store(ops_store),
                cookie_secure: config.app_environment.is_production(),
                policy,
                token_verifier,
                token_signer,
                idm_outbox,
                auth_audit,
                auth_events_bus,
                app_system_pool,
                content_system_pool,
                search_system_pool,
            },
            background_tasks: BackgroundTasks {
                relays: outbox_relays,
                projector,
                auth_projector,
                auth_retention,
            },
        })
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
    // app 的 system 池(后台任务);app.outbox 是全局表。
    app_pool: Option<&PgPool>,
) -> anyhow::Result<Vec<OutboxRelay>> {
    use std::time::Duration;
    let Some(nats_url) = config.nats_url.as_deref() else {
        return Ok(Vec::new());
    };
    let idm_source = if needs_idm { idm_pool } else { None };
    let app_source = if needs_app { app_pool } else { None };
    if idm_source.is_none() && app_source.is_none() {
        return Ok(Vec::new()); // nats 设了但本进程无相关 schema pool → 无可 relay
    }
    // 与 NatsEventBus::try_new 同哲学:nats 挂着起不来。
    let publisher: Arc<dyn EventPublisher> = Arc::new(JetStreamPublisher::try_new(nats_url).await?);
    // poll_interval/batch:P1 纯轮询的合理默认;P2 叠 NOTIFY 降延迟。
    let poll_interval = Duration::from_secs(1);
    let batch = 128;
    let mut relays = Vec::new();
    if let Some(pool) = idm_source {
        let repo: Arc<dyn OutboxRepo> = Arc::new(PgOutboxRepo::new(pool.clone()));
        let source: Arc<dyn OutboxSource> = Arc::new(IdmOutboxSource::new(repo));
        relays.push(OutboxRelay::new(source, publisher.clone(), poll_interval, batch).named("idm"));
    }
    if let Some(pool) = app_source {
        let source: Arc<dyn OutboxSource> = Arc::new(PgAppOutbox::new(pool.clone()));
        relays.push(OutboxRelay::new(source, publisher.clone(), poll_interval, batch).named("app"));
    }
    tracing::info!("装配 {} 个 outbox relay(JetStream 交付)", relays.len());
    Ok(relays)
}

/// 装配 projector:needs_idm 进程 + NATS_URL + search pool 三者齐才起(它连 nats consume + 写 search)。
/// 否则 None(无投影;P4 list 回退)。durable name 固定 "admin_user_projector"。
/// `search_pool` 传 **system 池**:账号 / 资料事件要改该用户在所有租户里的成员行,只有 BYPASSRLS 改得到。
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
        Projector::try_new(
            DurableConsumer {
                nats_url,
                durable_name: "admin_user_projector",
            },
            repo,
        )
        .await?,
    ))
}

/// 装配 auth_event 投影器:needs_idm + NATS_URL + search pool(system 池)三者齐才起。镜像 `build_projector`;
/// 独立 durable name "auth_event_projector",消费 `events.idm.auth.>`(见 `AuthEventProjector::try_new`)。
/// `bus`:落库成功后发布给 SSE 订阅者,转发给 `AuthEventProjector::try_new`。
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
        AuthEventProjector::try_new(
            DurableConsumer {
                nats_url,
                durable_name: "auth_event_projector",
            },
            repo,
            bus,
        )
        .await?,
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
        Schema::Ops => config.ops_database_url(),
    };
    match url {
        Some(url) => Ok(Some(connect_pool(&url, RUNTIME_POOL_MAX).await?)),
        None => Ok(None),
    }
}

/// 运行时账号连接池上限(请求路径)。
const RUNTIME_POOL_MAX: u32 = 10;
/// system 账号连接池上限:只跑后台任务 / 平台级读,用不了几条。
const SYSTEM_POOL_MAX: u32 = 4;

/// 按 `schema` 起 **system 账号**(`<schema>_system`,BYPASSRLS)的连接池。只有拆了账号的
/// app / content / search 有;idm / ops 不拆 → `None`。未配置对应 `*_DB_HOST` → `None`(内存模式)。
///
/// 只给后台任务 / 平台级跨租户读用 —— 请求路径用 [`connect_for_schema`] 的运行时账号 + `tenant_transaction`。
pub async fn connect_system_for_schema(
    config: &Config,
    schema: Schema,
) -> anyhow::Result<Option<PgPool>> {
    let url = match schema {
        Schema::App => config.app_system_database_url(),
        Schema::Content => config.content_system_database_url(),
        Schema::Search => config.search_system_database_url(),
        Schema::Idm | Schema::Ops => None,
    };
    match url {
        Some(url) => Ok(Some(
            connect_pool(&url, SYSTEM_POOL_MAX).await.with_context(|| {
                format!(
                    "连接 {schema:?} 的 system 账号失败(老库先补账号:just db-ensure-roles,\
                     或部署脚本跑 scripts/initdb/10-tenancy-roles.sh)"
                )
            })?,
        )),
        None => Ok(None),
    }
}

/// 连接 Postgres 并建连接池。范式:`PgPool` 自带连接池,无需 deadpool。
async fn connect_pool(url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    // 不在 app 启动时跑迁移:schema 变更由 sqlx-cli 显式执行(just migrate),是受控部署步骤,
    // 而非 app 启动副作用 —— 避免多实例并发抢迁移、回滚困难、启动期改 schema 等风险。
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
        .context("连接 Postgres 失败")
}

/// demo 样本数据(`mock.toml`)该不该写:app/idm 同进程(才解析得到 owner)+ seed 开启 + **非 prod**。
///
/// `!is_production()` 是唯一挡住 demo 数据污染生产库的东西,**不能靠"prod 都是分进程"**:
/// `IDM_EMBEDDED` 默认 true(`config::default_idm_embedded`),prod 单体默认就是 `Both`;而 prod 挂
/// `SEED_FILE`(真密码建号)恰是文档推荐用法,一挂 `seed_on_start()` 即为真。两条都真时,没有这道
/// prod 门就会把 `admin-w1` / `Sam Superadmin` 之类写进生产库。
/// **账号 seed 与 demo 数据的门必须分开**:prod 要建号,但绝不要 demo 数据。
///
/// 抽成函数是为了能直接断言:`AppState::try_new` 在 prod 下先因内嵌 dev JWT 钥拒启,测不到这道门。
fn should_apply_mock(config: &Config, needs_app: bool, needs_idm: bool) -> bool {
    needs_app && needs_idm && config.seed_on_start() && !config.app_environment.is_production()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::config::Profile;

    /// **prod 单体 + SEED_FILE 必须建号但绝不写 demo 数据**。这正是文档推荐的 prod 用法
    /// (`IDM_EMBEDDED` 默认 true → `Both`;`SEED_FILE` → `seed_on_start()` 真),
    /// 也正是旧门(缺 `!is_production()`)把 mock.toml 灌进生产库的那条路径。
    #[test]
    fn prod_monolith_with_seed_file_seeds_accounts_but_not_demo_data() {
        let config = Config {
            app_environment: Profile::Production,
            seed_file: Some("seed.prod.toml".to_owned()),
            ..Config::default()
        };
        assert!(config.seed_on_start(), "prod + SEED_FILE:账号 seed 该跑");
        assert!(
            !should_apply_mock(&config, /* needs_app= */ true, /* needs_idm= */ true),
            "但 demo 数据绝不能进生产库"
        );
    }

    /// 非 prod 单体照常灌 demo 数据(别把门收成谁都不跑)。
    #[test]
    fn dev_monolith_applies_demo_data() {
        assert!(should_apply_mock(
            &Config::default(),
            /* needs_app= */ true,
            /* needs_idm= */ true
        ));
    }

    /// 零配置(内存模式)照常启动,三个 system 池都是 None。
    #[tokio::test]
    async fn memory_mode_has_no_system_pools() {
        let state = match AppState::try_new(&Config::default(), Mount::Both).await {
            Ok(assembled) => assembled.state,
            Err(error) => panic!("零配置应能启动: {error:#}"),
        };
        assert!(state.app_system_pool.is_none());
        assert!(state.content_system_pool.is_none());
        assert!(state.search_system_pool.is_none());
    }

    /// idm / ops 不拆账号:没有 system 池(即使配了 host)。
    #[tokio::test]
    async fn idm_and_ops_have_no_system_pool() {
        let config = Config {
            idm_db_host: Some("unreachable.invalid".into()),
            ops_db_host: Some("unreachable.invalid".into()),
            ..Config::default()
        };
        assert!(connect_system_for_schema(&config, Schema::Idm)
            .await
            .unwrap()
            .is_none());
        assert!(connect_system_for_schema(&config, Schema::Ops)
            .await
            .unwrap()
            .is_none());
    }

    /// prod + 内嵌 dev 密钥 → 启动拒(公钥全进程;私钥仅 needs_idm)。
    #[tokio::test]
    async fn prod_rejects_embedded_dev_jwt_keys() {
        let config = Config {
            app_environment: Profile::Production,
            ..Config::default()
        };
        // AppState 无 Debug(含 trait object 字段),手动 match 而非 expect_err/unwrap_err。
        let error = match AppState::try_new(&config, Mount::Both).await {
            Ok(_) => panic!("prod+dev 钥应拒启动"),
            Err(startup_error) => startup_error,
        };
        assert!(error.to_string().contains("JWT"), "{error}");
    }
}

//! 用户资料模块:显示名 / 电话 / 头像(头像经 content,富化为相对头像端点路径)。
//!
//! **核心**(核心 crate;不依赖框架、数据库、HTTP):`model`(实体 / 命令 / 读模型 / 头像准入)、
//! `ports`(仓储、头像探针)、`ProfileService`(用例)、`in_memory_profile_repo` / `static_avatar_probe` /
//! `in_memory_app_outbox`(内存实现)。
//! **适配器**(`adapters/`):`http`、`pg_profile_repo`(PG 仓储)、`pg_app_outbox`(app schema 发件箱)。
//! 头像探针的真实现(经 content 领域库)在组合根 `app/adapters/`。
//!
//! **核心**(模型 / 端口 / 用例 / 内存适配器)在 `baserust-core`(`crates/core`),这里按名重新导出(不用 glob,见 CLAUDE.md「代码风格」),
//! 原有路径(`features::profile::model` 等)不变;本 crate 只放适配器。

pub use baserust_core::features::profile::{
    in_memory_app_outbox, in_memory_profile_repo, model, ports, static_avatar_probe,
    AppOutboxRecord, AvatarInfo, AvatarProbe, InMemoryAppOutbox, InMemoryProfileRepo, Profile,
    ProfileFields, ProfileRepo, ProfileService, ProfileView, PutProfile, PutProfileOutcome,
    StaticAvatarProbe, UpsertedProfile,
};

pub mod adapters;

pub use adapters::http::{admin_router, router};
pub use adapters::pg_app_outbox::PgAppOutbox;
pub use adapters::pg_profile_repo::PgProfileRepo;

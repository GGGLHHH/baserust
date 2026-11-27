//! 用户资料的**核心**:领域模型、端口、用例 + 内存适配器。数据库 / HTTP / outbox 适配器在主 crate。

pub mod in_memory_app_outbox;
pub mod in_memory_profile_repo;
pub mod model;
pub mod ports;
mod profile_service;
pub mod static_avatar_probe;

pub use in_memory_app_outbox::{AppOutboxRecord, InMemoryAppOutbox};
pub use in_memory_profile_repo::InMemoryProfileRepo;
pub use model::{
    Profile, ProfileFields, ProfileView, PutProfile, PutProfileOutcome, UpsertedProfile,
};
pub use ports::{AvatarInfo, AvatarProbe, ProfileRepo};
pub use profile_service::ProfileService;
pub use static_avatar_probe::StaticAvatarProbe;

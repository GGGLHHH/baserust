//! 用户资料的**核心**:领域模型、端口、用例 + 内存适配器。数据库 / HTTP / outbox 适配器在主 crate。

pub mod memory;
pub mod model;
pub mod outbox;
pub mod ports;
mod service;

pub use memory::{InMemoryProfileRepo, StaticAvatarProbe};
pub use model::{Profile, ProfileFields, ProfileView, PutProfile};
pub use outbox::{AppOutboxRecord, InMemoryAppOutbox};
pub use ports::{AvatarInfo, AvatarProbe, ProfileRepo};
pub use service::ProfileService;

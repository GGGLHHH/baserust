//! 跨模块**适配器**:把"他模块的接口"适配成"本地端口"的薄翻译 —— 组合根唯一耦合多模块处。
//! ports-and-adapters 的 adapter 一侧(端口在消费方 features,适配在此)。
//! 规矩:只做 map + 转调,**永不含业务决策**(那属于某个 feature)。一适配器一文件,mod.rs 只 re-export。

mod app_outbox_source;
mod content_avatar_probe;
mod idm_outbox_source;
mod idm_user_directory;
mod in_process_profile_directory;
mod profile_display_names;
mod user_search_index;

pub use content_avatar_probe::ContentAvatarProbe;
pub use idm_outbox_source::IdmOutboxSource;
pub use idm_user_directory::InProcessUserDirectory;
pub use in_process_profile_directory::InProcessProfileDirectory;
pub use profile_display_names::ProfileDisplayNames;
pub use user_search_index::SearchIndexAdapter;

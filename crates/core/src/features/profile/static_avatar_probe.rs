//! profile 头像探针端口的**静态替身**(单测 / 无富化源占位)。纯 Rust。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::ports::{AvatarInfo, AvatarProbe};
use crate::kernel::app_error::AppError;

/// 静态实现:预置 map 回答 —— 单测/无富化源占位用(镜像 widget 的 StaticUserDirectory)。
#[derive(Default)]
pub struct StaticAvatarProbe(pub HashMap<Uuid, AvatarInfo>);

impl StaticAvatarProbe {
    /// 空目录(什么都查不到)。
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl AvatarProbe for StaticAvatarProbe {
    async fn probe(&self, content_id: Uuid) -> Result<Option<AvatarInfo>, AppError> {
        Ok(self.0.get(&content_id).cloned())
    }
}

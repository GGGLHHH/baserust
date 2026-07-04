//! profile 的**跨模块需求端口**:头像绑定校验 + 读侧富化,都只需"content 存在吗/就绪吗/是图吗"。
//! 端口归消费方(profile 不 import content);适配在组合根 `app/adapters/`。

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::infra::error::AppError;

/// 头像探测的瘦快照 —— 只含 profile 要的两个事实(窄接口)。
#[derive(Clone, Debug)]
pub struct AvatarInfo {
    pub mime_type: Option<String>,
    /// 已 confirm 可读(Uploaded/Processed/Archived);false = prepare 了没传完(两步上传中途)。
    pub ready: bool,
}

/// 探测端口。`Ok(None)` = content 不存在/已删(能力性缺席,交调用方定语义)。
#[async_trait]
pub trait AvatarProbe: Send + Sync {
    async fn probe(&self, content_id: Uuid) -> Result<Option<AvatarInfo>, AppError>;
}

/// 静态实现:预置 map 回答 —— 单测/无富化源占位用(镜像 widget 的 StaticUserDirectory)。
pub struct StaticAvatarProbe(pub HashMap<Uuid, AvatarInfo>);

impl StaticAvatarProbe {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait]
impl AvatarProbe for StaticAvatarProbe {
    async fn probe(&self, content_id: Uuid) -> Result<Option<AvatarInfo>, AppError> {
        Ok(self.0.get(&content_id).cloned())
    }
}

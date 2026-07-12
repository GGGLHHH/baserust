//! `profile::AvatarProbe` 的进程内适配器:包 `ContentService`(同进程 content 模块),
//! 薄翻译:领域错误 NotFound → `Ok(None)`(能力性缺席),其余上抛;状态折算 ready。

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::{AvatarInfo, AvatarProbe};
use crate::infra::error::AppError;
use content::{ContentError, ContentService, ContentStatus};

pub struct ContentAvatarProbe {
    contents: ContentService,
}

impl ContentAvatarProbe {
    pub fn new(contents: ContentService) -> Self {
        Self { contents }
    }
}

#[async_trait]
impl AvatarProbe for ContentAvatarProbe {
    async fn probe(&self, content_id: Uuid) -> Result<Option<AvatarInfo>, AppError> {
        let c = match self.contents.get_content(content_id).await {
            Ok(c) => c,
            Err(ContentError::NotFound) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // ready 集合与库的 confirm 幂等集合一致(Uploaded|Processed|Archived = 已销账可读)。
        let ready = matches!(
            c.status,
            ContentStatus::Uploaded | ContentStatus::Processed | ContentStatus::Archived
        );
        // mime 取 content_metadata(用户声明,prepare 时即写);行在而 metadata 缺 → None(非错误)。
        let mime_type = match self.contents.get_content_metadata(content_id).await {
            Ok(m) => m.mime_type,
            Err(ContentError::NotFound) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(Some(AvatarInfo {
            mime_type,
            ready,
            owner_id: c.owner_id,
        }))
    }
}

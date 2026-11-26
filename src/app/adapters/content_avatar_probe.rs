//! `profile::AvatarProbe` 的进程内适配器:包 `ContentService`(同进程 content 模块),
//! 薄翻译:领域错误 NotFound → `Ok(None)`(能力性缺席),其余上抛;状态折算 ready。
//! **头像一律是个人内容**(资料全局一份,头像不属于任何租户,spec §4.4)→ 只按 `ContentScope::Personal` 查:
//! 租户作用域的内容查不到 = 不能当头像(绑定 422、富化降级 null)。历史上落进默认租户的旧头像由
//! `app::avatar_repair` 在启动 / seed 时转成个人内容。

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::{AvatarInfo, AvatarProbe};
use crate::kernel::error::AppError;
use content::{ContentError, ContentScope, ContentService, ContentStatus};

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
        let scope = ContentScope::Personal;
        let c = match self.contents.get_content(scope, content_id).await {
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
        let mime_type = match self.contents.get_content_metadata(scope, content_id).await {
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

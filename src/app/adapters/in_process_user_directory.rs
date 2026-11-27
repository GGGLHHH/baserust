//! `widget::UserDirectory` 的**进程内适配器**:复用 idm 的 `UserRepo` 批量读 + 映射成 `UserBrief`。
//! 薄翻译(map + 转调,无业务判断)。单体 `Both` 用它,零网络;分进程 `App` 将来换 `HttpUserDirectory`。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::widget::{UserBrief, UserDirectory};
use crate::kernel::app_error::AppError;
use idm::UserRepo;

/// widget 富化用的用户目录:同进程直接读 idm 的 `UserRepo`。
pub struct InProcessUserDirectory {
    users: Arc<dyn UserRepo>,
}

impl InProcessUserDirectory {
    #[must_use]
    pub fn new(users: Arc<dyn UserRepo>) -> Self {
        Self { users }
    }
}

#[async_trait]
impl UserDirectory for InProcessUserDirectory {
    async fn batch_by_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, UserBrief>, AppError> {
        // 一次 find_by_ids(WHERE id IN ...)→ 映射成瘦 brief。两条独立 SQL,绝不跨 schema join。
        let users = self.users.find_by_ids(ids).await?;
        Ok(users
            .into_iter()
            .map(|user| {
                (
                    user.id,
                    UserBrief {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                    },
                )
            })
            .collect())
    }
}

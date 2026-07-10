//! `search::DisplayNameSource` 的进程内适配器:`ProfileRepo::find_by_ids` → user_id→display_name 映射。
//! 薄翻译(map + 转调,无业务判断);供 `bin/rebuild_search` 装配与 rebuild 单测复用。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::features::profile::ProfileRepo;
use crate::features::search::DisplayNameSource;
use crate::infra::error::AppError;

pub struct ProfileDisplayNames {
    repo: Arc<dyn ProfileRepo>,
}

impl ProfileDisplayNames {
    pub fn new(repo: Arc<dyn ProfileRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl DisplayNameSource for ProfileDisplayNames {
    async fn display_names_by_ids(
        &self,
        user_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Option<String>>, AppError> {
        Ok(self
            .repo
            .find_by_ids(user_ids)
            .await?
            .into_iter()
            .map(|p| (p.user_id, p.display_name))
            .collect())
    }
}

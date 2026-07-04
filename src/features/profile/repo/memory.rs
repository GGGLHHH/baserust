//! 内存实现 —— 脚手架默认。镜像 PG upsert 的"替换保留 created_*"语义(conformance 对拍钉住)。

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ProfileFields, ProfileRepo};
use crate::features::profile::types::Profile;
use crate::infra::error::AppError;

pub struct InMemoryProfileRepo {
    store: Mutex<HashMap<Uuid, Profile>>,
}

impl InMemoryProfileRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryProfileRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileRepo for InMemoryProfileRepo {
    async fn get(&self, user_id: Uuid) -> Result<Option<Profile>, AppError> {
        Ok(self.store.lock().expect("锁未中毒").get(&user_id).cloned())
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        f: ProfileFields,
        by: Option<String>,
    ) -> Result<(Profile, bool), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let now = OffsetDateTime::now_utc();
        match store.entry(user_id) {
            Entry::Occupied(mut e) => {
                // 替换:业务字段全量覆盖 + updated_*;created_* 保留(镜像 PG 的 excluded 集)。
                let p = e.get_mut();
                p.first_name = f.first_name;
                p.middle_name = f.middle_name;
                p.last_name = f.last_name;
                p.phone = f.phone;
                p.avatar_content_id = f.avatar_content_id;
                p.updated_by = by;
                p.updated_at = now;
                Ok((p.clone(), false))
            }
            Entry::Vacant(v) => {
                let p = Profile {
                    user_id,
                    first_name: f.first_name,
                    middle_name: f.middle_name,
                    last_name: f.last_name,
                    phone: f.phone,
                    avatar_content_id: f.avatar_content_id,
                    created_by: by.clone(),
                    created_at: now,
                    updated_by: by,
                    updated_at: now,
                };
                Ok((v.insert(p).clone(), true))
            }
        }
    }
}

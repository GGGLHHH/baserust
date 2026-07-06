//! 内存实现 —— 脚手架默认。镜像 PG upsert 的"替换保留 created_*"语义(conformance 对拍钉住)。

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::outbox::OutboxStore;
use super::{ProfileFields, ProfileRepo};
use crate::features::profile::types::Profile;
use crate::infra::error::AppError;

pub struct InMemoryProfileRepo {
    store: Mutex<HashMap<Uuid, Profile>>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryProfileRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
            outbox: Arc::new(OutboxStore::default()),
        }
    }

    /// 供 `InMemoryAppOutbox::sharing_with` 取共享存储(镜像 idm 的 `sharing_with` 手法)。
    pub(crate) fn outbox_store(&self) -> &Arc<OutboxStore> {
        &self.outbox
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

    async fn find_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<Profile>, AppError> {
        let store = self.store.lock().expect("锁未中毒");
        Ok(user_ids
            .iter()
            .filter_map(|id| store.get(id).cloned())
            .collect())
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        f: ProfileFields,
        by: Option<String>,
    ) -> Result<(Profile, bool), AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let now = OffsetDateTime::now_utc();
        let (profile, created) = match store.entry(user_id) {
            Entry::Occupied(mut e) => {
                // 替换:业务字段全量覆盖 + updated_*;created_* 保留(镜像 PG 的 excluded 集)。
                let p = e.get_mut();
                p.display_name = f.display_name;
                p.phone = f.phone;
                p.avatar_content_id = f.avatar_content_id;
                p.updated_by = by;
                p.updated_at = now;
                (p.clone(), false)
            }
            Entry::Vacant(v) => {
                let p = Profile {
                    user_id,
                    display_name: f.display_name,
                    phone: f.phone,
                    avatar_content_id: f.avatar_content_id,
                    created_by: by.clone(),
                    created_at: now,
                    updated_by: by,
                    updated_at: now,
                };
                (v.insert(p).clone(), true)
            }
        };
        drop(store); // 锁内已完成写;emit 不需持锁(与 PG 侧"同锁/同事务落地"的等价语义已满足)

        // 写成功后(本方法无失败路径,恒执行)同锁单元内 push 到共享 outbox store。
        // avatar_url:同 service::enrich 的相对 preview 口径,但**不探测就绪性**——那是读侧关注,
        // 这里只记录写入意图(悬空/未就绪由后续 relay/读侧消费者各自决定语义)。
        let avatar_url = profile
            .avatar_content_id
            .map(|cid| format!("/api/v1/frontend/contents/{cid}/preview"));
        self.outbox.emit(
            "profile.updated",
            user_id,
            json!({
                "user_id": user_id,
                "display_name": profile.display_name,
                "avatar_url": avatar_url,
            }),
        );
        Ok((profile, created))
    }
}

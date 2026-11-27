//! profile 仓储端口的**内存适配器**(脚手架默认,镜像 PG upsert 的"替换保留 created_*"语义,
//! conformance 对拍钉住)。

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::in_memory_app_outbox::OutboxStore;
use crate::features::profile::model::{Profile, ProfileFields, UpsertedProfile};
use crate::features::profile::ports::ProfileRepo;
use crate::kernel::app_error::AppError;

/// 资料仓储的内存实现(脚手架默认 / 测试替身),自带一份发件箱存储:upsert 在同一把锁内 emit
/// `profile.updated`(镜像 PG 的同事务落地),经 [`InMemoryAppOutbox::new_shared_with`](super::in_memory_app_outbox::InMemoryAppOutbox::new_shared_with) 读出。
#[derive(Default)]
pub struct InMemoryProfileRepo {
    store: Mutex<HashMap<Uuid, Profile>>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryProfileRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 供 `InMemoryAppOutbox::new_shared_with` 取共享存储(镜像 idm 的 `new_shared_with` 手法)。
    pub(crate) fn outbox_store(&self) -> &Arc<OutboxStore> {
        &self.outbox
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
        fields: ProfileFields,
        by: Option<String>,
    ) -> Result<UpsertedProfile, AppError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let now = OffsetDateTime::now_utc();
        let (profile, created) = match store.entry(user_id) {
            Entry::Occupied(mut occupied) => {
                // 替换:业务字段全量覆盖 + updated_*;created_* 保留(镜像 PG 的 excluded 集)。
                let existing = occupied.get_mut();
                existing.display_name = fields.display_name;
                existing.phone = fields.phone;
                existing.avatar_content_id = fields.avatar_content_id;
                existing.updated_by = by;
                existing.updated_at = now;
                (existing.clone(), false)
            }
            Entry::Vacant(vacant) => {
                let new_profile = Profile {
                    user_id,
                    display_name: fields.display_name,
                    phone: fields.phone,
                    avatar_content_id: fields.avatar_content_id,
                    created_by: by.clone(),
                    created_at: now,
                    updated_by: by,
                    updated_at: now,
                };
                (vacant.insert(new_profile).clone(), true)
            }
        };
        // emit 必须留在 store 锁内:先放锁会让并发 upsert 的 profile 写序与 outbox 事件序
        // 倒挂(旧快照拿到更大 seq),投影按 seq 水位会用旧值覆盖新值。锁序恒 store→outbox,
        // InMemoryAppOutbox 只拿自己的锁,无死锁。(镜像 PG 侧"同事务落地"的语义)
        // avatar_url:同 `ProfileService::enrich` 的头像端点口径(按 user_id,非 content id),但**不探测
        // 就绪性**——那是读侧关注,这里只记录写入意图(悬空/未就绪由读侧消费者各自决定语义)。
        let avatar_url = profile
            .avatar_content_id
            .map(|_| format!("/api/v1/frontend/profiles/{user_id}/avatar"));
        self.outbox.emit(
            "profile.updated",
            user_id,
            json!({
                "user_id": user_id,
                "display_name": profile.display_name,
                "avatar_url": avatar_url,
            }),
        );
        Ok(UpsertedProfile { profile, created })
    }
}

//! profile 业务逻辑:garde 校验 → 头像三查(经端口)→ upsert → 富化。

use std::sync::Arc;

use garde::Validate;
use uuid::Uuid;

use super::port::AvatarProbe;
use super::repo::{ProfileFields, ProfileRepo};
use super::types::{Profile, ProfileResponse, PutProfileRequest};
use crate::infra::audit::AuditContext;
use crate::infra::error::AppError;

#[derive(Clone)]
pub struct ProfileService {
    repo: Arc<dyn ProfileRepo>,
    avatars: Arc<dyn AvatarProbe>,
}

impl ProfileService {
    pub fn new(repo: Arc<dyn ProfileRepo>, avatars: Arc<dyn AvatarProbe>) -> Self {
        Self { repo, avatars }
    }

    /// 读任意人的资料。未建 → 404。
    pub async fn get(&self, user_id: Uuid) -> Result<ProfileResponse, AppError> {
        let p = self.repo.get(user_id).await?.ok_or(AppError::NotFound)?;
        Ok(self.enrich(p).await)
    }

    /// 全量替换 upsert。bool = 新建(路由 201/200)。
    /// 头像**写前三查**(挡输入错误;读侧降级兜"绑定后被删"的竞态,各管一段):
    /// 不存在 / 未 confirm / 非 image → 422。
    pub async fn put(
        &self,
        user_id: Uuid,
        input: PutProfileRequest,
        ctx: &AuditContext,
    ) -> Result<(bool, ProfileResponse), AppError> {
        input.validate()?;
        if let Some(cid) = input.avatar_content_id {
            let info = self
                .avatars
                .probe(cid)
                .await? // 探测故障 → 500(写前校验必须可靠,不降级)
                .ok_or_else(|| AppError::Validation("avatar_content_id: content 不存在".into()))?;
            if !info.ready {
                return Err(AppError::Validation(
                    "avatar_content_id: content 未完成上传(先 confirm)".into(),
                ));
            }
            if !info
                .mime_type
                .as_deref()
                .is_some_and(|m| m.starts_with("image/"))
            {
                return Err(AppError::Validation(
                    "avatar_content_id: 头像必须是 image/*".into(),
                ));
            }
        }
        let fields = ProfileFields {
            first_name: input.first_name,
            middle_name: input.middle_name,
            last_name: input.last_name,
            phone: input.phone,
            avatar_content_id: input.avatar_content_id,
        };
        let (p, created) = self.repo.upsert(user_id, fields, ctx.audit_id()).await?;
        Ok((created, self.enrich(p).await))
    }

    /// 富化 avatar_url:就绪 → 相对 preview 路径;悬空/未就绪 → null;
    /// **探测故障也 → null + warn**(读路径不因旁路故障炸——与写前校验的 500 刻意相反)。
    async fn enrich(&self, p: Profile) -> ProfileResponse {
        let avatar_url = match p.avatar_content_id {
            None => None,
            Some(cid) => match self.avatars.probe(cid).await {
                Ok(Some(info)) if info.ready => Some(format!("/api/v1/contents/{cid}/preview")),
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!(error = %e, content_id = %cid, "avatar 富化探测失败,降级 null");
                    None
                }
            },
        };
        ProfileResponse::from_profile(p, avatar_url)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::features::profile::port::{AvatarInfo, StaticAvatarProbe};
    use crate::features::profile::repo::InMemoryProfileRepo;
    use crate::infra::audit::AuditContext;
    use async_trait::async_trait;

    fn ctx() -> AuditContext {
        AuditContext::system() // 镜像 widget service 测试的构造方式(anonymous/system 现成构造器)
    }

    fn svc_with(probe: impl AvatarProbe + 'static) -> ProfileService {
        ProfileService::new(Arc::new(InMemoryProfileRepo::new()), Arc::new(probe))
    }

    fn req(avatar: Option<Uuid>) -> PutProfileRequest {
        PutProfileRequest {
            first_name: Some("San".into()),
            middle_name: None,
            last_name: Some("Zhang".into()),
            phone: Some("13800000000".into()),
            avatar_content_id: avatar,
        }
    }

    /// 建 → created=true;再 put → created=false 且全量覆盖(未给字段清空)。
    #[tokio::test]
    async fn put_creates_then_replaces_wholesale() {
        let svc = svc_with(StaticAvatarProbe::empty());
        let uid = Uuid::now_v7();
        let (created, r) = svc.put(uid, req(None), &ctx()).await.unwrap();
        assert!(created);
        assert_eq!(r.first_name.as_deref(), Some("San"));
        let (created, r) = svc
            .put(
                uid,
                PutProfileRequest {
                    first_name: None,
                    middle_name: Some("Q".into()),
                    last_name: None,
                    phone: None,
                    avatar_content_id: None,
                },
                &ctx(),
            )
            .await
            .unwrap();
        assert!(!created);
        assert!(r.first_name.is_none(), "全量替换:未给字段必须清空");
        assert_eq!(r.middle_name.as_deref(), Some("Q"));
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let svc = svc_with(StaticAvatarProbe::empty());
        assert!(matches!(
            svc.get(Uuid::now_v7()).await,
            Err(AppError::NotFound)
        ));
    }

    /// 头像三查:不存在 / 未就绪 / 非 image → 422(Validation)。
    #[tokio::test]
    async fn avatar_validation_rejects_bad_bindings() {
        let ok_id = Uuid::now_v7();
        let raw_id = Uuid::now_v7();
        let txt_id = Uuid::now_v7();
        let probe = StaticAvatarProbe(HashMap::from([
            (
                ok_id,
                AvatarInfo {
                    mime_type: Some("image/png".into()),
                    ready: true,
                },
            ),
            (
                raw_id,
                AvatarInfo {
                    mime_type: Some("image/png".into()),
                    ready: false,
                },
            ),
            (
                txt_id,
                AvatarInfo {
                    mime_type: Some("text/plain".into()),
                    ready: true,
                },
            ),
        ]));
        let svc = svc_with(probe);
        let uid = Uuid::now_v7();
        for bad in [Uuid::now_v7(), raw_id, txt_id] {
            assert!(
                matches!(
                    svc.put(uid, req(Some(bad)), &ctx()).await,
                    Err(AppError::Validation(_))
                ),
                "{bad} 应被 422 拒"
            );
        }
        // 合法绑定:通过且富化出相对 preview 路径
        let (_, r) = svc.put(uid, req(Some(ok_id)), &ctx()).await.unwrap();
        assert_eq!(
            r.avatar_url.as_deref(),
            Some(format!("/api/v1/contents/{ok_id}/preview").as_str())
        );
    }

    /// 读侧降级:悬空(probe None)→ avatar_url null 但响应不炸;探测故障同样 null。
    #[tokio::test]
    async fn enrich_degrades_to_null() {
        struct FailingProbe;
        #[async_trait]
        impl AvatarProbe for FailingProbe {
            async fn probe(&self, _: Uuid) -> Result<Option<AvatarInfo>, AppError> {
                Err(AppError::Internal(anyhow::anyhow!("storage down")))
            }
        }
        // 先用"就绪"探针绑定成功,再换故障探针读 —— 模拟旁路故障
        let cid = Uuid::now_v7();
        let repo = Arc::new(InMemoryProfileRepo::new());
        let ok_probe = StaticAvatarProbe(HashMap::from([(
            cid,
            AvatarInfo {
                mime_type: Some("image/png".into()),
                ready: true,
            },
        )]));
        let uid = Uuid::now_v7();
        ProfileService::new(repo.clone(), Arc::new(ok_probe))
            .put(uid, req(Some(cid)), &ctx())
            .await
            .unwrap();
        let degraded = ProfileService::new(repo.clone(), Arc::new(FailingProbe));
        let r = degraded.get(uid).await.unwrap();
        assert!(r.avatar_url.is_none(), "探测故障应降级 null 而非 500");
        assert_eq!(r.avatar_content_id, Some(cid), "原始引用保留");
        // 悬空(probe None):换空 probe 同样 null
        let dangling = ProfileService::new(repo, Arc::new(StaticAvatarProbe::empty()));
        assert!(dangling.get(uid).await.unwrap().avatar_url.is_none());
    }

    /// 写侧与读侧刻意相反:probe 故障时 put **不降级**,上抛 500(写前校验必须可靠)。
    #[tokio::test]
    async fn put_propagates_probe_failure_as_internal() {
        struct FailingProbe;
        #[async_trait]
        impl AvatarProbe for FailingProbe {
            async fn probe(&self, _: Uuid) -> Result<Option<AvatarInfo>, AppError> {
                Err(AppError::Internal(anyhow::anyhow!("storage down")))
            }
        }
        let svc = svc_with(FailingProbe);
        assert!(matches!(
            svc.put(Uuid::now_v7(), req(Some(Uuid::now_v7())), &ctx())
                .await,
            Err(AppError::Internal(_))
        ));
    }

    /// garde:超长字段 → 422。
    #[tokio::test]
    async fn garde_rejects_overlong() {
        let svc = svc_with(StaticAvatarProbe::empty());
        let mut r = req(None);
        r.phone = Some("9".repeat(256));
        assert!(matches!(
            svc.put(Uuid::now_v7(), r, &ctx()).await,
            Err(AppError::Validation(_))
        ));
    }
}

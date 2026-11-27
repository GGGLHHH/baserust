//! profile 用例:garde 校验 → 头像四查(经端口)→ upsert → 富化成读模型 `ProfileView`。

use std::sync::Arc;

use uuid::Uuid;

use super::model::{
    is_allowed_avatar_mime, Profile, ProfileFields, ProfileView, PutProfile, PutProfileOutcome,
};
use super::ports::{AvatarProbe, ProfileRepo};
use crate::kernel::app_error::AppError;
use crate::kernel::audit::AuditContext;

/// 资料用例:读(任意人 / 自己)、全量替换写(含头像绑定校验)、读侧头像富化。`Clone` 廉价(只 clone `Arc`)。
#[derive(Clone)]
pub struct ProfileService {
    repo: Arc<dyn ProfileRepo>,
    avatars: Arc<dyn AvatarProbe>,
}

impl ProfileService {
    pub fn new(repo: Arc<dyn ProfileRepo>, avatars: Arc<dyn AvatarProbe>) -> Self {
        Self { repo, avatars }
    }

    /// 读任意人的资料。未建 → 404(那里存在性是真问题:问的是"某个 id 有没有资料")。
    pub async fn get(&self, user_id: Uuid) -> Result<ProfileView, AppError> {
        let profile = self.repo.get(user_id).await?.ok_or(AppError::NotFound)?;
        Ok(self.enrich(profile).await)
    }

    /// 读**自己**的资料 —— 未建 → **空资料(200)而非 404**:调用方已认证 ⇒ 账号必然存在 ⇒
    /// "profile 行还没写" 是空资料,不是资源不存在(profile 1:1 挂 user,是账号的延伸段)。
    ///
    /// 为什么不能沿用 `get` 的 404:那会锁死前端 —— 建资料只能 PUT,而 PUT 的那个页面
    /// (`/admin/profile`)的 loader 正是拿 me 的 404 抛错、根本渲染不出来。且没有任何路径
    /// 会预建 profile 行(注册/后台建号都在 idm 进程,写不了 app schema),所以**每个**新账号
    /// 都会撞上,不只 seed 出来的。
    pub async fn get_or_empty(&self, user_id: Uuid) -> Result<ProfileView, AppError> {
        match self.repo.get(user_id).await? {
            Some(profile) => Ok(self.enrich(profile).await),
            None => Ok(ProfileView::new(user_id)),
        }
    }

    /// 该用户当前绑定的头像 content id(无资料 / 未绑定 → None)。头像展示端点用它定位要出的 content。
    pub async fn avatar_content_id(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        Ok(self
            .repo
            .get(user_id)
            .await?
            .and_then(|p| p.avatar_content_id))
    }

    /// 全量替换 upsert。`created` = 新建(路由 201/200)。
    /// 头像**写前三查**(挡输入错误;读侧降级兜"绑定后被删"的竞态,各管一段):
    /// 不存在 / 未 confirm / 非 image → 422。
    pub async fn put(
        &self,
        user_id: Uuid,
        input: PutProfile,
        ctx: &AuditContext,
    ) -> Result<PutProfileOutcome, AppError> {
        use garde::Validate;

        input.validate()?;
        if let Some(content_id) = input.avatar_content_id {
            let info = self
                .avatars
                .probe(content_id)
                .await? // 探测故障 → 500(写前校验必须可靠,不降级)
                .ok_or_else(|| AppError::Validation("avatar_content_id: content 不存在".into()))?;
            // 归属校验:头像 content 必须是**本人**的(owner==目标 user)。否则用户可把别人的
            // 私有图片指成自己的 avatar_content_id,经头像端点跨用户泄露 —— fail-closed 422。
            if info.owner_id != user_id {
                return Err(AppError::Validation(
                    "avatar_content_id: 头像必须是本人的 content".into(),
                ));
            }
            if !info.ready {
                return Err(AppError::Validation(
                    "avatar_content_id: content 未完成上传(先 confirm)".into(),
                ));
            }
            if !info
                .mime_type
                .as_deref()
                .is_some_and(is_allowed_avatar_mime)
            {
                return Err(AppError::Validation(
                    "avatar_content_id: 头像必须是栅格图(png/jpeg/gif/webp)".into(),
                ));
            }
        }
        let fields = ProfileFields {
            display_name: input.display_name,
            phone: input.phone,
            avatar_content_id: input.avatar_content_id,
        };
        let upserted = self.repo.upsert(user_id, fields, ctx.audit_id()).await?;
        Ok(PutProfileOutcome {
            created: upserted.created,
            profile: self.enrich(upserted.profile).await,
        })
    }

    /// 富化 avatar_url:就绪**且 image/\***→ 头像端点相对路径;悬空/未就绪/已非图片 → null;
    /// **探测故障也 → null + warn**(读路径不因旁路故障炸——与写前校验的 500 刻意相反)。
    /// URL 指 `profiles/{user_id}/avatar`(头像专用端点,只服务本人 avatar);content 本体经
    /// `contents/{id}/preview` 严格按 owner 隔离,不再对他人放行任意 image(见 content::preview_content)。
    async fn enrich(&self, profile: Profile) -> ProfileView {
        let user_id = profile.user_id;
        let avatar_url = match profile.avatar_content_id {
            None => None,
            Some(content_id) => match self.avatars.probe(content_id).await {
                Ok(Some(info))
                    if info.ready
                        && info
                            .mime_type
                            .as_deref()
                            .is_some_and(|m| m.starts_with("image/")) =>
                {
                    Some(format!("/api/v1/frontend/profiles/{user_id}/avatar"))
                }
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(error = %error, content_id = %content_id, "avatar 富化探测失败,降级 null");
                    None
                }
            },
        };
        ProfileView::new_with_profile(profile, avatar_url)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::features::profile::in_memory_profile_repo::InMemoryProfileRepo;
    use crate::features::profile::ports::AvatarInfo;
    use crate::features::profile::static_avatar_probe::StaticAvatarProbe;
    use crate::kernel::audit::AuditContext;
    use async_trait::async_trait;

    fn ctx() -> AuditContext {
        AuditContext::new_system() // 镜像 widget service 测试的构造方式(anonymous/system 现成构造器)
    }

    fn service_with(probe: impl AvatarProbe + 'static) -> ProfileService {
        ProfileService::new(Arc::new(InMemoryProfileRepo::new()), Arc::new(probe))
    }

    fn put_request(avatar: Option<Uuid>) -> PutProfile {
        PutProfile {
            display_name: Some("San Zhang".into()),
            phone: Some("13800000000".into()),
            avatar_content_id: avatar,
        }
    }

    /// 建 → created=true;再 put → created=false 且全量覆盖(未给字段清空)。
    #[tokio::test]
    async fn put_creates_then_replaces_wholesale() {
        let service = service_with(StaticAvatarProbe::new());
        let user_id = Uuid::now_v7();
        let PutProfileOutcome {
            created,
            profile: view,
        } = service
            .put(user_id, put_request(None), &ctx())
            .await
            .unwrap();
        assert!(created);
        assert_eq!(view.display_name.as_deref(), Some("San Zhang"));
        let PutProfileOutcome {
            created,
            profile: view,
        } = service
            .put(
                user_id,
                PutProfile {
                    display_name: None,
                    phone: Some("139".into()),
                    avatar_content_id: None,
                },
                &ctx(),
            )
            .await
            .unwrap();
        assert!(!created);
        assert!(view.display_name.is_none(), "全量替换:未给字段必须清空");
        assert_eq!(view.phone.as_deref(), Some("139"));
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let service = service_with(StaticAvatarProbe::new());
        assert!(matches!(
            service.get(Uuid::now_v7()).await,
            Err(AppError::NotFound)
        ));
    }

    /// `/me` 的读:未建 **不 404**,而是 user_id 归位、其余 null 的空资料(前端据此渲染空表单 → PUT 建行);
    /// 建后与 `get` 等值。守住"读自己"与"读别人"的刻意分叉。
    #[tokio::test]
    async fn get_or_empty_returns_blank_then_real_row() {
        let service = service_with(StaticAvatarProbe::new());
        let user_id = Uuid::now_v7();
        let blank = service.get_or_empty(user_id).await.unwrap();
        assert_eq!(blank.user_id, user_id, "空资料也要带本人 id(前端 PUT 要用)");
        assert!(blank.display_name.is_none() && blank.phone.is_none());
        assert!(
            blank.created_at.is_none() && blank.updated_at.is_none(),
            "行不存在 → 时间戳 null,不编 now()"
        );

        service
            .put(user_id, put_request(None), &ctx())
            .await
            .unwrap();
        let real = service.get_or_empty(user_id).await.unwrap();
        assert_eq!(real.display_name.as_deref(), Some("San Zhang"));
        assert!(real.created_at.is_some(), "真行 → 真时间戳");
    }

    /// 头像四查:不存在 / 非本人 / 未就绪 / 非 image → 422(Validation)。
    #[tokio::test]
    async fn avatar_validation_rejects_bad_bindings() {
        let user_id = Uuid::now_v7();
        let ok_id = Uuid::now_v7();
        let raw_id = Uuid::now_v7();
        let text_id = Uuid::now_v7();
        let foreign_id = Uuid::now_v7(); // 就绪的 image,但 owner 是别人 → 也该 422
        let probe = StaticAvatarProbe(HashMap::from([
            (
                ok_id,
                AvatarInfo {
                    mime_type: Some("image/png".into()),
                    ready: true,
                    owner_id: user_id,
                },
            ),
            (
                raw_id,
                AvatarInfo {
                    mime_type: Some("image/png".into()),
                    ready: false,
                    owner_id: user_id,
                },
            ),
            (
                text_id,
                AvatarInfo {
                    mime_type: Some("text/plain".into()),
                    ready: true,
                    owner_id: user_id,
                },
            ),
            (
                foreign_id,
                AvatarInfo {
                    mime_type: Some("image/png".into()),
                    ready: true,
                    owner_id: Uuid::now_v7(),
                },
            ),
        ]));
        let service = service_with(probe);
        for bad in [Uuid::now_v7(), foreign_id, raw_id, text_id] {
            assert!(
                matches!(
                    service.put(user_id, put_request(Some(bad)), &ctx()).await,
                    Err(AppError::Validation(_))
                ),
                "{bad} 应被 422 拒"
            );
        }
        // 合法绑定(本人、就绪、image):通过且富化出头像端点路径
        let PutProfileOutcome { profile: view, .. } = service
            .put(user_id, put_request(Some(ok_id)), &ctx())
            .await
            .unwrap();
        assert_eq!(
            view.avatar_url.as_deref(),
            Some(format!("/api/v1/frontend/profiles/{user_id}/avatar").as_str())
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
        let content_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let repo = Arc::new(InMemoryProfileRepo::new());
        let ok_probe = StaticAvatarProbe(HashMap::from([(
            content_id,
            AvatarInfo {
                mime_type: Some("image/png".into()),
                ready: true,
                owner_id: user_id,
            },
        )]));
        ProfileService::new(repo.clone(), Arc::new(ok_probe))
            .put(user_id, put_request(Some(content_id)), &ctx())
            .await
            .unwrap();
        let degraded = ProfileService::new(repo.clone(), Arc::new(FailingProbe));
        let view = degraded.get(user_id).await.unwrap();
        assert!(view.avatar_url.is_none(), "探测故障应降级 null 而非 500");
        assert_eq!(view.avatar_content_id, Some(content_id), "原始引用保留");
        // 悬空(probe None):换空 probe 同样 null
        let dangling = ProfileService::new(repo, Arc::new(StaticAvatarProbe::new()));
        assert!(dangling.get(user_id).await.unwrap().avatar_url.is_none());
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
        let service = service_with(FailingProbe);
        assert!(matches!(
            service
                .put(Uuid::now_v7(), put_request(Some(Uuid::now_v7())), &ctx())
                .await,
            Err(AppError::Internal(_))
        ));
    }

    /// garde:超长字段 → 422。
    #[tokio::test]
    async fn garde_rejects_overlong() {
        let service = service_with(StaticAvatarProbe::new());
        let mut input = put_request(None);
        input.phone = Some("9".repeat(256));
        assert!(matches!(
            service.put(Uuid::now_v7(), input, &ctx()).await,
            Err(AppError::Validation(_))
        ));
    }
}

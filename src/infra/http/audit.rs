//! 审计上下文 / 鉴权身份的 **HTTP 提取器**。`AuditContext` / `Actor` 本身是核心数据(`kernel::audit`),
//! 这里只负责从请求里把它取出来:请求边界产 `AuditContext`,经 service 下传给 repo,落到 `created_by`/`updated_by`。
//!
//! 鉴权中间件(`features::auth::authenticate`)验过 JWT 后,在 `request.extensions` 塞一个
//! [`idm::AuthUser`];`AuditContext` 与 `CurrentUser` 都只**读** extension —— token 校验是单一
//! 真相源(中间件 / `idm::AuthService::authenticate_token`),这两个提取器不碰 JWT。
//!
//! 身份类型 `AuthUser` 由 idm 库提供(`authenticate_token` 的产物);这里只做 HTTP 提取。

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::infra::http::error::ApiError;
use crate::kernel::app_error::AppError;
use crate::kernel::audit::AuditContext;
use crate::kernel::tenant_id::TenantId;
use idm::AuthUser;

/// 审计上下文提取器(handler 写 `Audit(ctx): Audit`):鉴权中间件验过 JWT 会在 extensions 塞 `AuthUser`;
/// 有 → `User`(带 token 的当前租户),无 → `Anonymous`。`AuditContext` 在核心 crate,孤儿规则不许直接给它
/// 实现 axum 提取器 —— 包一层。
pub struct Audit(pub AuditContext);

impl<S: Send + Sync> FromRequestParts<S> for Audit {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(match parts.extensions.get::<AuthUser>() {
            // 畸形 tenant_id(nil)不当租户:审计里记 None,租户级接口由 CurrentTenant 拒掉。
            Some(user) => AuditContext::new_with_user(
                user.id.to_string(),
                user.tenant_id
                    .and_then(|tenant| TenantId::try_new(tenant).ok()),
            ),
            None => AuditContext::new_anonymous(),
        }))
    }
}

/// **当前租户**提取器(租户级接口一律用它取租户,spec §4.3):租户**只**从 token 来,
/// 绝不接受请求体 / 查询参数里的 `tenant_id`,也绝不悄悄落到默认租户。
/// - 未认证 → 401;
/// - 已认证但 token 没有当前租户(平台上下文)→ 403 `tenant_required`;
/// - token 里的租户是 nil(畸形,签发方不会这么签)→ 同样 403 `tenant_required`。
#[derive(Clone, Copy, Debug)]
pub struct CurrentTenant(pub TenantId);

impl<S: Send + Sync> FromRequestParts<S> for CurrentTenant {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<AuthUser>()
            .ok_or(ApiError(AppError::Unauthorized))?;
        user.tenant_id
            .and_then(|tenant| TenantId::try_new(tenant).ok())
            .map(CurrentTenant)
            .ok_or(ApiError(AppError::TenantRequired))
    }
}

/// 受保护端点提取器:**必须已认证**。读鉴权中间件塞的 `AuthUser`;无(未带/非法 token)→ 401。
pub struct CurrentUser(pub AuthUser);

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(CurrentUser)
            .ok_or(ApiError(AppError::Unauthorized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use uuid::Uuid;

    fn parts_with(user: Option<AuthUser>) -> Parts {
        let mut request = Request::new(());
        if let Some(authenticated_user) = user {
            request.extensions_mut().insert(authenticated_user);
        }
        request.into_parts().0
    }

    fn auth_user(tenant: Option<Uuid>) -> AuthUser {
        let mut user = AuthUser::new(Uuid::from_u128(5), "u".into(), vec![]);
        user.tenant_id = tenant;
        user
    }

    async fn current_tenant(user: Option<AuthUser>) -> Result<CurrentTenant, AppError> {
        CurrentTenant::from_request_parts(&mut parts_with(user), &())
            .await
            .map_err(|e| e.0)
    }

    #[tokio::test]
    async fn current_tenant_comes_only_from_the_token() {
        let tenant = Uuid::from_u128(42);
        let got = current_tenant(Some(auth_user(Some(tenant)))).await.unwrap();
        assert_eq!(got.0.as_uuid(), tenant);
        // 平台上下文 → tenant_required(不落默认租户)
        assert!(matches!(
            current_tenant(Some(auth_user(None))).await,
            Err(AppError::TenantRequired)
        ));
        // 畸形 nil 租户 → 同样 tenant_required
        assert!(matches!(
            current_tenant(Some(auth_user(Some(Uuid::nil())))).await,
            Err(AppError::TenantRequired)
        ));
        // 未认证 → 401
        assert!(matches!(
            current_tenant(None).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn audit_context_carries_tenant() {
        let tenant = Uuid::from_u128(42);
        let Audit(ctx) =
            Audit::from_request_parts(&mut parts_with(Some(auth_user(Some(tenant)))), &())
                .await
                .unwrap();
        assert_eq!(
            ctx.tenant_id.map(|tenant_id| tenant_id.as_uuid()),
            Some(tenant)
        );
        assert_eq!(
            ctx.actor.tenant_id().map(|tenant_id| tenant_id.as_uuid()),
            Some(tenant)
        );
        assert_eq!(ctx.audit_id(), Some(Uuid::from_u128(5).to_string()));
        let Audit(anonymous) = Audit::from_request_parts(&mut parts_with(None), &())
            .await
            .unwrap();
        assert!(anonymous.tenant_id.is_none());
    }
}

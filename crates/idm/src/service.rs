//! idm 认证业务。持 repo/hasher/jwt 端口,编排注册/登录/发会话。
//! 范式同 widget 的 service:依赖 trait 而非实现,在此做校验/编排/审计下传。

use std::sync::Arc;

use garde::Validate;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt::{self, JwtCodec};
use super::repo::{RoleRepo, SessionRepo, User, UserRepo};
use super::types::{
    ChangePasswordRequest, DeleteMeRequest, LoginRequest, RegisterRequest, UpdateMeRequest,
    UserResponse,
};
use super::PwHasher;
use crate::audit::{AuditContext, AuthUser};
use crate::error::IdmError;

/// 认证结果:用户信息 + 待写进 httponly cookie 的 token + cookie max-age(秒)。
/// routes 层把 token 写进 `Set-Cookie`、body 返 `user`;token 不进响应体。
pub struct AuthOutcome {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub access_max_age_secs: i64,
    pub refresh_max_age_secs: i64,
}

/// 认证服务。`Clone` 廉价(全是 Arc),可放进 `IdmState`。
#[derive(Clone)]
pub struct AuthService {
    inner: Arc<Inner>,
}

struct Inner {
    users: Arc<dyn UserRepo>,
    sessions: Arc<dyn SessionRepo>,
    roles: Arc<dyn RoleRepo>,
    hasher: Arc<dyn PwHasher>,
    jwt: JwtCodec,
    refresh_ttl_secs: i64,
}

impl AuthService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepo>,
        sessions: Arc<dyn SessionRepo>,
        roles: Arc<dyn RoleRepo>,
        hasher: Arc<dyn PwHasher>,
        jwt_secret: &str,
        access_ttl_secs: i64,
        refresh_ttl_secs: i64,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                users,
                sessions,
                roles,
                hasher,
                jwt: JwtCodec::new(jwt_secret, access_ttl_secs),
                refresh_ttl_secs,
            }),
        }
    }

    /// 注册:校验 → 归一 username/email → hash 密码 → 同事务建 user/password → 发会话。
    pub async fn register(
        &self,
        input: RegisterRequest,
        ctx: &AuditContext,
    ) -> Result<AuthOutcome, IdmError> {
        input.validate()?;
        let username = normalize(&input.username);
        let email = input.email.as_deref().map(normalize);
        let hash = self.hash_password(input.password).await?;
        let user = self
            .inner
            .users
            .create(&username, email.as_deref(), &hash, ctx.audit_id())
            .await?;
        self.issue_session(&user, ctx.audit_id()).await
    }

    /// 登录:校验 → 查用户(identifier=username 或 email)→ 验密 → 发会话。
    /// **防枚举**:不存在与密码错均返回同一 `Unauthorized`。
    pub async fn login(&self, input: LoginRequest) -> Result<AuthOutcome, IdmError> {
        input.validate()?;
        let identifier = normalize(&input.identifier);
        let Some(found) = self.inner.users.find_by_identifier(&identifier).await? else {
            return Err(IdmError::Unauthorized);
        };
        if !self
            .verify_password(input.password, found.password_hash)
            .await?
        {
            return Err(IdmError::Unauthorized);
        }
        self.issue_session(&found.user, None).await
    }

    /// 验 access token → 已认证身份(含角色,供 require_role)。失败 → `Unauthorized`。
    pub fn authenticate_token(&self, token: &str) -> Result<AuthUser, IdmError> {
        let claims = self.inner.jwt.decode(token)?;
        let id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| IdmError::Unauthorized)?;
        Ok(AuthUser {
            id,
            username: claims.username,
            roles: claims.roles,
        })
    }

    /// 当前用户资料(GET /me):查存活用户 + 角色 → `UserResponse`。已软删 → `NotFound`。
    pub async fn me(&self, user_id: Uuid) -> Result<UserResponse, IdmError> {
        let user = self.inner.users.find_by_id(user_id).await?;
        let roles = self.inner.roles.roles_for_user(user_id).await?;
        Ok(to_response(&user, roles))
    }

    /// 刷新:验 refresh hash → 轮换(撤旧 session、发新会话)。无效/过期/已撤销 → `Unauthorized`。
    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthOutcome, IdmError> {
        let hash = jwt::hash_refresh(refresh_token);
        let now = OffsetDateTime::now_utc();
        let Some(session) = self.inner.sessions.find_active(&hash, now).await? else {
            return Err(IdmError::Unauthorized);
        };
        // 轮换:旧 refresh 一次性,撤销后发新会话(防 refresh 重放)。
        self.inner.sessions.revoke(session.id).await?;
        let user = self.inner.users.find_by_id(session.user_id).await?;
        self.issue_session(&user, None).await
    }

    /// 登出:撤销该 refresh 对应的会话。幂等(找不到也 Ok)。
    pub async fn logout(&self, refresh_token: &str) -> Result<(), IdmError> {
        let hash = jwt::hash_refresh(refresh_token);
        if let Some(session) = self
            .inner
            .sessions
            .find_active(&hash, OffsetDateTime::now_utc())
            .await?
        {
            self.inner.sessions.revoke(session.id).await?;
        }
        Ok(())
    }

    /// 登出所有设备:撤销用户全部活跃会话。
    pub async fn logout_all(&self, user_id: Uuid) -> Result<(), IdmError> {
        self.inner.sessions.revoke_all(user_id, None).await
    }

    /// 改资料(PUT /me,**全量替换**):username 必填,email 给值=设/给空=清空。替换 email 会重置 email_verified。
    pub async fn update_me(
        &self,
        user_id: Uuid,
        input: UpdateMeRequest,
        ctx: &AuditContext,
    ) -> Result<UserResponse, IdmError> {
        input.validate()?;
        let username = normalize(&input.username);
        let email = input.email.as_deref().map(normalize);
        let user = self
            .inner
            .users
            .update(user_id, &username, email.as_deref(), ctx.audit_id())
            .await?;
        let roles = self.inner.roles.roles_for_user(user_id).await?;
        Ok(to_response(&user, roles))
    }

    /// 注销(DELETE /me):验密 → 撤销所有会话 → 软删账户。密码错 → `Unauthorized`。
    pub async fn delete_me(
        &self,
        user_id: Uuid,
        input: DeleteMeRequest,
        by: Option<String>,
    ) -> Result<(), IdmError> {
        input.validate()?;
        let hash = self
            .inner
            .users
            .password_hash(user_id)
            .await?
            .ok_or(IdmError::Unauthorized)?;
        if !self.verify_password(input.password, hash).await? {
            return Err(IdmError::Unauthorized);
        }
        self.inner.sessions.revoke_all(user_id, None).await?;
        self.inner.users.soft_delete(user_id, by).await
    }

    /// 改密(POST /me/password):验旧密码 → 换 hash → 撤销所有会话(强制重登录)。旧密码错 → `Unauthorized`。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        input: ChangePasswordRequest,
    ) -> Result<(), IdmError> {
        input.validate()?;
        let hash = self
            .inner
            .users
            .password_hash(user_id)
            .await?
            .ok_or(IdmError::Unauthorized)?;
        if !self.verify_password(input.current_password, hash).await? {
            return Err(IdmError::Unauthorized);
        }
        let new_hash = self.hash_password(input.new_password).await?;
        self.inner.users.update_password(user_id, &new_hash).await?;
        self.inner.sessions.revoke_all(user_id, None).await?;
        Ok(())
    }

    /// 发会话:查角色 → 生成 refresh + 签带 roles 的 access JWT,组 `AuthOutcome`。
    async fn issue_session(
        &self,
        user: &User,
        by: Option<String>,
    ) -> Result<AuthOutcome, IdmError> {
        let now = OffsetDateTime::now_utc();
        let roles = self.inner.roles.roles_for_user(user.id).await?;
        let (refresh, refresh_hash) = jwt::generate_refresh();
        let expires_at = now + Duration::seconds(self.inner.refresh_ttl_secs);
        let session = self
            .inner
            .sessions
            .create(user.id, &refresh_hash, expires_at, by)
            .await?;
        let access = self
            .inner
            .jwt
            .issue_access(user, session.id, roles.clone(), now)?;
        Ok(AuthOutcome {
            user: to_response(user, roles),
            access_token: access,
            refresh_token: refresh,
            access_max_age_secs: self.inner.jwt.access_ttl_secs(),
            refresh_max_age_secs: self.inner.refresh_ttl_secs,
        })
    }

    /// argon2 hash 是 CPU 密集 → `spawn_blocking`,不阻塞 tokio worker 线程。
    async fn hash_password(&self, plain: String) -> Result<String, IdmError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.hash(&plain))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("hash 任务异常: {e}")))?
    }

    async fn verify_password(&self, plain: String, phc: String) -> Result<bool, IdmError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.verify(&plain, &phc))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("verify 任务异常: {e}")))?
    }
}

fn to_response(user: &User, roles: Vec<String>) -> UserResponse {
    UserResponse {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        roles,
    }
}

/// 标识符归一:去空白 + 转小写(配合 username/email 存活唯一索引,避免大小写绕过唯一)。
fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

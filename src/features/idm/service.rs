//! idm 认证业务。持 repo/hasher/jwt 端口,编排注册/登录/发会话。
//! 范式同 widget 的 service:依赖 trait 而非实现,在此做校验/编排/审计下传。

use std::sync::Arc;

use garde::Validate;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt::{self, JwtCodec};
use super::repo::{SessionRepo, User, UserRepo};
use super::types::{LoginRequest, RegisterRequest, UserResponse};
use super::PwHasher;
use crate::infra::audit::{AuditContext, AuthUser};
use crate::infra::error::AppError;

/// 认证结果:用户信息 + 待写进 httponly cookie 的 token + cookie max-age(秒)。
/// routes 层把 token 写进 `Set-Cookie`、body 返 `user`;token 不进响应体。
pub struct AuthOutcome {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub access_max_age_secs: i64,
    pub refresh_max_age_secs: i64,
}

/// 认证服务。`Clone` 廉价(全是 Arc),可放进 `AppState`。
#[derive(Clone)]
pub struct AuthService {
    inner: Arc<Inner>,
}

struct Inner {
    users: Arc<dyn UserRepo>,
    sessions: Arc<dyn SessionRepo>,
    hasher: Arc<dyn PwHasher>,
    jwt: JwtCodec,
    refresh_ttl_secs: i64,
}

impl AuthService {
    pub fn new(
        users: Arc<dyn UserRepo>,
        sessions: Arc<dyn SessionRepo>,
        hasher: Arc<dyn PwHasher>,
        jwt_secret: &str,
        access_ttl_secs: i64,
        refresh_ttl_secs: i64,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                users,
                sessions,
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
    ) -> Result<AuthOutcome, AppError> {
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
    pub async fn login(&self, input: LoginRequest) -> Result<AuthOutcome, AppError> {
        input.validate()?;
        let identifier = normalize(&input.identifier);
        // ponytail: 第一版不做 timing 等长防护(dummy verify);响应体已逐字节不可区分,
        // timing 防护(对不存在的用户也跑一次 hash)留待后续。
        let Some(found) = self.inner.users.find_by_identifier(&identifier).await? else {
            return Err(AppError::Unauthorized);
        };
        if !self
            .verify_password(input.password, found.password_hash)
            .await?
        {
            return Err(AppError::Unauthorized);
        }
        self.issue_session(&found.user, None).await
    }

    /// 验 access token → 已认证身份(供 authenticate 中间件用)。失败(验签/过期/格式)→ `Unauthorized`。
    pub fn authenticate_token(&self, token: &str) -> Result<AuthUser, AppError> {
        let claims = self.inner.jwt.decode(token)?;
        let id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| AppError::Unauthorized)?;
        Ok(AuthUser {
            id,
            username: claims.username,
        })
    }

    /// 当前用户资料(GET /me):查存活用户 → `UserResponse`。已软删 → `NotFound`。
    pub async fn me(&self, user_id: Uuid) -> Result<UserResponse, AppError> {
        let user = self.inner.users.find_by_id(user_id).await?;
        Ok(to_response(&user))
    }

    /// 发会话:生成 refresh(随机 + 落 hash)+ 签 access JWT,组 `AuthOutcome`。
    async fn issue_session(
        &self,
        user: &User,
        by: Option<String>,
    ) -> Result<AuthOutcome, AppError> {
        let now = OffsetDateTime::now_utc();
        let (refresh, refresh_hash) = jwt::generate_refresh();
        let expires_at = now + Duration::seconds(self.inner.refresh_ttl_secs);
        let session = self
            .inner
            .sessions
            .create(user.id, &refresh_hash, expires_at, by)
            .await?;
        let access = self.inner.jwt.issue_access(user, session.id, now)?;
        Ok(AuthOutcome {
            user: to_response(user),
            access_token: access,
            refresh_token: refresh,
            access_max_age_secs: self.inner.jwt.access_ttl_secs(),
            refresh_max_age_secs: self.inner.refresh_ttl_secs,
        })
    }

    /// argon2 hash 是 CPU 密集 → `spawn_blocking`,不阻塞 tokio worker 线程。
    async fn hash_password(&self, plain: String) -> Result<String, AppError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.hash(&plain))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("hash 任务异常: {e}")))?
    }

    async fn verify_password(&self, plain: String, phc: String) -> Result<bool, AppError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.verify(&plain, &phc))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("verify 任务异常: {e}")))?
    }
}

fn to_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
    }
}

/// 标识符归一:去空白 + 转小写(配合 username/email 存活唯一索引,避免大小写绕过唯一)。
fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

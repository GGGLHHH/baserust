//! **app 显式拥有的 JWT claim 形状 + 签验**。idm 库零 HTTP、只给身份事实 `TokenClaims`、只回读核心
//! `VerifiedToken` —— access token 里到底放哪些 claim、用什么算法/密钥签,全由这里决定。
//!
//! 这是 idm `TokenSigner`/`TokenVerifier` 端口的 app 实现:`AppState::new` 经 builder 注入它,
//! 替代 idm 默认的 `Hs256Tokens`。**要加自定义 claim(tenant_id / 权限位 / 设备指纹…)就改 `AppClaims`**
//! —— sign 时从 `TokenClaims`(或外部源)补字段、verify 时读出,不必碰 idm 库。

use idm::{IdmError, TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::authz::Perm;

/// app 的 access token claim 形状(序列化进 JWT)。**在此显式定义** —— 自定义 claim 加在这里。
/// `#[serde(default)]` roles:旧 token(无 roles)解码不失败。
#[derive(Serialize, Deserialize)]
struct AppClaims {
    /// 用户 id。
    sub: String,
    /// 会话 id(= jti,可据此撤销)。
    jti: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    #[serde(default)]
    roles: Vec<String>,
    /// per-token 权限子集(降权令牌:PAT/第三方)。空/缺省 = 无 scope 限制(第一方满权令牌)。
    /// 授权归 app,故 scope 用 app 的 `Perm` 闭集;旧 token 无此字段 `default` 兜底。
    #[serde(default)]
    scope: Vec<Perm>,
    iat: i64,
    exp: i64,
    // 自定义 claim 加在此(如 `tenant: String`),sign 从 TokenClaims/外部补、verify 读出。
}

/// app 的 HS256 token 签验(实现 idm 的 `TokenSigner` + `TokenVerifier` 端口)。
/// 对称密钥:同一把既签又验;要分进程最小权限(RS256:idm 私钥签、app 公钥验)就拆成两个类型。
pub struct AppTokens {
    encoding: jsonwebtoken::EncodingKey,
    decoding: jsonwebtoken::DecodingKey,
}

impl AppTokens {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding: jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            decoding: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    /// 签一个**带 scope 的降权令牌**(PAT / 第三方授权 / 测试)。第一方满权令牌走正常登录(`sign`,scope 空)。
    /// `scope` 是该令牌允许的权限子集 —— 有效权限 = 用户 role 权限 ∩ scope(见 `Policy::require_scoped`)。
    pub fn mint_scoped(
        &self,
        user_id: Uuid,
        username: &str,
        roles: Vec<String>,
        scope: Vec<Perm>,
        ttl_secs: i64,
    ) -> Result<String, IdmError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let claims = AppClaims {
            sub: user_id.to_string(),
            jti: Uuid::nil().to_string(), // 非会话令牌:不可经 session 撤销
            username: username.to_owned(),
            email: None,
            email_verified: false,
            roles,
            scope,
            iat: now,
            exp: now + ttl_secs,
        };
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.encoding)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
    }

    /// 读出令牌的 scope claim(鉴权中间件用 —— idm 的 `VerifiedToken` 不带 scope)。
    /// **验签**:scope 只信任来自验签通过的令牌(否则攻击者剥掉 scope 即可绕过降权)。
    /// 验签失败 → 空(该令牌的身份闸 `authenticate_token` 也会失败,请求被 401 拦,不会到授权)。
    pub fn scope_of(&self, token: &str) -> Vec<Perm> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        jsonwebtoken::decode::<AppClaims>(token, &self.decoding, &validation)
            .map(|d| d.claims.scope)
            .unwrap_or_default()
    }
}

impl TokenSigner for AppTokens {
    fn sign(&self, c: &TokenClaims) -> Result<String, IdmError> {
        let claims = AppClaims {
            sub: c.user_id.to_string(),
            jti: c.session_id.to_string(),
            username: c.username.clone(),
            email: c.email.clone(),
            email_verified: c.email_verified,
            roles: c.roles.clone(),
            // 正常登录/刷新发的是第一方满权令牌:scope 空 = 不降权。降权令牌走 `mint_scoped`。
            scope: Vec::new(),
            iat: c.issued_at.unix_timestamp(),
            exp: c.expires_at.unix_timestamp(),
        };
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.encoding)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
    }
}

impl TokenVerifier for AppTokens {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        let claims = jsonwebtoken::decode::<AppClaims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|_| IdmError::Unauthorized)?;
        let user_id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| IdmError::Unauthorized)?;
        Ok(VerifiedToken {
            user_id,
            username: claims.username,
            roles: claims.roles,
        })
    }
}

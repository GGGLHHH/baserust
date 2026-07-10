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

// ── 非对称(Ed25519):签发/验证物理分离。签发密钥只进 idm 进程,app 进程只持公钥 ——
//    被攻破也铸不出 token。dev 密钥对内嵌(keys/,prod 由 AppState::new fail-fast 拒用)。 ──

/// 签发半边(私钥)。**只装配进 needs_idm 的进程**;`dev()` 用内嵌开发私钥(测试/默认装配共用)。
pub struct AppTokenSigner {
    encoding: jsonwebtoken::EncodingKey,
}

impl AppTokenSigner {
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        Ok(Self {
            encoding: jsonwebtoken::EncodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("JWT 私钥 PEM 无效: {e}"))?,
        })
    }

    pub fn dev() -> Self {
        Self::from_pem(crate::infra::config::DEV_JWT_PRIVATE_KEY_PEM)
            .expect("内嵌 dev 私钥必然合法")
    }

    /// 签一个**带 scope 的降权令牌**(PAT / 第三方授权 / 测试)。有效权限 = role ∩ scope。
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
        encode_eddsa(&claims, &self.encoding)
    }
}

impl TokenSigner for AppTokenSigner {
    fn sign(&self, c: &TokenClaims) -> Result<String, IdmError> {
        let claims = AppClaims {
            sub: c.user_id.to_string(),
            jti: c.session_id.to_string(),
            username: c.username.clone(),
            email: c.email.clone(),
            email_verified: c.email_verified,
            roles: c.roles.clone(),
            scope: Vec::new(), // 第一方满权令牌;降权走 mint_scoped
            iat: c.issued_at.unix_timestamp(),
            exp: c.expires_at.unix_timestamp(),
        };
        encode_eddsa(&claims, &self.encoding)
    }
}

/// **必须显式 EdDSA header**:`Header::default()` 是 HS256,签出来公钥验不过。
fn encode_eddsa(claims: &AppClaims, key: &jsonwebtoken::EncodingKey) -> Result<String, IdmError> {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        claims,
        key,
    )
    .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
}

/// 验证半边(公钥)。所有进程装配;只验不签。
pub struct AppTokenVerifier {
    decoding: jsonwebtoken::DecodingKey,
}

impl AppTokenVerifier {
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        Ok(Self {
            decoding: jsonwebtoken::DecodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("JWT 公钥 PEM 无效: {e}"))?,
        })
    }

    pub fn dev() -> Self {
        Self::from_pem(crate::infra::config::DEV_JWT_PUBLIC_KEY_PEM).expect("内嵌 dev 公钥必然合法")
    }

    /// 读出令牌 scope claim(测试/工具用)。**验签**通过才信;失败 → 空(身份闸随后 401)。
    pub fn scope_of(&self, token: &str) -> Vec<Perm> {
        self.verify_with_scope(token)
            .map(|(_, scope)| scope)
            .unwrap_or_default()
    }

    /// **单次 decode** 同时产出身份与 scope —— 鉴权中间件热路径专用,
    /// 避免 authenticate_token + scope_of 各做一次完整 Ed25519 验签。
    pub fn verify_with_scope(&self, token: &str) -> Result<(idm::AuthUser, Vec<Perm>), IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        let claims = jsonwebtoken::decode::<AppClaims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|_| IdmError::Unauthorized)?;
        let user_id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| IdmError::Unauthorized)?;
        Ok((
            idm::AuthUser {
                id: user_id,
                username: claims.username,
                roles: claims.roles,
            },
            claims.scope,
        ))
    }
}

impl TokenVerifier for AppTokenVerifier {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
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

/// 拓扑不变量的 fail-fast 实体:`Mount::App` 的 AuthService 注入它 —— app 进程不持签发密钥,
/// 该路径运行期本不可达(auth 路由不挂);真被调到就是 wiring bug,炸得响。
pub struct NoopSigner;

impl TokenSigner for NoopSigner {
    fn sign(&self, _: &TokenClaims) -> Result<String, IdmError> {
        panic!("app 进程不持签发密钥 —— 签发只发生在 idm 进程(Mount 装配错了?)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 dev 对无关的第二对密钥(仅测试:错钥必拒)。
    const ROGUE_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICyfeopijJ8JHWUtEbT5T9vqgQBMJiIyYu3ga9FkdW2L
-----END PRIVATE KEY-----
";
    const ROGUE_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAumo0Rm5V+h4e0LXhVM+Wrm/iQ8rwzhHes8dztR2HWXE=
-----END PUBLIC KEY-----
";

    /// 签→验 round-trip:roles/scope claim 完整穿越;scope_of 同源。
    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let signer = AppTokenSigner::dev();
        let verifier = AppTokenVerifier::dev();
        let token = signer
            .mint_scoped(
                Uuid::nil(),
                "alice",
                vec!["admin".to_owned()],
                vec![Perm::WidgetRead],
                900,
            )
            .unwrap();
        let v = verifier.verify(&token).unwrap();
        assert_eq!(v.username, "alice");
        assert_eq!(v.roles, vec!["admin".to_owned()]);
        assert_eq!(verifier.scope_of(&token), vec![Perm::WidgetRead]);
    }

    /// 篡改 payload 一字节 → 验签拒(scope_of 同步归空)。
    #[test]
    fn tampered_token_rejected() {
        let signer = AppTokenSigner::dev();
        let verifier = AppTokenVerifier::dev();
        let token = signer
            .mint_scoped(Uuid::nil(), "a", vec![], vec![Perm::WidgetRead], 900)
            .unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        // 换掉 payload 首字符(base64url 域内换字符,保证仍可解析结构)
        let mut payload: Vec<u8> = parts[1].clone().into_bytes();
        payload[0] = if payload[0] == b'A' { b'B' } else { b'A' };
        parts[1] = String::from_utf8(payload).unwrap();
        let tampered = parts.join(".");
        assert!(verifier.verify(&tampered).is_err(), "篡改应拒");
        assert!(
            verifier.scope_of(&tampered).is_empty(),
            "篡改令牌 scope 应空"
        );
    }

    /// 错钥必拒:rogue 私钥签的,dev 公钥不认;反向同理。
    #[test]
    fn wrong_key_rejected() {
        let rogue_signer = AppTokenSigner::from_pem(ROGUE_PRIVATE).unwrap();
        let dev_verifier = AppTokenVerifier::dev();
        let token = rogue_signer
            .mint_scoped(
                Uuid::nil(),
                "evil",
                vec!["superadmin".to_owned()],
                vec![],
                900,
            )
            .unwrap();
        assert!(
            dev_verifier.verify(&token).is_err(),
            "rogue 签名 dev 公钥应拒"
        );

        let dev_signer = AppTokenSigner::dev();
        let rogue_verifier = AppTokenVerifier::from_pem(ROGUE_PUBLIC).unwrap();
        let token = dev_signer
            .mint_scoped(Uuid::nil(), "a", vec![], vec![], 900)
            .unwrap();
        assert!(
            rogue_verifier.verify(&token).is_err(),
            "dev 签名 rogue 公钥应拒"
        );
    }

    /// NoopSigner:一调即 panic(拓扑不变量)。
    #[test]
    #[should_panic(expected = "app 进程不持签发密钥")]
    fn noop_signer_panics() {
        let c = TokenClaims {
            user_id: Uuid::nil(),
            session_id: Uuid::nil(),
            username: "x".into(),
            email: None,
            email_verified: false,
            roles: vec![],
            issued_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc(),
        };
        let _ = NoopSigner.sign(&c);
    }
}

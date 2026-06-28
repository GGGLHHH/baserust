//! idm JWT:access token 签发(HS256)+ 不透明 refresh token 生成/哈希。
//! 不解耦(唯一实现);要换 KMS/HSM 签名再抽 trait。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::repo::User;
use crate::error::IdmError;

/// JWT claims。`sub`=user_id、`jti`=session_id(可据此撤销)。roles 留待 RBAC 块加。
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub jti: String,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    /// 角色名列表。`#[serde(default)]`:旧 token(无 roles)解码不失败。
    #[serde(default)]
    pub roles: Vec<String>,
    pub iat: i64,
    pub exp: i64,
}

/// JWT 编码器(HS256,对称密钥)。解码(鉴权块)后续加。
pub struct JwtCodec {
    encoding: jsonwebtoken::EncodingKey,
    decoding: jsonwebtoken::DecodingKey,
    access_ttl_secs: i64,
}

impl JwtCodec {
    pub fn new(secret: &str, access_ttl_secs: i64) -> Self {
        Self {
            encoding: jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            decoding: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            access_ttl_secs,
        }
    }

    pub fn access_ttl_secs(&self) -> i64 {
        self.access_ttl_secs
    }

    /// 验签 + 解 `Claims`(HS256,校验 exp)。任何失败(验签/过期/格式)→ `Unauthorized`,不泄露原因。
    pub fn decode(&self, token: &str) -> Result<Claims, IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| IdmError::Unauthorized)
    }

    /// 签发 access JWT。`exp = now + access_ttl`。
    pub fn issue_access(
        &self,
        user: &User,
        session_id: Uuid,
        roles: Vec<String>,
        now: OffsetDateTime,
    ) -> Result<String, IdmError> {
        let iat = now.unix_timestamp();
        let claims = Claims {
            sub: user.id.to_string(),
            jti: session_id.to_string(),
            username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            roles,
            iat,
            exp: iat + self.access_ttl_secs,
        };
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.encoding)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
    }
}

/// 生成不透明 refresh token:32B CSPRNG → base64url。返回 (明文给客户端, SHA-256 hash 落库)。
pub fn generate_refresh() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh(&token);
    (token, hash)
}

/// refresh token 的 SHA-256(base64url)。**只存 hash**:明文一旦发出不再可从库反推。
pub fn hash_refresh(token: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

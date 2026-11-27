//! **app 显式拥有的 JWT claim 形状 + 签验**。idm 库零 HTTP、只给身份事实 `TokenClaims`、只回读核心
//! `VerifiedToken` —— access token 里到底放哪些 claim、用什么算法/密钥签,全由这里决定。
//!
//! 这是 idm `TokenSigner`/`TokenVerifier` 端口的 app 实现:`AppState::try_new` 经 builder 注入它,
//! 替代 idm 默认的 `Hs256Tokens`。**要加自定义 claim(tenant_id / 权限位 / 设备指纹…)就改 `AppClaims`**
//! —— sign 时从 `TokenClaims`(或外部源)补字段、verify 时读出,不必碰 idm 库。

use std::time::{SystemTime, UNIX_EPOCH};

use idm::{AuthUser, IdmError, TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::authorization::TokenTenant;
use crate::infra::config;
use crate::kernel::authorization::Permission;

/// app 的 access token claim 形状(序列化进 JWT)。**在此显式定义** —— 自定义 claim 加在这里。
/// `#[serde(default)]`:旧 token(无 roles / 无租户 claim)解码不失败。
#[derive(Serialize, Deserialize)]
struct AppClaims {
    /// 用户 id。
    sub: String,
    /// 会话 id(= jti,可据此撤销)。
    jti: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    /// **平台角色**(租户角色在 `tenant_roles`)。
    #[serde(default)]
    roles: Vec<String>,
    /// 当前租户;平台上下文时**缺省**(不写 null)。旧 token 无此字段 → `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    /// 当前租户内的角色。旧 token 无此字段 → 空。
    #[serde(default)]
    tenant_roles: Vec<String>,
    /// 当前租户的 slug / 名称(展示用,`GET /permissions/me` 的 `tenant`;app 不查 idm 库)。
    /// 平台上下文 / 降权令牌 / 旧 token → 缺省。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_name: Option<String>,
    /// per-token 权限子集(降权令牌:PAT/第三方)。空/缺省 = 无 scope 限制(第一方满权令牌)。
    /// 授权归 app,故 scope 用 app 的 `Permission` 闭集;旧 token 无此字段 `default` 兜底。
    #[serde(default)]
    scope: Vec<Permission>,
    iat: i64,
    exp: i64,
    // 自定义 claim 加在此,sign 从 TokenClaims/外部补、verify 读出。
}

// ── 非对称(Ed25519):签发/验证物理分离。签发密钥只进 idm 进程,app 进程只持公钥 ——
//    被攻破也铸不出 token。dev 密钥对内嵌(keys/,prod 由 AppState::try_new fail-fast 拒用)。 ──

/// 签发半边(私钥)。**只装配进 needs_idm 的进程**;`new_with_development_key()` 用内嵌开发私钥(测试/默认装配共用)。
pub struct AppTokenSigner {
    encoding: EncodingKey,
}

impl AppTokenSigner {
    /// 从 PKCS#8 PEM 编码的 Ed25519 私钥构造。PEM 无效(不是 Ed25519 / 格式坏)→ `Err`。
    pub fn try_new(pem: &str) -> anyhow::Result<Self> {
        Ok(Self {
            encoding: EncodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("JWT 私钥 PEM 无效: {e}"))?,
        })
    }

    /// 用内嵌的**开发**私钥构造(测试 / 默认装配)。prod 由 `AppState::try_new` fail-fast 拒用。
    ///
    /// # Panics
    ///
    /// 内嵌私钥解析失败时 panic —— 那是构建产物损坏,不是运行期可恢复的错误。
    #[must_use]
    pub fn new_with_development_key() -> Self {
        Self::try_new(config::DEVELOPMENT_JWT_PRIVATE_KEY_PEM).expect("内嵌 dev 私钥必然合法")
    }

    /// 签一个**带 scope 的降权令牌**(PAT / 第三方授权 / 测试)。
    ///
    /// `roles` = 平台角色;`tenant` = 令牌所在租户及其中的租户角色(`None` = 平台上下文,租户级接口一律
    /// 403 `tenant_required`)。有效权限 = (平台角色给的平台级 ∪ 租户角色给的租户级)∩ `scope`。
    /// **不校验成员关系**(签发方负责;app 进程不查 idm 库),也不带租户 slug / 名称。
    pub fn mint_scoped(
        &self,
        user_id: Uuid,
        username: &str,
        roles: Vec<String>,
        tenant: Option<ScopedTenant>,
        scope: Vec<Permission>,
        ttl_seconds: i64,
    ) -> Result<String, IdmError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let claims = AppClaims {
            sub: user_id.to_string(),
            jti: Uuid::nil().to_string(), // 非会话令牌:不可经 session 撤销
            username: username.to_owned(),
            email: None,
            email_verified: false,
            roles,
            tenant_id: tenant.as_ref().map(|scoped| scoped.id),
            tenant_roles: tenant.map(|scoped| scoped.roles).unwrap_or_default(),
            tenant_slug: None,
            tenant_name: None,
            scope,
            iat: now,
            exp: now + ttl_seconds,
        };
        encode_eddsa(&claims, &self.encoding)
    }
}

impl TokenSigner for AppTokenSigner {
    fn sign(&self, identity: &TokenClaims) -> Result<String, IdmError> {
        let claims = AppClaims {
            sub: identity.user_id.to_string(),
            jti: identity.session_id.to_string(),
            username: identity.username.clone(),
            email: identity.email.clone(),
            email_verified: identity.email_verified,
            roles: identity.roles.clone(),
            tenant_id: identity.tenant_id,
            tenant_roles: identity.tenant_roles.clone(),
            tenant_slug: identity.tenant_slug.clone(),
            tenant_name: identity.tenant_name.clone(),
            scope: Vec::new(), // 第一方满权令牌;降权走 mint_scoped
            iat: identity.issued_at.unix_timestamp(),
            exp: identity.expires_at.unix_timestamp(),
        };
        encode_eddsa(&claims, &self.encoding)
    }
}

/// **必须显式 EdDSA header**:`Header::default()` 是 HS256,签出来公钥验不过。
fn encode_eddsa(claims: &AppClaims, key: &EncodingKey) -> Result<String, IdmError> {
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, key)
        .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
}

/// 验证半边(公钥)。所有进程装配;只验不签。
pub struct AppTokenVerifier {
    decoding: DecodingKey,
}

impl AppTokenVerifier {
    /// 从 PEM 编码的 Ed25519 公钥构造。PEM 无效 → `Err`。
    pub fn try_new(pem: &str) -> anyhow::Result<Self> {
        Ok(Self {
            decoding: DecodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("JWT 公钥 PEM 无效: {e}"))?,
        })
    }

    /// 用内嵌的**开发**公钥构造(与 [`AppTokenSigner::new_with_development_key`] 成对)。
    ///
    /// # Panics
    ///
    /// 内嵌公钥解析失败时 panic —— 那是构建产物损坏,不是运行期可恢复的错误。
    #[must_use]
    pub fn new_with_development_key() -> Self {
        Self::try_new(config::DEVELOPMENT_JWT_PUBLIC_KEY_PEM).expect("内嵌 dev 公钥必然合法")
    }

    /// 读出令牌 scope claim(测试/工具用)。**验签**通过才信;失败 → 空(身份闸随后 401)。
    #[must_use]
    pub fn scope_of(&self, token: &str) -> Vec<Permission> {
        self.verify_with_scope(token)
            .map(|verified| verified.scope)
            .unwrap_or_default()
    }

    /// **单次 decode** 同时产出身份、scope 与当前租户 —— 鉴权中间件热路径专用,
    /// 避免 authenticate_token + scope_of 各做一次完整 Ed25519 验签。
    pub fn verify_with_scope(&self, token: &str) -> Result<VerifiedAccess, IdmError> {
        let validation = Validation::new(Algorithm::EdDSA);
        let claims: AppClaims = jsonwebtoken::decode(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| IdmError::Unauthorized)?;
        let user_id: Uuid = claims.sub.parse().map_err(|_| IdmError::Unauthorized)?;
        let tenant = claims.tenant_id.map(|id| TokenTenant {
            id,
            slug: claims.tenant_slug,
            name: claims.tenant_name,
        });
        // AuthUser 是 #[non_exhaustive]:用构造函数建,再把 claim 里的租户字段原样写进去(不经 `in_tenant`:
        // 畸形令牌「有 tenant_roles 没 tenant_id」也要原样保留,由 Policy 判它的租户角色不算)。
        let mut user = AuthUser::new(user_id, claims.username, claims.roles);
        user.tenant_id = claims.tenant_id;
        user.tenant_roles = claims.tenant_roles;
        Ok(VerifiedAccess {
            user,
            scope: claims.scope,
            tenant,
        })
    }
}

/// 降权令牌所在的租户(`mint_scoped` 用):租户 id + 令牌在该租户内的租户角色。
#[derive(Clone, Debug)]
pub struct ScopedTenant {
    pub id: Uuid,
    pub roles: Vec<String>,
}

/// [`AppTokenVerifier::verify_with_scope`] 的产物:身份 + per-token scope + 当前租户(含展示用 slug / 名称)。
#[derive(Clone, Debug)]
pub struct VerifiedAccess {
    pub user: idm::AuthUser,
    pub scope: Vec<Permission>,
    pub tenant: Option<TokenTenant>,
}

impl TokenVerifier for AppTokenVerifier {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        // 复用 verify_with_scope 的单次 decode,丢弃 scope(镜像 scope_of 的委托姿势)。
        let user = self.verify_with_scope(token)?.user;
        let mut verified = VerifiedToken::new(user.id, user.username, user.roles);
        verified.tenant_id = user.tenant_id;
        verified.tenant_roles = user.tenant_roles;
        Ok(verified)
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
    use idm::Session;

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
        let signer = AppTokenSigner::new_with_development_key();
        let verifier = AppTokenVerifier::new_with_development_key();
        let token = signer
            .mint_scoped(
                Uuid::nil(),
                "alice",
                vec!["admin".to_owned()],
                None,
                vec![Permission::WidgetRead],
                900,
            )
            .unwrap();
        let verified = verifier.verify(&token).unwrap();
        assert_eq!(verified.username, "alice");
        assert_eq!(verified.roles, vec!["admin".to_owned()]);
        assert_eq!(verifier.scope_of(&token), vec![Permission::WidgetRead]);
    }

    /// **过期必拒** —— 这是 access token 唯一的"吊销"。
    ///
    /// `verify_with_scope` 从不拿 `jti` 去查会话表,中间件又只信它一家:logout 撤的是 refresh 会话,
    /// **撤不掉已签发的 access token**,所以 `exp` 是它寿命的唯一终点。而这道检查完全是隐式的 ——
    /// 靠 `Validation::new(EdDSA)` 继承库默认的 `validate_exp: true`。哪天 jsonwebtoken 大版本翻了
    /// 这个默认,或有人在这手搓 `Validation`,所有令牌立刻永不过期,而原有三条测试(全是验签)照绿。
    ///
    /// **ttl 必须 < -60**:`Validation::new` 同时带 `leeway: 60`,`-1` 的令牌仍在宽限期内、
    /// 会被**正常接受** —— 拿 -1 写这条测试只会红,让人误以为过期校验坏了(其实是宽限期在起作用)。
    /// 实测过:-1 → verify 通过;-120 → 拒。别"顺手"把它改回 -1。
    #[test]
    fn expired_token_rejected() {
        let signer = AppTokenSigner::new_with_development_key();
        let verifier = AppTokenVerifier::new_with_development_key();
        let token = signer
            .mint_scoped(
                Uuid::nil(),
                "a",
                vec![],
                None,
                vec![Permission::WidgetRead],
                -120,
            )
            .unwrap();
        assert!(verifier.verify(&token).is_err(), "过期令牌必须拒");
        assert!(
            verifier.scope_of(&token).is_empty(),
            "过期令牌 scope 应空(空 scope 在本仓被读作'无限制',绝不能让它漏过去)"
        );
        // 对照:同一把钥匙、同样的 claim,只把 ttl 改成未来 → 必过。
        // 这条排除掉"是别的原因拒的"(否则上面两条断言可能因为签名/解析问题而假绿)。
        let fresh = signer
            .mint_scoped(
                Uuid::nil(),
                "a",
                vec![],
                None,
                vec![Permission::WidgetRead],
                900,
            )
            .unwrap();
        assert!(verifier.verify(&fresh).is_ok(), "未过期的同款令牌应通过");
    }

    /// 篡改 payload 一字节 → 验签拒(scope_of 同步归空)。
    #[test]
    fn tampered_token_rejected() {
        let signer = AppTokenSigner::new_with_development_key();
        let verifier = AppTokenVerifier::new_with_development_key();
        let token = signer
            .mint_scoped(
                Uuid::nil(),
                "a",
                vec![],
                None,
                vec![Permission::WidgetRead],
                900,
            )
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
        let rogue_signer = AppTokenSigner::try_new(ROGUE_PRIVATE).unwrap();
        let dev_verifier = AppTokenVerifier::new_with_development_key();
        let token = rogue_signer
            .mint_scoped(
                Uuid::nil(),
                "evil",
                vec!["superadmin".to_owned()],
                None,
                vec![],
                900,
            )
            .unwrap();
        assert!(
            dev_verifier.verify(&token).is_err(),
            "rogue 签名 dev 公钥应拒"
        );

        let dev_signer = AppTokenSigner::new_with_development_key();
        let rogue_verifier = AppTokenVerifier::try_new(ROGUE_PUBLIC).unwrap();
        let token = dev_signer
            .mint_scoped(Uuid::nil(), "a", vec![], None, vec![], 900)
            .unwrap();
        assert!(
            rogue_verifier.verify(&token).is_err(),
            "dev 签名 rogue 公钥应拒"
        );
    }

    /// 租户 claim 穿越 sign → verify;旧 token(没有 tenant_id / tenant_roles)照样能验,租户字段缺省。
    #[test]
    fn tenant_claims_roundtrip_and_old_token_compat() {
        let signer = AppTokenSigner::new_with_development_key();
        let verifier = AppTokenVerifier::new_with_development_key();
        let now = time::OffsetDateTime::now_utc();
        let tenant = Uuid::from_u128(7);
        let mut session = Session::new(Uuid::from_u128(1), Some(tenant));
        session.id = Uuid::from_u128(2);
        let mut claims =
            TokenClaims::new(&session, "alice".into(), now, time::Duration::minutes(5));
        claims.tenant_roles = vec!["admin".into()];
        claims.tenant_slug = Some("acme".into());
        claims.tenant_name = Some("Acme".into());
        let token = signer.sign(&claims).unwrap();
        let verified = verifier.verify(&token).unwrap();
        assert_eq!(verified.tenant_id, Some(tenant));
        assert_eq!(verified.tenant_roles, vec!["admin".to_owned()]);
        let token_tenant = verifier.verify_with_scope(&token).unwrap().tenant.unwrap();
        assert_eq!(
            (
                token_tenant.id,
                token_tenant.slug.as_deref(),
                token_tenant.name.as_deref()
            ),
            (tenant, Some("acme"), Some("Acme"))
        );

        // 旧形状:mint_scoped 不带租户(tenant_id 缺省),等价于多租户之前签的 token
        let old = signer
            .mint_scoped(Uuid::nil(), "a", vec!["user".into()], None, vec![], 900)
            .unwrap();
        let verified = verifier.verify_with_scope(&old).unwrap();
        assert_eq!(verified.user.roles, vec!["user".to_owned()]);
        assert_eq!(verified.user.tenant_id, None);
        assert!(verified.user.tenant_roles.is_empty());
        assert!(verified.tenant.is_none());
    }

    /// 降权令牌可以带租户:令牌在该租户里、只有给定的租户角色,不带 slug / 名称。
    #[test]
    fn scoped_token_acts_in_given_tenant() {
        let tenant = Uuid::from_u128(9);
        let token = AppTokenSigner::new_with_development_key()
            .mint_scoped(
                Uuid::from_u128(1),
                "bob",
                vec![],
                Some(ScopedTenant {
                    id: tenant,
                    roles: vec!["user".into()],
                }),
                vec![Permission::WidgetRead],
                900,
            )
            .unwrap();
        let verified = AppTokenVerifier::new_with_development_key()
            .verify_with_scope(&token)
            .unwrap();
        assert_eq!(verified.user.tenant_id, Some(tenant));
        assert_eq!(verified.user.tenant_roles, vec!["user".to_owned()]);
        assert_eq!(verified.scope, vec![Permission::WidgetRead]);
        let token_tenant = verified.tenant.unwrap();
        assert_eq!(
            (token_tenant.id, token_tenant.slug, token_tenant.name),
            (tenant, None, None)
        );
    }

    /// NoopSigner:一调即 panic(拓扑不变量)。
    #[test]
    #[should_panic(expected = "app 进程不持签发密钥")]
    fn noop_signer_panics() {
        let claims = TokenClaims::new(
            &Session::new(Uuid::nil(), None),
            "x".into(),
            time::OffsetDateTime::now_utc(),
            time::Duration::ZERO,
        );
        let _ = NoopSigner.sign(&claims);
    }
}

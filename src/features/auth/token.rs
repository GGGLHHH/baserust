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
    /// 当前激活租户。**必须是 Option** —— 0 租户是常规状态而非边角:
    /// `POST /public/auth/register` 仍是公开自助注册,新用户 0 membership ⇒ 铸出的 token
    /// 没有 tenant(spec §1.1)。`#[serde(default)]` 顺带让存量 token 解码不失败。
    /// **绝不 nil 兜底** —— `Tenant` extractor 在缺席时 401。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<Uuid>,
    iat: i64,
    exp: i64,
}

/// 把 `TenantRoleRepo` 偷渡的 `t:{uuid}` 哨兵从 roles 里摘出来,还原成真正的 tenant claim。
///
/// **这是整个多租户设计唯一的信任转换点**(spec §4.2)。上游 `TokenClaims` 没有扩展字段
/// (rust-idm/src/token.rs),`roles: Vec<String>` 是唯一能让租户信息穿过 idm 到达 signer 的通道。
///
/// 今天伪造不了:`idm.roles` 的行只来自 `seed.rs` 的 `for r in RoleName::PLATFORM`,全仓无建角色
/// 端点,`PUT /users/{id}/roles` 收的是角色 **id** 不是 name。**但这个防御必须在** —— 它挡的是
/// 未来某天有人加了建角色端点。
fn split_tenant(roles: Vec<String>) -> Result<(Option<Uuid>, Vec<String>), IdmError> {
    let (sentinels, rest): (Vec<_>, Vec<_>) = roles.into_iter().partition(|r| r.starts_with("t:"));
    match sentinels.len() {
        0 => Ok((None, rest)), // 0 租户,合法(spec §1.1)
        1 => {
            // strip_prefix 而非 split(':') —— uuid 里没有冒号,但别赌
            let id = sentinels[0]
                .strip_prefix("t:")
                .expect("partition 已保证前缀")
                .parse::<Uuid>()
                .map_err(|_| IdmError::Internal(anyhow::anyhow!("租户哨兵不是合法 uuid")))?;
            Ok((Some(id), rest))
        }
        // ≥2 只可能是平台角色表被污染(有人建了个叫 t:xxx 的平台角色)。
        // **拒签,绝不"挑一个"** —— 挑哪个都是在替攻击者做选择。
        n => Err(IdmError::Internal(anyhow::anyhow!(
            "roles 里出现 {n} 个租户哨兵,平台角色表可能被污染 —— 拒签"
        ))),
    }
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
    ///
    /// **`tenant` 是独立强类型入参,绝不从 `roles` 里解析**(spec §4.3)——
    /// 这是**第二条铸币路径**,不经过 `sign()`。让它也去解析哨兵,等于把偷渡通道从
    /// 「idm 端口的无奈」升格成「我们的 API 约定」,那才是真把 hack 扩散了。
    /// `split_tenant` 只准在 `impl TokenSigner for AppTokenSigner::sign` 里调,一处。
    pub fn mint_scoped(
        &self,
        user_id: Uuid,
        username: &str,
        roles: Vec<String>,
        tenant: Option<Uuid>,
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
            tenant,
            iat: now,
            exp: now + ttl_secs,
        };
        encode_eddsa(&claims, &self.encoding)
    }
}

impl TokenSigner for AppTokenSigner {
    fn sign(&self, c: &TokenClaims) -> Result<String, IdmError> {
        // **唯一准调 split_tenant 的地方**:把 TenantRoleRepo 偷渡进 roles 的 `t:{uuid}` 哨兵
        // 摘出来,签成真正的 tenant claim;`tn:*` 的租户角色留在 roles 里(Policy 按它查权限)。
        let (tenant, roles) = split_tenant(c.roles.clone())?;
        let claims = AppClaims {
            sub: c.user_id.to_string(),
            jti: c.session_id.to_string(),
            username: c.username.clone(),
            email: c.email.clone(),
            email_verified: c.email_verified,
            roles,
            scope: Vec::new(), // 第一方满权令牌;降权走 mint_scoped
            tenant,
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
            .map(|(_, scope, _)| scope)
            .unwrap_or_default()
    }

    /// 读出令牌 tenant claim(测试/工具用)。**验签**通过才信;失败/无 → `None`。
    pub fn tenant_of(&self, token: &str) -> Option<Uuid> {
        self.verify_with_scope(token)
            .ok()
            .and_then(|(_, _, tenant)| tenant)
    }

    /// **单次 decode** 同时产出身份、scope 与租户 —— 鉴权中间件热路径专用,
    /// 避免 authenticate_token + scope_of 各做一次完整 Ed25519 验签。
    ///
    /// `tenant` 为 `None` 有两种合法来源:0 租户用户(register 的常规出口,spec §1.1)、
    /// 或存量的无该字段的 token。两者中间件都译成「无 `Tenant` extension」⇒ 下游 401。
    pub fn verify_with_scope(
        &self,
        token: &str,
    ) -> Result<(idm::AuthUser, Vec<Perm>, Option<Uuid>), IdmError> {
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
            claims.tenant,
        ))
    }
}

impl TokenVerifier for AppTokenVerifier {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        // 复用 verify_with_scope 的单次 decode,丢弃 scope/tenant(镜像 scope_of 的委托姿势)——
        // 这是 idm 端口的形状,它不认识租户。租户走 app 自己的 `Tenant` extractor。
        let (user, _scope, _tenant) = self.verify_with_scope(token)?;
        Ok(VerifiedToken {
            user_id: user.id,
            username: user.username,
            roles: user.roles,
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
                None,
                vec![Perm::WidgetRead],
                900,
            )
            .unwrap();
        let v = verifier.verify(&token).unwrap();
        assert_eq!(v.username, "alice");
        assert_eq!(v.roles, vec!["admin".to_owned()]);
        assert_eq!(verifier.scope_of(&token), vec![Perm::WidgetRead]);
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
        let signer = AppTokenSigner::dev();
        let verifier = AppTokenVerifier::dev();
        let token = signer
            .mint_scoped(Uuid::nil(), "a", vec![], None, vec![Perm::WidgetRead], -120)
            .unwrap();
        assert!(verifier.verify(&token).is_err(), "过期令牌必须拒");
        assert!(
            verifier.scope_of(&token).is_empty(),
            "过期令牌 scope 应空(空 scope 在本仓被读作'无限制',绝不能让它漏过去)"
        );
        // 对照:同一把钥匙、同样的 claim,只把 ttl 改成未来 → 必过。
        // 这条排除掉"是别的原因拒的"(否则上面两条断言可能因为签名/解析问题而假绿)。
        let fresh = signer
            .mint_scoped(Uuid::nil(), "a", vec![], None, vec![Perm::WidgetRead], 900)
            .unwrap();
        assert!(verifier.verify(&fresh).is_ok(), "未过期的同款令牌应通过");
    }

    /// 篡改 payload 一字节 → 验签拒(scope_of 同步归空)。
    #[test]
    fn tampered_token_rejected() {
        let signer = AppTokenSigner::dev();
        let verifier = AppTokenVerifier::dev();
        let token = signer
            .mint_scoped(Uuid::nil(), "a", vec![], None, vec![Perm::WidgetRead], 900)
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
                None,
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
            .mint_scoped(Uuid::nil(), "a", vec![], None, vec![], 900)
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

    // ── split_tenant:全设计唯一的信任转换点(spec §4.2)。三态各钉一条。 ──

    fn claims_with_roles(roles: Vec<String>) -> TokenClaims {
        TokenClaims {
            user_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            username: "u".into(),
            email: None,
            email_verified: false,
            roles,
            issued_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::seconds(900),
        }
    }

    /// 0 哨兵 → tenant 缺席,**不是错误**:register 的常规出口(0 租户,spec §1.1)。
    /// 且平台角色原样留在 roles 里。
    #[test]
    fn split_tenant_absent_is_legal() {
        let (tenant, roles) = split_tenant(vec!["superadmin".into(), "user".into()]).unwrap();
        assert_eq!(tenant, None, "0 租户是常规状态,不该报错");
        assert_eq!(roles, vec!["superadmin".to_owned(), "user".to_owned()]);
    }

    /// 1 哨兵 → 摘出真 tenant;`tn:*` 的租户角色**留在 roles 里**(Policy 按它查权限)。
    #[test]
    fn split_tenant_extracts_and_keeps_tn_roles() {
        let t = Uuid::now_v7();
        let (tenant, roles) =
            split_tenant(vec!["user".into(), format!("t:{t}"), "tn:admin".into()]).unwrap();
        assert_eq!(tenant, Some(t));
        assert_eq!(
            roles,
            vec!["user".to_owned(), "tn:admin".to_owned()],
            "哨兵被摘走,平台角色与 tn:* 租户角色都留下"
        );
    }

    /// ≥2 哨兵 → **拒签**,绝不"挑一个"。只可能是平台角色表被污染
    /// (有人建了个叫 `t:xxx` 的平台角色)—— 挑哪个都是在替攻击者做选择。
    #[test]
    fn split_tenant_rejects_multiple_sentinels() {
        let e = split_tenant(vec![
            format!("t:{}", Uuid::now_v7()),
            format!("t:{}", Uuid::now_v7()),
        ])
        .unwrap_err();
        assert!(matches!(e, IdmError::Internal(_)), "多哨兵必须拒签");
    }

    /// 哨兵不是合法 uuid → 拒签(而非静默当成没有租户)。
    #[test]
    fn split_tenant_rejects_malformed_sentinel() {
        let e = split_tenant(vec!["t:not-a-uuid".into()]).unwrap_err();
        assert!(matches!(e, IdmError::Internal(_)));
    }

    /// **端到端**:sign 把哨兵签成 tenant claim,verify 读回来 —— 且 claim 里**没有**哨兵残留。
    #[test]
    fn sign_translates_sentinel_to_tenant_claim() {
        let t = Uuid::now_v7();
        let token = AppTokenSigner::dev()
            .sign(&claims_with_roles(vec![
                "user".into(),
                format!("t:{t}"),
                "tn:member".into(),
            ]))
            .unwrap();
        let (user, _scope, tenant) = AppTokenVerifier::dev().verify_with_scope(&token).unwrap();
        assert_eq!(tenant, Some(t), "哨兵必须被签成真正的 tenant claim");
        assert_eq!(
            user.roles,
            vec!["user".to_owned(), "tn:member".to_owned()],
            "**哨兵绝不能残留在 roles 里** —— 否则会泄漏到 /me 与 /permissions/me"
        );
    }

    /// `mint_scoped` 是**第二条铸币路径**:tenant 只能经独立入参进,
    /// **绝不从 roles 解析**(spec §4.3)—— 传个像哨兵的 roles 也不该被当成租户。
    #[test]
    fn mint_scoped_never_parses_sentinel_from_roles() {
        let fake = Uuid::now_v7();
        let real = Uuid::now_v7();
        let token = AppTokenSigner::dev()
            .mint_scoped(
                Uuid::now_v7(),
                "pat",
                vec![format!("t:{fake}")], // 像哨兵,但 mint_scoped 不该理它
                Some(real),                // 真租户只走这里
                vec![],
                900,
            )
            .unwrap();
        let (user, _s, tenant) = AppTokenVerifier::dev().verify_with_scope(&token).unwrap();
        assert_eq!(tenant, Some(real), "tenant 只认独立入参");
        assert_eq!(
            user.roles,
            vec![format!("t:{fake}")],
            "roles 原样保留 —— mint_scoped 不解析哨兵,那是 sign() 一处的职责"
        );
    }
}

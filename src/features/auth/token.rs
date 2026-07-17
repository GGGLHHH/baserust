//! **app 显式拥有的 JWT claim 形状 + 签验**。idm 库零 HTTP、只给身份事实 `TokenClaims`、只回读核心
//! `VerifiedToken` —— access token 里到底放哪些 claim、用什么算法/密钥签,全由这里决定。
//!
//! 这是 idm `TokenSigner`/`TokenVerifier` 端口的 app 实现:`AppState::new` 经 builder 注入它,
//! 替代 idm 默认的 `Hs256Tokens`。**要加自定义 claim(tenant_id / 权限位 / 设备指纹…)就改 `AppClaims`**
//! —— 值从 `TokenClaims::extra` 来(由组合根装的 `idm::ClaimsExtender` 在铸币时填),sign 时读出。
//!
//! ## 为什么自定义 claim 的值必须经 `extra` 进来
//!
//! `TokenSigner::sign` 是**同步**的:它只拿得到 `&TokenClaims`,不能 await 一次查库。所以
//! 「签发时去查这人的租户」在 signer 里做不到 —— 值必须由 idm 在 `issue_session` 里先查好、
//! 经 `extra` 递进来。`extra` 就是那条正门(idm v0.6.0 `ClaimsExtender`)。
//!
//! **历史**:v0.5.0 的 `TokenClaims` 没有 `extra`,于是这里曾把 tenant 编码成 `t:{uuid}` 塞进
//! `roles: Vec<String>` 走私过来,再在 sign 里摘出。那个设计让租户 id 变成了「角色」,污染角色
//! 闭集、绕开所有按角色判定的授权闸,且泄漏路径要靠三处手写 `starts_with("t:")` 各自记得堵。
//! 已随 v0.6.0 整体删除 —— 别再走回去。

use idm::{IdmError, TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::authz::Perm;

/// app 塞进 `TokenClaims::extra` 的自定义 claim 载荷。
///
/// **生产方与消费方都在本仓**(组合根的 `TenantClaimsExtender` 产、下面的 `sign()` 消费),
/// idm 只负责把这坨 `Value` 原样运过来、不解释内容 —— 所以它可以是强类型的,不必是散字符串。
/// 加新的自定义 claim = 在这里加字段 + 在对应的 extender 里填。
#[derive(Serialize, Deserialize, Default)]
pub struct ExtraClaims {
    /// 当前激活租户。`None` = 0 租户(register 的常规出口,spec §1.1),合法。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<Uuid>,
}

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

/// 从 idm 运来的 `extra` 里读出 app 的自定义 claim。
///
/// `Null` = 没装 `ClaimsExtender`(或装了但这人没什么可加的)⇒ 默认值,合法。
/// **非 Null 但形状不对 = wiring bug ⇒ 拒签,绝不 `unwrap_or_default()`** ——
/// 那会静默签出一枚少了 tenant 的 token,而少了授权输入的 token 是静默降权/越权:
/// 没有异常、没有日志,只有用户看见了不该看见的数据。
fn extra_claims(extra: &serde_json::Value) -> Result<ExtraClaims, IdmError> {
    if extra.is_null() {
        return Ok(ExtraClaims::default());
    }
    serde_json::from_value(extra.clone()).map_err(|e| {
        IdmError::Internal(anyhow::anyhow!("TokenClaims::extra 形状不对 —— 拒签: {e}"))
    })
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
    /// **第二条铸币路径**:不经 idm 的 `issue_session`,故也不经 `ClaimsExtender` ——
    /// tenant 由调用方作为独立入参直接给。
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
        // roles 原样进 claim —— **它只装平台角色闭集,不再兼职运租户**(见模块头「历史」)。
        let extra = extra_claims(&c.extra)?;
        let claims = AppClaims {
            sub: c.user_id.to_string(),
            jti: c.session_id.to_string(),
            username: c.username.clone(),
            email: c.email.clone(),
            email_verified: c.email_verified,
            roles: c.roles.clone(),
            scope: Vec::new(), // 第一方满权令牌;降权走 mint_scoped
            tenant: extra.tenant,
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

/// 一次验签产出的**全部**已验证事实。
///
/// 用结构体而不是元组:字段从 3 个涨到 4 个之后,`(_, _, _, exp)` 这种解构没人读得懂,
/// 而且加字段要改每个调用点的位置。这里字段有名字,加字段只动用得上的那几处。
pub struct VerifiedClaims {
    pub user: idm::AuthUser,
    /// per-token 权限子集;空 = 无限制(第一方满权令牌)。
    pub scope: Vec<Perm>,
    /// 当前激活租户。`None` 有两种合法来源:0 租户用户(register 的常规出口,spec §1.1)、
    /// 或存量的无该字段的 token。中间件把两者都译成「无 `Tenant` extension」⇒ 下游 401。
    pub tenant: Option<Uuid>,
    /// claim 的 `exp`(unix 秒)。**长连接要它** —— SSE 得在 token 过期时截流,
    /// 否则流能活过 token(见 `widget_events`)。
    pub exp: i64,
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
            .map(|v| v.scope)
            .unwrap_or_default()
    }

    /// **单次 decode** 同时产出身份、scope 与租户 —— 鉴权中间件热路径专用,
    /// 避免 authenticate_token + scope_of 各做一次完整 Ed25519 验签。
    ///
    /// `tenant` 为 `None` 有两种合法来源:0 租户用户(register 的常规出口,spec §1.1)、
    /// 或存量的无该字段的 token。两者中间件都译成「无 `Tenant` extension」⇒ 下游 401。
    pub fn verify_with_scope(&self, token: &str) -> Result<VerifiedClaims, IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        let claims = jsonwebtoken::decode::<AppClaims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|_| IdmError::Unauthorized)?;
        let user_id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| IdmError::Unauthorized)?;
        Ok(VerifiedClaims {
            user: idm::AuthUser {
                id: user_id,
                username: claims.username,
                roles: claims.roles,
            },
            scope: claims.scope,
            tenant: claims.tenant,
            exp: claims.exp,
        })
    }
}

impl TokenVerifier for AppTokenVerifier {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        // 复用 verify_with_scope 的单次 decode,丢弃 scope/tenant(镜像 scope_of 的委托姿势)——
        // 这是 idm 端口的形状,它不认识租户。租户走 app 自己的 `Tenant` extractor。
        let v = self.verify_with_scope(token)?;
        Ok(VerifiedToken {
            user_id: v.user.id,
            username: v.user.username,
            roles: v.user.roles,
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
            extra: serde_json::Value::Null,
            issued_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc(),
        };
        let _ = NoopSigner.sign(&c);
    }

    // ── tenant claim 经 `TokenClaims::extra` 进来(idm v0.6.0 ClaimsExtender)。 ──

    fn claims_with(roles: Vec<String>, extra: serde_json::Value) -> TokenClaims {
        TokenClaims {
            user_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            username: "u".into(),
            email: None,
            email_verified: false,
            roles,
            extra,
            issued_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::seconds(900),
        }
    }

    /// `extra` 有租户 → 签进 tenant claim,**roles 一个字节都不动**。
    #[test]
    fn extra_tenant_becomes_tenant_claim() {
        let t = Uuid::now_v7();
        let token = AppTokenSigner::dev()
            .sign(&claims_with(
                vec!["user".into()],
                serde_json::json!({ "tenant": t }),
            ))
            .unwrap();
        let v = AppTokenVerifier::dev().verify_with_scope(&token).unwrap();
        let (user, tenant) = (v.user, v.tenant);
        assert_eq!(tenant, Some(t));
        assert_eq!(
            user.roles,
            vec!["user".to_owned()],
            "租户经 extra 走,roles 只装平台角色 —— 两条通道不再交叉"
        );
    }

    /// `extra` 是 `Null`(没装 extender)→ tenant 缺席,**不是错误**:
    /// 0 租户是常规状态(register 的常规出口,spec §1.1),且这也是 idm v0.5.0 的行为。
    #[test]
    fn null_extra_is_legal_and_yields_no_tenant() {
        let token = AppTokenSigner::dev()
            .sign(&claims_with(
                vec!["superadmin".into(), "user".into()],
                serde_json::Value::Null,
            ))
            .unwrap();
        let v = AppTokenVerifier::dev().verify_with_scope(&token).unwrap();
        let (user, tenant) = (v.user, v.tenant);
        assert_eq!(tenant, None, "0 租户是常规状态,不该报错");
        assert_eq!(user.roles, vec!["superadmin".to_owned(), "user".to_owned()]);
    }

    /// `extra` 非 Null 但形状不对 → **拒签**,绝不静默当成「没有租户」。
    ///
    /// 静默降级是这里最坏的失败模式:签出的 token 少了授权输入,没有异常、没有日志,
    /// 只有用户看见了不该看见的数据。宁可让登录炸。
    #[test]
    fn malformed_extra_refuses_to_sign() {
        let e = AppTokenSigner::dev()
            .sign(&claims_with(
                vec!["user".into()],
                serde_json::json!({ "tenant": "not-a-uuid" }),
            ))
            .unwrap_err();
        assert!(matches!(e, IdmError::Internal(_)), "形状不对必须拒签");
    }

    /// **回归钉**:叫 `t:{uuid}` 的角色现在只是个**普通角色**,不是租户。
    ///
    /// v0.5.0 时代 tenant 靠 `t:{uuid}` 哨兵混在 roles 里走私,于是任何能往 `idm.roles`
    /// 塞一行 `t:{受害租户uuid}` 的人,都能让自己被签进一个从没被邀请进的租户。
    /// idm v0.6.0 有了 `extra` 正门后,roles 不再兼职运租户 —— 这条钉死它别回去。
    #[test]
    fn a_role_named_like_the_old_sentinel_is_just_a_role() {
        let victim = Uuid::now_v7();
        let token = AppTokenSigner::dev()
            .sign(&claims_with(
                vec!["user".into(), format!("t:{victim}")],
                serde_json::Value::Null, // 没有 extra ⇒ 无租户
            ))
            .unwrap();
        let v = AppTokenVerifier::dev().verify_with_scope(&token).unwrap();
        let (user, tenant) = (v.user, v.tenant);
        assert_eq!(
            tenant, None,
            "**roles 里的 t:{{uuid}} 绝不能再被当成租户** —— 那是已删除的走私通道"
        );
        assert_eq!(
            user.roles,
            vec!["user".to_owned(), format!("t:{victim}")],
            "它就是个名字古怪的普通角色,原样穿过"
        );
    }

    /// `mint_scoped` 是**第二条铸币路径**:不经 idm 的 `issue_session`,也就不经
    /// `ClaimsExtender` —— tenant 由调用方作为独立入参直接给。
    #[test]
    fn mint_scoped_takes_tenant_as_its_own_param() {
        let t = Uuid::now_v7();
        let token = AppTokenSigner::dev()
            .mint_scoped(
                Uuid::now_v7(),
                "pat",
                vec!["user".into()],
                Some(t),
                vec![],
                900,
            )
            .unwrap();
        let tenant = AppTokenVerifier::dev()
            .verify_with_scope(&token)
            .unwrap()
            .tenant;
        assert_eq!(tenant, Some(t));
    }
}

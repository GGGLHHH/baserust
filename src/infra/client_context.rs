//! 认证审计用的客户端上下文提取器(HTTP 边界)。IP 反伪造:不信 XFF 最左(客户端可写),
//! 按"信任 N 层反代"取 `XFF[len - N]`(最外层可信代理追加的那条);forwarded_chain 存 XFF 全文供取证。
//! UA/request-id 直读头。

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;

/// 认证事件的来源维度。channel(public/admin)由 handler 决定,不在此。
#[derive(Clone, Debug, Default)]
pub struct ClientContext {
    pub ip: Option<IpAddr>,
    pub forwarded_chain: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// 解析可信客户端 IP。`trusted_hops` = 我方信任的反代层数(nginx=1,CDN+nginx=2…),它们各在 XFF
/// 右侧追加一条(记录各自收到连接的来源)。真实客户端 = 最外层可信代理追加的那条 = `XFF[len - trusted_hops]`
/// (其左侧均为客户端可伪造,忽略)。`trusted_hops == 0`(无可信代理/直连暴露)→ 只信 socket peer。
/// XFF 缺失/短于可信层数/该位不可解析 → 回退 X-Real-IP(nginx 设 = $remote_addr)→ peer;绝不退回可伪造值。
pub fn resolve_client_ip(
    xff: Option<&str>,
    real_ip: Option<&str>,
    peer: Option<IpAddr>,
    trusted_hops: usize,
) -> Option<IpAddr> {
    if trusted_hops == 0 {
        return peer;
    }
    if let Some(xff) = xff {
        let hops: Vec<&str> = xff
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(ip) = hops
            .len()
            .checked_sub(trusted_hops)
            .and_then(|i| hops.get(i))
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
        // XFF 存在但短于可信层数/该位坏 → 落到下方回退,不硬猜、不退回可伪造的最左值。
    }
    real_ip.and_then(|r| r.parse::<IpAddr>().ok()).or(peer)
}

/// headers + peer → 可信客户端 IP(header 取值 + `resolve_client_ip` 一体)。
/// 审计 `ClientContext` 与限流 `TrustedIpKeyExtractor` 共享**整个提取层**,不只末端解析。
pub fn client_ip_from_headers(
    headers: &axum::http::HeaderMap,
    peer: Option<IpAddr>,
    trusted_hops: usize,
) -> Option<IpAddr> {
    let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    resolve_client_ip(get("x-forwarded-for"), get("x-real-ip"), peer, trusted_hops)
}

/// 单条上下文文本入库的上限(字符数)。真实 UA 约 200 字符,512 宽裕得很。
///
/// **必须有上限**:这几个字段全是**原样的请求头**(攻击者可控),而登录失败会把它们写进审计事件
/// (`user_agent` / `forwarded_chain`)经 outbox → NATS → 投影落 `auth_events` 的无界 text 列 ——
/// **这条路未认证可达**(限流还是 opt-in)。不封顶时唯一的界是 hyper 的 header 缓冲(几百 KB),
/// 等于匿名者每次瞎登录就能持久化几百 KB 可控文本。同 `LoginRequest.identifier` 的 320 上限,
/// 那个是同一 payload、同一条匿名路径 —— 只封它一个而漏掉这几个,等于没封。
/// 收在**捕获点**:每个 emit 站点自动继承,不靠各处自觉。
const MAX_CTX_TEXT: usize = 512;

/// 按**字符**截断(不是字节切片:多字节 UA 上按字节切会 panic)。
fn truncate_ctx(s: &str) -> String {
    s.chars().take(MAX_CTX_TEXT).collect()
}

impl<S: Send + Sync> FromRequestParts<S> for ClientContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let forwarded_chain = header("x-forwarded-for").map(truncate_ctx);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        // trusted_hops 由 router 经 extension 注入(见 Task 8);缺省信 1 层。
        let trusted_hops = parts
            .extensions
            .get::<TrustedHops>()
            .map(|t| t.0)
            .unwrap_or(1);
        let ip = client_ip_from_headers(&parts.headers, peer, trusted_hops);
        Ok(Self {
            ip,
            forwarded_chain,
            user_agent: parts
                .headers
                .get(USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(truncate_ctx),
            request_id: header("x-request-id").map(truncate_ctx),
        })
    }
}

/// 经 router extension 注入的可信反代层数(避免提取器依赖全局 config)。
#[derive(Clone, Copy)]
pub struct TrustedHops(pub usize);

#[cfg(test)]
mod tests {
    use super::{resolve_client_ip, truncate_ctx, MAX_CTX_TEXT};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// 上下文文本封顶:攻击者可控的头(UA / XFF)会经审计事件落库,且这条路匿名可达。
    /// 按**字符**截断 —— 多字节内容上按字节切会 panic(真实 UA 里带中文/emoji 并不稀奇)。
    #[test]
    fn ctx_text_is_truncated_on_char_boundary() {
        assert_eq!(truncate_ctx("Mozilla/5.0"), "Mozilla/5.0", "短的原样");

        let long = "a".repeat(MAX_CTX_TEXT * 3);
        assert_eq!(
            truncate_ctx(&long).chars().count(),
            MAX_CTX_TEXT,
            "超长截断"
        );

        // 多字节:按字符数截断,且不 panic、不产生半个字符
        let multi = "界".repeat(MAX_CTX_TEXT * 2);
        let cut = truncate_ctx(&multi);
        assert_eq!(cut.chars().count(), MAX_CTX_TEXT);
        assert!(cut.chars().all(|c| c == '界'), "不该切出半个字符");
    }

    #[test]
    fn single_nginx_takes_the_appended_client_entry() {
        // nginx `$proxy_add_x_forwarded_for` 单条 = 客户端真实 IP;信 1 层 → 取它。
        assert_eq!(
            resolve_client_ip(Some("203.0.113.9"), None, None, 1),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn two_hops_ignore_client_forged_leftmost() {
        // 客户端伪造 1.2.3.4;CDN 追加真实客户端 203.0.113.9;nginx 追加 CDN 10.0.0.1。信 2 层 → XFF[len-2]。
        let xff = "1.2.3.4, 203.0.113.9, 10.0.0.1";
        assert_eq!(
            resolve_client_ip(Some(xff), None, None, 2),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn falls_back_to_real_ip_then_peer_never_forged() {
        assert_eq!(
            resolve_client_ip(None, Some("198.51.100.7"), None, 1),
            Some(ip("198.51.100.7"))
        );
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(resolve_client_ip(None, None, Some(peer), 1), Some(peer));
        assert_eq!(resolve_client_ip(None, None, None, 1), None);
        // trusted_hops=0 → 只信 peer,忽略客户端自送 XFF。
        assert_eq!(
            resolve_client_ip(Some("9.9.9.9"), None, Some(peer), 0),
            Some(peer)
        );
        // XFF 短于可信层数 → 不退回伪造的最左值,落回退(此处无 real/peer → None)。
        assert_eq!(resolve_client_ip(Some("1.2.3.4"), None, None, 2), None);
    }

    #[test]
    fn short_or_unresolvable_xff_falls_back_to_real_ip_not_none() {
        // XFF 存在但短于可信层数 → 必须回退 X-Real-IP(nginx 设、不可伪造),绝不能硬 return None(旧 bug),
        // 也不能退回可伪造的最左值。
        assert_eq!(
            resolve_client_ip(Some("1.2.3.4"), Some("198.51.100.7"), None, 2),
            Some(ip("198.51.100.7")),
        );
        // 无 real_ip 时继续退到 peer。
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(
            resolve_client_ip(Some("1.2.3.4"), None, Some(peer), 2),
            Some(peer)
        );
    }
}

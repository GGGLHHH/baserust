//! 百分号编码:把任意字符串编成只含 RFC3986 unreserved(`A-Za-z0-9-._~`)+ `%XX` 的纯 ASCII。
//! 两处消费:连接串 userinfo([`config`](super::config))、`Content-Disposition` 的 `filename*`
//! (content 下载)—— 都要把不可控字符塞进受限语法且对端能还原。过度编码(把 unreserved 也编)无害。

/// 编码为 RFC3986 unreserved 之外全部 `%XX`(UTF-8 多字节逐字节编码)。
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// 构造 RFC 6266 `Content-Disposition: attachment`。`filename=` 用净化后的 ASCII 兜底(老客户端),
/// `filename*=UTF-8''<pct>` 承载真实(可含非 ASCII / 控制字符 / 引号 / 反斜杠)文件名。content 下载的
/// **两条**出字节路径(代理回退 + presign 签进 `response-content-disposition`)共用它,口径一致 ——
/// 裸插值会让控制字符构造 HeaderValue 失败(500)、非 ASCII 被浏览器按 latin-1 解成乱码。
pub(crate) fn content_disposition_attachment(filename: &str) -> String {
    let ascii_fallback: String = filename
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() && c != '"') || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{}",
        encode(filename)
    )
}

#[cfg(test)]
mod tests {
    use super::{content_disposition_attachment, encode};

    #[test]
    fn encodes_reserved_control_and_utf8() {
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
        assert_eq!(encode("p/w@x?y#z"), "p%2Fw%40x%3Fy%23z");
        assert_eq!(encode("résumé"), "r%C3%A9sum%C3%A9"); // UTF-8 逐字节
        assert_eq!(encode("safe-._~"), "safe-._~"); // unreserved 原样
    }

    #[test]
    fn disposition_sanitizes_ascii_and_encodes_utf8() {
        let d = content_disposition_attachment("报表 \"final\".pdf");
        // ascii 兜底:非 ASCII / 引号 → '_',空格与 .pdf 保留。
        assert!(
            d.starts_with("attachment; filename=\"__ _final_.pdf\""),
            "{d}"
        );
        // filename*:UTF-8 百分号编码(引号与非 ASCII 均编码,浏览器解码得原名)。
        assert!(
            d.contains("filename*=UTF-8''%E6%8A%A5%E8%A1%A8%20%22final%22.pdf"),
            "{d}"
        );
        // 控制字符不进 header(否则 HeaderValue 构造失败 → 500)。
        let ctrl = content_disposition_attachment("a\nb\tc");
        assert!(!ctrl.contains('\n') && !ctrl.contains('\t'), "{ctrl}");
    }
}

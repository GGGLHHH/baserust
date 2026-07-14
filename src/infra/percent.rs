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

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn encodes_reserved_control_and_utf8() {
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
        assert_eq!(encode("p/w@x?y#z"), "p%2Fw%40x%3Fy%23z");
        assert_eq!(encode("résumé"), "r%C3%A9sum%C3%A9"); // UTF-8 逐字节
        assert_eq!(encode("safe-._~"), "safe-._~"); // unreserved 原样
    }
}

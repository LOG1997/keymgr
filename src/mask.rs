/// 根据题目要求的规则对密钥值进行掩码。
///
/// - 长度 > 8: 显示前4位和后4位，中间用 `***` 代替。
/// - 长度 ≤ 8: 隐藏总长度的一半（向下取整），首尾显示的位数尽量平分。
///
/// # 示例
///
/// | 原始值 | 掩码结果 |
/// |--------|----------|
/// | `my-secret-token-abc123` | `my-s***c123` |
/// | `abcdefgh` | `ab****gh` |
/// | `abcdefg`  | `ab***fg`  |
/// | `abcd`     | `a**d`     |
/// | `a`        | `a`        |
pub fn mask_value(value: &str) -> String {
    let len = value.len();

    if len == 0 {
        return String::new();
    }

    // 长度为 1 时全部显示
    if len == 1 {
        return value.to_string();
    }

    if len > 8 {
        // 前4 + "***" + 后4
        format!("{}***{}", &value[..4], &value[len - 4..])
    } else {
        let hidden = len / 2; // 隐藏的字符数（向下取整）
        let visible = len - hidden; // 总可见字符数
        let head = visible / 2; // 前半可见字符数（向下取整）
        let tail = visible - head; // 后半可见字符数

        format!(
            "{}{}{}",
            &value[..head],
            "*".repeat(hidden),
            &value[len - tail..],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_long() {
        assert_eq!(mask_value("my-secret-token-abc123"), "my-s***c123");
        assert_eq!(mask_value("1234567890"), "1234***7890");
    }

    #[test]
    fn test_mask_short() {
        assert_eq!(mask_value("abcdefgh"), "ab****gh"); // len=8
        assert_eq!(mask_value("abcdefg"), "ab***fg"); // len=7
        assert_eq!(mask_value("abcdef"), "a***ef"); // len=6
        assert_eq!(mask_value("abcde"), "a**de"); // len=5
        assert_eq!(mask_value("abcd"), "a**d"); // len=4
        assert_eq!(mask_value("abc"), "a*c"); // len=3
        assert_eq!(mask_value("ab"), "*b"); // len=2
        assert_eq!(mask_value("a"), "a"); // len=1
        assert_eq!(mask_value(""), ""); // len=0
    }

    #[test]
    fn test_mask_reversible_length() {
        // 掩码字符串长度应与原始值相同（>8 时不强制，因为用 *** 代替了中间部分）
        let cases = vec!["a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"];
        for case in cases {
            assert_eq!(mask_value(case).len(), case.len(),
                "掩码后的长度应与原始值相同: '{}'", case);
        }
    }
}

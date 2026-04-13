pub(crate) fn suspicious_string_matches(value: &str) -> Vec<String> {
    if !has_suspicious_ascii_seed(value.as_bytes()) {
        return Vec::new();
    }

    let lower = value.to_ascii_lowercase();
    let mut matches = Vec::new();
    if value.contains("__")
        && contains_magic_method(value)
        && !is_common_dunder_metadata_literal(value)
    {
        matches.push("magic method".to_string());
    }
    if lower.contains("base64.b64decode") {
        matches.push("base64.b64decode".to_string());
    }
    if contains_call_like(&lower, "eval") {
        matches.push("eval(".to_string());
    }
    if contains_call_like(&lower, "exec") {
        matches.push("exec(".to_string());
    }
    if lower.contains("os.system") {
        matches.push("os.system".to_string());
    }
    if lower.contains("os.popen") {
        matches.push("os.popen".to_string());
    }
    if lower.contains("os.spawn") {
        matches.push("os.spawn*".to_string());
    }
    for needle in [
        "subprocess.popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.run",
        "subprocess.check_call",
    ] {
        if lower.contains(needle) {
            matches.push("subprocess call".to_string());
            break;
        }
    }
    if lower.contains("commands.getoutput") || lower.contains("commands.getstatusoutput") {
        matches.push("commands call".to_string());
    }
    if lower.contains("import") && contains_import_statement(&lower) {
        matches.push("import statement".to_string());
    }
    if lower.contains("importlib") {
        matches.push("importlib".to_string());
    }
    if contains_call_like(&lower, "__import__") {
        matches.push("__import__(".to_string());
    }
    if lower.contains("\\x") && contains_hex_escape(value) {
        matches.push("hex escape".to_string());
    }
    if lower.contains("getattr") {
        if contains_getattr_target(value, "system") {
            matches.push("getattr system".to_string());
        }
        if contains_getattr_target(value, "exec") {
            matches.push("getattr exec".to_string());
        }
        if contains_getattr_target(value, "eval") {
            matches.push("getattr eval".to_string());
        }
        if contains_getattr_target(value, "popen") {
            matches.push("getattr popen".to_string());
        }
        for method in ["spawn", "call", "run", "popen"] {
            if contains_getattr_target(value, method) {
                matches.push("getattr process call".to_string());
                break;
            }
        }
        if contains_nested_getattr(value) {
            matches.push("nested getattr".to_string());
        }
    }
    matches
}

fn has_suspicious_ascii_seed(bytes: &[u8]) -> bool {
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index].to_ascii_lowercase() {
            b'_' => {
                if bytes.get(index + 1) == Some(&b'_') {
                    return true;
                }
            }
            b'\\' => {
                if bytes
                    .get(index + 1)
                    .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'x'))
                {
                    return true;
                }
            }
            b'b' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"base64") {
                    return true;
                }
            }
            b'c' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"commands") {
                    return true;
                }
            }
            b'e' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"eval")
                    || starts_with_ascii_case_insensitive(bytes, index, b"exec")
                {
                    return true;
                }
            }
            b'g' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"getattr") {
                    return true;
                }
            }
            b'i' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"import") {
                    return true;
                }
            }
            b'o' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"os.") {
                    return true;
                }
            }
            b's' => {
                if starts_with_ascii_case_insensitive(bytes, index, b"subprocess") {
                    return true;
                }
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn starts_with_ascii_case_insensitive(haystack: &[u8], start: usize, needle: &[u8]) -> bool {
    haystack
        .get(start..start.saturating_add(needle.len()))
        .is_some_and(|candidate| {
            candidate
                .iter()
                .zip(needle)
                .all(|(actual, expected)| actual.to_ascii_lowercase() == *expected)
        })
}

fn is_common_dunder_metadata_literal(value: &str) -> bool {
    matches!(
        value,
        "__version__" | "__metadata__" | "__schema__" | "__name__" | "__author__" | "__license__"
    )
}

fn contains_call_like(lower: &str, name: &str) -> bool {
    let mut offset = 0usize;
    let needle = format!("{}(", name);
    while let Some(found) = lower[offset..].find(name) {
        let start = offset + found;
        let after = start + name.len();
        let rest = &lower[after..];
        if rest.trim_start().starts_with('(') || lower[start..].starts_with(&needle) {
            return true;
        }
        offset = after;
    }
    false
}

fn contains_magic_method(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 5 {
        return false;
    }

    for start in 0..chars.len().saturating_sub(3) {
        if start > 0 && is_python_word_char(chars[start - 1]) {
            continue;
        }
        if chars[start] != '_' || chars[start + 1] != '_' {
            continue;
        }
        if !chars
            .get(start + 2)
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        {
            continue;
        }

        let mut end = start + 3;
        while end + 1 < chars.len() {
            if chars[end] == '_' && chars[end + 1] == '_' {
                let previous = chars[end - 1];
                let next_is_word = chars
                    .get(end + 2)
                    .is_some_and(|next| is_python_word_char(*next));
                if previous.is_ascii_alphabetic() && !next_is_word {
                    return true;
                }
            }
            if !is_ascii_regex_word_char(chars[end]) {
                break;
            }
            end += 1;
        }
    }
    false
}

fn contains_getattr_target(value: &str, target: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let lower_chars: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let mut index = 0usize;
    while let Some(start) = find_ascii_word(&lower_chars, "getattr", index) {
        let mut cursor = start + "getattr".len();
        skip_whitespace(&chars, &mut cursor);
        if !consume_char(&chars, &mut cursor, '(') {
            index = start + 1;
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        if !consume_python_word(&chars, &mut cursor) {
            index = start + 1;
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        if !consume_char(&chars, &mut cursor, ',') {
            index = start + 1;
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        let Some(quote) = chars
            .get(cursor)
            .copied()
            .filter(|ch| *ch == '\'' || *ch == '"')
        else {
            index = start + 1;
            continue;
        };
        cursor += 1;
        if !consume_case_insensitive_literal(&chars, &mut cursor, target) {
            index = start + 1;
            continue;
        }
        if !consume_char(&chars, &mut cursor, quote) {
            index = start + 1;
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        if consume_char(&chars, &mut cursor, ')') {
            return true;
        }
        index = start + 1;
    }
    false
}

fn contains_nested_getattr(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let lower_chars: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let mut index = 0usize;
    while let Some(start) = find_ascii_word(&lower_chars, "getattr", index) {
        let mut cursor = start + "getattr".len();
        skip_whitespace(&chars, &mut cursor);
        if !consume_char(&chars, &mut cursor, '(') {
            index = start + 1;
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        if consume_case_insensitive_literal(&chars, &mut cursor, "getattr") {
            skip_whitespace(&chars, &mut cursor);
            if consume_char(&chars, &mut cursor, '(') {
                return true;
            }
        }
        index = start + 1;
    }
    false
}

fn find_ascii_word(chars: &[char], word: &str, start: usize) -> Option<usize> {
    let word_chars: Vec<char> = word.chars().collect();
    if word_chars.is_empty() || chars.len() < word_chars.len() {
        return None;
    }
    let max_start = chars.len().saturating_sub(word_chars.len());
    for index in start..=max_start {
        if chars[index..index + word_chars.len()] == word_chars[..] {
            return Some(index);
        }
    }
    None
}

fn skip_whitespace(chars: &[char], cursor: &mut usize) {
    while chars.get(*cursor).is_some_and(|ch| ch.is_whitespace()) {
        *cursor += 1;
    }
}

fn consume_char(chars: &[char], cursor: &mut usize, expected: char) -> bool {
    if chars.get(*cursor) == Some(&expected) {
        *cursor += 1;
        return true;
    }
    false
}

fn consume_python_word(chars: &[char], cursor: &mut usize) -> bool {
    let start = *cursor;
    while chars
        .get(*cursor)
        .is_some_and(|ch| is_python_word_char(*ch))
    {
        *cursor += 1;
    }
    *cursor > start
}

fn consume_case_insensitive_literal(chars: &[char], cursor: &mut usize, literal: &str) -> bool {
    let literal_chars: Vec<char> = literal.chars().collect();
    if chars.len().saturating_sub(*cursor) < literal_chars.len() {
        return false;
    }
    for (offset, expected) in literal_chars.iter().enumerate() {
        let actual = chars[*cursor + offset].to_ascii_lowercase();
        if actual != expected.to_ascii_lowercase() {
            return false;
        }
    }
    *cursor += literal_chars.len();
    true
}

fn is_ascii_regex_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_python_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn contains_import_statement(lower: &str) -> bool {
    let mut previous_was_import = false;
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.') {
        if token.is_empty() {
            continue;
        }
        if previous_was_import {
            return true;
        }
        previous_was_import = token == "import";
    }
    false
}

fn contains_hex_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).any(|window| {
        window[0] == b'\\' && window[1] == b'x' && is_hex_byte(window[2]) && is_hex_byte(window[3])
    })
}

fn is_hex_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_string_matching_keeps_magic_method_boundaries() {
        assert!(suspicious_string_matches("__reduce__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("__1__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("a__b__c").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__version__").is_empty());
    }

    #[test]
    fn suspicious_string_matching_detects_getattr_variants() {
        let matches = suspicious_string_matches(r#"getattr (target, "popen")"#);

        assert!(matches.contains(&"getattr popen".to_string()));
        assert!(matches.contains(&"getattr process call".to_string()));
    }

    #[test]
    fn suspicious_string_matching_fast_rejects_benign_literals() {
        assert!(suspicious_string_matches(&"A".repeat(1024 * 1024)).is_empty());
    }

    #[test]
    fn suspicious_string_matching_keeps_case_insensitive_patterns() {
        assert!(suspicious_string_matches("OS.System('id')").contains(&"os.system".to_string()));
        assert!(suspicious_string_matches("Import OS").contains(&"import statement".to_string()));
    }
}

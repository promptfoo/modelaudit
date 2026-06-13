use crate::strings_policy::{
    BASE64_DANGEROUS_SEEDS, CALL_LIKE_PATTERNS, COMMANDS_CALL_NEEDLES, COPYREG_EXTENSION_NEEDLES,
    GETATTR_PROCESS_TARGETS, GETATTR_TARGET_PATTERNS, MAX_BASE64_TEXT_TOKENS,
    MAX_BASE64_TEXT_TOKEN_CHARS, MIN_BASE64_TEXT_TOKEN_CHARS, MIN_LITERAL_PADDING_BOUNDARY_CHARS,
    MODULE_ATTR_PATTERNS, PICKLE_LOADER_NEEDLES, SIMPLE_SUBSTRING_PATTERNS,
    SUBPROCESS_CALL_NEEDLES,
};
use std::borrow::Cow;

const MAX_SUFFIX_CALL_LOOKAHEAD_CHARS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedParseStep {
    Consumed,
    NoMatch,
    LimitReached,
}

#[derive(Default)]
struct GetattrMatches {
    system: bool,
    exec: bool,
    eval: bool,
    popen: bool,
    spawn: bool,
    call: bool,
    run: bool,
    nested: bool,
}

impl GetattrMatches {
    fn record_target(&mut self, target: &str) {
        match target {
            "system" => self.system = true,
            "exec" => self.exec = true,
            "eval" => self.eval = true,
            "popen" => self.popen = true,
            "spawn" => self.spawn = true,
            "call" => self.call = true,
            "run" => self.run = true,
            _ => {}
        }
    }

    fn contains_target(&self, target: &str) -> bool {
        match target {
            "system" => self.system,
            "exec" => self.exec,
            "eval" => self.eval,
            "popen" => self.popen,
            "spawn" => self.spawn,
            "call" => self.call,
            "run" => self.run,
            _ => false,
        }
    }

    fn contains_process_target(&self) -> bool {
        GETATTR_PROCESS_TARGETS
            .iter()
            .any(|target| self.contains_target(target))
    }
}

pub(crate) fn suspicious_string_matches(value: &str) -> Vec<String> {
    if value.len() >= 1024 && is_repeated_single_byte(value.as_bytes()) {
        return Vec::new();
    }

    let plain_value = strip_url_spans(value);
    let has_plain_seed = has_suspicious_ascii_seed(plain_value.as_bytes());
    let has_encoded_seed = has_base64_dangerous_seed(plain_value.as_ref());
    if !has_plain_seed && !has_encoded_seed {
        return Vec::new();
    }

    let mut matches = Vec::new();
    if has_encoded_seed {
        matches.extend(encoded_dangerous_string_matches(plain_value.as_ref()));
    }
    if !has_plain_seed {
        return matches;
    }

    let lower = plain_value.to_ascii_lowercase();
    let plain = plain_value.as_ref();
    if plain.contains("__")
        && contains_magic_method(plain)
        && !contains_only_common_dunder_metadata_literals(plain)
    {
        matches.push("magic method".to_string());
    }

    for (needle, label) in SIMPLE_SUBSTRING_PATTERNS {
        if contains_qualified_call_like(&lower, needle) {
            matches.push((*label).to_string());
        }
    }
    for (name, label) in CALL_LIKE_PATTERNS {
        if contains_call_like(&lower, name) {
            matches.push((*label).to_string());
        }
    }
    for pattern in MODULE_ATTR_PATTERNS {
        if find_module_attr(&lower, pattern.module, pattern.attr, pattern.prefix) {
            matches.push(pattern.label.to_string());
        }
    }
    if any_qualified_call_like(&lower, SUBPROCESS_CALL_NEEDLES) {
        matches.push("subprocess call".to_string());
    }
    if any_qualified_call_like(&lower, COMMANDS_CALL_NEEDLES) {
        matches.push("commands call".to_string());
    }
    if any_qualified_call_like(&lower, PICKLE_LOADER_NEEDLES) {
        matches.push("pickle loader call".to_string());
    }
    if any_qualified_call_like(&lower, COPYREG_EXTENSION_NEEDLES) {
        matches.push("copyreg extension".to_string());
    }
    if lower.contains("import") && contains_import_statement(&lower) {
        matches.push("import statement".to_string());
    }
    if lower.contains("importlib")
        && (contains_qualified_call_like(&lower, "importlib.import_module")
            || contains_qualified_call_like(&lower, "importlib.reload")
            || contains_import_statement(&lower))
    {
        matches.push("importlib".to_string());
    }
    if contains_call_like(&lower, "__import__") {
        matches.push("__import__(".to_string());
    }
    if lower.contains("\\x") && contains_hex_escape(value) {
        matches.push("hex escape".to_string());
    }
    if lower.contains("getattr") {
        let getattr_matches = find_getattr_matches(plain);
        for (target, label) in GETATTR_TARGET_PATTERNS {
            if getattr_matches.contains_target(target) {
                matches.push((*label).to_string());
            }
        }
        if getattr_matches.contains_process_target() {
            matches.push("getattr process call".to_string());
        }
        if getattr_matches.nested {
            matches.push("nested getattr".to_string());
        }
    }
    matches
}

const URL_SCHEMES: &[&[u8]] = &[
    b"http://",
    b"https://",
    b"ftp://",
    b"ftps://",
    b"ssh://",
    b"telnet://",
    b"ws://",
    b"wss://",
    b"s3://",
    b"gs://",
    b"az://",
    b"wasb://",
    b"wasbs://",
    b"abfs://",
    b"abfss://",
];

fn strip_url_spans(value: &str) -> Cow<'_, str> {
    let bytes = value.as_bytes();
    let mut output: Option<String> = None;
    let mut cursor = 0;

    while let Some(relative_start) = find_url_start(&bytes[cursor..]) {
        let start = cursor + relative_start;
        let end = url_end(bytes, start);
        if end <= start {
            cursor = start + 1;
            continue;
        }
        let stripped = output.get_or_insert_with(|| String::with_capacity(value.len()));
        stripped.push_str(&value[cursor..start]);
        stripped.push(' ');
        cursor = end;
    }

    match output {
        Some(mut stripped) => {
            stripped.push_str(&value[cursor..]);
            Cow::Owned(stripped)
        }
        None => Cow::Borrowed(value),
    }
}

fn find_url_start(bytes: &[u8]) -> Option<usize> {
    (0..bytes.len()).find(|index| {
        URL_SCHEMES.iter().any(|scheme| {
            bytes
                .get(*index..index + scheme.len())
                .is_some_and(|candidate| ascii_eq_ignore_case(candidate, scheme))
        })
    })
}

fn url_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() {
        if is_http_url_byte(bytes[end]) {
            end += 1;
            continue;
        }
        if bytes[end] == b'\''
            && bytes
                .get(end + 1)
                .is_some_and(|next| is_http_url_apostrophe_continuation(*next))
        {
            end += 1;
            continue;
        }
        break;
    }
    end
}

fn ascii_eq_ignore_case(candidate: &[u8], expected: &[u8]) -> bool {
    candidate.len() == expected.len()
        && candidate
            .iter()
            .zip(expected.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_http_url_apostrophe_continuation(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'*'
                | b'+'
                | b','
                | b'='
                | b'%'
        )
}

fn is_http_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
}

fn any_qualified_call_like(lower: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_qualified_call_like(lower, needle))
}

fn contains_qualified_call_like(lower: &str, qualified_name: &str) -> bool {
    contains_call_like(lower, qualified_name)
}

fn has_base64_dangerous_seed(value: &str) -> bool {
    BASE64_DANGEROUS_SEEDS
        .iter()
        .any(|seed| value.contains(seed))
}

pub(crate) fn is_repeated_single_byte(bytes: &[u8]) -> bool {
    let Some(first) = bytes.first() else {
        return false;
    };
    bytes.iter().all(|byte| byte == first)
}

fn encoded_dangerous_string_matches(value: &str) -> Vec<String> {
    let mut matches = Vec::new();
    for (token_count, token) in base64_tokens(value).enumerate() {
        if token_count >= MAX_BASE64_TEXT_TOKENS {
            break;
        }
        let bounded = if token.len() > MAX_BASE64_TEXT_TOKEN_CHARS {
            &token[..MAX_BASE64_TEXT_TOKEN_CHARS]
        } else {
            token
        };
        let Some(decoded) = decode_base64(bounded) else {
            continue;
        };
        let lower = ascii_lowercase_bytes(&decoded);
        for (needle, label) in [
            (b"os.system".as_slice(), "base64 os.system"),
            (b"eval(".as_slice(), "base64 eval("),
            (b"exec(".as_slice(), "base64 exec("),
            (b"__import__".as_slice(), "base64 __import__"),
            (b"subprocess".as_slice(), "base64 subprocess"),
        ] {
            if contains_bytes(&lower, needle) {
                matches.push(label.to_string());
            }
        }
    }
    matches
}

fn base64_tokens(value: &str) -> impl Iterator<Item = &str> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    std::iter::from_fn(move || loop {
        while index < bytes.len() && !is_base64_body_byte(bytes[index]) {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && is_base64_body_byte(bytes[index]) {
            index += 1;
        }
        while index < bytes.len() && bytes[index] == b'=' {
            index += 1;
        }
        if index.saturating_sub(start) >= MIN_BASE64_TEXT_TOKEN_CHARS {
            return value.get(start..index);
        }
        if index >= bytes.len() {
            return None;
        }
    })
}

fn is_base64_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut values = [0u8; 4];
    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0usize;
    while index < bytes.len() {
        let remaining = bytes.len() - index;
        if remaining == 1 {
            return None;
        }
        let chunk_len = remaining.min(4);
        values.fill(64);
        for offset in 0..chunk_len {
            let byte = bytes[index + offset];
            values[offset] = if byte == b'=' {
                64
            } else {
                base64_value(byte)?
            };
        }
        decoded.push((values[0] << 2) | (values[1] >> 4));
        if values[2] != 64 {
            decoded.push((values[1] << 4) | (values[2] >> 2));
        }
        if values[3] != 64 {
            decoded.push((values[2] << 6) | values[3]);
        }
        index += chunk_len;
    }
    Some(decoded)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn ascii_lowercase_bytes(value: &[u8]) -> Vec<u8> {
    value.iter().map(u8::to_ascii_lowercase).collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn has_suspicious_ascii_seed(bytes: &[u8]) -> bool {
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index].to_ascii_lowercase() {
            b'_' if bytes.get(index + 1) == Some(&b'_') => return true,
            b'\\'
                if bytes
                    .get(index + 1)
                    .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'x')) =>
            {
                return true;
            }
            b'b' if starts_with_ascii_case_insensitive(bytes, index, b"base64") => return true,
            b'c' if starts_with_ascii_case_insensitive(bytes, index, b"commands")
                || starts_with_ascii_case_insensitive(bytes, index, b"cloudpickle")
                || starts_with_ascii_case_insensitive(bytes, index, b"compile")
                || starts_with_ascii_case_insensitive(bytes, index, b"copyreg")
                || starts_with_ascii_case_insensitive(bytes, index, b"ctypes")
                || starts_with_ascii_case_insensitive(bytes, index, b"codecs") =>
            {
                return true;
            }
            b'e' if starts_with_ascii_case_insensitive(bytes, index, b"eval")
                || starts_with_ascii_case_insensitive(bytes, index, b"exec") =>
            {
                return true;
            }
            b'g' if starts_with_ascii_case_insensitive(bytes, index, b"getattr") => return true,
            b'i' if starts_with_ascii_case_insensitive(bytes, index, b"import") => return true,
            b'j' if starts_with_ascii_case_insensitive(bytes, index, b"joblib") => return true,
            b'o' if starts_with_ascii_case_insensitive(bytes, index, b"os.")
                || starts_with_ascii_case_insensitive(bytes, index, b"os ")
                || starts_with_ascii_case_insensitive(bytes, index, b"os\t")
                || starts_with_ascii_case_insensitive(bytes, index, b"os\n")
                || starts_with_ascii_case_insensitive(bytes, index, b"os\r") =>
            {
                return true;
            }
            b's' if starts_with_ascii_case_insensitive(bytes, index, b"subprocess") => return true,
            b'w' if starts_with_ascii_case_insensitive(bytes, index, b"webbrowser") => return true,
            b'p' if starts_with_ascii_case_insensitive(bytes, index, b"pickle")
                || starts_with_ascii_case_insensitive(bytes, index, b"popen") =>
            {
                return true;
            }
            b'r' if starts_with_ascii_case_insensitive(bytes, index, b"runpy") => return true,
            b'm' if starts_with_ascii_case_insensitive(bytes, index, b"marshal") => return true,
            b'd' if starts_with_ascii_case_insensitive(bytes, index, b"dill") => return true,
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
        value.trim(),
        "__version__"
            | "__metadata__"
            | "__schema__"
            | "__name__"
            | "__author__"
            | "__license__"
            | "__dict__"
            | "__slots__"
            | "__module__"
            | "__qualname__"
            | "__doc__"
            | "__all__"
            | "__annotations__"
    )
}

pub(crate) fn is_suspicious_magic_method(value: &str) -> bool {
    matches!(
        value,
        "__reduce__"
            | "__reduce_ex__"
            | "__setstate__"
            | "__getstate__"
            | "__getnewargs__"
            | "__getnewargs_ex__"
            | "__subclasses__"
            | "__globals__"
            | "__code__"
            | "__builtins__"
            | "__import__"
            | "__mro__"
            | "__base__"
            | "__bases__"
            | "__abs__"
            | "__add__"
            | "__aiter__"
            | "__and__"
            | "__anext__"
            | "__bool__"
            | "__bytes__"
            | "__call__"
            | "__ceil__"
            | "__contains__"
            | "__del__"
            | "__delitem__"
            | "__enter__"
            | "__eq__"
            | "__exit__"
            | "__floor__"
            | "__format__"
            | "__fspath__"
            | "__ge__"
            | "__getattribute__"
            | "__getattr__"
            | "__getitem__"
            | "__gt__"
            | "__hash__"
            | "__iadd__"
            | "__iand__"
            | "__ilshift__"
            | "__imatmul__"
            | "__imod__"
            | "__imul__"
            | "__index__"
            | "__invert__"
            | "__ior__"
            | "__ipow__"
            | "__irshift__"
            | "__iter__"
            | "__isub__"
            | "__itruediv__"
            | "__ixor__"
            | "__le__"
            | "__len__"
            | "__length_hint__"
            | "__lshift__"
            | "__lt__"
            | "__matmul__"
            | "__mod__"
            | "__mul__"
            | "__ne__"
            | "__neg__"
            | "__next__"
            | "__or__"
            | "__pos__"
            | "__pow__"
            | "__radd__"
            | "__rand__"
            | "__rlshift__"
            | "__rmatmul__"
            | "__rmod__"
            | "__rmul__"
            | "__ror__"
            | "__rpow__"
            | "__repr__"
            | "__reversed__"
            | "__round__"
            | "__rshift__"
            | "__rrshift__"
            | "__rsub__"
            | "__rtruediv__"
            | "__rxor__"
            | "__setitem__"
            | "__setattr__"
            | "__set_name__"
            | "__str__"
            | "__sub__"
            | "__trunc__"
            | "__truediv__"
            | "__xor__"
            | "__delattr__"
    )
}

fn contains_only_common_dunder_metadata_literals(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0usize;
    let mut saw_dunder = false;
    while index + 3 < chars.len() {
        if chars[index] != '_' || chars[index + 1] != '_' {
            index += 1;
            continue;
        }
        let mut end = index + 2;
        while end + 1 < chars.len() {
            if chars[end] == '_' && chars[end + 1] == '_' {
                let token: String = chars[index..=end + 1].iter().collect();
                if !is_common_dunder_metadata_literal(&token) {
                    return false;
                }
                saw_dunder = true;
                index = end + 2;
                break;
            }
            end += 1;
        }
        if end + 1 >= chars.len() {
            break;
        }
    }
    saw_dunder
}

fn contains_call_like(lower: &str, name: &str) -> bool {
    let mut offset = 0usize;
    let needle = format!("{}(", name);
    while let Some(found) = lower[offset..].find(name) {
        let start = offset + found;
        let after = start + name.len();
        if start > 0 && is_python_word_byte(lower.as_bytes()[start - 1]) {
            offset = after;
            continue;
        }
        let rest = &lower[after..];
        if rest.trim_start().starts_with('(') || lower[start..].starts_with(&needle) {
            if call_like_has_prose_suffix(rest) {
                offset = after;
                continue;
            }
            return true;
        }
        offset = after;
    }
    false
}

fn call_like_has_prose_suffix(rest_after_name: &str) -> bool {
    let trimmed = rest_after_name.trim_start();
    if !trimmed.starts_with('(') {
        return false;
    }

    let mut depth = 0usize;
    for (index, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let raw_suffix = &trimmed[index + ch.len_utf8()..];
                    let suffix = raw_suffix.trim_start();
                    if leading_whitespace_has_line_break(raw_suffix)
                        && suffix_starts_with_call_expression(suffix)
                    {
                        return false;
                    }
                    return suffix
                        .chars()
                        .next()
                        .is_some_and(|next| next.is_ascii_alphabetic())
                        && !has_literal_padding_boundary_after(suffix);
                }
            }
            _ => {}
        }
    }
    false
}

fn leading_whitespace_has_line_break(value: &str) -> bool {
    value
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .any(|ch| matches!(ch, '\n' | '\r'))
}

fn suffix_starts_with_call_expression(value: &str) -> bool {
    let mut chars = value
        .chars()
        .take(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS + 1)
        .collect::<Vec<_>>();
    let truncated = chars.len() > MAX_SUFFIX_CALL_LOOKAHEAD_CHARS;
    chars.truncate(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS);
    let mut cursor = 0usize;
    // Python identifiers are unbounded, so exhausting this cap is treated as
    // code-like instead of scanning attacker-controlled suffixes without limit.
    match consume_python_identifier(&chars, &mut cursor, truncated) {
        BoundedParseStep::Consumed => {}
        BoundedParseStep::NoMatch => return false,
        BoundedParseStep::LimitReached => return true,
    }
    let first_identifier = &chars[..cursor];
    if starts_expression_statement(first_identifier) {
        match skip_call_expression_spacing(&chars, &mut cursor, truncated) {
            BoundedParseStep::Consumed => {}
            BoundedParseStep::NoMatch => return false,
            BoundedParseStep::LimitReached => return true,
        }
        if first_identifier.iter().copied().eq("yield".chars())
            && chars
                .get(cursor..cursor + 4)
                .is_some_and(|candidate| candidate.iter().copied().eq("from".chars()))
            && chars
                .get(cursor + 4)
                .is_none_or(|ch| !is_suffix_identifier_continue(*ch))
        {
            cursor += 4;
            match skip_call_expression_spacing(&chars, &mut cursor, truncated) {
                BoundedParseStep::Consumed => {}
                BoundedParseStep::NoMatch => return false,
                BoundedParseStep::LimitReached => return true,
            }
        }
        if chars.get(cursor) != Some(&'(') {
            match consume_python_identifier(&chars, &mut cursor, truncated) {
                BoundedParseStep::Consumed => {}
                BoundedParseStep::NoMatch => return false,
                BoundedParseStep::LimitReached => return true,
            }
        }
    }
    loop {
        let spacing_start = cursor;
        match skip_call_expression_spacing(&chars, &mut cursor, truncated) {
            BoundedParseStep::Consumed => {}
            BoundedParseStep::NoMatch => return false,
            BoundedParseStep::LimitReached => return true,
        }
        match chars.get(cursor) {
            Some('(') => {
                return cursor == spacing_start || chars[spacing_start..cursor].contains(&'\\');
            }
            Some('.') => {
                cursor += 1;
                match skip_call_expression_spacing(&chars, &mut cursor, truncated) {
                    BoundedParseStep::Consumed => {}
                    BoundedParseStep::NoMatch => return false,
                    BoundedParseStep::LimitReached => return true,
                }
                match consume_python_identifier(&chars, &mut cursor, truncated) {
                    BoundedParseStep::Consumed => {}
                    BoundedParseStep::NoMatch => return false,
                    BoundedParseStep::LimitReached => return true,
                }
            }
            Some('[') => match consume_balanced_expression(&chars, &mut cursor, truncated) {
                BoundedParseStep::Consumed => {}
                BoundedParseStep::NoMatch => return false,
                BoundedParseStep::LimitReached => return true,
            },
            None if truncated => return true,
            _ => return false,
        }
    }
}

fn starts_expression_statement(identifier: &[char]) -> bool {
    ["await", "return", "raise", "yield", "assert"]
        .iter()
        .any(|keyword| identifier.iter().copied().eq(keyword.chars()))
}

fn skip_call_expression_spacing(
    chars: &[char],
    cursor: &mut usize,
    truncated: bool,
) -> BoundedParseStep {
    loop {
        match chars.get(*cursor).copied() {
            Some(ch) if ch.is_whitespace() && !matches!(ch, '\n' | '\r') => {
                *cursor += 1;
            }
            Some('\\') => {
                *cursor += 1;
                match chars.get(*cursor).copied() {
                    Some('\n') => *cursor += 1,
                    Some('\r') => {
                        *cursor += 1;
                        if chars.get(*cursor) == Some(&'\n') {
                            *cursor += 1;
                        }
                    }
                    None if truncated => return BoundedParseStep::LimitReached,
                    _ => return BoundedParseStep::NoMatch,
                }
            }
            None if truncated => return BoundedParseStep::LimitReached,
            _ => return BoundedParseStep::Consumed,
        }
    }
}

fn consume_python_identifier(
    chars: &[char],
    cursor: &mut usize,
    truncated: bool,
) -> BoundedParseStep {
    let Some(first) = chars.get(*cursor).copied() else {
        return if truncated {
            BoundedParseStep::LimitReached
        } else {
            BoundedParseStep::NoMatch
        };
    };
    if !(first == '_' || first.is_alphabetic()) {
        return BoundedParseStep::NoMatch;
    }
    *cursor += 1;
    while chars
        .get(*cursor)
        .is_some_and(|ch| is_suffix_identifier_continue(*ch))
    {
        *cursor += 1;
    }
    if *cursor == chars.len() && truncated {
        BoundedParseStep::LimitReached
    } else {
        BoundedParseStep::Consumed
    }
}

fn is_suffix_identifier_continue(ch: char) -> bool {
    is_python_word_char(ch)
        || matches!(
            ch,
            '\u{0300}'..='\u{036f}'
                | '\u{1ab0}'..='\u{1aff}'
                | '\u{1dc0}'..='\u{1dff}'
                | '\u{20d0}'..='\u{20ff}'
                | '\u{fe20}'..='\u{fe2f}'
        )
}

fn consume_balanced_expression(
    chars: &[char],
    cursor: &mut usize,
    truncated: bool,
) -> BoundedParseStep {
    if chars.get(*cursor) != Some(&'[') {
        return BoundedParseStep::NoMatch;
    }

    let mut delimiters = Vec::with_capacity(4);
    let mut quote = None;
    let mut escaped = false;
    while let Some(ch) = chars.get(*cursor).copied() {
        *cursor += 1;
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '#' => {
                while chars
                    .get(*cursor)
                    .is_some_and(|next| !matches!(next, '\n' | '\r'))
                {
                    *cursor += 1;
                }
            }
            '[' | '(' | '{' => delimiters.push(ch),
            ']' | ')' | '}' => {
                let expected = match ch {
                    ']' => '[',
                    ')' => '(',
                    '}' => '{',
                    _ => unreachable!(),
                };
                if delimiters.pop() != Some(expected) {
                    return BoundedParseStep::NoMatch;
                }
                if delimiters.is_empty() {
                    return BoundedParseStep::Consumed;
                }
            }
            _ => {}
        }
    }

    if truncated {
        BoundedParseStep::LimitReached
    } else {
        BoundedParseStep::NoMatch
    }
}

fn find_module_attr(lower: &str, module: &str, attr: &str, prefix: bool) -> bool {
    let chars: Vec<char> = lower.chars().collect();
    let module_chars: Vec<char> = module.chars().collect();
    let attr_chars: Vec<char> = attr.chars().collect();
    if chars.len() < module_chars.len() + attr_chars.len() + 1 {
        return false;
    }

    let max_start = chars.len().saturating_sub(module_chars.len());
    for start in 0..=max_start {
        if start > 0
            && is_python_word_char(chars[start - 1])
            && !has_literal_padding_boundary_before(&chars, start)
        {
            continue;
        }
        if chars[start..start + module_chars.len()] != module_chars[..] {
            continue;
        }
        let mut cursor = start + module_chars.len();
        skip_whitespace(&chars, &mut cursor);
        if !consume_char(&chars, &mut cursor, '.') {
            continue;
        }
        skip_whitespace(&chars, &mut cursor);
        if chars.len().saturating_sub(cursor) < attr_chars.len() {
            continue;
        }
        if chars[cursor..cursor + attr_chars.len()] != attr_chars[..] {
            continue;
        }
        let mut after = cursor + attr_chars.len();
        if prefix {
            while chars.get(after).is_some_and(|ch| is_python_word_char(*ch)) {
                after += 1;
            }
        } else if chars.get(after).is_some_and(|ch| is_python_word_char(*ch)) {
            continue;
        }
        if suffix_starts_non_prose_call(&chars[after..]) {
            return true;
        }
    }
    false
}

fn suffix_starts_non_prose_call(chars: &[char]) -> bool {
    let rest = chars.iter().collect::<String>();
    let trimmed = rest.trim_start();
    trimmed.starts_with('(') && !call_like_has_prose_suffix(trimmed)
}

fn has_literal_padding_boundary_before(chars: &[char], start: usize) -> bool {
    if start < MIN_LITERAL_PADDING_BOUNDARY_CHARS {
        return false;
    }
    let padding = chars[start - 1];
    if !padding.is_ascii_alphanumeric() {
        return false;
    }
    chars[start - MIN_LITERAL_PADDING_BOUNDARY_CHARS..start]
        .iter()
        .all(|ch| *ch == padding)
}

fn has_literal_padding_boundary_after(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(padding) = chars.next().filter(|ch| ch.is_ascii_alphanumeric()) else {
        return false;
    };
    chars
        .take(MIN_LITERAL_PADDING_BOUNDARY_CHARS.saturating_sub(1))
        .filter(|ch| *ch == padding)
        .count()
        == MIN_LITERAL_PADDING_BOUNDARY_CHARS.saturating_sub(1)
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
                let token = chars[start..=end + 1]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase();
                if previous.is_ascii_alphabetic()
                    && !next_is_word
                    && is_suspicious_magic_method(&token)
                    && !magic_method_looks_like_prose(&chars, start, end + 2)
                {
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

fn magic_method_looks_like_prose(chars: &[char], start: usize, token_end: usize) -> bool {
    let before_is_prose_gap = start == 0 || chars[start - 1].is_whitespace();
    if !before_is_prose_gap {
        return false;
    }
    let mut cursor = token_end;
    let mut saw_whitespace = false;
    while chars.get(cursor).is_some_and(|ch| ch.is_whitespace()) {
        saw_whitespace = true;
        cursor += 1;
    }
    saw_whitespace && chars.get(cursor).is_some_and(|ch| ch.is_ascii_alphabetic())
}

fn find_getattr_matches(value: &str) -> GetattrMatches {
    let chars: Vec<char> = value.chars().collect();
    let lower_chars: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let mut matches = GetattrMatches::default();
    let mut index = 0usize;
    while let Some(start) = find_ascii_word(&lower_chars, "getattr", index) {
        if let Some(target) = parse_getattr_target_at(&chars, start) {
            matches.record_target(&target);
        }
        if starts_nested_getattr_at(&chars, start) {
            matches.nested = true;
        }
        index = start + 1;
    }
    matches
}

fn parse_getattr_target_at(chars: &[char], start: usize) -> Option<String> {
    let mut cursor = start + "getattr".len();
    skip_whitespace(chars, &mut cursor);
    if !consume_char(chars, &mut cursor, '(') {
        return None;
    }
    skip_whitespace(chars, &mut cursor);
    if !consume_python_word(chars, &mut cursor) {
        return None;
    }
    skip_whitespace(chars, &mut cursor);
    if !consume_char(chars, &mut cursor, ',') {
        return None;
    }
    skip_whitespace(chars, &mut cursor);
    let quote = chars
        .get(cursor)
        .copied()
        .filter(|ch| *ch == '\'' || *ch == '"')?;
    cursor += 1;
    let target_start = cursor;
    while chars.get(cursor).is_some_and(|ch| *ch != quote) {
        cursor += 1;
    }
    let target = chars[target_start..cursor]
        .iter()
        .collect::<String>()
        .to_ascii_lowercase();
    if !consume_char(chars, &mut cursor, quote) {
        return None;
    }
    skip_whitespace(chars, &mut cursor);
    if !consume_char(chars, &mut cursor, ')') {
        return None;
    }
    Some(target)
}

fn starts_nested_getattr_at(chars: &[char], start: usize) -> bool {
    let mut cursor = start + "getattr".len();
    skip_whitespace(chars, &mut cursor);
    if !consume_char(chars, &mut cursor, '(') {
        return false;
    }
    skip_whitespace(chars, &mut cursor);
    if !consume_case_insensitive_literal(chars, &mut cursor, "getattr") {
        return false;
    }
    skip_whitespace(chars, &mut cursor);
    consume_char(chars, &mut cursor, '(')
}

fn find_ascii_word(chars: &[char], word: &str, start: usize) -> Option<usize> {
    let word_chars: Vec<char> = word.chars().collect();
    if word_chars.is_empty() || chars.len() < word_chars.len() {
        return None;
    }
    let max_start = chars.len().saturating_sub(word_chars.len());
    for index in start..=max_start {
        let end = index + word_chars.len();
        let has_word_boundary_before = index == 0 || !is_ascii_word_char(chars[index - 1]);
        let has_word_boundary_after = end == chars.len() || !is_ascii_word_char(chars[end]);
        if has_word_boundary_before
            && has_word_boundary_after
            && chars[index..end] == word_chars[..]
        {
            return Some(index);
        }
    }
    None
}

fn is_ascii_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
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
    lower
        .split([';', '\n', '\r'])
        .map(str::trim_start)
        .any(|statement| {
            statement
                .strip_prefix("import")
                .is_some_and(starts_with_whitespace)
                || statement.strip_prefix("from").is_some_and(|suffix| {
                    starts_with_whitespace(suffix) && suffix.contains(" import ")
                })
        })
}

fn starts_with_whitespace(value: &str) -> bool {
    value.chars().next().is_some_and(char::is_whitespace)
}

fn contains_hex_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .windows(4)
        .filter(|window| {
            window[0] == b'\\'
                && window[1].eq_ignore_ascii_case(&b'x')
                && is_hex_byte(window[2])
                && is_hex_byte(window[3])
        })
        .take(2)
        .count()
        >= 2
}

fn is_hex_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_python_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_string_matching_keeps_magic_method_boundaries() {
        assert!(suspicious_string_matches("__reduce__").contains(&"magic method".to_string()));
        assert!(
            suspicious_string_matches("__getnewargs_ex__").contains(&"magic method".to_string())
        );
        assert!(suspicious_string_matches("__abs__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__add__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__aiter__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__and__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__anext__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__bool__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__bytes__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ceil__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__contains__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__del__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__delitem__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__enter__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__eq__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__exit__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__floor__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__format__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__fspath__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ge__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__getitem__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__gt__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__hash__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__iadd__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__iand__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ilshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__imatmul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__imod__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__imul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__index__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__invert__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ior__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ipow__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__irshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__iter__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__isub__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__itruediv__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ixor__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__le__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__len__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__length_hint__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__lshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__lt__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__matmul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__mod__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__mul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ne__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__neg__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__next__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__or__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__pos__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__pow__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__radd__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rand__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rlshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rmatmul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rmod__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rmul__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__ror__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rpow__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__repr__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__reversed__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__round__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rrshift__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rsub__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rtruediv__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__rxor__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__setitem__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__set_name__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__str__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__sub__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__trunc__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__truediv__").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__xor__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("__1__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("__a__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("__x_y__").contains(&"magic method".to_string()));
        assert!(!suspicious_string_matches("a__b__c").contains(&"magic method".to_string()));
        assert!(suspicious_string_matches("__version__").is_empty());
        assert!(suspicious_string_matches("__dict__").is_empty());
        assert!(suspicious_string_matches("['__slots__', '__module__']").is_empty());
        assert!(suspicious_string_matches("['__version__']").is_empty());
    }

    #[test]
    fn suspicious_string_matching_detects_getattr_variants() {
        let matches = suspicious_string_matches(r#"getattr (target, "popen")"#);

        assert!(matches.contains(&"getattr popen".to_string()));
        assert!(matches.contains(&"getattr process call".to_string()));

        let nested_matches =
            suspicious_string_matches(r#"getattr(getattr(obj, "runner"), "system")"#);

        assert!(nested_matches.contains(&"nested getattr".to_string()));
        assert!(suspicious_string_matches(r#"mygetattr(target, "system")"#).is_empty());
    }

    #[test]
    fn suspicious_string_matching_fast_rejects_benign_literals() {
        assert!(suspicious_string_matches(&"A".repeat(1024 * 1024)).is_empty());
    }

    #[test]
    fn suspicious_string_matching_keeps_case_insensitive_patterns() {
        assert!(suspicious_string_matches("OS.System('id')").contains(&"os.system".to_string()));
        assert!(suspicious_string_matches("OS . system('id')").contains(&"os.system".to_string()));
        assert!(
            suspicious_string_matches(&format!("{}os.system('id')", "A".repeat(32)))
                .contains(&"os.system".to_string())
        );
        assert!(
            suspicious_string_matches(&format!("os.system('id'){}", "B".repeat(32)))
                .contains(&"os.system".to_string())
        );
        assert!(suspicious_string_matches("Import OS").contains(&"import statement".to_string()));
    }

    #[test]
    fn suspicious_string_matching_keeps_word_boundaries() {
        assert!(suspicious_string_matches("eval(x)").contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("os.system('id')").contains(&"os.system".to_string()));
        assert!(suspicious_string_matches("recompile(x)").is_empty());
        assert!(suspicious_string_matches("foos.system('id')").is_empty());
        assert!(suspicious_string_matches("subprocess_eval_guard").is_empty());
    }

    #[test]
    fn suspicious_string_matching_ignores_prose_call_mentions() {
        assert!(suspicious_string_matches("Use eval() function to compute results").is_empty());
        assert!(suspicious_string_matches("eval(x + 2) where x is input").is_empty());
        assert!(suspicious_string_matches("eval(x); exec(y)").contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("eval(payload)\nfoo()").contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("eval(payload)\nos.system('id')")
            .contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("eval(payload)\ncallbacks[0]()")
            .contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("eval(payload)\nawait callback()")
            .contains(&"eval(".to_string()));
        assert!(
            suspicious_string_matches("eval(payload)\nawait (callback())")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nawait callbacks[0]()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nreturn callback()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nraise RuntimeError()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nyield from callbacks[0]()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\n回调[0]()").contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nregistry['handler]'].run()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\ncallbacks[lookup(0)]()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\ncallbacks[{'key': [0]}['key'][0]]()")
                .contains(&"eval(".to_string())
        );
        assert!(suspicious_string_matches(
            "eval(payload)\ncallbacks[ # ] closes only in comment\n0\n]()"
        )
        .contains(&"eval(".to_string()));
        assert!(
            suspicious_string_matches("eval(payload)\na\u{301}()").contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\ncallbacks[\n0\n]()")
                .contains(&"eval(".to_string())
        );
        assert!(
            suspicious_string_matches("eval(payload)\nfoo \\\n()").contains(&"eval(".to_string())
        );
        assert!(suspicious_string_matches("eval(payload)\nfoo \\\r\n.bar()")
            .contains(&"eval(".to_string()));
        assert!(suspicious_string_matches("eval(x)\nwhere x is input").is_empty());
        assert!(suspicious_string_matches("eval(x)\nexample\n(text)").is_empty());
        assert!(suspicious_string_matches("eval(x)\nexample.\ntext()").is_empty());
        assert!(suspicious_string_matches("eval(x)\ncallbacks[0] is documented").is_empty());
        assert!(suspicious_string_matches("eval(x)\ncallbacks[0]\n(text)").is_empty());
        assert!(suspicious_string_matches("eval(x)\ncallbacks[0").is_empty());
        assert!(suspicious_string_matches("eval(x)\nresult == expected").is_empty());
        assert!(suspicious_string_matches("eval(x)\nresult: documented prose").is_empty());
        assert!(suspicious_string_matches("eval(x)\nawaiting callback completion").is_empty());
        assert!(suspicious_string_matches("eval(x)\nreturning value documentation").is_empty());
        assert!(suspicious_string_matches("eval(x)\nreturn value documentation").is_empty());
        assert!(suspicious_string_matches("eval(x)\nfor example, continue reading").is_empty());
        assert!(suspicious_string_matches("eval(x)\nif needed, continue reading").is_empty());
        assert!(suspicious_string_matches("eval(x)\nNote (details follow)").is_empty());
        assert!(
            suspicious_string_matches("eval(x)\nR\u{e9}sum\u{e9}\u{2014}details follow").is_empty()
        );
        let overlong_identifier = "a".repeat(2 * 1024 * 1024);
        assert!(suffix_starts_with_call_expression(&overlong_identifier));
        assert!(
            suspicious_string_matches("Do not call os.system(command) from loaders").is_empty()
        );
        assert!(
            suspicious_string_matches("Do not call os.system(command)\nfrom loaders").is_empty()
        );
        assert!(suspicious_string_matches("subprocess.run(args) is documented here").is_empty());
        assert!(suspicious_string_matches("base64.b64decode(data) decodes text").is_empty());
        assert!(suspicious_string_matches("importlib.import_module(name) is an API").is_empty());
        assert!(suspicious_string_matches("An import statement loads a module").is_empty());
        assert!(suspicious_string_matches(r"The bytes are written as \x80 in docs").is_empty());
        assert!(suspicious_string_matches("https://example.invalid/os.system").is_empty());
        assert!(
            suspicious_string_matches("https://example.invalid/docs/os.system(command)").is_empty()
        );
        assert!(
            suspicious_string_matches("https://example.invalid/api/subprocess.run(args)")
                .is_empty()
        );
        assert!(suspicious_string_matches(
            "https://example.invalid/path?x=1&handler=os.system(cmd)"
        )
        .is_empty());
        assert!(suspicious_string_matches(
            "https://example.invalid/path?x=1;handler=os.system(cmd)"
        )
        .is_empty());
        assert!(suspicious_string_matches(
            "https://example.invalid/path?x=1,handler=requests.get(url)"
        )
        .is_empty());
        assert!(suspicious_string_matches("https://example.invalid/a'b/os.system(cmd)").is_empty());
        assert!(suspicious_string_matches("s3://bucket/docs/os.system(cmd)").is_empty());
        assert!(
            suspicious_string_matches("ftp://example.invalid/docs/subprocess.run(args)").is_empty()
        );
        assert!(suspicious_string_matches("__reduce__ is a pickle protocol hook").is_empty());
    }

    #[test]
    fn suspicious_string_matching_preserves_code_around_url_literals() {
        assert!(
            suspicious_string_matches("os.system('curl https://example.invalid/p.sh')")
                .contains(&"os.system".to_string())
        );
        assert!(
            suspicious_string_matches("u='https://example.invalid/p';os.system('id')")
                .contains(&"os.system".to_string())
        );
        assert!(suspicious_string_matches(
            "subprocess.run(['curl', 'https://example.invalid/p.sh'])"
        )
        .contains(&"subprocess call".to_string()));
    }

    #[test]
    fn suspicious_string_matching_detects_pickle_loader_literals() {
        assert!(suspicious_string_matches("joblib.load(path)")
            .contains(&"pickle loader call".to_string()));
        assert!(suspicious_string_matches("cloudpickle.loads(blob)")
            .contains(&"pickle loader call".to_string()));
        assert!(
            suspicious_string_matches("copyreg.add_extension(module, name, code)")
                .contains(&"copyreg extension".to_string())
        );
    }

    #[test]
    fn suspicious_string_matching_ignores_importlib_comment_text() {
        assert!(suspicious_string_matches("importlib # harmless").is_empty());
        assert!(
            suspicious_string_matches("import importlib; importlib.import_module('os')")
                .contains(&"importlib".to_string())
        );
    }

    #[test]
    fn suspicious_string_matching_detects_base64_encoded_code() {
        let matches = suspicious_string_matches("b3Muc3lzdGVtKCdpZCcp");

        assert!(matches.contains(&"base64 os.system".to_string()));
        assert!(suspicious_string_matches("ZXZhbCh4KQ==").contains(&"base64 eval(".to_string()));
        assert!(
            suspicious_string_matches("https://example.invalid/path?q=b3Muc3lzdGVtKCdpZCcp")
                .is_empty()
        );
        assert!(suspicious_string_matches(
            "loader=b3Muc3lzdGVtKCdpZCcp; docs=https://example.invalid/path"
        )
        .contains(&"base64 os.system".to_string()));
    }
}

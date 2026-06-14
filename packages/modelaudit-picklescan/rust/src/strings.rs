use crate::strings_policy::{
    BASE64_CASEFOLD_DANGEROUS_SEEDS, BASE64_DANGEROUS_SEEDS, CALL_LIKE_PATTERNS,
    COMMANDS_CALL_NEEDLES, COPYREG_EXTENSION_NEEDLES, GETATTR_PROCESS_TARGETS,
    GETATTR_TARGET_PATTERNS, MAX_BASE64_TEXT_CANDIDATES, MAX_BASE64_TEXT_TOKEN_CHARS,
    MIN_BASE64_TEXT_TOKEN_CHARS, MIN_LITERAL_PADDING_BOUNDARY_CHARS, MODULE_ATTR_PATTERNS,
    PICKLE_LOADER_NEEDLES, SUBPROCESS_CALL_NEEDLES,
};
use std::borrow::Cow;

const MAX_SUFFIX_CALL_LOOKAHEAD_CHARS: usize = 256;
const MAX_URL_LOCAL_PREFIX_BYTES: usize = 512;
const MAX_STRING_LEXER_DEPTH: usize = 64;
pub(crate) const MAX_STRIPPED_URL_SPANS: usize = 128;
pub(crate) const URL_SCAN_LIMIT_SENTINEL: &str = "__url_scan_limit_exceeded__";
pub(crate) const URL_CONTEXT_INCOMPLETE_SENTINEL: &str = "__url_context_incomplete__";
pub(crate) const BASE64_SCAN_LIMIT_SENTINEL: &str = "__base64_scan_limit_exceeded__";
pub(crate) const BASE64_WORK_LIMIT_SENTINEL: &str = "__base64_work_limit_exceeded__";
pub(crate) const BASE64_ALIGNMENT_AMBIGUITY_SENTINEL: &str = "__base64_alignment_ambiguous__";
pub(crate) const MAX_BASE64_TOTAL_SCAN_CHARS: usize = 8 * MAX_BASE64_TEXT_TOKEN_CHARS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedParseStep {
    Consumed,
    NoMatch,
    LimitReached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringLexFrame {
    String(u8, usize, bool),
    FormattedExpression(usize, usize),
    FormatSpec,
    Comment(bool),
}

fn getattr_target_bit(target: &str) -> u8 {
    match target {
        "system" => 1,
        "exec" => 2,
        "eval" => 4,
        "popen" => 8,
        "spawn" => 16,
        "call" => 32,
        "run" => 64,
        _ => 0,
    }
}

pub(crate) fn suspicious_string_matches(value: &str) -> Vec<String> {
    suspicious_string_matches_impl(value, true)
}

fn suspicious_string_matches_impl(value: &str, scan_base64: bool) -> Vec<String> {
    if value.len() >= 1024 && is_repeated_single_byte(value.as_bytes()) {
        return Vec::new();
    }

    let raw_has_plain_seed = has_suspicious_ascii_seed(value.as_bytes());
    let raw_has_encoded_seed = scan_base64
        && has_base64_dangerous_seed(
            value
                .bytes()
                .filter(|byte| !is_base64_ignored_whitespace(*byte)),
        );
    if !raw_has_plain_seed && !raw_has_encoded_seed {
        return Vec::new();
    }

    let (plain_value, url_limit_exceeded, url_context_incomplete) = strip_url_spans(value);
    let has_plain_seed = raw_has_plain_seed && has_suspicious_ascii_seed(plain_value.as_bytes());
    let has_encoded_seed = raw_has_encoded_seed
        && has_base64_dangerous_seed(
            plain_value
                .bytes()
                .filter(|byte| !is_base64_ignored_whitespace(*byte)),
        );
    let mut matches = Vec::new();
    if url_limit_exceeded {
        matches.push(URL_SCAN_LIMIT_SENTINEL.to_string());
    }
    if url_context_incomplete {
        matches.push(URL_CONTEXT_INCOMPLETE_SENTINEL.to_string());
    }
    if has_encoded_seed {
        matches.extend(encoded_dangerous_string_matches(plain_value.as_ref()));
    }
    if !has_plain_seed {
        return matches;
    }

    let lower = plain_value.to_ascii_lowercase();
    let plain = plain_value.as_ref();
    if plain.contains("__") && contains_magic_method(plain) {
        matches.push("magic method".to_string());
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
        && (contains_call_like(&lower, "importlib.import_module")
            || contains_call_like(&lower, "importlib.reload")
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
        let (getattr_targets, nested_getattr) = find_getattr_matches(plain);
        for (target, label) in GETATTR_TARGET_PATTERNS {
            if getattr_targets & getattr_target_bit(target) != 0 {
                matches.push((*label).to_string());
            }
        }
        if GETATTR_PROCESS_TARGETS
            .iter()
            .any(|target| getattr_targets & getattr_target_bit(target) != 0)
        {
            matches.push("getattr process call".to_string());
        }
        if nested_getattr {
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

const URL_CODE_PADDING_BYTES: &[u8] = b" \t\r\n'\"!+-/%*|&;@=<>^~:,.[]{}()";

fn strip_url_spans(value: &str) -> (Cow<'_, str>, bool, bool) {
    let bytes = value.as_bytes();
    let mut output: Option<String> = None;
    let mut copied_through = 0usize;
    let mut cursor = 0usize;
    let mut url_count = 0usize;
    let mut span_limit_exceeded = false;
    let mut context_incomplete = false;
    let mut lex_stack: Vec<StringLexFrame> = Vec::new();

    while cursor < bytes.len() {
        if url_scheme_starts(bytes, cursor) {
            url_count += 1;
            span_limit_exceeded |= url_count > MAX_STRIPPED_URL_SPANS;
            let (end, uncertain) = url_end(bytes, cursor, lex_stack.last().copied());
            context_incomplete |= uncertain;
            let stripped = output.get_or_insert_with(|| String::with_capacity(value.len()));
            stripped.push_str(&value[copied_through..cursor]);
            // Keep bytes on opposite sides of a removed URL in separate
            // lexical tokens. MIME-Base64 whitespace must not stitch them.
            stripped.push('\0');
            copied_through = end;
            cursor = end;
            continue;
        }

        let byte = bytes[cursor];
        match lex_stack.last().copied() {
            Some(StringLexFrame::Comment(_)) => {
                if matches!(byte, b'\r' | b'\n') {
                    lex_stack.pop();
                }
            }
            Some(StringLexFrame::String(delimiter, width, formatted)) => {
                if width == 1 && matches!(byte, b'\r' | b'\n') {
                    lex_stack.pop();
                } else if formatted && byte == b'{' {
                    if bytes.get(cursor + 1) == Some(&b'{') {
                        cursor += 1;
                    } else {
                        context_incomplete |= !push_lex_frame(
                            &mut lex_stack,
                            StringLexFrame::FormattedExpression(1, 0),
                        );
                    }
                } else if byte == b'\\' {
                    if !formatted || bytes.get(cursor + 1) != Some(&b'{') {
                        cursor += if bytes.get(cursor + 1..cursor + 3) == Some(b"\r\n") {
                            2
                        } else {
                            1
                        };
                    }
                } else if url_quote_closes(bytes, cursor, Some((delimiter, width))) {
                    lex_stack.pop();
                    cursor += width - 1;
                }
            }
            Some(StringLexFrame::FormattedExpression(depth, grouping_depth)) => match byte {
                b'#' => {
                    context_incomplete |=
                        !push_lex_frame(&mut lex_stack, StringLexFrame::Comment(false));
                }
                b'\'' | b'"' => {
                    if let Some((frame, width)) = string_lex_frame(bytes, cursor) {
                        context_incomplete |= !push_lex_frame(&mut lex_stack, frame);
                        cursor += width - 1;
                    }
                }
                b'{' => set_expr(&mut lex_stack, depth + 1, grouping_depth),
                b'(' | b'[' => set_expr(&mut lex_stack, depth, grouping_depth + 1),
                b')' | b']' if grouping_depth > 0 => {
                    set_expr(&mut lex_stack, depth, grouping_depth - 1)
                }
                b':' if depth == 1 && grouping_depth == 0 => {
                    context_incomplete |=
                        !push_lex_frame(&mut lex_stack, StringLexFrame::FormatSpec);
                }
                b'}' if depth == 1 => {
                    lex_stack.pop();
                }
                b'}' => set_expr(&mut lex_stack, depth - 1, grouping_depth),
                _ => {}
            },
            Some(StringLexFrame::FormatSpec) => match byte {
                b'{' if bytes.get(cursor + 1) == Some(&b'{') => cursor += 1,
                b'{' => {
                    context_incomplete |=
                        !push_lex_frame(&mut lex_stack, StringLexFrame::FormattedExpression(1, 0));
                }
                b'}' => {
                    lex_stack.pop();
                    if matches!(
                        lex_stack.last(),
                        Some(StringLexFrame::FormattedExpression(..))
                    ) {
                        lex_stack.pop();
                    }
                }
                _ => {}
            },
            None => {
                if byte == b'#' {
                    lex_stack.push(StringLexFrame::Comment(!starts_comment(bytes, cursor)));
                } else if matches!(byte, b'\'' | b'"') {
                    let quote_run = bytes[cursor..]
                        .iter()
                        .take_while(|candidate| **candidate == byte)
                        .count();
                    if quote_run > 6 {
                        context_incomplete = true;
                        cursor += quote_run - 1;
                    } else if let Some((frame, width)) = string_lex_frame(bytes, cursor) {
                        lex_stack.push(frame);
                        cursor += width - 1;
                    }
                }
            }
        }
        cursor += 1;
    }

    match output {
        Some(mut stripped) => {
            stripped.push_str(&value[copied_through..]);
            (
                Cow::Owned(stripped),
                span_limit_exceeded,
                context_incomplete,
            )
        }
        None => (
            Cow::Borrowed(value),
            span_limit_exceeded,
            context_incomplete,
        ),
    }
}

fn push_lex_frame(stack: &mut Vec<StringLexFrame>, frame: StringLexFrame) -> bool {
    if stack.len() >= MAX_STRING_LEXER_DEPTH {
        false
    } else {
        stack.push(frame);
        true
    }
}

fn set_expr(stack: &mut [StringLexFrame], depth: usize, grouping_depth: usize) {
    *stack.last_mut().unwrap() = StringLexFrame::FormattedExpression(depth, grouping_depth);
}

fn string_lex_frame(bytes: &[u8], quote: usize) -> Option<(StringLexFrame, usize)> {
    let formatted = string_quote_prefix(bytes, quote)?;
    let delimiter = bytes[quote];
    let width = if bytes.get(quote..quote + 3) == Some([delimiter; 3].as_slice()) {
        3
    } else {
        1
    };
    Some((StringLexFrame::String(delimiter, width, formatted), width))
}

fn url_scheme_starts(bytes: &[u8], start: usize) -> bool {
    URL_SCHEMES.iter().any(|scheme| {
        bytes
            .get(start..start + scheme.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(scheme))
    })
}

fn url_end(bytes: &[u8], start: usize, context: Option<StringLexFrame>) -> (usize, bool) {
    let (quote, formatted, comment) = match context {
        Some(StringLexFrame::String(delimiter, width, formatted)) => {
            (Some((delimiter, width)), formatted, None)
        }
        Some(StringLexFrame::FormatSpec) => (Some((b'}', 1)), true, None),
        Some(StringLexFrame::Comment(ambiguous)) => (None, false, Some(ambiguous)),
        _ => (None, false, None),
    };
    let unquoted_or_ambiguous = quote.is_none() && comment != Some(false);
    let mut escaped_single_quote = false;
    let mut known_noncall_padding_until = 0usize;
    let mut end = start;
    while end < bytes.len() {
        if url_quote_closes(bytes, end, quote) {
            break;
        }
        if formatted && bytes[end] == b'\\' && bytes.get(end + 1) == Some(&b'{') {
            break;
        }
        if let Some((delimiter, _)) = quote.filter(|_| bytes[end] == b'\\') {
            escaped_single_quote |= delimiter == b'\'' && bytes.get(end + 1) == Some(&b'\'');
            end = (end
                + if bytes.get(end + 1..end + 3) == Some(b"\r\n") {
                    3
                } else {
                    2
                })
            .min(bytes.len());
            continue;
        }
        let (code_boundary, padding_end) = if end < known_noncall_padding_until {
            (false, known_noncall_padding_until)
        } else {
            url_code_boundary_starts(bytes, end)
        };
        known_noncall_padding_until = padding_end;
        if code_boundary {
            match quote {
                None if unquoted_or_ambiguous => break,
                Some((b'"', _)) if !formatted && bytes[end..].starts_with(b"$(") => break,
                Some((b'\'', _)) if escaped_single_quote => break,
                _ => {}
            }
        }
        match bytes[end] {
            b'{' if formatted && bytes.get(end + 1) != Some(&b'{') => break,
            b'{' if formatted => end += 2,
            b'`' if quote == Some((b'\'', 1)) && escaped_single_quote => break,
            b'`' if matches!(quote, Some((b'"', _))) && !formatted || unquoted_or_ambiguous => {
                break
            }
            b'\'' if unquoted_or_ambiguous => {
                if unquoted_url_apostrophe_ends_url(bytes, end) {
                    break;
                }
                if bytes
                    .get(end + 1)
                    .is_some_and(|next| is_http_url_byte(*next) || *next == b'\'')
                {
                    end += 1;
                } else {
                    break;
                }
            }
            b'\r' | b'\n' if comment.is_some() || matches!(quote, Some((_, 1))) => break,
            _ if quote.is_some() || comment == Some(false) => end += 1,
            _ if is_http_url_byte(bytes[end]) => end += 1,
            _ => break,
        }
    }
    let uncertain = quote.is_some() && end == bytes.len()
        || unquoted_or_ambiguous
            && start > MAX_URL_LOCAL_PREFIX_BYTES
            && bytes[start..end].contains(&b'\'');
    (end, uncertain)
}

fn starts_comment(bytes: &[u8], start: usize) -> bool {
    start == 0 || bytes[start - 1].is_ascii_whitespace() || b";&|()".contains(&bytes[start - 1])
}

fn unquoted_url_apostrophe_ends_url(bytes: &[u8], quote: usize) -> bool {
    bytes
        .get(quote + 1)
        .is_some_and(|byte| !b"/.?#".contains(byte) && URL_CODE_PADDING_BYTES.contains(byte))
        && url_call_expression_starts(bytes, quote + 1).0
}

fn string_quote_prefix(bytes: &[u8], quote: usize) -> Option<bool> {
    if quote_is_escaped(bytes, quote) {
        return None;
    }
    let mut prefix_start = quote;
    while prefix_start > 0
        && quote - prefix_start < 2
        && is_python_word_byte(bytes[prefix_start - 1])
    {
        prefix_start -= 1;
    }
    if prefix_start > 0
        && (!bytes[prefix_start - 1].is_ascii() || is_python_word_byte(bytes[prefix_start - 1]))
    {
        return None;
    }
    let prefix = bytes[prefix_start..quote].to_ascii_lowercase();
    if !matches!(
        prefix.as_slice(),
        b"" | b"r" | b"u" | b"b" | b"f" | b"br" | b"rb" | b"fr" | b"rf"
    ) {
        return None;
    }
    Some(prefix.contains(&b'f'))
}

fn quote_is_escaped(bytes: &[u8], quote: usize) -> bool {
    bytes[..quote]
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

fn url_code_boundary_starts(bytes: &[u8], start: usize) -> (bool, usize) {
    let suffix = &bytes[start..];
    let cursor =
        if suffix.starts_with(b"$(") || suffix.starts_with(b"&&") || suffix.starts_with(b"||") {
            start + 2
        } else if suffix.starts_with(b";") || suffix.starts_with(b"&") || suffix.starts_with(b"|") {
            start + 1
        } else {
            return (false, start);
        };
    url_call_expression_starts(bytes, cursor)
}

fn url_call_expression_starts(bytes: &[u8], mut cursor: usize) -> (bool, usize) {
    let limit = (cursor + MAX_SUFFIX_CALL_LOOKAHEAD_CHARS).min(bytes.len());
    while cursor < limit
        && bytes
            .get(cursor)
            .is_some_and(|byte| URL_CODE_PADDING_BYTES.contains(byte))
    {
        cursor += 1;
    }
    if cursor == limit && limit < bytes.len() {
        return (true, cursor);
    }
    let parse_end = cursor
        .saturating_add(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS + 1)
        .min(bytes.len());
    (
        std::str::from_utf8(&bytes[cursor..parse_end])
            .map(suffix_starts_with_url_call_expression)
            .unwrap_or(true),
        cursor,
    )
}

fn url_quote_closes(bytes: &[u8], start: usize, quote: Option<(u8, usize)>) -> bool {
    quote.is_some_and(|(delimiter, width)| {
        bytes
            .get(start..start + width)
            .is_some_and(|part| part.iter().all(|byte| *byte == delimiter))
    })
}

fn is_http_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&()*+,;=%".contains(&byte)
}

fn any_qualified_call_like(lower: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_call_like(lower, needle))
}

pub(crate) fn is_repeated_single_byte(bytes: &[u8]) -> bool {
    let Some(first) = bytes.first() else {
        return false;
    };
    bytes.iter().all(|byte| byte == first)
}

fn encoded_dangerous_string_matches(value: &str) -> Vec<String> {
    let mut matches = Vec::new();
    let mut candidate_count = 0usize;
    let mut remaining_scan_chars = MAX_BASE64_TOTAL_SCAN_CHARS;
    for token in value
        .split(|ch: char| {
            !ch.is_ascii()
                || (base64_value(ch as u8).is_none() && !is_base64_ignored_whitespace(ch as u8))
        })
        .filter(|token| token.len() >= MIN_BASE64_TEXT_TOKEN_CHARS.saturating_sub(2))
    {
        let compact: Vec<_> = token
            .bytes()
            .filter(|byte| !is_base64_ignored_whitespace(*byte))
            .collect();
        let whole_is_unpadded_base64 = compact.len() % 4 != 1;
        let mut alignment_ambiguous = false;
        let mut whole_candidate_matched = false;
        let mut oversized_match_found = false;
        for offset in base64_candidate_start_offsets(token, &compact) {
            let candidate = &compact[offset..];
            if !has_base64_dangerous_seed(candidate.iter().copied()) {
                continue;
            }
            if candidate_count >= MAX_BASE64_TEXT_CANDIDATES {
                push_unique(&mut matches, BASE64_SCAN_LIMIT_SENTINEL);
                return matches;
            }
            candidate_count += 1;
            let scanned = candidate.len().min(remaining_scan_chars);
            let exhausted = scanned < candidate.len();
            remaining_scan_chars -= scanned;
            let decoded_chars = scanned - usize::from(exhausted && scanned % 4 == 1);
            let decoded_matches = decode_base64(&candidate[..decoded_chars])
                .map(|decoded| decoded_dangerous_string_matches(&decoded))
                .unwrap_or_default();
            let candidate_matched = decoded_matches.iter().any(|label| {
                !matches!(
                    label.as_str(),
                    URL_SCAN_LIMIT_SENTINEL | URL_CONTEXT_INCOMPLETE_SENTINEL
                )
            });
            let oversized_match =
                candidate.len() > MAX_BASE64_TEXT_TOKEN_CHARS && candidate_matched;
            if offset == 0 && candidate_matched {
                whole_candidate_matched = true;
            }
            if offset % 4 != 0
                && whole_is_unpadded_base64
                && !whole_candidate_matched
                && candidate_matched
            {
                push_unique(&mut matches, BASE64_ALIGNMENT_AMBIGUITY_SENTINEL);
                alignment_ambiguous = true;
            } else {
                for label in decoded_matches {
                    push_unique(&mut matches, &label);
                }
                oversized_match_found |= oversized_match;
            }
            if exhausted {
                push_unique(&mut matches, BASE64_WORK_LIMIT_SENTINEL);
                return matches;
            }
        }
        if oversized_match_found && !alignment_ambiguous {
            push_unique(&mut matches, "base64 encoded text exceeds scan limit");
        }
    }
    matches
}
fn decoded_dangerous_string_matches(decoded: &[u8]) -> Vec<String> {
    let decoded_text = String::from_utf8_lossy(decoded);
    let mut matches = Vec::new();
    for pattern in suspicious_string_matches_impl(decoded_text.as_ref(), false) {
        let label = match pattern.as_str() {
            "os.system" | "getattr system" => "base64 os.system",
            "eval(" | "getattr eval" => "base64 eval(",
            "exec(" | "getattr exec" => "base64 exec(",
            "__import__(" => "base64 __import__",
            "subprocess call" | "getattr process call" | "getattr popen" => "base64 subprocess",
            URL_SCAN_LIMIT_SENTINEL | URL_CONTEXT_INCOMPLETE_SENTINEL => pattern.as_str(),
            _ => continue,
        };
        push_unique(&mut matches, label);
    }
    let (plain, _, _) = strip_url_spans(decoded_text.as_ref());
    let lower = plain.to_ascii_lowercase();
    for (name, label) in [
        ("os.system", "base64 os.system"),
        ("eval", "base64 eval("),
        ("exec", "base64 exec("),
        ("__import__", "base64 __import__"),
    ] {
        if contains_dangerous_callable_invocation(&lower, name) {
            push_unique(&mut matches, label);
        }
    }
    if SUBPROCESS_CALL_NEEDLES
        .iter()
        .any(|name| contains_dangerous_callable_invocation(&lower, name))
    {
        push_unique(&mut matches, "base64 subprocess");
    }
    matches
}

fn is_base64_ignored_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn base64_candidate_start_offsets(token: &str, compact: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0];
    let mut seen_alignment = [false; 4];
    let mut compact_offset = 0usize;
    for byte in token.bytes() {
        if base64_value(byte).is_some() {
            compact_offset += 1;
            continue;
        }
        let candidate = &compact[compact_offset..];
        let alignment = compact_offset % 4;
        if compact_offset > 0
            && !seen_alignment[alignment]
            && candidate.len() >= 8
            && candidate.len() % 4 != 1
        {
            offsets.push(compact_offset);
            seen_alignment[alignment] = true;
        }
    }
    offsets
}

fn decode_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut values = [0u8; 4];
    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        values.fill(64);
        for (index, byte) in chunk.iter().enumerate() {
            values[index] = match *byte {
                b'=' => 64,
                byte => base64_value(byte)?,
            };
        }
        decoded.push((values[0] << 2) | (values[1] >> 4));
        if values[2] != 64 {
            decoded.push((values[1] << 4) | (values[2] >> 2));
        }
        if values[3] != 64 {
            decoded.push((values[2] << 6) | values[3]);
        }
    }
    Some(decoded)
}

fn has_base64_dangerous_seed(bytes: impl Iterator<Item = u8>) -> bool {
    let mut quartet = [0u8; 4];
    let mut octet = [0u8; 8];
    let mut seen = 0usize;
    for byte in bytes {
        quartet.rotate_left(1);
        quartet[3] = byte;
        octet.rotate_left(1);
        octet[7] = byte;
        seen += 1;
        if BASE64_DANGEROUS_SEEDS
            .iter()
            .any(|seed| seed.as_bytes() == quartet)
            || seen >= octet.len() && base64_window_has_casefold_seed(&octet)
        {
            return true;
        }
    }
    false
}

fn base64_window_has_casefold_seed(window: &[u8; 8]) -> bool {
    let mut values = [0u8; 8];
    for (value, byte) in values.iter_mut().zip(window) {
        *value = match base64_value(*byte) {
            Some(value) => value,
            None => return false,
        };
    }
    let decoded = [
        (values[0] << 2) | (values[1] >> 4),
        (values[1] << 4) | (values[2] >> 2),
        (values[2] << 6) | values[3],
        (values[4] << 2) | (values[5] >> 4),
        (values[5] << 4) | (values[6] >> 2),
        (values[6] << 6) | values[7],
    ];
    decoded.windows(4).any(|fragment| {
        BASE64_CASEFOLD_DANGEROUS_SEEDS
            .iter()
            .any(|seed| fragment.eq_ignore_ascii_case(seed))
    })
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn push_unique(matches: &mut Vec<String>, label: &str) {
    if !matches.iter().any(|existing| existing == label) {
        matches.push(label.to_string());
    }
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

fn contains_call_like(lower: &str, name: &str) -> bool {
    lower.match_indices(name).any(|(start, _)| {
        let after = start + name.len();
        if start > 0 && is_python_word_byte(lower.as_bytes()[start - 1]) {
            return false;
        }
        suffix_starts_non_prose_call(&lower[..start], &lower[after..])
    })
}

fn contains_dangerous_callable_invocation(lower: &str, name: &str) -> bool {
    lower.match_indices(name).any(|(start, _)| {
        if start > 0 && is_python_word_byte(lower.as_bytes()[start - 1]) {
            return false;
        }
        let after = start + name.len();
        if lower
            .as_bytes()
            .get(after)
            .is_some_and(|byte| is_python_word_byte(*byte))
        {
            return false;
        }
        let rest = &lower[after..];
        let bounded_end = rest
            .char_indices()
            .nth(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS)
            .map_or(rest.len(), |(index, _)| index);
        let bounded_rest = &rest[..bounded_end];
        let prefix = lower[..start].trim_end();
        let direct = trim_call_expression_spacing(bounded_rest).is_some_and(|suffix| {
            suffix.starts_with('(') || suffix.is_empty() && bounded_end < rest.len()
        });
        let assignment = prefix.ends_with('=')
            && !prefix
                .as_bytes()
                .get(prefix.len().saturating_sub(2))
                .is_some_and(|byte| b"!<=>".contains(byte));
        let wrappers = prefix
            .chars()
            .rev()
            .take_while(|ch| ch.is_whitespace() || *ch == '(')
            .filter(|ch| *ch == '(')
            .count();
        let mut suffix = bounded_rest;
        let wrapped = (0..wrappers).any(|_| {
            let Some(after_close) =
                trim_call_expression_spacing(suffix).and_then(|trimmed| trimmed.strip_prefix(')'))
            else {
                return false;
            };
            suffix = after_close;
            trim_call_expression_spacing(suffix)
                .is_some_and(|suffix| suffix.starts_with('(') || suffix_starts_dunder_call(suffix))
        });
        direct || suffix_starts_dunder_call(bounded_rest) || assignment || wrapped
    })
}

fn suffix_starts_dunder_call(value: &str) -> bool {
    trim_call_expression_spacing(value)
        .and_then(|value| value.strip_prefix('.'))
        .and_then(trim_call_expression_spacing)
        .and_then(|value| value.strip_prefix("__call__"))
        .filter(|value| !value.chars().next().is_some_and(is_python_word_char))
        .and_then(trim_call_expression_spacing)
        .is_some_and(|suffix| suffix.starts_with('('))
}

fn prefix_ends_with_code_context(value: &str) -> bool {
    let trimmed = value.trim_end();
    trimmed
        .as_bytes()
        .last()
        .is_some_and(|byte| matches!(*byte, b'=' | b';' | b'(' | b'[' | b'+' | b'-' | b'/' | b'%'))
        || ["if", "and", "or", "is", "in"].iter().any(|keyword| {
            trimmed
                .strip_suffix(keyword)
                .is_some_and(|prefix| prefix.trim_end().ends_with(['\'', '"', ')', ']']))
        })
}

fn suffix_starts_with_url_call_expression(value: &str) -> bool {
    suffix_starts_with_call_expression(value, true)
}

fn suffix_starts_with_call_expression(value: &str, allow_plain_call_spacing: bool) -> bool {
    macro_rules! consume {
        ($step:expr) => {
            match $step {
                BoundedParseStep::Consumed => {}
                BoundedParseStep::NoMatch => return false,
                BoundedParseStep::LimitReached => return true,
            }
        };
    }

    let mut chars = value
        .chars()
        .take(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS + 1)
        .collect::<Vec<_>>();
    let truncated = chars.len() > MAX_SUFFIX_CALL_LOOKAHEAD_CHARS;
    chars.truncate(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS);
    let mut cursor = 0usize;
    // Python identifiers are unbounded, so exhausting this cap is treated as
    // code-like instead of scanning attacker-controlled suffixes without limit.
    consume!(consume_python_identifier(&chars, &mut cursor, truncated));
    let first_identifier = &chars[..cursor];
    if starts_expression_statement(first_identifier) {
        consume!(skip_call_expression_spacing(&chars, &mut cursor, truncated));
        if first_identifier.iter().copied().eq("yield".chars())
            && chars
                .get(cursor..cursor + 4)
                .is_some_and(|candidate| candidate.iter().copied().eq("from".chars()))
            && chars
                .get(cursor + 4)
                .is_none_or(|ch| !is_suffix_identifier_continue(*ch))
        {
            cursor += 4;
            consume!(skip_call_expression_spacing(&chars, &mut cursor, truncated));
        }
        if chars.get(cursor) != Some(&'(') {
            consume!(consume_python_identifier(&chars, &mut cursor, truncated));
        }
    }
    loop {
        let spacing_start = cursor;
        consume!(skip_call_expression_spacing(&chars, &mut cursor, truncated));
        match chars.get(cursor) {
            Some('(') => {
                return allow_plain_call_spacing
                    || cursor == spacing_start
                    || chars[spacing_start..cursor].contains(&'\\');
            }
            Some('.') => {
                cursor += 1;
                consume!(skip_call_expression_spacing(&chars, &mut cursor, truncated));
                consume!(consume_python_identifier(&chars, &mut cursor, truncated));
            }
            Some('[') => {
                consume!(consume_balanced_expression(&chars, &mut cursor, truncated));
            }
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
        match chars.get(*cursor..) {
            Some([ch, ..]) if ch.is_whitespace() && !matches!(ch, '\n' | '\r') => *cursor += 1,
            Some(['\\', '\r', '\n', ..]) => *cursor += 3,
            Some(['\\', '\n' | '\r', ..]) => *cursor += 2,
            Some(['\\']) if truncated => return BoundedParseStep::LimitReached,
            Some(['\\', ..]) => return BoundedParseStep::NoMatch,
            Some([]) if truncated => return BoundedParseStep::LimitReached,
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
    match chars.get(*cursor).copied() {
        Some(first) if first == '_' || first.is_alphabetic() => *cursor += 1,
        Some(_) => return BoundedParseStep::NoMatch,
        None if truncated => return BoundedParseStep::LimitReached,
        None => return BoundedParseStep::NoMatch,
    };
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
                    _ => '{',
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
    lower.match_indices(module).any(|(start, matched)| {
        let before = &lower[..start];
        if before.chars().next_back().is_some_and(is_python_word_char)
            && !has_literal_padding_boundary(before.chars().rev())
        {
            return false;
        }
        let Some(mut rest) = trim_call_expression_spacing(&lower[start + matched.len()..])
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(trim_call_expression_spacing)
            .and_then(|rest| rest.strip_prefix(attr))
        else {
            return false;
        };
        if prefix {
            rest = rest.trim_start_matches(is_python_word_char);
        } else if rest.chars().next().is_some_and(is_python_word_char) {
            return false;
        }
        suffix_starts_non_prose_call(before, rest)
    })
}

fn suffix_starts_non_prose_call(prefix: &str, rest: &str) -> bool {
    let Some(trimmed) = trim_call_expression_spacing(rest) else {
        return false;
    };
    if !trimmed.starts_with('(') {
        return false;
    }
    if prefix_ends_with_code_context(prefix) {
        return true;
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
                    return raw_suffix
                        .chars()
                        .take_while(|ch| ch.is_whitespace())
                        .any(|ch| matches!(ch, '\n' | '\r'))
                        && suffix_starts_with_call_expression(suffix, false)
                        || !suffix
                            .chars()
                            .next()
                            .is_some_and(|next| next.is_ascii_alphabetic())
                        || has_literal_padding_boundary(suffix.chars());
                }
            }
            _ => {}
        }
    }
    true
}

fn trim_call_expression_spacing(mut value: &str) -> Option<&str> {
    loop {
        value = value.trim_start();
        match value.as_bytes() {
            [b'\\', b'\r', b'\n', ..] => value = &value[3..],
            [b'\\', b'\n' | b'\r', ..] => value = &value[2..],
            [b'\\', ..] => return None,
            _ => return Some(value),
        }
    }
}

fn has_literal_padding_boundary(mut chars: impl Iterator<Item = char>) -> bool {
    let Some(padding) = chars.next().filter(|ch| ch.is_ascii_alphanumeric()) else {
        return false;
    };
    let needed = MIN_LITERAL_PADDING_BOUNDARY_CHARS.saturating_sub(1);
    chars.take(needed).filter(|ch| *ch == padding).count() == needed
}

fn contains_magic_method(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
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
            if !is_ascii_word_char(chars[end]) {
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

fn find_getattr_matches(value: &str) -> (u8, bool) {
    const GETATTR_LEN: usize = "getattr".len();

    let bytes = value.as_bytes();
    let mut matches = (0, false);
    for (start, keyword) in bytes.windows(GETATTR_LEN).enumerate() {
        let end = start + GETATTR_LEN;
        if !keyword.eq_ignore_ascii_case(b"getattr")
            || start > 0 && is_python_word_byte(bytes[start - 1])
            || bytes
                .get(end)
                .is_some_and(|byte| is_python_word_byte(*byte))
        {
            continue;
        }

        let Some(arguments) = value[end..]
            .trim_start()
            .strip_prefix('(')
            .map(str::trim_start)
        else {
            continue;
        };
        if arguments
            .get(..GETATTR_LEN)
            .is_some_and(|name| name.eq_ignore_ascii_case("getattr"))
            && arguments[GETATTR_LEN..].trim_start().starts_with('(')
        {
            matches.1 = true;
        }

        let argument_end = arguments
            .find(|ch| !is_python_word_char(ch))
            .unwrap_or(arguments.len());
        if argument_end == 0 {
            continue;
        }
        let Some(target_literal) = arguments[argument_end..]
            .trim_start()
            .strip_prefix(',')
            .map(str::trim_start)
        else {
            continue;
        };
        let Some(quote @ ('\'' | '"')) = target_literal.chars().next() else {
            continue;
        };
        let quoted = &target_literal[1..];
        let Some(target_end) = quoted.find(quote) else {
            continue;
        };
        if quoted[target_end + 1..].trim_start().starts_with(')') {
            matches.0 |= getattr_target_bit(&quoted[..target_end].to_ascii_lowercase());
        }
    }
    matches
}

fn is_ascii_word_char(ch: char) -> bool {
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
                && window[2].is_ascii_hexdigit()
                && window[3].is_ascii_hexdigit()
        })
        .nth(1)
        .is_some()
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
        assert!(
            suspicious_string_matches("x=1; Do not call os.system(command) from loaders")
                .is_empty()
        );
        assert!(
            suspicious_string_matches("Documentation: if os.system(command) is referenced")
                .is_empty()
        );
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
        assert!(suffix_starts_with_call_expression(
            &overlong_identifier,
            false
        ));
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
        for literal in [
            "https://example.invalid/os.system",
            "https://example.invalid/docs/os.system(command)",
            "https://example.invalid/api/subprocess.run(args)",
            "https://example.invalid/path?x=1&handler=os.system(cmd)",
            "https://example.invalid/path?x=1;handler=os.system(cmd)",
            "https://example.invalid/path?x=1,handler=requests.get(url)",
            "https://example.invalid/a'b/os.system(cmd)",
            "s3://bucket/docs/os.system(cmd)",
            "ftp://example.invalid/docs/subprocess.run(args)",
        ] {
            assert!(suspicious_string_matches(literal).is_empty(), "{literal}");
        }
        assert!(suspicious_string_matches("__reduce__ is a pickle protocol hook").is_empty());
    }

    #[test]
    fn suspicious_string_matching_preserves_code_around_url_literals() {
        for (literal, pattern) in [
            (
                "os.system('curl https://example.invalid/p.sh')",
                "os.system",
            ),
            ("u='https://example.invalid/p';os.system('id')", "os.system"),
            (
                "subprocess.run(['curl', 'https://example.invalid/p.sh'])",
                "subprocess call",
            ),
            ("https://a'-os.system('id')", "os.system"),
            ("https://a'+eval(x)", "eval("),
            ("https://a'@os.system('id')", "os.system"),
            ("https://a'[eval(x)]", "eval("),
            ("作者's docs: https://a;eval(x); payload='end'", "eval("),
            ("作者r'https://a;eval(x); payload='end'", "eval("),
            ("x=1# \"\"\"\nu='https://a';eval(x)\ny=2# \"\"\"", "eval("),
        ] {
            assert!(suspicious_string_matches(literal).contains(&pattern.to_string()));
        }
        let bounded_quote_run = format!(
            "{}https://a',os.system('id')",
            "'".repeat(MAX_URL_LOCAL_PREFIX_BYTES + 1)
        );
        assert!(suspicious_string_matches(&bounded_quote_run).contains(&"os.system".to_string()));
    }

    #[test]
    fn url_suffix_call_proof_honors_lookahead_boundaries() {
        let chars = format!("eval{}", " ".repeat(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS - 4))
            .chars()
            .collect::<Vec<_>>();
        let mut cursor = 4;
        assert_eq!(
            skip_call_expression_spacing(&chars, &mut cursor, true),
            BoundedParseStep::LimitReached
        );

        let padded_call = format!(
            "https://example.invalid/a;{}eval(x)",
            " ".repeat(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS - 2)
        );
        assert!(suspicious_string_matches(&padded_call).contains(&"eval(".to_string()));

        let bounded_identifier = format!(
            "https://example.invalid/a;{}(x)",
            "a".repeat(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS)
        );
        let boundary = bounded_identifier.find(';').unwrap();
        assert_eq!(
            url_end(bounded_identifier.as_bytes(), 0, None),
            (boundary, false)
        );
    }

    #[test]
    fn url_boundary_scanning_handles_dense_noncall_padding() {
        let segment = format!("{}a/", ";".repeat(MAX_SUFFIX_CALL_LOOKAHEAD_CHARS - 2));
        let literal = format!(
            "https://example.invalid/{}/os.system(cmd)",
            segment.repeat(1024)
        );

        assert!(suspicious_string_matches(&literal).is_empty());
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

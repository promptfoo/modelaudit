use crate::opcode::{parse_opcode, ParsedOpcode};

const BASE64_LITERAL_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_LITERAL_CHARS: &[u8] = b"0123456789abcdefABCDEF";
const ENCODED_LITERAL_PROBE_CHARS: usize = 64;
pub(crate) const MAX_NESTED_PAYLOAD_PROBES: usize = 64;
const MAX_ENCODED_LITERAL_MID_SCAN_BYTES: usize = 1024 * 1024;

pub(crate) struct NestedProbeOffsets {
    pub(crate) offsets: Vec<usize>,
    pub(crate) limit_exceeded: bool,
}

pub(crate) struct EncodedNestedProbeWindows {
    pub(crate) windows: Vec<String>,
    pub(crate) limit_exceeded: bool,
    pub(crate) limit_exceeded_encoding: Option<&'static str>,
}

pub(crate) fn decode_possible_encoded_pickle(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<(&'static str, Vec<u8>)> {
    let stripped = value.trim();
    if stripped.len() < 16 || !encoded_literal_may_contain_pickle(stripped) {
        return Vec::new();
    }

    let mut decoded_values = Vec::new();
    let max_base64_nested_pickle_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_hex_nested_pickle_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_nested_pickle_chars = max_nested_pickle_bytes * 4;

    for candidate in encoded_literal_candidates(stripped) {
        if base64_prefix_has_pickle_prefix(&candidate) && is_base64_candidate(&candidate) {
            let bounded = take_bytes_str(&candidate, max_base64_nested_pickle_chars);
            let padded = pad_base64(&bounded);
            if let Some(decoded) = decode_base64(&padded) {
                for payload in decoded_pickle_payloads(&decoded, max_nested_pickle_bytes) {
                    decoded_values.push(("base64", payload));
                }
            }
        }

        if hex_prefix_has_pickle_prefix(&candidate) {
            let encoding = hex_encoding_label(&candidate);
            let hex_candidate = strip_escaped_hex_markers(&take_bytes_str(
                &candidate,
                max_escaped_hex_nested_pickle_chars,
            ));
            if hex_candidate.len() >= 16
                && hex_candidate.len() % 2 == 0
                && is_hex_candidate(&hex_candidate)
                && !is_repeated_single_char(&hex_candidate)
            {
                let bounded_hex_candidate =
                    take_bytes_str(&hex_candidate, max_hex_nested_pickle_chars);
                if let Some(decoded) = decode_hex(&bounded_hex_candidate) {
                    for payload in decoded_pickle_payloads(&decoded, max_nested_pickle_bytes) {
                        decoded_values.push((encoding, payload));
                    }
                }
            }
        }
    }

    decoded_values
}

fn decoded_pickle_payloads(decoded: &[u8], max_nested_pickle_bytes: usize) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut search_start = 0usize;
    if let Some(payload_len) = pickle_payload_extent(decoded, max_nested_pickle_bytes) {
        payloads.push(decoded[..payload_len].to_vec());
        search_start = payload_len;
        if search_start >= decoded.len() {
            return payloads;
        }
    }

    let mut seen_spans = Vec::new();
    for offset in nested_pickle_probe_offsets_unbounded(&decoded[search_start..]) {
        let offset = search_start.saturating_add(offset);
        let end = decoded
            .len()
            .min(offset.saturating_add(max_nested_pickle_bytes));
        let probe = &decoded[offset..end];
        let Some(payload_len) = pickle_payload_extent(probe, max_nested_pickle_bytes) else {
            continue;
        };
        let span = (offset, offset.saturating_add(payload_len));
        if seen_spans.contains(&span) {
            continue;
        }
        seen_spans.push(span);
        payloads.push(decoded[span.0..span.1].to_vec());
    }
    payloads
}

pub(crate) fn detect_oversized_encoded_pickle_prefixes(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<(&'static str, usize)> {
    let stripped = value.trim();
    if stripped.len() < 16 || !encoded_literal_may_contain_pickle(stripped) {
        return Vec::new();
    }

    let mut detected = Vec::new();
    let probe_decoded_bytes = (max_nested_pickle_bytes + 1).max(2);

    if base64_prefix_has_pickle_prefix(stripped) && is_base64_candidate(stripped) {
        let max_base64_probe_chars = (probe_decoded_bytes.div_ceil(3) * 4).max(16);
        let bounded = take_bytes_str(stripped, max_base64_probe_chars);
        let padded = pad_base64(&bounded);
        if let Some(decoded) = decode_base64(&padded) {
            if decoded.len() > max_nested_pickle_bytes && has_pickle_prefix(&decoded) {
                detected.push(("base64", estimate_base64_decoded_size(stripped)));
            }
        }
    }

    if hex_prefix_has_pickle_prefix(stripped) {
        let encoding = hex_encoding_label(stripped);
        let max_hex_probe_chars = (probe_decoded_bytes * 4).max(16);
        let mut hex_candidate =
            strip_escaped_hex_markers(&take_bytes_str(stripped, max_hex_probe_chars));
        if hex_candidate.len() % 2 == 1 {
            hex_candidate.pop();
        }
        if hex_candidate.len() >= 16
            && is_hex_candidate(&hex_candidate)
            && !is_repeated_single_char(&hex_candidate)
        {
            if let Some(decoded) = decode_hex(&hex_candidate) {
                if decoded.len() > max_nested_pickle_bytes && has_pickle_prefix(&decoded) {
                    detected.push((encoding, estimate_hex_decoded_size(stripped)));
                }
            }
        }
    }

    detected
}

pub(crate) fn looks_like_pickle_payload(value: &[u8], max_bytes: usize) -> bool {
    pickle_payload_extent(value, max_bytes).is_some()
}

pub(crate) fn pickle_payload_extent(value: &[u8], max_bytes: usize) -> Option<usize> {
    if value.len() < 2 || value.len() > max_bytes || !has_pickle_prefix(value) {
        return None;
    }
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths: Vec<usize> = Vec::new();
    while index < value.len() {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };
        index = parsed.next;
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return None;
        }
        if parsed.name == "STOP" {
            return (stack_depth > 0).then_some(index);
        }
    }
    None
}

pub(crate) fn has_execution_opcode(value: &[u8]) -> bool {
    let mut index = 0usize;
    while index < value.len() {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        match parsed.name {
            "INST" if protocol0_opcode_operands_are_plausible(&parsed, value) => return true,
            "REDUCE" | "NEWOBJ" | "NEWOBJ_EX" | "OBJ" | "BUILD" | "PERSID" | "BINPERSID" => {
                return true;
            }
            _ => {}
        }
        index = parsed.next;
        if parsed.name == "STOP" {
            return false;
        }
    }
    false
}

fn validate_pickle_stack_effect(
    opcode: &ParsedOpcode,
    stack_depth: &mut usize,
    mark_depths: &mut Vec<usize>,
) -> bool {
    match opcode.name {
        "MARK" => {
            mark_depths.push(*stack_depth);
            true
        }
        "POP" => {
            if mark_depths.last().copied() == Some(*stack_depth) {
                mark_depths.pop();
                return true;
            }
            if *stack_depth == 0 {
                return false;
            }
            *stack_depth -= 1;
            true
        }
        "POP_MARK" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth;
                true
            }
            None => false,
        },
        "TUPLE" | "LIST" | "DICT" | "FROZENSET" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth + 1;
                true
            }
            None => false,
        },
        "APPENDS" | "SETITEMS" | "ADDITEMS" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth;
                true
            }
            None => false,
        },
        "TUPLE1" => *stack_depth >= 1,
        "TUPLE2" => {
            if *stack_depth < 2 {
                return false;
            }
            *stack_depth -= 1;
            true
        }
        "TUPLE3" => {
            if *stack_depth < 3 {
                return false;
            }
            *stack_depth -= 2;
            true
        }
        "APPEND" => {
            if *stack_depth < 2 {
                return false;
            }
            *stack_depth -= 1;
            true
        }
        "PERSID" => {
            *stack_depth += 1;
            true
        }
        "BINPERSID" => *stack_depth >= 1,
        "SETITEM" => {
            if *stack_depth < 3 {
                return false;
            }
            *stack_depth -= 2;
            true
        }
        "REDUCE" | "NEWOBJ" | "BUILD" => {
            if *stack_depth < 2 {
                return false;
            }
            *stack_depth -= 1;
            true
        }
        "NEWOBJ_EX" => {
            if *stack_depth < 3 {
                return false;
            }
            *stack_depth -= 2;
            true
        }
        "OBJ" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth + 1;
                true
            }
            None => false,
        },
        "INST" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth + 1;
                true
            }
            None => false,
        },
        "STACK_GLOBAL" => {
            if *stack_depth < 2 {
                return false;
            }
            *stack_depth -= 1;
            true
        }
        "DUP" => {
            if *stack_depth == 0 {
                return false;
            }
            *stack_depth += 1;
            true
        }
        "GET" | "BINGET" | "LONG_BINGET" => {
            *stack_depth += 1;
            true
        }
        "PUT" | "BINPUT" | "LONG_BINPUT" | "MEMOIZE" | "PROTO" | "FRAME" | "STOP" => true,
        "NEXT_BUFFER" => {
            *stack_depth += 1;
            true
        }
        "READONLY_BUFFER" => true,
        _ => {
            *stack_depth += 1;
            true
        }
    }
}

fn hex_encoding_label(value: &str) -> &'static str {
    if contains_escaped_hex_marker(value) {
        "escaped_hex"
    } else {
        "hex"
    }
}

pub(crate) fn has_pickle_prefix(value: &[u8]) -> bool {
    if value.len() < 2 {
        return false;
    }
    if !is_pickle_prefix_start_byte(value[0]) {
        return false;
    }
    has_binary_pickle_prefix(value)
        || protocol0_global_or_inst_prefix_has_complete_lines(value)
        || matches!(value[0], b'(' | b'd' | b'l' | b'I' | b'S' | b'V')
        || pickle_prefix_has_structured_opcodes(value, false)
}

pub(crate) fn has_binary_pickle_prefix(value: &[u8]) -> bool {
    value.len() >= 2 && value[0] == 0x80 && matches!(value[1], 1..=5)
}

pub(crate) fn truncated_pickle_prefix_requires_fail_closed(value: &[u8]) -> bool {
    (has_binary_pickle_prefix(value) && pickle_prefix_has_structured_opcodes(value, true))
        || protocol0_global_or_inst_prefix_has_lines(value)
        || has_execution_opcode(value)
}

pub(crate) fn protocol0_global_or_inst_prefix_has_import_reference_lines(value: &[u8]) -> bool {
    if !matches!(value.first().copied(), Some(b'c' | b'i')) {
        return false;
    }
    let mut fields = value[1..].splitn(3, |byte| *byte == b'\n');
    let Some(module) = fields.next() else {
        return false;
    };
    let Some(name) = fields.next() else {
        return false;
    };
    is_protocol0_import_reference(module) && is_protocol0_import_reference(name)
}

fn pickle_prefix_has_structured_opcodes(value: &[u8], allow_truncated: bool) -> bool {
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    let mut parsed_count = 0usize;
    let mut saw_probe_anchor = false;
    while index < value.len() && parsed_count < 4 {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => {
                if allow_truncated {
                    return parsed_count > 0 && value.get(index).is_some_and(is_pickle_opcode_byte);
                }
                return saw_probe_anchor && parsed_count >= 2;
            }
        };
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        saw_probe_anchor |= is_structured_nested_probe_anchor(parsed.name);
        parsed_count += 1;
        index = parsed.next;
        if parsed.name == "STOP" {
            return stack_depth > 0 && (allow_truncated || saw_probe_anchor);
        }
    }
    parsed_count >= 2 && stack_depth > 0 && (allow_truncated || saw_probe_anchor)
}

fn is_pickle_opcode_byte(byte: &u8) -> bool {
    matches!(
        *byte,
        b'(' | b')'
            | b'.'
            | b'0'
            | b'1'
            | b'2'
            | b'B'
            | b'C'
            | b'F'
            | b'G'
            | b'I'
            | b'J'
            | b'K'
            | b'L'
            | b'M'
            | b'N'
            | b'P'
            | b'Q'
            | b'R'
            | b'S'
            | b'T'
            | b'U'
            | b'V'
            | b'X'
            | b']'
            | b'a'
            | b'b'
            | b'c'
            | b'd'
            | b'e'
            | b'g'
            | b'h'
            | b'i'
            | b'j'
            | b'l'
            | b'o'
            | b'p'
            | b'q'
            | b'r'
            | b's'
            | b't'
            | b'u'
            | b'}'
            | 0x80..=0x98
    )
}

fn is_structured_nested_probe_anchor(name: &str) -> bool {
    matches!(
        name,
        "GLOBAL"
            | "STACK_GLOBAL"
            | "EXT1"
            | "EXT2"
            | "EXT4"
            | "REDUCE"
            | "NEWOBJ"
            | "NEWOBJ_EX"
            | "OBJ"
            | "BUILD"
            | "PERSID"
            | "BINPERSID"
    )
}

fn is_pickle_prefix_start_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')'
            | b'B'
            | b'C'
            | b'F'
            | b'G'
            | b'I'
            | b'J'
            | b'K'
            | b'L'
            | b'M'
            | b'N'
            | b'P'
            | b'S'
            | b'T'
            | b'U'
            | b'V'
            | b'X'
            | b']'
            | b'c'
            | b'd'
            | b'i'
            | b'l'
            | b'}'
            | 0x80..=0x98
    )
}

fn protocol0_global_or_inst_prefix_has_lines(value: &[u8]) -> bool {
    if !matches!(value.first().copied(), Some(b'c' | b'i')) {
        return false;
    }
    let mut fields = value[1..].splitn(3, |byte| *byte == b'\n');
    let Some(module) = fields.next() else {
        return false;
    };
    let Some(name) = fields.next() else {
        return false;
    };
    is_protocol0_global_operand(module) && (name.is_empty() || is_protocol0_global_operand(name))
}

fn protocol0_global_or_inst_prefix_has_complete_lines(value: &[u8]) -> bool {
    if !matches!(value.first().copied(), Some(b'c' | b'i')) {
        return false;
    }
    let mut fields = value[1..].splitn(3, |byte| *byte == b'\n');
    let Some(module) = fields.next() else {
        return false;
    };
    let Some(name) = fields.next() else {
        return false;
    };
    is_protocol0_global_operand(module) && is_protocol0_global_operand(name)
}

fn protocol0_opcode_operands_are_plausible(opcode: &ParsedOpcode, value: &[u8]) -> bool {
    let (module, name) = opcode.arg.global_parts(value);
    is_protocol0_global_operand(module.as_bytes()) && is_protocol0_global_operand(name.as_bytes())
}

fn is_protocol0_global_operand(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .iter()
            .all(|byte| matches!(*byte, b'\t' | b' '..=b'~'))
}

fn is_protocol0_import_reference(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split(|byte| *byte == b'.').all(|component| {
            component
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                && component
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        })
}

pub(crate) fn nested_pickle_probe_offsets(value: &[u8]) -> NestedProbeOffsets {
    nested_pickle_probe_offsets_with_limit(value, Some(MAX_NESTED_PAYLOAD_PROBES))
}

fn nested_pickle_probe_offsets_unbounded(value: &[u8]) -> Vec<usize> {
    nested_pickle_probe_offsets_with_limit(value, None).offsets
}

fn nested_pickle_probe_offsets_with_limit(
    value: &[u8],
    limit: Option<usize>,
) -> NestedProbeOffsets {
    let mut offsets = Vec::new();
    for index in 0..value.len().saturating_sub(1) {
        if has_pickle_prefix(&value[index..]) {
            if limit.is_some_and(|max_offsets| offsets.len() >= max_offsets) {
                return NestedProbeOffsets {
                    offsets,
                    limit_exceeded: true,
                };
            }
            offsets.push(index);
        }
    }
    NestedProbeOffsets {
        offsets,
        limit_exceeded: false,
    }
}

#[cfg(test)]
pub(crate) fn encoded_nested_literal_probe_windows(
    value: &str,
    max_window_chars: usize,
) -> Vec<String> {
    encoded_nested_literal_probe_windows_with_limit(value, max_window_chars).windows
}

pub(crate) fn encoded_nested_literal_probe_windows_with_limit(
    value: &str,
    max_window_chars: usize,
) -> EncodedNestedProbeWindows {
    let mut windows = Vec::new();
    let mut limit_exceeded = false;
    let mut limit_exceeded_encoding = None;
    let prefix_has_base64_pickle = base64_prefix_has_pickle_prefix(value);
    let prefix_has_hex_pickle = !prefix_has_base64_pickle && hex_prefix_has_pickle_prefix(value);
    if prefix_has_base64_pickle || prefix_has_hex_pickle {
        push_unique_window(&mut windows, take_chars(value, max_window_chars));
        if encoded_prefix_consumes_literal(value, prefix_has_base64_pickle, prefix_has_hex_pickle) {
            return EncodedNestedProbeWindows {
                windows,
                limit_exceeded,
                limit_exceeded_encoding,
            };
        }
    }
    let suffix_probe = take_last_chars(value, ENCODED_LITERAL_PROBE_CHARS);
    if encoded_prefix_has_pickle_prefix(&suffix_probe) {
        push_unique_window(&mut windows, take_last_chars(value, max_window_chars));
    }

    let bytes = value.as_bytes();
    let mid_scan_len = bytes.len().min(MAX_ENCODED_LITERAL_MID_SCAN_BYTES);
    for index in 0..mid_scan_len {
        let Some(candidate_encoding) = encoded_pickle_kind_at(bytes, index) else {
            continue;
        };
        if !value.is_char_boundary(index) {
            continue;
        }
        if windows.len() >= MAX_NESTED_PAYLOAD_PROBES {
            limit_exceeded = true;
            limit_exceeded_encoding = Some(candidate_encoding);
            break;
        }
        push_unique_window(
            &mut windows,
            take_bytes_str(&value[index..], max_window_chars),
        );
    }

    EncodedNestedProbeWindows {
        windows,
        limit_exceeded,
        limit_exceeded_encoding,
    }
}

pub(crate) fn encoded_nested_literal_probe_coverage_incomplete(value: &str) -> bool {
    if value.len() <= MAX_ENCODED_LITERAL_MID_SCAN_BYTES {
        return false;
    }

    let stripped = value.trim();
    let prefix_has_base64_pickle = base64_prefix_has_pickle_prefix(stripped);
    let prefix_has_hex_pickle = !prefix_has_base64_pickle && hex_prefix_has_pickle_prefix(stripped);
    !encoded_prefix_consumes_literal(stripped, prefix_has_base64_pickle, prefix_has_hex_pickle)
}

pub(crate) fn encoded_literal_may_contain_pickle(value: &str) -> bool {
    let stripped = value.trim();
    if stripped.len() < 16 {
        return false;
    }
    if encoded_prefix_has_pickle_prefix(stripped) {
        return true;
    }

    let suffix_probe = take_last_chars(stripped, ENCODED_LITERAL_PROBE_CHARS);
    if encoded_prefix_has_pickle_prefix(&suffix_probe) {
        return true;
    }

    let bytes = stripped.as_bytes();
    for index in 0..bytes.len() {
        if starts_encoded_pickle_at(bytes, index) && stripped.is_char_boundary(index) {
            return true;
        }
    }
    false
}

fn starts_encoded_pickle_at(bytes: &[u8], index: usize) -> bool {
    encoded_pickle_kind_at(bytes, index).is_some()
}

fn encoded_pickle_kind_at(bytes: &[u8], index: usize) -> Option<&'static str> {
    let suffix = &bytes[index..];
    let starts_base64_pickle =
        encoded_base64_first_byte(suffix).is_some_and(is_pickle_prefix_start_byte);
    let starts_hex_pickle = encoded_hex_first_byte(suffix).is_some_and(is_pickle_prefix_start_byte);
    if !starts_base64_pickle && !starts_hex_pickle {
        return None;
    }

    let probe_len = suffix.len().min(ENCODED_LITERAL_PROBE_CHARS * 4);
    let Ok(probe) = std::str::from_utf8(&suffix[..probe_len]) else {
        return None;
    };
    if starts_base64_pickle && base64_prefix_has_pickle_prefix(probe) {
        return Some("base64");
    }
    if starts_hex_pickle && hex_prefix_has_pickle_prefix(probe) {
        return Some("hex");
    }
    None
}

fn encoded_prefix_has_pickle_prefix(value: &str) -> bool {
    base64_prefix_has_pickle_prefix(value) || hex_prefix_has_pickle_prefix(value)
}

fn encoded_prefix_consumes_literal(
    value: &str,
    prefix_has_base64_pickle: bool,
    prefix_has_hex_pickle: bool,
) -> bool {
    (prefix_has_base64_pickle
        && take_base64_literal_prefix(value).len() == value.len()
        && is_base64_candidate(value))
        || (prefix_has_hex_pickle && take_hex_literal_prefix(value).len() == value.len())
}

fn encoded_literal_candidates(stripped: &str) -> Vec<String> {
    let mut candidates = vec![stripped.to_string()];
    for candidate in wrapped_encoded_literal_candidates(stripped) {
        if !candidates.iter().any(|existing| existing == &candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn wrapped_encoded_literal_candidates(value: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut current = String::new();
    for line in value.lines() {
        let line_body = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .unwrap_or_else(|| line.trim_start());
        let compact = line_body
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        if compact.is_empty() {
            continue;
        }
        let starts_encoded = encoded_prefix_has_pickle_prefix(&compact);
        let continues_encoded = !current.is_empty()
            && compact.len() >= 8
            && chars_are_in_alphabet(compact.as_bytes(), BASE64_LITERAL_CHARS);
        if starts_encoded || continues_encoded {
            current.push_str(&compact);
            continue;
        }
        push_current_encoded_candidate(&mut candidates, &mut current);
    }
    push_current_encoded_candidate(&mut candidates, &mut current);
    candidates
}

fn push_current_encoded_candidate(candidates: &mut Vec<String>, current: &mut String) {
    if current.len() >= 16 {
        candidates.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

fn push_unique_window(windows: &mut Vec<String>, candidate: String) {
    if candidate.is_empty() || windows.iter().any(|window| window == &candidate) {
        return;
    }
    windows.push(candidate);
}

pub(crate) fn encoded_nested_window_char_limit(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> usize {
    let max_base64_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_plain_hex_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_chars = max_nested_pickle_bytes * 4;
    let probe = encoded_literal_probe(value);
    if contains_escaped_hex_marker(&probe) {
        return 16.max(max_escaped_hex_chars);
    }
    if chars_are_in_alphabet(probe.as_bytes(), HEX_LITERAL_CHARS) {
        return 16.max(max_plain_hex_chars);
    }
    if chars_are_in_alphabet(probe.as_bytes(), BASE64_LITERAL_CHARS) {
        return 16.max(max_base64_chars);
    }
    16.max(max_base64_chars)
        .max(max_plain_hex_chars)
        .max(max_escaped_hex_chars)
}

fn encoded_literal_probe(value: &str) -> String {
    let stripped = value.trim();
    let max_probe_chars = ENCODED_LITERAL_PROBE_CHARS * 2;
    if stripped.len() <= max_probe_chars {
        return stripped.to_string();
    }
    let prefix_bytes = stripped.get(..ENCODED_LITERAL_PROBE_CHARS);
    let suffix_start = stripped.len().saturating_sub(ENCODED_LITERAL_PROBE_CHARS);
    let suffix_bytes = stripped.get(suffix_start..);
    if let (Some(prefix), Some(suffix)) = (prefix_bytes, suffix_bytes) {
        if prefix.is_ascii() && suffix.is_ascii() {
            return format!("{prefix}{suffix}");
        }
    }
    if stripped.chars().count() <= max_probe_chars {
        return stripped.to_string();
    }
    format!(
        "{}{}",
        take_chars(stripped, ENCODED_LITERAL_PROBE_CHARS),
        take_last_chars(stripped, ENCODED_LITERAL_PROBE_CHARS)
    )
}

fn chars_are_in_alphabet(value: &[u8], alphabet: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|byte| alphabet.contains(byte))
}

fn is_base64_candidate(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut padding_seen = false;
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' if !padding_seen => {}
            b'=' => padding_seen = true,
            _ => return false,
        }
    }
    value
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b'=')
        .count()
        <= 2
}

fn is_hex_candidate(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_hex_byte)
}

fn is_hex_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_repeated_single_char(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    chars.all(|char_value| char_value == first)
}

fn pad_base64(value: &str) -> String {
    let mut padded = value.to_string();
    let padding = (4 - padded.len() % 4) % 4;
    for _ in 0..padding {
        padded.push('=');
    }
    padded
}

fn base64_prefix_has_pickle_prefix(value: &str) -> bool {
    let candidate = take_base64_literal_prefix(value);
    let prefix = take_bytes_str(&candidate, candidate.len().min(ENCODED_LITERAL_PROBE_CHARS));
    let padded = pad_base64(&prefix);
    decode_base64(&padded)
        .map(|decoded| has_pickle_prefix(&decoded))
        .unwrap_or(false)
}

fn hex_prefix_has_pickle_prefix(value: &str) -> bool {
    let candidate = take_hex_literal_prefix(value);
    let mut hex_candidate =
        strip_escaped_hex_markers(&take_bytes_str(&candidate, ENCODED_LITERAL_PROBE_CHARS * 4));
    if hex_candidate.len() % 2 == 1 {
        hex_candidate.pop();
    }
    if hex_candidate.len() < 4 || !is_hex_candidate(&hex_candidate) {
        return false;
    }
    decode_hex(&hex_candidate)
        .map(|decoded| has_pickle_prefix(&decoded))
        .unwrap_or(false)
}

fn take_base64_literal_prefix(value: &str) -> String {
    let mut end = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        if BASE64_LITERAL_CHARS.contains(&byte) {
            end = index + 1;
            continue;
        }
        break;
    }
    take_bytes_str(value, end)
}

fn take_hex_literal_prefix(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' && matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
            if bytes.get(index + 2).is_some_and(|byte| is_hex_byte(*byte))
                && bytes.get(index + 3).is_some_and(|byte| is_hex_byte(*byte))
            {
                index += 4;
                continue;
            }
            break;
        }
        if is_hex_byte(bytes[index]) {
            index += 1;
            continue;
        }
        break;
    }
    take_bytes_str(value, index)
}

fn encoded_base64_first_byte(value: &[u8]) -> Option<u8> {
    if value.len() < 2 {
        return None;
    }
    let first = base64_value(value[0])?;
    let second = base64_value(value[1])?;
    Some((first << 2) | (second >> 4))
}

fn encoded_hex_first_byte(value: &[u8]) -> Option<u8> {
    let mut index = 0usize;
    if value.first() == Some(&b'\\') && matches!(value.get(1), Some(b'x' | b'X')) {
        index = 2;
    }
    let high = hex_value(*value.get(index)?)?;
    let low = hex_value(*value.get(index + 1)?)?;
    Some((high << 4) | low)
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    for chunk in bytes.chunks(4) {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                values[index] = 0;
                padding += 1;
            } else {
                values[index] = base64_value(*byte)?;
            }
        }
        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding < 1 {
            output.push((values[2] << 6) | values[3]);
        }
    }
    Some(output)
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

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !is_hex_candidate(value) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for chunk in bytes.chunks(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn estimate_base64_decoded_size(value: &str) -> usize {
    let padding_chars = value.len() - value.trim_end_matches('=').len();
    ((value.len() * 3) / 4).saturating_sub(padding_chars)
}

fn estimate_hex_decoded_size(value: &str) -> usize {
    strip_escaped_hex_markers(value).len() / 2
}

fn strip_escaped_hex_markers(value: &str) -> String {
    value.replace("\\x", "").replace("\\X", "")
}

fn contains_escaped_hex_marker(value: &str) -> bool {
    value.contains("\\x") || value.contains("\\X")
}

fn take_chars(value: &str, count: usize) -> String {
    if value.is_ascii() {
        return value[..value.len().min(count)].to_string();
    }
    value.chars().take(count).collect()
}

fn take_last_chars(value: &str, count: usize) -> String {
    if value.is_ascii() {
        let start = value.len().saturating_sub(count);
        return value[start..].to_string();
    }
    let len = value.chars().count();
    value.chars().skip(len.saturating_sub(count)).collect()
}

fn take_bytes_str(value: &str, count: usize) -> String {
    if count >= value.len() {
        return value.to_string();
    }
    let mut end = count;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAX_NESTED_PICKLE_BYTES: usize = 2 * 1024 * 1024;

    #[test]
    fn encoded_prefix_gates_recognize_pickle_prefixes() {
        assert!(base64_prefix_has_pickle_prefix("gAR9Lg=="));
        assert!(hex_prefix_has_pickle_prefix("80047d2e"));
        assert!(hex_prefix_has_pickle_prefix(r"\x80\x04\x7d\x2e"));
    }

    #[test]
    fn encoded_prefix_gates_recognize_binary_protocols_1_to_5() {
        for encoded in ["gAF9Lg==", "gAJ9Lg==", "gAN9Lg==", "gAR9Lg==", "gAV9Lg=="] {
            assert!(base64_prefix_has_pickle_prefix(encoded));
            let wrapped = format!("prefix-{encoded}-suffix");
            let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
            assert!(windows.iter().any(|window| window.starts_with(encoded)));
        }

        for protocol in 1..=5 {
            let encoded = format!("800{protocol}7d2e");
            assert!(hex_prefix_has_pickle_prefix(&encoded));
            let wrapped = format!("prefix-{encoded}-suffix");
            let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
            assert!(windows.iter().any(|window| window.starts_with(&encoded)));
        }
    }

    #[test]
    fn pickle_prefix_recognizes_protocol1_binary_header() {
        let payload = b"\x80\x01}.";

        assert!(has_binary_pickle_prefix(payload));
        assert!(looks_like_pickle_payload(
            payload,
            TEST_MAX_NESTED_PICKLE_BYTES
        ));
        assert_eq!(
            pickle_payload_extent(payload, TEST_MAX_NESTED_PICKLE_BYTES),
            Some(payload.len())
        );
    }

    #[test]
    fn encoded_prefix_gates_reject_benign_repeated_literals() {
        assert!(!base64_prefix_has_pickle_prefix("AAAAAAAAAAAAAAAA"));
        assert!(!hex_prefix_has_pickle_prefix("4141414141414141"));
        assert!(!encoded_literal_may_contain_pickle(&"A".repeat(1024)));
        assert!(
            decode_possible_encoded_pickle(&"A".repeat(1024), TEST_MAX_NESTED_PICKLE_BYTES)
                .is_empty()
        );
        assert!(detect_oversized_encoded_pickle_prefixes(
            &"A".repeat(1024),
            TEST_MAX_NESTED_PICKLE_BYTES
        )
        .is_empty());
    }

    #[test]
    fn encoded_probe_windows_reject_benign_hexish_large_literals() {
        let value = format!("{}os.system('id'){}", "A".repeat(4096), "B".repeat(4096));

        assert!(encoded_nested_literal_probe_windows(&value, 4096).is_empty());
    }

    #[test]
    fn encoded_probe_windows_keep_embedded_encoded_pickle_candidates() {
        let value = format!("{}gAR9Lg=={}", "A".repeat(128), "B".repeat(128));
        let windows = encoded_nested_literal_probe_windows(&value, 64);

        assert!(encoded_literal_may_contain_pickle(&value));
        assert!(windows.iter().any(|window| window.starts_with("gAR9Lg==")));
    }

    #[test]
    fn encoded_probe_windows_report_limit_after_decoys_exhaust_cap() {
        let mut value = String::new();
        for index in 0..MAX_NESTED_PAYLOAD_PROBES {
            value.push_str(&format!("gAR9Lg==-decoy-{index}|"));
        }
        let hidden_payload = "Y29zCnN5c3RlbQopUi4";
        value.push_str(hidden_payload);
        value.push_str(&"A".repeat(ENCODED_LITERAL_PROBE_CHARS + 1));

        let probed = encoded_nested_literal_probe_windows_with_limit(&value, 64);

        assert!(probed.limit_exceeded);
        assert_eq!(probed.limit_exceeded_encoding, Some("base64"));
        assert_eq!(probed.windows.len(), MAX_NESTED_PAYLOAD_PROBES);
        assert!(!probed
            .windows
            .iter()
            .any(|window| window.starts_with(hidden_payload)));
    }

    #[test]
    fn encoded_probe_windows_skip_mid_scan_for_whole_encoded_literals() {
        for value in ["gAR9Lg==", "80047d2e", r"\x80\x04\x7d\x2e"] {
            let windows = encoded_nested_literal_probe_windows(value, 64);

            assert_eq!(windows, vec![value.to_string()]);
        }
    }

    #[test]
    fn encoded_probe_windows_bound_mid_literal_scan_cost() {
        let within_bound = format!(
            "{}gAR9Lg=={}",
            "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES.saturating_sub(16)),
            "B".repeat(128)
        );
        let within_windows = encoded_nested_literal_probe_windows(&within_bound, 64);
        assert!(within_windows
            .iter()
            .any(|window| window.starts_with("gAR9Lg==")));

        let beyond_bound = format!(
            "{}gAR9Lg=={}",
            "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES + 16),
            "B".repeat(ENCODED_LITERAL_PROBE_CHARS + 1)
        );
        let beyond_windows = encoded_nested_literal_probe_windows(&beyond_bound, 64);
        assert!(!beyond_windows
            .iter()
            .any(|window| window.starts_with("gAR9Lg==")));
        assert!(encoded_nested_literal_probe_coverage_incomplete(
            &beyond_bound
        ));
    }

    #[test]
    fn encoded_probe_coverage_treats_trimmed_whole_literals_as_complete() {
        let whole_literal = format!("gAR9{}\n", "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES));

        assert!(!encoded_nested_literal_probe_coverage_incomplete(
            &whole_literal
        ));
    }

    #[test]
    fn encoded_probe_windows_keep_protocol0_embedded_encoded_pickle_candidates() {
        let value = format!("{}Y29zCnN5c3RlbQopUi4={}", "A".repeat(128), "B".repeat(128));
        let windows = encoded_nested_literal_probe_windows(&value, 64);

        assert!(windows
            .iter()
            .any(|window| window.starts_with("Y29zCnN5c3RlbQopUi4=")));
    }

    #[test]
    fn wrapped_base64_nested_literals_ignore_comment_leaders() {
        let value = "# this is doc\n# Y29zCnN5\n# c3RlbQopUi4=\n# more";
        let decoded = decode_possible_encoded_pickle(value, TEST_MAX_NESTED_PICKLE_BYTES);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, "base64");
        assert_eq!(decoded[0].1, b"cos\nsystem\n)R.");
    }

    #[test]
    fn encoded_nested_literals_keep_later_decoded_payloads() {
        let decoded = decode_possible_encoded_pickle(
            "gAR9LmNvcwpzeXN0ZW0KKVIu",
            TEST_MAX_NESTED_PICKLE_BYTES,
        );

        assert!(decoded
            .iter()
            .any(|(encoding, payload)| *encoding == "base64" && payload == b"\x80\x04}."));
        assert!(decoded
            .iter()
            .any(|(encoding, payload)| *encoding == "base64" && payload == b"cos\nsystem\n)R."));
    }

    #[test]
    fn encoded_probe_windows_keep_protocol0_escaped_hex_pickle_candidates() {
        for encoded in [
            r"\x28\x64\x2e",
            r"\x49\x31\x0a\x2e",
            r"\x53\x27\x78\x27\x0a\x2e",
            r"\x56\x78\x0a\x2e",
            r"\x63\x6f\x73\x0a\x73\x79\x73\x74\x65\x6d\x0a\x2e",
            r"\X63\X6f\X73\X0a\X73\X79\X73\X74\X65\X6d\X0a\X2e",
            r"\x64\x2e",
            r"\x6c\x2e",
            r"\x69\x6f\x73\x0a\x73\x79\x73\x74\x65\x6d\x0a\x2e",
        ] {
            let value = format!("prefix-{encoded}-suffix");
            let windows = encoded_nested_literal_probe_windows(&value, 64);

            assert!(
                windows.iter().any(|window| window.starts_with(encoded)),
                "missing escaped-hex candidate window for {encoded}"
            );
        }
    }

    #[test]
    fn execution_opcode_detection_distinguishes_structural_nested_payloads() {
        assert!(!has_execution_opcode(b"\x80\x04}q\x00."));
        assert!(has_execution_opcode(
            b"\x80\x04\x8c\x08builtins\x94\x8c\x05print\x94\x93\x8c\x02hi\x85R."
        ));
        assert!(has_execution_opcode(b"\x80\x04cos\nsystem\nPfake_id\n."));
        assert!(looks_like_pickle_payload(
            b"\x80\x04cos\nsystem\nPfake_id\n.",
            TEST_MAX_NESTED_PICKLE_BYTES
        ));
        assert!(!has_execution_opcode(
            b"i\x69\xb2\x09\x48\xbe\x7d\x02\x6b\x23\x5f\xe0\xf7\x0a\x8a\x5c\x77"
        ));
    }

    #[test]
    fn truncated_prefix_fail_closed_ignores_structural_protocol0_near_matches() {
        assert!(truncated_pickle_prefix_requires_fail_closed(
            b"\x80\x04]K\x01aK\x02aK\x03a"
        ));
        assert!(truncated_pickle_prefix_requires_fail_closed(
            b"\x80\x04\x95\x1f\x00\x00\x00\x00"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"\x80\x04AAAAAAAA"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"\x80\x04\xff\xff\xff\xff"
        ));
        assert!(truncated_pickle_prefix_requires_fail_closed(
            b"cos\nsystem\nAAAAAAAA"
        ));
        assert!(truncated_pickle_prefix_requires_fail_closed(
            b"ios\nsystem\nAAAAAAAA"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"i\x69\xb2\x09\x48\xbe\x7d\x02\x6b\x23\x5f\xe0\xf7\x0a\x8a\x5c\x77"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"inner\x94\x8c\x04data\x94s.BBBBB"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"S'not-a-full-pickle'\nAAAA"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"Vnot-a-full-pickle\nAAAA"
        ));
        assert!(!truncated_pickle_prefix_requires_fail_closed(
            b"}q\x00BBBBBBBB"
        ));
    }

    #[test]
    fn stack_validation_models_batch_container_mutation_and_protocol5_buffers() {
        assert!(!looks_like_pickle_payload(
            b"\x80\x04](ea.",
            TEST_MAX_NESTED_PICKLE_BYTES
        ));
        assert!(looks_like_pickle_payload(
            b"\x80\x05\x97.",
            TEST_MAX_NESTED_PICKLE_BYTES
        ));
    }

    #[test]
    fn byte_bounded_string_windows_preserve_utf8_boundaries() {
        assert_eq!(take_bytes_str("abc", 2), "ab");
        assert_eq!(take_bytes_str("a\u{2603}b", 2), "a");
        assert_eq!(take_bytes_str("a\u{2603}b", 4), "a\u{2603}");
    }
}

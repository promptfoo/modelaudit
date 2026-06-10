use crate::opcode::{parse_opcode, ParseError, ParsedOpcode};
use crate::options::DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS;
use crate::policy::global_severity;

const BASE64_LITERAL_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_LITERAL_CHARS: &[u8] = b"0123456789abcdefABCDEF";
const ENCODED_LITERAL_PROBE_CHARS: usize = 64;
const PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES: usize = 256;
const LONG_PROTOCOL0_LINE_PROBE_BYTES: usize = PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES + 1;
const LONG_PROTOCOL0_LINE_PROBE_CHARS: usize = LONG_PROTOCOL0_LINE_PROBE_BYTES.div_ceil(3) * 4;
const MAX_CONTEXTUAL_PROTOCOL0_LINE_STEPS: usize = 20_000;
const NESTED_STRUCTURAL_PROBE_BYTES: usize = 1024;
pub(crate) const MAX_NESTED_PAYLOAD_PROBES: usize = 64;
const MAX_ENCODED_LITERAL_MID_SCAN_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES: usize =
    MAX_ENCODED_LITERAL_MID_SCAN_BYTES + ENCODED_LITERAL_PROBE_CHARS;

pub(crate) struct NestedProbeOffsets {
    pub(crate) offsets: Vec<usize>,
    pub(crate) limit_exceeded: bool,
}

pub(crate) struct EncodedNestedProbeWindows {
    pub(crate) windows: Vec<EncodedNestedProbeWindow>,
    pub(crate) limit_exceeded: bool,
    pub(crate) limit_exceeded_encoding: Option<&'static str>,
}

pub(crate) struct EncodedNestedProbeWindow {
    pub(crate) value: String,
    pub(crate) synthetic_prefix_bytes: usize,
}

pub(crate) struct DecodedNestedPayload {
    pub(crate) encoding: &'static str,
    pub(crate) payload: Vec<u8>,
    pub(crate) analysis_incomplete: bool,
}

pub(crate) struct PicklePayloadExtentError {
    error: ParseError,
    structured_pickle_evidence: bool,
}

impl PicklePayloadExtentError {
    pub(crate) fn is_structured_protocol0_line_operand_limit(&self) -> bool {
        self.structured_pickle_evidence && self.error.is_protocol0_line_operand_limit()
    }
}

pub(crate) fn decode_possible_encoded_pickle(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<DecodedNestedPayload> {
    let stripped = value.trim();
    if stripped.len() < 16 || !encoded_literal_may_contain_pickle(stripped) {
        return Vec::new();
    }

    let mut decoded_values: Vec<DecodedNestedPayload> = Vec::new();
    let decoded_probe_bytes = max_nested_pickle_bytes.max(DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS);
    let max_base64_nested_pickle_chars = decoded_probe_bytes.div_ceil(3).saturating_mul(4);
    let max_hex_nested_pickle_chars = decoded_probe_bytes.saturating_mul(2);
    let max_escaped_hex_nested_pickle_chars = decoded_probe_bytes.saturating_mul(4);

    for candidate in encoded_literal_candidates(stripped) {
        if base64_structural_prefix_has_pickle_prefix(&candidate) {
            for bounded_base64 in base64_literal_candidates(
                &candidate,
                max_base64_nested_pickle_chars,
                candidate.len(),
            ) {
                if let Some(decoded) = canonical_base64_candidate(&bounded_base64)
                    .as_deref()
                    .and_then(decode_base64)
                {
                    for (payload, analysis_incomplete) in
                        decoded_pickle_payloads(&decoded, max_nested_pickle_bytes)
                    {
                        if decoded_values.iter().any(|existing| {
                            existing.encoding == "base64"
                                && existing.payload == payload
                                && existing.analysis_incomplete == analysis_incomplete
                        }) {
                            continue;
                        }
                        decoded_values.push(DecodedNestedPayload {
                            encoding: "base64",
                            payload,
                            analysis_incomplete,
                        });
                    }
                }
            }
        }

        if hex_structural_prefix_has_pickle_prefix(&candidate) {
            let hex_token = take_hex_literal_prefix(&candidate, candidate.len());
            let encoding = hex_encoding_label(hex_token);
            let bounded_hex =
                take_hex_literal_prefix(hex_token, max_escaped_hex_nested_pickle_chars);
            let mut hex_candidate = strip_escaped_hex_markers(bounded_hex);
            hex_candidate.truncate(hex_candidate.len() - (hex_candidate.len() % 2));
            if hex_candidate.len() >= 16
                && is_hex_candidate(&hex_candidate)
                && !is_repeated_single_char(&hex_candidate)
            {
                let bounded_hex_candidate =
                    take_bytes_str(&hex_candidate, max_hex_nested_pickle_chars);
                if let Some(decoded) = decode_hex(&bounded_hex_candidate) {
                    for (payload, analysis_incomplete) in
                        decoded_pickle_payloads(&decoded, max_nested_pickle_bytes)
                    {
                        decoded_values.push(DecodedNestedPayload {
                            encoding,
                            payload,
                            analysis_incomplete,
                        });
                    }
                }
            }
        }
    }

    decoded_values
}

fn decoded_pickle_payloads(decoded: &[u8], max_nested_pickle_bytes: usize) -> Vec<(Vec<u8>, bool)> {
    let mut payloads = Vec::new();
    let mut search_start = 0usize;
    match pickle_payload_extent_result(decoded, max_nested_pickle_bytes) {
        Ok(Some(payload_len)) => {
            payloads.push((decoded[..payload_len].to_vec(), false));
            search_start = payload_len;
            if search_start >= decoded.len() {
                return payloads;
            }
        }
        Err(error) if error.is_structured_protocol0_line_operand_limit() => {
            payloads.push((decoded.to_vec(), true));
            return payloads;
        }
        Ok(None) | Err(_) => {}
    }

    let remaining = &decoded[search_start..];
    let remaining_is_complete = pickle_payload_extent_result(remaining, max_nested_pickle_bytes)
        .is_ok_and(|extent| extent.is_some());
    if remaining.len() <= max_nested_pickle_bytes
        && !remaining_is_complete
        && has_high_confidence_truncated_execution_prefix(remaining)
    {
        let payload_len = remaining.len().min(max_nested_pickle_bytes);
        payloads.push((remaining[..payload_len].to_vec(), true));
        return payloads;
    }

    let mut seen_spans = Vec::new();
    for offset in nested_pickle_probe_offsets_unbounded(&decoded[search_start..]) {
        let offset = search_start.saturating_add(offset);
        let end = decoded
            .len()
            .min(offset.saturating_add(max_nested_pickle_bytes));
        let probe = &decoded[offset..end];
        let (payload_len, analysis_incomplete) =
            match pickle_payload_extent_result(probe, max_nested_pickle_bytes) {
                Ok(Some(payload_len)) => (payload_len, false),
                Err(error) if error.is_structured_protocol0_line_operand_limit() => {
                    (probe.len(), true)
                }
                Ok(None) | Err(_)
                    if (has_binary_pickle_prefix(probe)
                        || protocol0_global_or_inst_prefix_has_import_reference_lines(probe))
                        && has_high_confidence_truncated_execution_prefix(probe) =>
                {
                    (probe.len(), true)
                }
                Ok(None) | Err(_) => continue,
            };
        let span = (offset, offset.saturating_add(payload_len));
        if seen_spans.contains(&span) {
            continue;
        }
        seen_spans.push(span);
        payloads.push((decoded[span.0..span.1].to_vec(), analysis_incomplete));
        if analysis_incomplete {
            break;
        }
    }
    payloads
}

fn has_high_confidence_truncated_execution_prefix(value: &[u8]) -> bool {
    let first_is_persid =
        parse_opcode(value, 0, value.len()).is_ok_and(|opcode| opcode.name == "PERSID");
    first_is_persid
        || ((has_binary_pickle_prefix(value)
            || protocol0_global_or_inst_prefix_has_import_reference_lines(value))
            && has_structurally_valid_execution_prefix(value))
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
    let probe_decoded_bytes = max_nested_pickle_bytes
        .saturating_add(1)
        .max(DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS);

    if base64_structural_prefix_has_pickle_prefix(stripped) {
        let max_base64_probe_chars = probe_decoded_bytes.div_ceil(3).saturating_mul(4).max(16);
        let oversized_prefix_found =
            base64_literal_candidates(stripped, max_base64_probe_chars, stripped.len())
                .into_iter()
                .any(|bounded| {
                    canonical_base64_candidate(&bounded)
                        .as_deref()
                        .and_then(decode_base64)
                        .is_some_and(|decoded| {
                            oversized_decoded_pickle_prefix_requires_fail_closed(
                                &decoded,
                                max_nested_pickle_bytes,
                            )
                        })
                });
        if oversized_prefix_found {
            let strict_token = take_base64_literal_prefix(stripped, stripped.len());
            let payload_size = estimate_base64_decoded_size(strict_token)
                .max(estimate_lenient_base64_decoded_size(stripped));
            if payload_size > max_nested_pickle_bytes {
                detected.push(("base64", payload_size));
            }
        }
    }

    if hex_structural_prefix_has_pickle_prefix(stripped) {
        let hex_token = take_hex_literal_prefix(stripped, stripped.len());
        let encoding = hex_encoding_label(hex_token);
        let max_hex_probe_chars = probe_decoded_bytes
            .saturating_mul(4)
            .max(ENCODED_LITERAL_PROBE_CHARS);
        let bounded_hex = take_hex_literal_prefix(hex_token, max_hex_probe_chars);
        let mut hex_candidate = strip_escaped_hex_markers(bounded_hex);
        hex_candidate.truncate(hex_candidate.len() - (hex_candidate.len() % 2));
        if hex_candidate.len() >= 16
            && is_hex_candidate(&hex_candidate)
            && !is_repeated_single_char(&hex_candidate)
        {
            if let Some(decoded) = decode_hex(&hex_candidate) {
                if oversized_decoded_pickle_prefix_requires_fail_closed(
                    &decoded,
                    max_nested_pickle_bytes,
                ) {
                    detected.push((encoding, estimate_hex_decoded_size(hex_token)));
                }
            }
        }
    }

    detected
}

fn oversized_decoded_pickle_prefix_requires_fail_closed(
    decoded: &[u8],
    max_nested_pickle_bytes: usize,
) -> bool {
    nested_pickle_probe_offsets_unbounded(decoded)
        .into_iter()
        .any(|offset| {
            let candidate = &decoded[offset..];
            if candidate.len() <= max_nested_pickle_bytes {
                return false;
            }
            bounded_truncated_pickle_prefix_requires_fail_closed(candidate, max_nested_pickle_bytes)
        })
}

pub(crate) fn looks_like_pickle_payload(value: &[u8], max_bytes: usize) -> bool {
    pickle_payload_extent(value, max_bytes).is_some()
}

pub(crate) fn pickle_payload_extent(value: &[u8], max_bytes: usize) -> Option<usize> {
    pickle_payload_extent_result(value, max_bytes)
        .ok()
        .flatten()
}

pub(crate) fn pickle_payload_extent_result(
    value: &[u8],
    max_bytes: usize,
) -> Result<Option<usize>, PicklePayloadExtentError> {
    if value.len() < 2 || value.len() > max_bytes || !has_pickle_prefix(value) {
        return Ok(None);
    }
    confirmed_pickle_payload_extent_result(value, max_bytes)
}

fn confirmed_pickle_payload_extent_result(
    value: &[u8],
    max_bytes: usize,
) -> Result<Option<usize>, PicklePayloadExtentError> {
    if value.len() < 2 || value.len() > max_bytes {
        return Ok(None);
    }
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths: Vec<usize> = Vec::new();
    let mut structured_pickle_evidence = has_binary_pickle_prefix(value);
    while index < value.len() {
        let parsed =
            parse_opcode(value, index, value.len()).map_err(|error| PicklePayloadExtentError {
                error,
                structured_pickle_evidence,
            })?;
        index = parsed.next;
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return Ok(None);
        }
        structured_pickle_evidence |= is_structured_nested_probe_anchor(parsed.name);
        if parsed.name == "STOP" {
            return Ok((stack_depth > 0).then_some(index));
        }
    }
    Ok(None)
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

fn has_structurally_valid_execution_prefix(value: &[u8]) -> bool {
    if !has_pickle_prefix(value) {
        return false;
    }

    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    while index < value.len() {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        if matches!(parsed.name, "GLOBAL" | "INST")
            && !protocol0_opcode_operands_are_import_references(&parsed, value)
        {
            return false;
        }
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        if matches!(
            parsed.name,
            "INST" | "REDUCE" | "NEWOBJ" | "NEWOBJ_EX" | "OBJ" | "BUILD" | "PERSID" | "BINPERSID"
        ) {
            return true;
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
        || matches!(value[0], b'(' | b'd' | b'l')
        || is_protocol0_long_line_probe_opcode(value[0])
        || pickle_prefix_has_structured_opcodes(value, false)
}

fn has_nested_probe_prefix(value: &[u8]) -> bool {
    match value.first() {
        Some(b'c') => {
            return protocol0_global_prefix_is_nested_probe(value);
        }
        Some(b'd' | b'i' | b'l') => return false,
        _ => {}
    }
    has_pickle_prefix(value)
        && (!value
            .first()
            .is_some_and(|byte| is_protocol0_long_line_probe_opcode(*byte))
            || protocol0_line_prefix_has_bounded_operand(value))
}

fn protocol0_global_prefix_is_nested_probe(value: &[u8]) -> bool {
    let probe_len = value.len().min(NESTED_STRUCTURAL_PROBE_BYTES);
    let probe = &value[..probe_len];
    let Ok(global) = parse_opcode(probe, 0, probe.len()) else {
        return false;
    };
    if global.name != "GLOBAL" || !protocol0_opcode_operands_are_plausible(&global, probe) {
        return false;
    }
    let (module, name) = global.arg.global_parts(probe);
    if !is_protocol0_import_reference(module.as_bytes())
        || !is_protocol0_import_reference(name.as_bytes())
    {
        return false;
    }
    if global_severity(&module, &name).is_some() {
        return true;
    }
    if value.len() <= DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS
        && pickle_payload_extent_result(value, value.len()).is_ok_and(|extent| extent.is_some())
    {
        return true;
    }
    pickle_prefix_has_structured_opcodes_with_minimum_anchors(probe, false, 2)
}

fn protocol0_line_prefix_has_bounded_operand(value: &[u8]) -> bool {
    value
        .first()
        .is_some_and(|byte| is_protocol0_long_line_probe_opcode(*byte))
        && value
            .iter()
            .skip(1)
            .take(PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES)
            .any(|byte| *byte == b'\n')
}

fn is_protocol0_long_line_probe_opcode(byte: u8) -> bool {
    matches!(byte, b'F' | b'I' | b'L' | b'P' | b'S' | b'V' | b'g' | b'p')
}

pub(crate) fn has_binary_pickle_prefix(value: &[u8]) -> bool {
    value.len() >= 2 && value[0] == 0x80 && matches!(value[1], 0..=5)
}

pub(crate) fn truncated_pickle_prefix_requires_fail_closed(value: &[u8]) -> bool {
    is_minimum_binary_pickle_prefix(value)
        || (has_binary_pickle_prefix(value) && pickle_prefix_has_structured_opcodes(value, true))
        || protocol0_global_or_inst_prefix_has_lines(value)
        || has_execution_opcode(value)
}

pub(crate) fn bounded_truncated_pickle_prefix_requires_fail_closed(
    value: &[u8],
    max_nested_pickle_bytes: usize,
) -> bool {
    let probe_len = value
        .len()
        .min(max_nested_pickle_bytes.max(NESTED_STRUCTURAL_PROBE_BYTES));
    truncated_pickle_prefix_requires_fail_closed(&value[..probe_len])
}

fn is_minimum_binary_pickle_prefix(value: &[u8]) -> bool {
    value.len() == 2 && has_binary_pickle_prefix(value)
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
    pickle_prefix_has_structured_opcodes_with_minimum_anchors(value, allow_truncated, 1)
}

fn pickle_prefix_has_structured_opcodes_with_minimum_anchors(
    value: &[u8],
    allow_truncated: bool,
    minimum_incomplete_anchors: usize,
) -> bool {
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    let mut parsed_count = 0usize;
    let mut probe_anchor_count = 0usize;
    while index < value.len() && parsed_count < 4 {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => {
                if allow_truncated {
                    return parsed_count > 0 && value.get(index).is_some_and(is_pickle_opcode_byte);
                }
                return probe_anchor_count >= minimum_incomplete_anchors && parsed_count >= 2;
            }
        };
        if matches!(parsed.name, "GLOBAL" | "INST")
            && !protocol0_opcode_operands_are_import_references(&parsed, value)
        {
            return false;
        }
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        probe_anchor_count += usize::from(is_structured_nested_probe_anchor(parsed.name));
        parsed_count += 1;
        index = parsed.next;
        if parsed.name == "STOP" {
            return stack_depth > 0 && (allow_truncated || probe_anchor_count > 0);
        }
    }
    parsed_count >= 2
        && stack_depth > 0
        && (allow_truncated || probe_anchor_count >= minimum_incomplete_anchors)
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
            | "INST"
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
        return is_protocol0_global_operand(module);
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

fn protocol0_opcode_operands_are_import_references(opcode: &ParsedOpcode, value: &[u8]) -> bool {
    let (module, name) = opcode.arg.global_parts(value);
    is_protocol0_import_reference(module.as_bytes())
        && is_protocol0_import_reference(name.as_bytes())
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
        if has_nested_probe_prefix(&value[index..]) {
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
    encoded_nested_literal_probe_windows_with_limit(value, max_window_chars)
        .windows
        .into_iter()
        .map(|window| window.value)
        .collect()
}

pub(crate) fn encoded_nested_literal_probe_windows_with_limit(
    value: &str,
    max_window_chars: usize,
) -> EncodedNestedProbeWindows {
    let value = value.trim();
    let mut windows = Vec::new();
    let mut limit_exceeded = false;
    let mut limit_exceeded_encoding = None;
    let prefix_has_base64_pickle = base64_prefix_has_pickle_prefix(value);
    let prefix_has_hex_pickle = !prefix_has_base64_pickle && hex_prefix_has_pickle_prefix(value);
    let mut prefix_consumes_literal = false;
    if prefix_has_base64_pickle || prefix_has_hex_pickle {
        push_unique_window(&mut windows, take_chars(value, max_window_chars));
        prefix_consumes_literal = encoded_probe_prefix_consumes_literal(
            value,
            prefix_has_base64_pickle,
            prefix_has_hex_pickle,
            MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES,
            max_window_chars,
        );
    }
    if !prefix_consumes_literal {
        let suffix_probe = take_last_chars(value, ENCODED_LITERAL_PROBE_CHARS);
        if encoded_prefix_has_pickle_prefix(&suffix_probe) {
            push_unique_window(&mut windows, take_last_chars(value, max_window_chars));
        }
    }
    if prefix_consumes_literal {
        return EncodedNestedProbeWindows {
            windows,
            limit_exceeded,
            limit_exceeded_encoding,
        };
    }

    let prefix_is_complete_long_protocol0 = encoded_base64_first_byte(value.as_bytes())
        .is_some_and(is_protocol0_long_line_probe_opcode)
        && base64_protocol0_line_has_terminator(value, 0, 0)
        && base64_prefix_has_complete_protocol0_line(value, value.len());
    let confirmed_spans = if value
        .as_bytes()
        .first()
        .is_none_or(|byte| base64_value(*byte).is_none())
        || prefix_has_base64_pickle
        || prefix_is_complete_long_protocol0
    {
        confirmed_base64_pickle_spans(value.as_bytes(), max_window_chars)
    } else {
        Vec::new()
    };
    for (start, end) in confirmed_spans.iter().copied() {
        push_unique_window(&mut windows, value[start..end].to_string());
    }
    if confirmed_spans.len() >= MAX_NESTED_PAYLOAD_PROBES {
        limit_exceeded = true;
        limit_exceeded_encoding = Some("base64");
    }

    let leading_base64_prefix = take_base64_literal_prefix(value, value.len());
    let leading_prefix_is_exact_pickle = (prefix_has_base64_pickle
        || prefix_is_complete_long_protocol0)
        && decode_possible_encoded_pickle(leading_base64_prefix, max_window_chars)
            .iter()
            .any(|decoded| {
                base64_prefix_len_for_payload(leading_base64_prefix, &decoded.payload)
                    == Some(leading_base64_prefix.len())
            });
    let padded_prefix_end =
        if leading_base64_prefix.ends_with('=') && leading_prefix_is_exact_pickle {
            leading_base64_prefix.len()
        } else {
            0
        };
    let long_line_windows =
        embedded_long_protocol0_base64_probe_windows(&value[padded_prefix_end..], max_window_chars);
    for candidate in long_line_windows.windows.into_iter().rev() {
        if windows.iter().any(|window| window.value == candidate.value) {
            continue;
        }
        if windows.len() >= MAX_NESTED_PAYLOAD_PROBES {
            limit_exceeded = true;
            limit_exceeded_encoding = Some("base64");
            break;
        }
        windows.insert(0, candidate);
    }
    if long_line_windows.limit_exceeded {
        limit_exceeded = true;
        limit_exceeded_encoding = Some("base64");
    }
    let mid_scan_len = value.len().min(MAX_ENCODED_LITERAL_MID_SCAN_BYTES);
    for index in padded_prefix_end..mid_scan_len {
        if !value.is_char_boundary(index) {
            continue;
        }
        if confirmed_spans.len() < MAX_NESTED_PAYLOAD_PROBES
            && confirmed_spans
                .iter()
                .any(|(start, end)| *start <= index && index < *end)
        {
            continue;
        }
        if let Some(encoding) = encoded_pickle_prefix_probe_limit_kind_at(value, index) {
            let suffix = &value[index..];
            let normalized = if encoding == "base64" {
                normalize_base64_literal(suffix, max_window_chars, suffix.len())
            } else {
                normalize_hex_literal(suffix, max_window_chars, suffix.len())
            };
            push_unique_window(&mut windows, normalized);
            break;
        }
        let Some(candidate_encoding) = encoded_pickle_kind_at(value, index) else {
            continue;
        };
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

pub(crate) fn encoded_nested_literal_probe_coverage_incomplete(
    value: &str,
    max_window_chars: usize,
    max_nested_pickle_bytes: usize,
) -> bool {
    if value.len() <= MAX_ENCODED_LITERAL_MID_SCAN_BYTES {
        return false;
    }

    let stripped = value.trim();
    let prefix_has_base64_pickle =
        base64_prefix_has_pickle_prefix_with_limit(stripped, stripped.len());
    let prefix_has_hex_pickle = !prefix_has_base64_pickle
        && hex_prefix_has_pickle_prefix_with_limit(stripped, stripped.len());
    !encoded_probe_prefix_consumes_literal(
        stripped,
        prefix_has_base64_pickle,
        prefix_has_hex_pickle,
        max_nested_pickle_bytes.div_ceil(3) * 4,
        max_window_chars,
    )
}

pub(crate) fn encoded_literal_may_contain_pickle(value: &str) -> bool {
    let stripped = value.trim();
    if stripped.len() < 16 {
        return false;
    }
    if encoded_structural_prefix_has_pickle_prefix(stripped) {
        return true;
    }
    let leading_base64_token = take_base64_literal_prefix(stripped, stripped.len());
    if leading_base64_token.len() == stripped.len()
        && encoded_base64_first_byte(stripped.as_bytes())
            .is_some_and(is_protocol0_long_line_probe_opcode)
        && !base64_protocol0_line_has_terminator(stripped, 0, 0)
    {
        return false;
    }

    let suffix_probe = take_last_chars(stripped, ENCODED_LITERAL_PROBE_CHARS);
    if encoded_prefix_has_pickle_prefix(&suffix_probe) {
        return true;
    }
    let long_line_windows =
        embedded_long_protocol0_base64_probe_windows(stripped, LONG_PROTOCOL0_LINE_PROBE_CHARS);
    if !long_line_windows.windows.is_empty() || long_line_windows.limit_exceeded {
        return true;
    }

    for index in 0..stripped.len() {
        if stripped.is_char_boundary(index)
            && (starts_encoded_pickle_at(stripped, index)
                || encoded_pickle_prefix_probe_limit_kind_at(stripped, index).is_some())
        {
            return true;
        }
    }
    false
}

fn embedded_long_protocol0_base64_probe_windows(
    value: &str,
    max_window_chars: usize,
) -> EncodedNestedProbeWindows {
    let tail_compact_chars = max_window_chars
        .max(LONG_PROTOCOL0_LINE_PROBE_CHARS)
        .saturating_add(ENCODED_LITERAL_PROBE_CHARS);
    let max_compact_chars = MAX_ENCODED_LITERAL_MID_SCAN_BYTES.saturating_add(tail_compact_chars);
    let mut compact = String::with_capacity(value.len().min(max_compact_chars));
    let mut raw_positions = Vec::with_capacity(value.len().min(max_compact_chars));
    let mut compact_chars_at_mid_scan = None;
    for (raw_index, byte) in value.bytes().enumerate() {
        if raw_index >= MAX_ENCODED_LITERAL_MID_SCAN_BYTES {
            let compact_chars_at_mid_scan = *compact_chars_at_mid_scan.get_or_insert(compact.len());
            if compact.len().saturating_sub(compact_chars_at_mid_scan) >= tail_compact_chars {
                break;
            }
        }
        if base64_value(byte).is_some() {
            compact.push(char::from(byte));
            raw_positions.push(raw_index);
        }
    }

    let mut windows = Vec::new();
    for alignment in 0..4usize {
        if compact.len().saturating_sub(alignment) < LONG_PROTOCOL0_LINE_PROBE_CHARS {
            continue;
        }
        let mut probe_end = compact.len();
        if (probe_end - alignment) % 4 == 1 {
            probe_end -= 1;
        }
        let Some(decoded) = canonical_base64_candidate(&compact[alignment..probe_end])
            .as_deref()
            .and_then(decode_base64)
        else {
            continue;
        };

        let contextual_starts = decoded
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| is_pickle_prefix_start_byte(*byte).then_some(index))
            .take(MAX_NESTED_PAYLOAD_PROBES + 1)
            .collect::<Vec<_>>();
        let mut contextual_steps = 0usize;
        let mut decoded_index = 0usize;
        while decoded_index.saturating_add(LONG_PROTOCOL0_LINE_PROBE_BYTES) <= decoded.len() {
            if !decoded
                .get(decoded_index)
                .is_some_and(|byte| is_protocol0_long_line_probe_opcode(*byte))
            {
                decoded_index += 1;
                continue;
            }

            let encoded_start = alignment + (decoded_index / 3) * 4;
            let decoded_prefix_skip = decoded_index % 3;
            let Some(line_end_offset) = decoded[decoded_index + 1..]
                .iter()
                .position(|byte| *byte == b'\n')
            else {
                let Some(raw_start) = raw_positions.get(encoded_start).copied() else {
                    break;
                };
                if base64_protocol0_line_has_terminator(value, raw_start, decoded_prefix_skip) {
                    return EncodedNestedProbeWindows {
                        windows,
                        limit_exceeded: true,
                        limit_exceeded_encoding: Some("base64"),
                    };
                }
                // An unterminated line consumes the remainder of the decoded value, so
                // later bytes cannot be interpreted as pickle opcodes.
                break;
            };
            let long_operand_prefix_bytes = LONG_PROTOCOL0_LINE_PROBE_BYTES - 1;
            if line_end_offset < long_operand_prefix_bytes {
                decoded_index = decoded_index
                    .saturating_add(line_end_offset)
                    .saturating_add(2);
                continue;
            }
            let newline_offset = line_end_offset - long_operand_prefix_bytes;

            let candidate_start = if matches!(decoded[decoded_index], b'g' | b'p') {
                match contextual_protocol0_line_candidate_start(
                    &decoded,
                    decoded_index,
                    &contextual_starts,
                    &mut contextual_steps,
                ) {
                    Ok(Some(start)) => start,
                    Ok(None) => {
                        decoded_index += 1;
                        continue;
                    }
                    Err(()) => {
                        return EncodedNestedProbeWindows {
                            windows,
                            limit_exceeded: true,
                            limit_exceeded_encoding: Some("base64"),
                        };
                    }
                }
            } else {
                decoded_index
            };
            let candidate_encoded_start = alignment + (candidate_start / 3) * 4;
            let starts_within_mid_scan = raw_positions
                .get(candidate_encoded_start)
                .is_some_and(|raw_index| *raw_index < MAX_ENCODED_LITERAL_MID_SCAN_BYTES);
            let probe = &decoded[candidate_start..];
            let extent = if candidate_start == decoded_index {
                pickle_payload_extent_result(probe, probe.len())
            } else {
                confirmed_pickle_payload_extent_result(probe, probe.len())
            };
            let candidate_is_pickle = match extent {
                Ok(Some(_)) => true,
                Err(error) if error.is_structured_protocol0_line_operand_limit() => true,
                Ok(None) | Err(_) => false,
            };
            if candidate_is_pickle {
                if !starts_within_mid_scan {
                    return EncodedNestedProbeWindows {
                        windows,
                        limit_exceeded: true,
                        limit_exceeded_encoding: Some("base64"),
                    };
                }
                let (candidate, synthetic_prefix_bytes) = if candidate_start == decoded_index {
                    (
                        encode_base64_with_prefix_limit(&[], probe, max_window_chars),
                        0,
                    )
                } else {
                    (
                        encode_base64_with_prefix_limit(
                            b"\x80\x04",
                            probe,
                            max_window_chars.saturating_add(4),
                        ),
                        2,
                    )
                };
                if !candidate.is_empty() && !windows.iter().any(|window| window.value == candidate)
                {
                    if windows.len() >= MAX_NESTED_PAYLOAD_PROBES {
                        return EncodedNestedProbeWindows {
                            windows,
                            limit_exceeded: true,
                            limit_exceeded_encoding: Some("base64"),
                        };
                    }
                    windows.push(EncodedNestedProbeWindow {
                        value: candidate,
                        synthetic_prefix_bytes,
                    });
                }
            }
            decoded_index = decoded_index
                .saturating_add(LONG_PROTOCOL0_LINE_PROBE_BYTES)
                .saturating_add(newline_offset)
                .saturating_add(1);
        }
    }

    EncodedNestedProbeWindows {
        windows,
        limit_exceeded: false,
        limit_exceeded_encoding: None,
    }
}

fn contextual_protocol0_line_candidate_start(
    decoded: &[u8],
    line_index: usize,
    candidate_starts: &[usize],
    steps: &mut usize,
) -> Result<Option<usize>, ()> {
    let mut candidate_count = 0usize;
    for start in candidate_starts
        .iter()
        .copied()
        .take_while(|start| *start < line_index)
    {
        candidate_count += 1;
        *steps = steps.saturating_add(1);
        if candidate_count > MAX_NESTED_PAYLOAD_PROBES
            || *steps > MAX_CONTEXTUAL_PROTOCOL0_LINE_STEPS
        {
            return Err(());
        }
        if pickle_prefix_reaches_protocol0_line(decoded, start, line_index, steps)? {
            return Ok(Some(start));
        }
    }
    Ok(None)
}

fn pickle_prefix_reaches_protocol0_line(
    value: &[u8],
    start: usize,
    line_index: usize,
    steps: &mut usize,
) -> Result<bool, ()> {
    let mut index = start;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    let mut parsed_count = 0usize;
    let mut saw_memo_write = false;
    while index < line_index {
        *steps = steps.saturating_add(1);
        if *steps > MAX_CONTEXTUAL_PROTOCOL0_LINE_STEPS {
            return Err(());
        }
        let Ok(parsed) = parse_opcode(value, index, line_index) else {
            return Ok(false);
        };
        if parsed.next > line_index
            || !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths)
        {
            return Ok(false);
        }
        saw_memo_write |= matches!(parsed.name, "PUT" | "BINPUT" | "LONG_BINPUT" | "MEMOIZE");
        parsed_count += 1;
        index = parsed.next;
    }
    if index != line_index || parsed_count == 0 {
        return Ok(false);
    }
    Ok(match value.get(line_index) {
        Some(b'p') => stack_depth > 0,
        Some(b'g') => saw_memo_write,
        _ => false,
    })
}

fn base64_protocol0_line_has_terminator(
    value: &str,
    raw_start: usize,
    decoded_prefix_skip: usize,
) -> bool {
    let Some(raw_candidate) = value.as_bytes().get(raw_start..) else {
        return false;
    };
    let mut quartet = [0u8; 4];
    let mut quartet_len = 0usize;
    let mut decoded_index = 0usize;

    let mut is_terminator = |byte: u8| {
        let result = decoded_index
            >= LONG_PROTOCOL0_LINE_PROBE_BYTES.saturating_add(decoded_prefix_skip)
            && byte == b'\n';
        decoded_index = decoded_index.saturating_add(1);
        result
    };

    for byte in raw_candidate {
        let Some(value) = base64_value(*byte) else {
            continue;
        };
        quartet[quartet_len] = value;
        quartet_len += 1;
        if quartet_len < quartet.len() {
            continue;
        }

        for decoded in [
            (quartet[0] << 2) | (quartet[1] >> 4),
            (quartet[1] << 4) | (quartet[2] >> 2),
            (quartet[2] << 6) | quartet[3],
        ] {
            if is_terminator(decoded) {
                return true;
            }
        }
        quartet_len = 0;
    }

    if quartet_len >= 2 && is_terminator((quartet[0] << 2) | (quartet[1] >> 4)) {
        return true;
    }
    quartet_len >= 3 && is_terminator((quartet[1] << 4) | (quartet[2] >> 2))
}

pub(crate) fn encoded_pickle_consumes_literal(value: &str) -> bool {
    let stripped = value.trim();
    let prefix_has_base64_pickle = base64_structural_prefix_has_pickle_prefix(stripped);
    let prefix_has_hex_pickle =
        !prefix_has_base64_pickle && hex_structural_prefix_has_pickle_prefix(stripped);
    encoded_prefix_consumes_literal(stripped, prefix_has_base64_pickle, prefix_has_hex_pickle)
}

fn starts_encoded_pickle_at(value: &str, index: usize) -> bool {
    encoded_pickle_kind_at(value, index).is_some()
}

fn encoded_pickle_kind_at(value: &str, index: usize) -> Option<&'static str> {
    let suffix = &value[index..];
    let suffix_bytes = suffix.as_bytes();
    let starts_base64_pickle =
        encoded_base64_first_byte(suffix_bytes).is_some_and(is_pickle_prefix_start_byte);
    let starts_hex_pickle =
        encoded_hex_first_byte(suffix_bytes).is_some_and(is_pickle_prefix_start_byte);
    if !starts_base64_pickle && !starts_hex_pickle {
        return None;
    }

    let probe = take_bytes_str_slice(suffix, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
    let starts_base64_token = starts_base64_token_at(value, index);
    if !starts_base64_token && follows_terminal_base64_padding(value, index) {
        return None;
    }
    let base64_has_pickle_prefix = if starts_base64_token {
        base64_prefix_has_pickle_prefix(probe)
    } else {
        base64_prefix_has_nested_probe_prefix(probe, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
    };
    if starts_base64_pickle && base64_has_pickle_prefix {
        return Some("base64");
    }
    if starts_hex_pickle && hex_prefix_has_pickle_prefix(probe) {
        return Some("hex");
    }
    None
}

fn encoded_pickle_prefix_probe_limit_kind_at(value: &str, index: usize) -> Option<&'static str> {
    let suffix = &value[index..];
    if suffix.len() <= MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES {
        return None;
    }

    let suffix_bytes = suffix.as_bytes();
    let base64_first_byte = encoded_base64_first_byte_unbounded(suffix_bytes);
    let starts_base64_pickle = base64_first_byte.is_some_and(is_pickle_prefix_start_byte);
    let starts_hex_pickle =
        encoded_hex_first_byte(suffix_bytes).is_some_and(is_pickle_prefix_start_byte);
    if !starts_base64_pickle && !starts_hex_pickle {
        return None;
    }

    let probe = take_bytes_str_slice(suffix, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
    let starts_base64_token = starts_base64_token_at(value, index);
    let base64_after_padding =
        !starts_base64_token && follows_terminal_base64_padding(value, index);
    let probe_has_base64_pickle = if base64_after_padding {
        false
    } else if starts_base64_token {
        base64_prefix_has_pickle_prefix(probe)
    } else {
        base64_prefix_has_nested_probe_prefix(probe, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
    };
    if starts_base64_pickle && !base64_after_padding && !probe_has_base64_pickle {
        let suffix_has_base64_pickle = if starts_base64_token {
            base64_prefix_has_pickle_prefix_with_limit(suffix, suffix.len())
        } else {
            base64_prefix_has_nested_probe_prefix(suffix, suffix.len())
        };
        if suffix_has_base64_pickle {
            return Some("base64");
        }
    }

    if starts_hex_pickle
        && !hex_prefix_has_pickle_prefix(probe)
        && hex_prefix_has_pickle_prefix_with_limit(suffix, suffix.len())
    {
        return Some(hex_encoding_label(suffix));
    }
    None
}

fn encoded_prefix_has_pickle_prefix(value: &str) -> bool {
    base64_prefix_has_pickle_prefix(value) || hex_prefix_has_pickle_prefix(value)
}

fn encoded_structural_prefix_has_pickle_prefix(value: &str) -> bool {
    base64_structural_prefix_has_pickle_prefix(value)
        || hex_structural_prefix_has_pickle_prefix(value)
}

fn encoded_prefix_consumes_literal(
    value: &str,
    prefix_has_base64_pickle: bool,
    prefix_has_hex_pickle: bool,
) -> bool {
    (prefix_has_base64_pickle
        && take_base64_literal_prefix(value, value.len()).len() == value.len()
        && base64_candidate_unpadded(value).is_some())
        || (prefix_has_hex_pickle
            && take_hex_literal_prefix(value, value.len()).len() == value.len())
}

fn encoded_probe_prefix_consumes_literal(
    value: &str,
    prefix_has_base64_pickle: bool,
    prefix_has_hex_pickle: bool,
    max_encoded_chars: usize,
    max_window_chars: usize,
) -> bool {
    let prefix_may_be_long_protocol0_line = encoded_base64_first_byte_unbounded(value.as_bytes())
        .is_some_and(is_protocol0_long_line_probe_opcode);
    encoded_prefix_consumes_literal(value, prefix_has_base64_pickle, prefix_has_hex_pickle)
        || ((prefix_has_base64_pickle || prefix_may_be_long_protocol0_line)
            && lenient_base64_decodes_to_single_pickle(value, max_encoded_chars, max_window_chars))
}

fn lenient_base64_decodes_to_single_pickle(
    value: &str,
    max_encoded_chars: usize,
    max_input_bytes: usize,
) -> bool {
    if value.len() > max_input_bytes || !is_lenient_base64_candidate(value) {
        return false;
    }
    let normalized =
        normalize_base64_literal(value, max_encoded_chars.saturating_add(1), value.len());
    if normalized.len() > max_encoded_chars {
        return false;
    }
    canonical_base64_candidate(&normalized)
        .as_deref()
        .and_then(decode_base64)
        .is_some_and(|decoded| {
            pickle_payload_extent_result(&decoded, decoded.len())
                .ok()
                .flatten()
                == Some(decoded.len())
        })
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

fn push_unique_window(windows: &mut Vec<EncodedNestedProbeWindow>, candidate: String) {
    if candidate.is_empty() || windows.iter().any(|window| window.value == candidate) {
        return;
    }
    windows.push(EncodedNestedProbeWindow {
        value: candidate,
        synthetic_prefix_bytes: 0,
    });
}

pub(crate) fn encoded_nested_window_char_limit(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> usize {
    let max_base64_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_plain_hex_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_chars = max_nested_pickle_bytes * 4;
    let base64_window_chars = MAX_ENCODED_LITERAL_MID_SCAN_BYTES
        .saturating_add(max_base64_chars.max(ENCODED_LITERAL_PROBE_CHARS));
    let plain_hex_window_chars = MAX_ENCODED_LITERAL_MID_SCAN_BYTES
        .saturating_add(max_plain_hex_chars.max(ENCODED_LITERAL_PROBE_CHARS));
    let escaped_hex_window_chars = MAX_ENCODED_LITERAL_MID_SCAN_BYTES
        .saturating_add(max_escaped_hex_chars.max(ENCODED_LITERAL_PROBE_CHARS));
    let probe = encoded_literal_probe(value);
    if contains_escaped_hex_marker(&probe) {
        return escaped_hex_window_chars;
    }
    if chars_are_in_alphabet(probe.as_bytes(), HEX_LITERAL_CHARS) {
        return plain_hex_window_chars;
    }
    if chars_are_in_alphabet(probe.as_bytes(), BASE64_LITERAL_CHARS) {
        return base64_window_chars;
    }
    base64_window_chars
        .max(plain_hex_window_chars)
        .max(escaped_hex_window_chars)
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

fn is_lenient_base64_candidate(value: &str) -> bool {
    let mut unpadded_chars = 0usize;
    let mut padding_seen = false;
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' if !padding_seen => {
                unpadded_chars = unpadded_chars.saturating_add(1);
            }
            b'=' if unpadded_chars % 4 == 0 => {}
            b'=' => padding_seen = true,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => return false,
            _ => {}
        }
    }
    unpadded_chars > 0 && unpadded_chars % 4 != 1
}

fn canonical_base64_candidate(value: &str) -> Option<String> {
    base64_candidate_unpadded(value).map(pad_base64)
}

fn base64_candidate_unpadded(value: &str) -> Option<&str> {
    let unpadded = value.trim_end_matches('=');
    if unpadded.is_empty()
        || unpadded.len() % 4 == 1
        || !unpadded
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
    {
        return None;
    }
    Some(unpadded)
}

pub(crate) fn is_strict_base64_literal(value: &[u8]) -> bool {
    let Some(padding_start) = value.iter().position(|byte| *byte == b'=') else {
        return !value.is_empty()
            && value.len() % 4 != 1
            && value.iter().all(
                |byte| matches!(*byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'),
            );
    };
    let (unpadded, padding) = value.split_at(padding_start);
    !unpadded.is_empty()
        && unpadded.len() % 4 != 1
        && unpadded
            .iter()
            .all(|byte| matches!(*byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
        && padding.len() <= 2
        && padding.iter().all(|byte| *byte == b'=')
        && value.len() % 4 == 0
}

fn high_confidence_raw_persistent_id_prefix_end(value: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    for _ in 0..MAX_NESTED_PAYLOAD_PROBES {
        if index >= value.len() {
            return None;
        }
        // Strict Base64 cannot contain the newline required by protocol-0 line operands.
        // Reject these opcodes before parse_opcode performs a linear terminator search.
        if matches!(
            value[index],
            b'F' | b'I' | b'L' | b'P' | b'S' | b'V' | b'g' | b'p' | b'c' | b'i'
        ) {
            return None;
        }
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return None;
        }
        match parsed.name {
            "PERSID" | "BINPERSID" => return Some(parsed.next),
            "INST" | "REDUCE" | "NEWOBJ" | "NEWOBJ_EX" | "OBJ" | "BUILD" => return None,
            _ => {}
        }
        index = parsed.next;
        if parsed.name == "STOP" {
            return None;
        }
    }
    value[index..].contains(&b'Q').then_some(index)
}

pub(crate) fn strict_base64_literal_raw_execution_probe_offsets(
    value: &[u8],
    _max_nested_pickle_bytes: usize,
) -> NestedProbeOffsets {
    if !is_strict_base64_literal(value) {
        return NestedProbeOffsets {
            offsets: Vec::new(),
            limit_exceeded: false,
        };
    }
    let mut offsets = Vec::new();
    let mut q_offsets = value
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'Q').then_some(index))
        .peekable();
    for (offset, byte) in value.iter().enumerate() {
        if !is_pickle_prefix_start_byte(*byte) {
            continue;
        }
        while q_offsets.peek().is_some_and(|q_offset| *q_offset < offset) {
            q_offsets.next();
        }
        if q_offsets.peek().is_none() {
            continue;
        }
        if high_confidence_raw_persistent_id_prefix_end(&value[offset..]).is_some() {
            if offsets.len() >= MAX_NESTED_PAYLOAD_PROBES {
                return NestedProbeOffsets {
                    offsets,
                    limit_exceeded: true,
                };
            }
            offsets.push(offset);
        }
    }
    NestedProbeOffsets {
        offsets,
        limit_exceeded: false,
    }
}

pub(crate) fn strict_base64_literal_raw_execution_probe_offset(
    value: &[u8],
    max_nested_pickle_bytes: usize,
) -> Option<usize> {
    strict_base64_literal_raw_execution_probe_offsets(value, max_nested_pickle_bytes)
        .offsets
        .into_iter()
        .next()
}

pub(crate) fn strict_base64_literal_has_encoded_pickle_candidate(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    if value.len() > NESTED_STRUCTURAL_PROBE_BYTES {
        if is_strict_base64_literal(value)
            && encoded_base64_first_byte(text.as_bytes())
                .is_some_and(is_protocol0_long_line_probe_opcode)
            && !base64_protocol0_line_has_terminator(text, 0, 0)
        {
            return false;
        }
        return encoded_literal_may_contain_pickle(text);
    }
    (0..text.len()).any(|index| {
        if !text.is_char_boundary(index) {
            return false;
        }
        let suffix = &text[index..];
        encoded_pickle_kind_at(text, index).is_some()
            || (encoded_base64_first_byte(suffix.as_bytes())
                .is_some_and(is_protocol0_long_line_probe_opcode)
                && base64_prefix_has_complete_protocol0_line(suffix, suffix.len()))
    })
}

#[cfg(test)]
pub(crate) fn strict_base64_literal_has_raw_execution_probe(
    value: &[u8],
    max_nested_pickle_bytes: usize,
) -> bool {
    strict_base64_literal_has_encoded_pickle_candidate(value)
        && strict_base64_literal_raw_execution_probe_offset(value, max_nested_pickle_bytes)
            .is_some()
}

fn base64_prefix_len_for_payload(value: &str, payload: &[u8]) -> Option<usize> {
    let unpadded_len =
        payload
            .len()
            .checked_div(3)?
            .checked_mul(4)?
            .checked_add(match payload.len() % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })?;
    let padded_len = payload
        .len()
        .checked_add(2)?
        .checked_div(3)?
        .checked_mul(4)?;
    for candidate_len in [padded_len, unpadded_len] {
        let Some(candidate) = value.get(..candidate_len) else {
            continue;
        };
        let next_is_base64 = value
            .as_bytes()
            .get(candidate_len)
            .is_some_and(|byte| base64_value(*byte).is_some());
        if candidate_len == unpadded_len && candidate_len % 4 != 0 && next_is_base64 {
            continue;
        }
        if !is_strict_base64_literal(candidate.as_bytes()) {
            continue;
        }
        if canonical_base64_candidate(candidate)
            .as_deref()
            .and_then(decode_base64)
            .as_deref()
            == Some(payload)
        {
            return Some(candidate_len);
        }
    }
    None
}

pub(crate) fn confirmed_base64_pickle_spans(
    value: &[u8],
    max_nested_pickle_bytes: usize,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let Ok(text) = std::str::from_utf8(value) else {
        return spans;
    };
    let mut candidate_count = 0usize;
    let scan_len = value.len().min(MAX_ENCODED_LITERAL_MID_SCAN_BYTES);
    let mut index = 0usize;
    while index < scan_len {
        if !text.is_char_boundary(index) {
            index += 1;
            continue;
        }
        let suffix = &text[index..];
        if !encoded_base64_first_byte(&value[index..value.len().min(index + 2)])
            .is_some_and(is_pickle_prefix_start_byte)
        {
            index += 1;
            continue;
        }
        candidate_count += 1;
        if candidate_count > MAX_NESTED_PAYLOAD_PROBES {
            break;
        }
        let starts_long_protocol0_pickle = encoded_base64_first_byte(suffix.as_bytes())
            .is_some_and(is_protocol0_long_line_probe_opcode)
            && base64_prefix_has_complete_protocol0_line(suffix, suffix.len());
        if encoded_pickle_kind_at(text, index) != Some("base64") && !starts_long_protocol0_pickle {
            index += 1;
            continue;
        }
        let mut confirmed_end = None;
        for decoded in decode_possible_encoded_pickle(suffix, max_nested_pickle_bytes) {
            let Some(token_len) = base64_prefix_len_for_payload(suffix, &decoded.payload) else {
                continue;
            };
            let token = &suffix.as_bytes()[..token_len];
            if strict_base64_literal_raw_execution_probe_offset(token, max_nested_pickle_bytes)
                .is_some_and(|raw_offset| raw_offset <= 16)
            {
                continue;
            }
            confirmed_end = Some(index.saturating_add(token_len));
            break;
        }
        if let Some(end) = confirmed_end {
            spans.push((index, end));
            index = end;
        } else {
            index += 1;
        }
    }
    spans
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
    base64_prefix_has_pickle_prefix_with_limit(value, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
}

fn base64_structural_prefix_has_pickle_prefix(value: &str) -> bool {
    let max_encoded_chars = NESTED_STRUCTURAL_PROBE_BYTES.div_ceil(3) * 4;
    base64_prefix_has_pickle_prefix_with_probe_chars(
        value,
        MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES,
        max_encoded_chars,
    ) || base64_prefix_has_complete_protocol0_line(value, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
}

fn base64_prefix_has_pickle_prefix_with_limit(value: &str, max_input_bytes: usize) -> bool {
    base64_prefix_has_pickle_prefix_with_probe_chars(
        value,
        max_input_bytes,
        ENCODED_LITERAL_PROBE_CHARS,
    )
}

fn base64_prefix_has_pickle_prefix_with_probe_chars(
    value: &str,
    max_input_bytes: usize,
    max_encoded_chars: usize,
) -> bool {
    let strict = take_base64_literal_prefix(value, max_encoded_chars.min(max_input_bytes));
    if canonical_base64_candidate(strict)
        .as_deref()
        .and_then(decode_base64)
        .is_some_and(|decoded| decoded_contains_pickle_prefix(&decoded))
    {
        return true;
    }

    let lenient = normalize_base64_literal(value, max_encoded_chars, max_input_bytes);
    lenient != strict
        && canonical_base64_candidate(&lenient)
            .as_deref()
            .and_then(decode_base64)
            .is_some_and(|decoded| has_nested_probe_prefix(&decoded))
}

fn base64_prefix_has_nested_probe_prefix(value: &str, max_input_bytes: usize) -> bool {
    base64_literal_candidates(value, ENCODED_LITERAL_PROBE_CHARS, max_input_bytes)
        .into_iter()
        .any(|prefix| {
            canonical_base64_candidate(&prefix)
                .as_deref()
                .and_then(decode_base64)
                .is_some_and(|decoded| has_nested_probe_prefix(&decoded))
        })
}

fn base64_prefix_has_complete_protocol0_line(value: &str, max_input_bytes: usize) -> bool {
    let strict_limit = max_input_bytes.min(MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
    let strict = take_base64_literal_prefix(value, strict_limit);
    if strict.len() <= ENCODED_LITERAL_PROBE_CHARS
        || !encoded_base64_first_byte(strict.as_bytes())
            .is_some_and(is_protocol0_long_line_probe_opcode)
    {
        return false;
    }

    canonical_base64_candidate(strict)
        .as_deref()
        .and_then(decode_base64)
        .is_some_and(|decoded| {
            decoded
                .first()
                .is_some_and(|byte| is_protocol0_long_line_probe_opcode(*byte))
                && pickle_payload_extent_result(&decoded, decoded.len())
                    .ok()
                    .flatten()
                    .is_some()
        })
}

fn starts_base64_token_at(value: &str, index: usize) -> bool {
    index == 0
        || value.as_bytes().get(index - 1).is_some_and(|byte| {
            !matches!(
                *byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'
            )
        })
}

fn follows_terminal_base64_padding(value: &str, index: usize) -> bool {
    const PADDING_SUFFIX_LOOKBACK_BYTES: usize = 64;

    value.as_bytes()[index.saturating_sub(PADDING_SUFFIX_LOOKBACK_BYTES)..index]
        .iter()
        .rev()
        .find(|byte| !matches!(**byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
        .is_some_and(|byte| *byte == b'=')
}

fn hex_prefix_has_pickle_prefix(value: &str) -> bool {
    hex_prefix_has_pickle_prefix_with_limit(value, MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
}

fn hex_structural_prefix_has_pickle_prefix(value: &str) -> bool {
    hex_prefix_has_pickle_prefix_with_probe_digits(
        value,
        MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES,
        NESTED_STRUCTURAL_PROBE_BYTES * 2,
    )
}

fn hex_prefix_has_pickle_prefix_with_limit(value: &str, max_input_bytes: usize) -> bool {
    hex_prefix_has_pickle_prefix_with_probe_digits(
        value,
        max_input_bytes,
        ENCODED_LITERAL_PROBE_CHARS * 4,
    )
}

fn hex_prefix_has_pickle_prefix_with_probe_digits(
    value: &str,
    max_input_bytes: usize,
    max_hex_digits: usize,
) -> bool {
    let mut hex_candidate = normalize_hex_literal(value, max_hex_digits, max_input_bytes);
    if hex_candidate.len() % 2 == 1 {
        hex_candidate.pop();
    }
    if hex_candidate.len() < 4 || !is_hex_candidate(&hex_candidate) {
        return false;
    }
    decode_hex(&hex_candidate)
        .map(|decoded| decoded_contains_pickle_prefix(&decoded))
        .unwrap_or(false)
}

fn decoded_contains_pickle_prefix(decoded: &[u8]) -> bool {
    (0..decoded.len().saturating_sub(1)).any(|offset| {
        let candidate = &decoded[offset..];
        if candidate
            .first()
            .is_some_and(|byte| is_protocol0_long_line_probe_opcode(*byte))
        {
            has_nested_probe_prefix(candidate)
        } else {
            has_pickle_prefix(candidate)
        }
    })
}

fn take_base64_literal_prefix(value: &str, max_chars: usize) -> &str {
    let bytes = value.as_bytes();
    let limit = bytes.len().min(max_chars);
    let mut end = 0usize;
    while end < limit && matches!(bytes[end], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
    {
        end += 1;
    }
    while end < limit && bytes[end] == b'=' {
        end += 1;
    }
    &value[..end]
}

fn normalize_base64_literal(
    value: &str,
    max_encoded_chars: usize,
    max_input_bytes: usize,
) -> String {
    if value
        .as_bytes()
        .first()
        .is_none_or(|byte| base64_value(*byte).is_none())
    {
        return String::new();
    }
    let mut normalized = String::with_capacity(value.len().min(max_encoded_chars));
    let mut padding_seen = false;
    let mut unpadded_chars = 0usize;
    for byte in value.bytes().take(max_input_bytes) {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' if !padding_seen => {
                normalized.push(char::from(byte));
                unpadded_chars = unpadded_chars.saturating_add(1);
            }
            b'=' if unpadded_chars % 4 == 0 => {}
            b'=' => {
                padding_seen = true;
                normalized.push('=');
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => break,
            _ => {}
        }
        if normalized.len() >= max_encoded_chars {
            break;
        }
    }
    normalized
}

fn base64_literal_candidates(
    value: &str,
    max_encoded_chars: usize,
    max_input_bytes: usize,
) -> Vec<String> {
    let mut candidates = Vec::with_capacity(2);
    let strict = take_base64_literal_prefix(value, max_encoded_chars).to_string();
    if !strict.is_empty() {
        candidates.push(strict);
    }
    let lenient = normalize_base64_literal(value, max_encoded_chars, max_input_bytes);
    if !lenient.is_empty() && !candidates.iter().any(|candidate| candidate == &lenient) {
        candidates.push(lenient);
    }
    candidates
}

fn take_hex_literal_prefix(value: &str, max_chars: usize) -> &str {
    let bytes = value.as_bytes();
    let limit = bytes.len().min(max_chars);
    let mut index = 0usize;
    while index < limit {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'\\' && matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
            if index + 4 <= limit
                && bytes.get(index + 2).is_some_and(|byte| is_hex_byte(*byte))
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
    &value[..index]
}

fn normalize_hex_literal(value: &str, max_hex_digits: usize, max_input_bytes: usize) -> String {
    let bytes = value.as_bytes();
    let limit = bytes.len().min(max_input_bytes);
    let mut normalized = String::with_capacity(max_hex_digits.min(limit));
    let mut index = 0usize;
    while index < limit && normalized.len() < max_hex_digits {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'\\' && matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
            if index + 4 <= limit
                && bytes.get(index + 2).is_some_and(|byte| is_hex_byte(*byte))
                && bytes.get(index + 3).is_some_and(|byte| is_hex_byte(*byte))
            {
                normalized.push(char::from(bytes[index + 2]));
                if normalized.len() < max_hex_digits {
                    normalized.push(char::from(bytes[index + 3]));
                }
                index += 4;
                continue;
            }
            break;
        }
        if is_hex_byte(bytes[index]) {
            normalized.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        break;
    }
    normalized
}

fn encoded_base64_first_byte(value: &[u8]) -> Option<u8> {
    let first = base64_value(*value.first()?)?;
    let second = value
        .iter()
        .skip(1)
        .take(MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES)
        .find_map(|byte| base64_value(*byte))?;
    Some((first << 2) | (second >> 4))
}

fn encoded_base64_first_byte_unbounded(value: &[u8]) -> Option<u8> {
    let first = base64_value(*value.first()?)?;
    let second = value.iter().skip(1).find_map(|byte| base64_value(*byte))?;
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

fn encode_base64(value: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[(first >> 2) as usize]));
        encoded.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize],
            ));
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[(third & 0x3f) as usize]));
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn encode_base64_with_prefix_limit(prefix: &[u8], value: &[u8], max_chars: usize) -> String {
    let max_input_bytes = max_chars.div_ceil(4).saturating_mul(3);
    let prefix_len = prefix.len().min(max_input_bytes);
    let value_len = value.len().min(max_input_bytes.saturating_sub(prefix_len));
    let mut bounded = Vec::with_capacity(prefix_len.saturating_add(value_len));
    bounded.extend_from_slice(&prefix[..prefix_len]);
    bounded.extend_from_slice(&value[..value_len]);
    take_bytes_str(&encode_base64(&bounded), max_chars)
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
    value.trim_end_matches('=').len().saturating_mul(3) / 4
}

fn estimate_lenient_base64_decoded_size(value: &str) -> usize {
    let mut unpadded_chars = 0usize;
    let mut padding_seen = false;
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' if !padding_seen => {
                unpadded_chars = unpadded_chars.saturating_add(1);
            }
            b'=' if unpadded_chars % 4 == 0 => {}
            b'=' => padding_seen = true,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => break,
            _ => {}
        }
    }
    unpadded_chars.saturating_mul(3) / 4
}

fn estimate_hex_decoded_size(value: &str) -> usize {
    strip_escaped_hex_markers(value).len() / 2
}

fn strip_escaped_hex_markers(value: &str) -> String {
    value
        .replace("\\x", "")
        .replace("\\X", "")
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
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

fn take_bytes_str_slice(value: &str, count: usize) -> &str {
    if count >= value.len() {
        return value;
    }
    let mut end = count;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAX_NESTED_PICKLE_BYTES: usize = 2 * 1024 * 1024;

    fn encode_base64_for_test(value: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
        for chunk in value.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            encoded.push(char::from(ALPHABET[(first >> 2) as usize]));
            encoded.push(char::from(
                ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
            ));
            if chunk.len() > 1 {
                encoded.push(char::from(
                    ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize],
                ));
            } else {
                encoded.push('=');
            }
            if chunk.len() > 2 {
                encoded.push(char::from(ALPHABET[(third & 0x3f) as usize]));
            } else {
                encoded.push('=');
            }
        }
        encoded
    }

    fn long_protocol0_line_payload_for_test(opcode: u8) -> Vec<u8> {
        let mut payload = match opcode {
            b'F' => b"F".to_vec(),
            b'I' => b"I".to_vec(),
            b'L' => b"L".to_vec(),
            b'P' => b"P".to_vec(),
            b'S' => b"S'".to_vec(),
            b'V' => b"V".to_vec(),
            b'g' => b"Np0\n0g".to_vec(),
            b'p' => b"Np".to_vec(),
            _ => unreachable!(),
        };
        let fill = match opcode {
            b'F' | b'I' | b'L' => b'1',
            b'g' | b'p' => b'0',
            _ => b'A',
        };
        let fill_len = if opcode == b'L' {
            PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES
        } else {
            PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES + 1
        };
        payload.extend(std::iter::repeat_n(fill, fill_len));
        if matches!(opcode, b'L' | b'S') {
            payload.push(if opcode == b'L' { b'L' } else { b'\'' });
        }
        payload.extend_from_slice(b"\n0cos\nsystem\n(S'id'\ntR.");
        payload
    }

    #[test]
    fn encoded_prefix_gates_recognize_pickle_prefixes() {
        assert!(base64_prefix_has_pickle_prefix("gAR9Lg=="));
        assert!(hex_prefix_has_pickle_prefix("80047d2e"));
        assert!(hex_prefix_has_pickle_prefix(r"\x80\x04\x7d\x2e"));
    }

    #[test]
    fn complete_base64_constructor_pickle_has_no_truncated_candidates() {
        let decoded = concat!(
            "gASVNQAAAAAAAACMC2NvbGxlY3Rpb25zlIwHQ291bnRlcpSTlH2UKIwBYZRLA4wB",
            "YpRLAowBY5RLAXWFlFKULg==",
        );

        let candidates = decode_possible_encoded_pickle(decoded, TEST_MAX_NESTED_PICKLE_BYTES);
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].analysis_incomplete);
        assert_eq!(candidates[0].payload.len(), 64);
        let windows = encoded_nested_literal_probe_windows_with_limit(
            decoded,
            encoded_nested_window_char_limit(decoded, TEST_MAX_NESTED_PICKLE_BYTES),
        );
        assert_eq!(
            windows
                .windows
                .iter()
                .map(|window| window.value.as_str())
                .collect::<Vec<_>>(),
            vec![decoded],
        );
    }

    #[test]
    fn encoded_mid_scan_uses_resolved_base64_first_bytes() {
        let benign = "YA".repeat((MAX_ENCODED_LITERAL_MID_SCAN_BYTES / 2) + 65);

        assert!(!encoded_literal_may_contain_pickle(&benign));
        assert!(encoded_nested_literal_probe_windows(&benign, 64).is_empty());
    }

    #[test]
    fn encoded_windows_include_probe_allowance_and_payload_budget() {
        let max_nested_pickle_bytes = 4;
        let window_chars = encoded_nested_window_char_limit("Y!...", max_nested_pickle_bytes);

        assert!(
            window_chars
                >= MAX_ENCODED_LITERAL_MID_SCAN_BYTES
                    + max_nested_pickle_bytes
                        .saturating_mul(4)
                        .max(ENCODED_LITERAL_PROBE_CHARS)
        );
    }

    #[test]
    fn encoded_token_prefixes_stop_at_boundaries_and_terminal_padding() {
        assert_eq!(
            take_base64_literal_prefix("Y29zCnN5c3RlbQopUi4=suffix", usize::MAX),
            "Y29zCnN5c3RlbQopUi4="
        );
        assert_eq!(
            take_base64_literal_prefix("Y29zCnN5c3RlbQopUi4=-suffix", usize::MAX),
            "Y29zCnN5c3RlbQopUi4="
        );
        assert_eq!(
            take_hex_literal_prefix("636f730a73797374656d0a29522e-suffix", usize::MAX),
            "636f730a73797374656d0a29522e"
        );
        assert_eq!(
            normalize_base64_literal("Y29z!CnN5c3RlbQopUi4=", usize::MAX, usize::MAX),
            "Y29zCnN5c3RlbQopUi4="
        );
        assert_eq!(
            strip_escaped_hex_markers("63 6f 73 0a 73 79 73 74 65 6d 0a 29 52 2e"),
            "636f730a73797374656d0a29522e"
        );
    }

    #[test]
    fn oversized_encoded_detection_uses_delimited_token_prefixes() {
        assert_eq!(
            detect_oversized_encoded_pickle_prefixes(
                "gASVCgAAAAAAAAB9lIwBYZRLAXMu-trailing-suffix",
                4
            ),
            vec![("base64", 31)]
        );
        assert_eq!(
            detect_oversized_encoded_pickle_prefixes(
                "8004950a000000000000007d948c0161944b01732e-trailing-suffix",
                4
            ),
            vec![("hex", 21)]
        );
    }

    #[test]
    fn encoded_prefix_gates_recognize_binary_protocols_0_to_5() {
        for encoded in [
            "gAB9Lg==", "gAF9Lg==", "gAJ9Lg==", "gAN9Lg==", "gAR9Lg==", "gAV9Lg==",
        ] {
            assert!(base64_prefix_has_pickle_prefix(encoded));
            let wrapped = format!("prefix-{encoded}-suffix");
            let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
            assert!(windows.iter().any(|window| window.starts_with(encoded)));
        }

        for protocol in 0..=5 {
            let encoded = format!("800{protocol}7d2e");
            assert!(hex_prefix_has_pickle_prefix(&encoded));
            let wrapped = format!("prefix-{encoded}-suffix");
            let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
            assert!(windows.iter().any(|window| window.starts_with(&encoded)));
        }
    }

    #[test]
    fn whole_encoded_pickle_detection_requires_full_literal_consumption() {
        assert!(encoded_pickle_consumes_literal("gAR9Lg==\n"));
        assert!(encoded_pickle_consumes_literal("80047d2e"));
        assert!(encoded_pickle_consumes_literal(r"\x80\x04\x7d\x2e"));
        assert!(!encoded_pickle_consumes_literal("prefix-gAR9Lg=="));
        assert!(!encoded_pickle_consumes_literal("# gAR9Lg==\n# metadata"));
        assert!(!encoded_pickle_consumes_literal("gAROLg!cos\nsystem\n)R."));
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
    fn protocol0_scalar_prefixes_require_bounded_line_operands() {
        assert!(has_nested_probe_prefix(b"I1\n."));
        assert!(has_nested_probe_prefix(b"S'x'\n."));
        assert!(has_nested_probe_prefix(b"Vtext\n."));
        assert!(has_pickle_prefix(b"I$$$$$$$$"));
        assert!(!has_nested_probe_prefix(b"I$$$$$$$$"));
        assert!(!has_nested_probe_prefix(
            format!("S{}", "A".repeat(PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES + 1)).as_bytes()
        ));
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
            .any(|window| window.value.starts_with(hidden_payload)));
    }

    #[test]
    fn encoded_probe_windows_normalize_candidates_beyond_prefix_probe() {
        let gap = "!".repeat(MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES + 1);
        for (value, expected_prefix) in [
            (format!("Y{gap}29zCnN5c3RlbQopUi4="), "Y29zCnN5c3RlbQopUi4="),
            (format!("g{gap}AROLg=="), "gAROLg=="),
            (
                format!(
                    "80{}044e2e",
                    " ".repeat(MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES + 1)
                ),
                "80044e2e",
            ),
        ] {
            assert!(encoded_literal_may_contain_pickle(&value));
            let probed = encoded_nested_literal_probe_windows_with_limit(&value, 64);
            assert!(probed
                .windows
                .iter()
                .any(|window| window.value.starts_with(expected_prefix)));
        }
    }

    #[test]
    fn encoded_probe_windows_skip_mid_scan_for_whole_encoded_literals() {
        for value in [
            "gAR9Lg==",
            "gAR9Lg==\n",
            "80047d2e",
            "80047d2e\n",
            r"\x80\x04\x7d\x2e",
        ] {
            let windows = encoded_nested_literal_probe_windows(value, 64);

            assert_eq!(windows, vec![value.trim().to_string()]);
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
            &beyond_bound,
            64,
            64,
        ));
    }

    #[test]
    fn encoded_probe_coverage_treats_trimmed_whole_literals_as_complete() {
        let whole_literal = format!("gAR9{}\n", "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES));

        assert!(!encoded_nested_literal_probe_coverage_incomplete(
            &whole_literal,
            whole_literal.len(),
            whole_literal.len(),
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
    fn base64_prefix_gate_recognizes_complete_long_protocol0_scalar_pickle() {
        for opcode in [b'F', b'I', b'L', b'P', b'S', b'V'] {
            let payload = long_protocol0_line_payload_for_test(opcode);
            let encoded = encode_base64_for_test(&payload);

            assert!(base64_structural_prefix_has_pickle_prefix(&encoded));
            assert!(
                decode_possible_encoded_pickle(&encoded, TEST_MAX_NESTED_PICKLE_BYTES)
                    .iter()
                    .any(|candidate| candidate.payload == payload)
            );
        }
    }

    #[test]
    fn encoded_probe_windows_keep_embedded_long_protocol0_scalar_candidates() {
        let mut payload = b"V".to_vec();
        payload.extend(std::iter::repeat_n(
            b'A',
            PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES + 1,
        ));
        payload.extend_from_slice(b"\n0cos\nsystem\n(S'id'\ntR.");
        let encoded = encode_base64_for_test(&payload);
        let unpadded = encoded.trim_end_matches('=');
        let separated = encoded
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("!");

        for value in [format!("A{encoded}"), format!("={encoded}"), separated] {
            assert!(encoded_literal_may_contain_pickle(&value));
            let windows = encoded_nested_literal_probe_windows(&value, value.len());
            assert!(
                windows.iter().any(|window| window.starts_with(unpadded)),
                "missing normalized payload for value prefix {:?}: {:?}",
                take_chars(&value, 16),
                windows
            );
        }

        let beyond_mid_scan = format!(
            "{}{}{}",
            "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES + 1),
            encoded,
            "B".repeat(ENCODED_LITERAL_PROBE_CHARS + 1)
        );
        assert!(encoded_literal_may_contain_pickle(&beyond_mid_scan));
        let probed = encoded_nested_literal_probe_windows_with_limit(
            &beyond_mid_scan,
            beyond_mid_scan.len(),
        );
        assert!(probed.limit_exceeded);
        assert_eq!(probed.limit_exceeded_encoding, Some("base64"));
    }

    #[test]
    fn encoded_probe_windows_keep_long_scalar_candidates_at_each_decoded_offset() {
        for opcode in [b'F', b'I', b'L', b'P', b'S', b'V', b'g', b'p'] {
            let payload = long_protocol0_line_payload_for_test(opcode);
            for prefix_len in 0..3usize {
                let mut wrapped = vec![b'X'; prefix_len];
                wrapped.extend_from_slice(&payload);
                let encoded = encode_base64_for_test(&wrapped);
                let windows = encoded_nested_literal_probe_windows(&encoded, encoded.len());

                assert!(
                    windows.iter().any(|window| {
                        decode_possible_encoded_pickle(window, TEST_MAX_NESTED_PICKLE_BYTES)
                            .iter()
                            .any(|candidate| {
                                candidate.payload == payload
                                    || (matches!(opcode, b'g' | b'p')
                                        && candidate.payload.starts_with(b"\x80\x04")
                                        && candidate.payload[2..] == payload)
                            })
                    }),
                    "missing opcode {} at decoded offset {prefix_len}",
                    char::from(opcode)
                );
            }
        }
    }

    #[test]
    fn encoded_probe_windows_keep_benign_long_scalar_candidates_at_decoded_offsets() {
        let mut payload = b"V".to_vec();
        payload.extend(std::iter::repeat_n(
            b'A',
            PROTOCOL0_SCALAR_PREFIX_PROBE_BYTES + 1,
        ));
        payload.extend_from_slice(b"\n.");

        for prefix_len in 1..3usize {
            let mut wrapped = vec![b'X'; prefix_len];
            wrapped.extend_from_slice(&payload);
            let encoded = encode_base64_for_test(&wrapped);

            assert!(encoded_literal_may_contain_pickle(&encoded));
            let windows = encoded_nested_literal_probe_windows(&encoded, encoded.len());
            assert!(
                windows.iter().any(|window| {
                    decode_possible_encoded_pickle(window, TEST_MAX_NESTED_PICKLE_BYTES)
                        .iter()
                        .any(|candidate| candidate.payload == payload)
                }),
                "missing benign payload at decoded offset {prefix_len}: {windows:?}",
            );
        }
    }

    #[test]
    fn encoded_probe_windows_continue_after_lenient_benign_prefix() {
        let benign = encode_base64_for_test(b"I42\n.")
            .trim_end_matches('=')
            .to_string();
        let malicious = encode_base64_for_test(b"cos\nsystem\n)R.")
            .trim_end_matches('=')
            .to_string();
        let value = format!("{benign}!{malicious}");
        let windows = encoded_nested_literal_probe_windows(&value, value.len());

        assert!(windows.iter().any(|window| window.starts_with(&malicious)));
    }

    #[test]
    fn encoded_probe_coverage_accepts_large_lenient_single_pickle() {
        let body_len = (MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES * 3 / 4) + 1024;
        let mut payload = b"\x80\x04X".to_vec();
        payload.extend_from_slice(&(body_len as u32).to_le_bytes());
        payload.extend(std::iter::repeat_n(b'A', body_len));
        payload.push(b'.');
        let encoded = encode_base64_for_test(&payload);
        let separated = encoded
            .as_bytes()
            .chunks(76)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(separated.len() > MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
        assert!(!encoded_nested_literal_probe_coverage_incomplete(
            &separated,
            separated.len(),
            payload.len(),
        ));
    }

    #[test]
    fn long_protocol0_base64_probe_ignores_unterminated_scalar_without_structure() {
        let body_len = (MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES * 3 / 4) + 1024;
        let mut payload = b"V".to_vec();
        payload.extend(std::iter::repeat_n(b'A', body_len));
        let encoded = encode_base64_for_test(&payload);

        let probes =
            embedded_long_protocol0_base64_probe_windows(&encoded, LONG_PROTOCOL0_LINE_PROBE_CHARS);

        assert!(encoded.len() > MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
        assert!(probes.windows.is_empty());
        assert!(!probes.limit_exceeded);
    }

    #[test]
    fn long_protocol0_base64_probe_fails_closed_on_terminator_beyond_window() {
        let body_len = (MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES * 3 / 4) + 1024;
        let mut payload = b"V".to_vec();
        payload.extend(std::iter::repeat_n(b'A', body_len));
        payload.extend_from_slice(b"\n0cos\nsystem\n(S'id'\ntR.");
        let encoded = encode_base64_for_test(&payload);

        let probes =
            embedded_long_protocol0_base64_probe_windows(&encoded, LONG_PROTOCOL0_LINE_PROBE_CHARS);

        assert!(encoded.len() > MAX_ENCODED_LITERAL_PREFIX_SCAN_BYTES);
        assert!(probes.windows.is_empty());
        assert!(probes.limit_exceeded);
        assert_eq!(probes.limit_exceeded_encoding, Some("base64"));
    }

    #[test]
    fn wrapped_base64_nested_literals_ignore_comment_leaders() {
        let value = "# this is doc\n# Y29zCnN5\n# c3RlbQopUi4=\n# more";
        let decoded = decode_possible_encoded_pickle(value, TEST_MAX_NESTED_PICKLE_BYTES);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].encoding, "base64");
        assert_eq!(decoded[0].payload, b"cos\nsystem\n)R.");
        assert!(!decoded[0].analysis_incomplete);
    }

    #[test]
    fn inline_encoded_pickle_candidates_stop_before_suffixes() {
        let payload = b"cos\nsystem\n)R.";
        for (value, encoding) in [
            ("Y29zCnN5c3RlbQopUi4=-suffix", "base64"),
            ("Y29zCnN5c3RlbQopUi4-suffix", "base64"),
            ("636f730a73797374656d0a29522e-suffix", "hex"),
        ] {
            let decoded = decode_possible_encoded_pickle(value, TEST_MAX_NESTED_PICKLE_BYTES);

            assert!(decoded
                .iter()
                .any(|candidate| candidate.encoding == encoding && candidate.payload == payload));
        }
    }

    #[test]
    fn inline_encoded_pickle_candidates_model_lenient_decoder_tails() {
        let payload = b"cos\nsystem\n)R.";
        for (value, encoding) in [
            ("Y29zCnN5c3RlbQopUi4===-suffix", "base64"),
            ("Y29z!CnN5c3RlbQopUi4=-suffix", "base64"),
            ("636f730a73797374656d0a29522ef-suffix", "hex"),
            ("63 6f 73 0a 73 79 73 74 65 6d 0a 29 52 2e-suffix", "hex"),
        ] {
            let decoded = decode_possible_encoded_pickle(value, TEST_MAX_NESTED_PICKLE_BYTES);
            assert!(decoded
                .iter()
                .any(|candidate| candidate.encoding == encoding && candidate.payload == payload));
            assert_eq!(
                detect_oversized_encoded_pickle_prefixes(value, 4),
                vec![(encoding, payload.len())]
            );
        }
    }

    #[test]
    fn encoded_nested_literals_keep_later_decoded_payloads() {
        let decoded = decode_possible_encoded_pickle(
            "gAR9LmNvcwpzeXN0ZW0KKVIu",
            TEST_MAX_NESTED_PICKLE_BYTES,
        );

        assert!(decoded
            .iter()
            .any(|candidate| candidate.encoding == "base64" && candidate.payload == b"\x80\x04}."));
        assert!(decoded
            .iter()
            .any(|candidate| candidate.encoding == "base64"
                && candidate.payload == b"cos\nsystem\n)R."));
    }

    #[test]
    fn decoded_payloads_preserve_protocol0_operand_limit_failures() {
        let mut payload = b"cos\nsystem\n(S'".to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
            b'A',
        );
        payload.extend_from_slice(b"'\ntR.");

        let decoded = decoded_pickle_payloads(&payload, payload.len() + 16);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, payload);
        assert!(decoded[0].1);
    }

    #[test]
    fn decoded_payloads_preserve_protocol0_operand_limit_after_inst() {
        let mut payload = b"(ios\nsystem\n(S'".to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
            b'A',
        );
        payload.extend_from_slice(b"'\ntR.");

        let decoded = decoded_pickle_payloads(&payload, payload.len() + 16);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, payload);
        assert!(decoded[0].1);
    }

    #[test]
    fn decoded_payloads_ignore_unstructured_protocol0_operand_limit_failures() {
        let mut payload = b"S'".to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1,
            b'A',
        );

        assert!(decoded_pickle_payloads(&payload, payload.len() + 16).is_empty());
        let error = pickle_payload_extent_result(&payload, payload.len() + 16)
            .expect_err("overlong protocol 0 string should preserve its parse error");
        assert!(!error.is_structured_protocol0_line_operand_limit());
    }

    #[test]
    fn decoded_payloads_preserve_truncated_execution_prefixes() {
        for payload in [b"Pevil\nAAAAAAAA".as_slice(), b"\x80\x04N.Pevil\n"] {
            let decoded = decoded_pickle_payloads(payload, payload.len() + 16);

            assert!(decoded.iter().any(|(candidate, analysis_incomplete)| {
                *analysis_incomplete && candidate.starts_with(b"Pevil\n")
            }));
        }
    }

    #[test]
    fn decoded_payloads_ignore_execution_like_benign_text_and_suffixes() {
        let payloads = decoded_pickle_payloads(b"\x80\x04N.README", 64);
        assert_eq!(payloads, vec![(b"\x80\x04N.".to_vec(), false)]);

        assert!(decoded_pickle_payloads(b"(README benign text", 64).is_empty());
    }

    #[test]
    fn decoded_payloads_ignore_unstructured_execution_opcode_near_matches() {
        for payload in [
            b"\x80\x04N.README".as_slice(),
            b"(README is ordinary text",
            b"README is ordinary text",
            b"G12345678Q ordinary text",
            b"J1234Q ordinary text",
            b"K1Q ordinary text",
            b"NQ ordinary text",
        ] {
            assert!(!decoded_pickle_payloads(payload, payload.len() + 16)
                .iter()
                .any(|(_, analysis_incomplete)| *analysis_incomplete));
        }
    }

    #[test]
    fn execution_fallback_requires_valid_pickle_structure() {
        assert!(has_structurally_valid_execution_prefix(b"Pevil\n"));
        assert!(has_structurally_valid_execution_prefix(
            b"cos\nsystem\n(S'id'\ntR"
        ));
        assert!(!has_structurally_valid_execution_prefix(b"RREADME"));
        assert!(!has_structurally_valid_execution_prefix(
            b"(README is ordinary text"
        ));
        assert!(has_structurally_valid_execution_prefix(b"NQAAgAROLgAAAAAA"));
    }

    #[test]
    fn decoded_payloads_ignore_truncated_data_only_scalars() {
        for payload in [
            b"F1".as_slice(),
            b"I1",
            b"L1",
            b"S'value'",
            b"Vvalue",
            b"g0",
            b"p0",
        ] {
            assert!(decoded_pickle_payloads(payload, payload.len() + 16).is_empty());
        }
    }

    #[test]
    fn strict_base64_literals_require_terminal_canonical_padding() {
        assert!(is_strict_base64_literal(b"gAR9Lg=="));
        assert!(is_strict_base64_literal(b"gAR9Lg"));
        assert!(!is_strict_base64_literal(b"gAR9Lg==NQ"));
        assert!(!is_strict_base64_literal(b"=gAR9Lg="));
        assert!(!is_strict_base64_literal(b"g=AR9Lg="));
        assert!(!is_strict_base64_literal(b"gAR9Lg===="));
        assert!(strict_base64_literal_has_raw_execution_probe(
            b"NQAAAAAAgAROLg==",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(strict_base64_literal_has_raw_execution_probe(
            b"NNQAgAROLgAAAAAA",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(strict_base64_literal_has_raw_execution_probe(
            b"N0NQgAROLgAAAAAA",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(strict_base64_literal_has_raw_execution_probe(
            b"AAAANQAAAAAAgAROLg==",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        let mut separated_raw_probe = b"NQ".to_vec();
        separated_raw_probe.extend_from_slice(&[b'A'; 18]);
        separated_raw_probe.extend_from_slice(b"VkFBQUFBQUFBQUFBQUFBQUEKLg==");
        assert!(strict_base64_literal_has_raw_execution_probe(
            &separated_raw_probe,
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        let mut long_raw_probe = Vec::new();
        for _ in 0..6 {
            long_raw_probe.extend_from_slice(b"C+");
            long_raw_probe.extend_from_slice(&[b'A'; 43]);
        }
        long_raw_probe.extend_from_slice(b"QgAROLgAAAAAA");
        assert!(strict_base64_literal_has_raw_execution_probe(
            &long_raw_probe,
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        let mut opcode_budget_raw_probe = b"N".to_vec();
        opcode_budget_raw_probe.extend_from_slice(&[b'2'; 80]);
        opcode_budget_raw_probe.extend_from_slice(b"QgAROLgAAAAAA");
        assert!(strict_base64_literal_has_raw_execution_probe(
            &opcode_budget_raw_probe,
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(!strict_base64_literal_has_raw_execution_probe(
            b"KFJFQURNRSBpcyBvcmRpbmFyeSB0ZXh0",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(!strict_base64_literal_has_raw_execution_probe(
            b"ordinaryCNQHtext",
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(!strict_base64_literal_has_raw_execution_probe(
            &vec![b'V'; 500_000],
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert!(!strict_base64_literal_has_raw_execution_probe(
            &[b"junk".repeat(25_000), b"Q".to_vec()].concat(),
            TEST_MAX_NESTED_PICKLE_BYTES,
        ));
        assert_eq!(
            confirmed_base64_pickle_spans(b"!VkFBQUFBQUFBQUFBQUFBQUEKLg==ab", 64),
            vec![(1, 29)]
        );
        let long_scalar = concat!(
            "VkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            "QUFBQUFBQUFBQUFBQUFBQUFBCi4=",
        );
        assert_eq!(
            confirmed_base64_pickle_spans(
                format!("!{long_scalar}ab").as_bytes(),
                TEST_MAX_NESTED_PICKLE_BYTES,
            ),
            vec![(1, 1 + long_scalar.len())]
        );
        assert!(confirmed_base64_pickle_spans(b"gAR9LgNQ", 64).is_empty());
        assert!(confirmed_base64_pickle_spans(b"=gAR9Lg=", 64).is_empty());
        assert!(confirmed_base64_pickle_spans(b"NQAAAAAAgAROLg==", 64).is_empty());
    }

    #[test]
    fn protocol0_operand_limit_requires_prior_structured_opcode() {
        let mut payload = b"cos\nsystem\n(S'".to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
            b'A',
        );

        let error = pickle_payload_extent_result(&payload, payload.len() + 16)
            .expect_err("overlong nested operand should preserve its parse error");
        assert!(error.is_structured_protocol0_line_operand_limit());
    }

    #[test]
    fn protocol0_operand_limit_tracks_structured_evidence_beyond_prefix_probe() {
        let mut payload = b"(NNNNcos\nsystem\n(S'".to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
            b'A',
        );

        let error = pickle_payload_extent_result(&payload, payload.len() + 16)
            .expect_err("structured evidence after setup opcodes should survive the operand cap");
        assert!(error.is_structured_protocol0_line_operand_limit());
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
    fn truncated_prefix_fail_closed_handles_minimum_evidence_and_near_matches() {
        assert!(truncated_pickle_prefix_requires_fail_closed(b"\x80\x00"));
        assert!(truncated_pickle_prefix_requires_fail_closed(b"\x80\x04"));
        assert!(!truncated_pickle_prefix_requires_fail_closed(b"\x80\x06"));
        assert!(truncated_pickle_prefix_requires_fail_closed(b"cp"));
        assert!(truncated_pickle_prefix_requires_fail_closed(b"cposix\n"));
        assert!(!truncated_pickle_prefix_requires_fail_closed(b"c"));
        assert!(!truncated_pickle_prefix_requires_fail_closed(b"c\xff"));
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
        assert_eq!(
            nested_pickle_probe_offsets_unbounded(b"cxxx\nxxx\n)R."),
            vec![0]
        );
        assert!(nested_pickle_probe_offsets_unbounded(b"config\nvalue\nplain prose").is_empty());
        assert!(nested_pickle_probe_offsets_unbounded(b"config\nvalue\nplain prose\n").is_empty());
        assert!(nested_pickle_probe_offsets_unbounded(b"instance\nvalue\nplain prose").is_empty());
        assert!(
            nested_pickle_probe_offsets_unbounded(b"instance\nvalue\nplain prose\n").is_empty()
        );
        assert!(
            nested_pickle_probe_offsets_unbounded(
                b"instance prose instance instance audit\nlist status prose nested config nested list\nclient budget value\nstatus audit audit audit nested plain client\n",
            )
            .is_empty()
        );
        assert!(
            nested_pickle_probe_offsets_unbounded(
                b"client config instance\nvalue list budget client\nclient nested model\naudit instance plain config budget client report\n",
            )
            .is_empty()
        );
        assert!(
            nested_pickle_probe_offsets_unbounded(
                b"client plain config report instance list client instance\nstatus\nconfig\ninstance budget report value\n",
            )
            .is_empty()
        );
        assert!(nested_pickle_probe_offsets_unbounded(
            b"audit client\nbudget instance instance budget instance\nplain\nprose client status\n",
        )
        .is_empty());
        assert!(
            nested_pickle_probe_offsets_unbounded(b"client\nstatus\njust plain prose\nget\n")
                .is_empty()
        );
        let mut long_global = b"cattacker\nfactory\n(".to_vec();
        long_global.extend_from_slice(&vec![b'N'; 2000]);
        long_global.extend_from_slice(b"tR.");
        assert!(nested_pickle_probe_offsets_unbounded(&long_global).contains(&0));
        let mut long_global_operand = b"cattacker\nfactory\n(V".to_vec();
        long_global_operand.extend_from_slice(&vec![b'A'; 2000]);
        long_global_operand.extend_from_slice(b"\ntR.");
        assert!(nested_pickle_probe_offsets_unbounded(&long_global_operand).contains(&0));
        let mut long_binary_operand = b"cattacker\nfactory\nX".to_vec();
        long_binary_operand.extend_from_slice(&2000u32.to_le_bytes());
        long_binary_operand.extend_from_slice(&vec![b'A'; 2000]);
        long_binary_operand.extend_from_slice(b"\x85R.");
        assert!(nested_pickle_probe_offsets_unbounded(&long_binary_operand).contains(&0));
        assert!(nested_pickle_probe_offsets_unbounded(b"cos\nsystem\nAAAAAAAA").contains(&0));
        assert_eq!(
            nested_pickle_probe_offsets_unbounded(b"(ios\nsystem\n."),
            vec![0]
        );
        assert_eq!(nested_pickle_probe_offsets_unbounded(b"(d."), vec![0]);
        assert_eq!(nested_pickle_probe_offsets_unbounded(b"(l."), vec![0]);
        assert!(oversized_decoded_pickle_prefix_requires_fail_closed(
            b"\x80\x06cos\nsystem\n)R.",
            2
        ));
        assert!(!oversized_decoded_pickle_prefix_requires_fail_closed(
            b"config\nvalue\nplain prose",
            2
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

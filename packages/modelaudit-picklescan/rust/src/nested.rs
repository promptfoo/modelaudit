use crate::opcode::{parse_opcode, ParseError, ParsedOpcode, MAX_PROTOCOL0_LINE_OPERAND_BYTES};
use crate::policy::global_module_has_dangerous_callables;

const BASE64_LITERAL_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_LITERAL_CHARS: &[u8] = b"0123456789abcdefABCDEF";
const ENCODED_LITERAL_PROBE_CHARS: usize = 64;
pub(crate) const MAX_NESTED_PAYLOAD_PROBES: usize = 64;
const MAX_ENCODED_LITERAL_MID_SCAN_BYTES: usize = 1024 * 1024;
const OVERSIZED_ENCODED_PICKLE_SUFFIX_PROBE_BYTES: usize = 64 * 1024;
const OVERSIZED_ENCODED_PICKLE_INITIAL_PROBE_BYTES: usize = 512;

pub(crate) struct NestedProbeOffsets {
    pub(crate) offsets: Vec<usize>,
    pub(crate) limit_exceeded: bool,
}

pub(crate) struct EncodedNestedProbeWindows {
    pub(crate) windows: Vec<String>,
    pub(crate) limit_exceeded: bool,
    pub(crate) limit_exceeded_encoding: Option<&'static str>,
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

    pub(crate) fn is_structured_protocol0_line_operand_truncated(&self) -> bool {
        self.structured_pickle_evidence && self.error.is_protocol0_line_operand_truncated()
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

    let mut decoded_values = Vec::new();
    let max_base64_nested_pickle_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_hex_nested_pickle_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_nested_pickle_chars = max_nested_pickle_bytes * 4;

    for candidate in encoded_literal_candidates(stripped) {
        if base64_prefix_has_pickle_prefix(&candidate) && is_base64_candidate(&candidate) {
            let bounded = take_bytes_str(&candidate, max_base64_nested_pickle_chars);
            let padded = pad_base64(&bounded);
            if let Some(decoded) = decode_base64(&padded) {
                for (payload, analysis_incomplete) in
                    decoded_pickle_payloads(&decoded, max_nested_pickle_bytes)
                {
                    decoded_values.push(DecodedNestedPayload {
                        encoding: "base64",
                        payload,
                        analysis_incomplete,
                    });
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

pub(crate) fn detect_oversized_encoded_pickle_prefixes(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<(&'static str, usize)> {
    let stripped = value.trim();
    if stripped.len() < 16 {
        return Vec::new();
    }

    let mut detected = Vec::new();
    let probe_decoded_bytes = max_nested_pickle_bytes.saturating_add(1).max(2);
    let proof_decoded_bytes = probe_decoded_bytes.max(
        MAX_PROTOCOL0_LINE_OPERAND_BYTES
            .saturating_add(1)
            .saturating_add(OVERSIZED_ENCODED_PICKLE_SUFFIX_PROBE_BYTES),
    );

    let base64_literal = take_base64_literal_prefix(stripped);
    if encoded_base64_first_byte(base64_literal.as_bytes()).is_some_and(is_pickle_prefix_start_byte)
        && is_base64_candidate(base64_literal)
    {
        let payload_size = estimate_base64_decoded_size(base64_literal);
        let initial =
            decode_base64_prefix(base64_literal, OVERSIZED_ENCODED_PICKLE_INITIAL_PROBE_BYTES);
        if payload_size > max_nested_pickle_bytes
            && initial
                .as_deref()
                .is_some_and(encoded_oversized_pickle_prefix_is_plausible)
            && decode_base64_prefix(base64_literal, proof_decoded_bytes).is_some_and(|decoded| {
                oversized_decoded_pickle_prefix_requires_fail_closed(
                    &decoded,
                    max_nested_pickle_bytes,
                    decoded.len() >= payload_size,
                )
            })
        {
            detected.push(("base64", payload_size));
        }
    }

    let hex_literal = take_hex_literal_prefix(stripped);
    if encoded_hex_first_byte(hex_literal.as_bytes()).is_some_and(is_pickle_prefix_start_byte) {
        let encoding = hex_encoding_label(hex_literal);
        if let Some(payload_size) = hex_decoded_size(hex_literal) {
            let initial =
                decode_hex_prefix(hex_literal, OVERSIZED_ENCODED_PICKLE_INITIAL_PROBE_BYTES);
            if payload_size > max_nested_pickle_bytes
                && initial
                    .as_deref()
                    .is_some_and(encoded_oversized_pickle_prefix_is_plausible)
                && decode_hex_prefix(hex_literal, proof_decoded_bytes).is_some_and(|decoded| {
                    oversized_decoded_pickle_prefix_requires_fail_closed(
                        &decoded,
                        max_nested_pickle_bytes,
                        decoded.len() >= payload_size,
                    )
                })
            {
                detected.push((encoding, payload_size));
            }
        }
    }

    detected
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
    pickle_payload_extent_result_unchecked(value)
}

fn pickle_payload_extent_result_unchecked(
    value: &[u8],
) -> Result<Option<usize>, PicklePayloadExtentError> {
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths: Vec<usize> = Vec::new();
    let mut structured_pickle_evidence = has_binary_pickle_prefix(value);
    while index < value.len() {
        let parsed = parse_opcode(value, index, value.len()).map_err(|error| {
            let structured_suffix_evidence =
                protocol0_line_operand_failure_has_structured_evidence(value, index, &error);
            PicklePayloadExtentError {
                error,
                structured_pickle_evidence: structured_pickle_evidence
                    || structured_suffix_evidence,
            }
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

pub(crate) fn has_structured_execution_prefix(value: &[u8]) -> bool {
    has_execution_opcode(value) && pickle_prefix_has_structured_opcodes(value, true)
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
        || protocol0_global_or_inst_prefix_has_long_or_overlimit_name_line(value)
        || matches!(value[0], b'(' | b'd' | b'l' | b'I' | b'S' | b'V')
        || pickle_prefix_has_structured_opcodes(value, false)
}

pub(crate) fn has_binary_pickle_prefix(value: &[u8]) -> bool {
    value.len() >= 2 && value[0] == 0x80 && matches!(value[1], 1..=5)
}

pub(crate) fn truncated_pickle_prefix_requires_fail_closed(value: &[u8]) -> bool {
    (has_binary_pickle_prefix(value) && pickle_prefix_has_structured_opcodes(value, true))
        || protocol0_global_or_inst_prefix_has_lines(value)
        || protocol0_global_or_inst_prefix_has_long_or_overlimit_name_line(value)
        || has_execution_opcode(value)
}

pub(crate) fn protocol0_global_or_inst_prefix_has_import_reference_lines(value: &[u8]) -> bool {
    let Some((module, name)) = protocol0_global_or_inst_prefix_fields(value) else {
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
        if matches!(parsed.name, "GLOBAL" | "INST")
            && !protocol0_opcode_operands_are_plausible(&parsed, value)
        {
            return false;
        }
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

pub(crate) fn protocol0_global_or_inst_prefix_has_long_or_overlimit_name_line(
    value: &[u8],
) -> bool {
    let Some((module, name_start)) = protocol0_global_or_inst_prefix_module_line(value) else {
        return false;
    };
    if !is_protocol0_import_reference(module) {
        return false;
    }

    let bounded_name_end = value
        .len()
        .min(name_start.saturating_add(MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1));
    let name_probe = &value[name_start..bounded_name_end];
    match name_probe.iter().position(|byte| *byte == b'\n') {
        Some(name_end) => {
            name_end > 256
                && protocol0_global_or_inst_suffix_is_structured(
                    &value[name_start + name_end + 1..],
                )
        }
        None => {
            name_probe.len() > MAX_PROTOCOL0_LINE_OPERAND_BYTES
                && std::str::from_utf8(module)
                    .ok()
                    .is_some_and(global_module_has_dangerous_callables)
        }
    }
}

fn protocol0_global_or_inst_suffix_is_structured(value: &[u8]) -> bool {
    let mut index = 0usize;
    let mut stack_depth = 1usize;
    let mut mark_depths = Vec::new();
    let mut parsed_count = 0usize;
    while index < value.len() && parsed_count < 64 {
        let Ok(parsed) = parse_opcode(value, index, value.len()) else {
            return false;
        };
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        parsed_count += 1;
        index = parsed.next;
        if parsed.name == "STOP" {
            return stack_depth > 0;
        }
    }
    false
}

fn encoded_oversized_pickle_prefix_is_plausible(value: &[u8]) -> bool {
    has_pickle_prefix(value) || protocol0_global_or_inst_prefix_has_valid_module_line(value)
}

fn oversized_decoded_pickle_prefix_requires_fail_closed(
    value: &[u8],
    max_nested_pickle_bytes: usize,
    decoded_complete: bool,
) -> bool {
    match pickle_payload_extent_result_unchecked(value) {
        Ok(Some(payload_len)) => payload_len > max_nested_pickle_bytes,
        Err(error) if error.is_structured_protocol0_line_operand_limit() => {
            value.len() > max_nested_pickle_bytes
        }
        Err(error)
            if !decoded_complete && error.is_structured_protocol0_line_operand_truncated() =>
        {
            value.len() > max_nested_pickle_bytes
        }
        Ok(None) | Err(_) => {
            protocol0_global_or_inst_prefix_has_long_or_overlimit_name_line(value)
                || (!decoded_complete
                    && value.len() > max_nested_pickle_bytes
                    && truncated_pickle_prefix_requires_fail_closed(value))
        }
    }
}

fn protocol0_global_or_inst_prefix_has_valid_module_line(value: &[u8]) -> bool {
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths = Vec::new();
    for _ in 0..8 {
        let opcode = value.get(index).copied();
        if matches!(opcode, Some(b'c' | b'i')) {
            let Some((module, _)) = protocol0_global_or_inst_prefix_module_line(&value[index..])
            else {
                return false;
            };
            return is_protocol0_import_reference(module);
        }
        let Ok(parsed) = parse_opcode(value, index, value.len()) else {
            return false;
        };
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        index = parsed.next;
        if parsed.name == "STOP" || index >= value.len() {
            return false;
        }
    }
    false
}

fn protocol0_line_operand_failure_has_structured_evidence(
    value: &[u8],
    opcode_index: usize,
    error: &ParseError,
) -> bool {
    if !error.is_protocol0_line_operand_limit() && !error.is_protocol0_line_operand_truncated() {
        return false;
    }
    if matches!(value.get(opcode_index).copied(), Some(b'c' | b'i')) {
        return true;
    }
    if !error.is_protocol0_line_operand_limit() {
        return false;
    }
    let search_start = error.report_index.unwrap_or(0).min(value.len());
    let Some(relative_newline) = value[search_start..].iter().position(|byte| *byte == b'\n')
    else {
        return false;
    };
    let suffix_start = search_start
        .saturating_add(relative_newline)
        .saturating_add(1);
    protocol0_suffix_has_structured_execution(&value[suffix_start..])
}

fn protocol0_suffix_has_structured_execution(value: &[u8]) -> bool {
    let probe_offsets = nested_pickle_probe_offsets(value);
    if probe_offsets.limit_exceeded {
        return true;
    }
    probe_offsets.offsets.into_iter().any(|offset| {
        let candidate = &value[offset..];
        match pickle_payload_extent_result(candidate, candidate.len()) {
            Ok(Some(payload_len)) => has_execution_opcode(&candidate[..payload_len]),
            Err(error) => error.is_structured_protocol0_line_operand_limit(),
            Ok(None) => false,
        }
    })
}

fn protocol0_global_or_inst_prefix_has_lines(value: &[u8]) -> bool {
    let Some((module, name)) = protocol0_global_or_inst_prefix_fields(value) else {
        return false;
    };
    is_protocol0_global_operand(module) && (name.is_empty() || is_protocol0_global_operand(name))
}

fn protocol0_global_or_inst_prefix_has_complete_lines(value: &[u8]) -> bool {
    let Some((module, name)) = protocol0_global_or_inst_prefix_fields(value) else {
        return false;
    };
    is_protocol0_global_operand(module) && is_protocol0_global_operand(name)
}

fn protocol0_global_or_inst_prefix_fields(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let (module, name_start) = protocol0_global_or_inst_prefix_module_line(value)?;
    let bounded_name_end = value.len().min(name_start.saturating_add(257));
    let name = match value[name_start..bounded_name_end]
        .iter()
        .position(|byte| *byte == b'\n')
    {
        Some(relative_end) => &value[name_start..name_start + relative_end],
        None if bounded_name_end == value.len() => &value[name_start..],
        None => return None,
    };
    Some((module, name))
}

fn protocol0_global_or_inst_prefix_module_line(value: &[u8]) -> Option<(&[u8], usize)> {
    if !matches!(value.first().copied(), Some(b'c' | b'i')) {
        return None;
    }
    let bounded_module_end = value.len().min(258);
    let relative_end = value[1..bounded_module_end]
        .iter()
        .position(|byte| *byte == b'\n')?;
    let module_end = 1 + relative_end;
    Some((&value[1..module_end], module_end + 1))
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
    if std::str::from_utf8(value)
        .ok()
        .is_some_and(is_whole_encoded_pickle_literal)
    {
        return NestedProbeOffsets {
            offsets: Vec::new(),
            limit_exceeded: false,
        };
    }

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

pub(crate) fn is_whole_encoded_pickle_literal(value: &str) -> bool {
    let stripped = value.trim();
    let prefix_has_base64_pickle = base64_prefix_has_pickle_prefix(stripped);
    let prefix_has_hex_pickle = !prefix_has_base64_pickle && hex_prefix_has_pickle_prefix(stripped);
    (prefix_has_base64_pickle || prefix_has_hex_pickle)
        && encoded_prefix_consumes_literal(
            stripped,
            prefix_has_base64_pickle,
            prefix_has_hex_pickle,
        )
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
    let prefix = take_bytes_str(candidate, candidate.len().min(ENCODED_LITERAL_PROBE_CHARS));
    let padded = pad_base64(&prefix);
    decode_base64(&padded)
        .map(|decoded| has_pickle_prefix(&decoded))
        .unwrap_or(false)
}

fn hex_prefix_has_pickle_prefix(value: &str) -> bool {
    let candidate = take_hex_literal_prefix(value);
    let mut hex_candidate =
        strip_escaped_hex_markers(&take_bytes_str(candidate, ENCODED_LITERAL_PROBE_CHARS * 4));
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

fn take_base64_literal_prefix(value: &str) -> &str {
    let mut end = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        if BASE64_LITERAL_CHARS.contains(&byte) {
            end = index + 1;
            continue;
        }
        break;
    }
    &value[..end]
}

fn take_hex_literal_prefix(value: &str) -> &str {
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
    &value[..index]
}

fn decode_base64_prefix(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let max_chars = max_bytes.div_ceil(3).saturating_mul(4);
    let bounded = take_bytes_str(value, value.len().min(max_chars));
    let mut decoded = decode_base64(&pad_base64(&bounded))?;
    decoded.truncate(max_bytes);
    Some(decoded)
}

fn decode_hex_prefix(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(max_bytes.min(bytes.len() / 2));
    let mut index = 0usize;
    while index < bytes.len() && decoded.len() < max_bytes {
        let (byte, next) = decode_hex_token(bytes, index)?;
        decoded.push(byte);
        index = next;
    }
    Some(decoded)
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
    (value.len().saturating_mul(3) / 4).saturating_sub(padding_chars)
}

fn hex_decoded_size(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    let mut decoded_size = 0usize;
    while index < bytes.len() {
        let (_, next) = decode_hex_token(bytes, index)?;
        decoded_size = decoded_size.saturating_add(1);
        index = next;
    }
    Some(decoded_size)
}

fn decode_hex_token(value: &[u8], index: usize) -> Option<(u8, usize)> {
    if value.get(index) == Some(&b'\\') && matches!(value.get(index + 1), Some(b'x' | b'X')) {
        let high = hex_value(*value.get(index + 2)?)?;
        let low = hex_value(*value.get(index + 3)?)?;
        return Some(((high << 4) | low, index + 4));
    }
    let high = hex_value(*value.get(index)?)?;
    let low = hex_value(*value.get(index + 1)?)?;
    Some(((high << 4) | low, index + 2))
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
mod tests;

use std::collections::{HashMap, HashSet};

use crate::opcode::{parse_opcode, ParsedOpcode};
use crate::policy::global_severity;
use crate::stack::{
    collapse_tuple_values, resolve_global_operand, stack_value_from_integer_arg,
    stack_value_from_text_arg, GlobalRef, StackValue,
};

const POST_BUDGET_REDUCE_PROXIMITY_BYTES: usize = 64;
const POST_BUDGET_REDUCE_BYTES: &[u8] = b"Rob\x81\x92";

pub(crate) struct PostBudgetGlobalMatch {
    pub(crate) module: String,
    pub(crate) name: String,
    pub(crate) pattern_start: usize,
    pub(crate) reduce_proximate: bool,
    pub(crate) severity: &'static str,
}

impl PostBudgetGlobalMatch {
    pub(crate) fn pattern(&self) -> String {
        format!("{}\n{}", self.module, self.name)
    }
}

struct PostBudgetGlobalCandidate<'a> {
    module: &'a str,
    name: &'a str,
    pattern_start: usize,
    proximity_start: usize,
    severity: &'static str,
    force_reduce_proximate: bool,
}

struct PostBudgetRecordSink<'a> {
    seen: &'a mut HashSet<(usize, String, String)>,
    matches: &'a mut Vec<PostBudgetGlobalMatch>,
}

pub(crate) fn post_budget_global_matches(
    tail: &[u8],
    tail_prefix_len: usize,
    initial_stack: &[StackValue],
    initial_memo_len: usize,
    resolve_memo_value: impl Fn(i64) -> Option<StackValue>,
) -> Vec<PostBudgetGlobalMatch> {
    let mut matches = Vec::new();
    let mut seen = HashSet::new();

    record_post_budget_opcode_stream(
        tail,
        tail_prefix_len,
        initial_stack,
        initial_memo_len,
        &resolve_memo_value,
        &mut seen,
        &mut matches,
    );

    if tail_prefix_len > 0 {
        record_post_budget_module_name_pair(tail, 0, 0, &mut seen, &mut matches);
    }

    let mut index = 0;
    while index < tail.len() {
        if matches!(tail[index], b'c' | b'i') {
            record_post_budget_module_name_pair(
                tail,
                index + 1,
                index + 1,
                &mut seen,
                &mut matches,
            );
        }
        record_post_budget_extension_ref(tail, index, &mut seen, &mut matches);
        index += 1;
    }

    matches
}

pub(crate) fn post_budget_absolute_position(
    stream_offset: usize,
    read_offset: usize,
    tail_prefix_len: usize,
    tail_offset: usize,
) -> usize {
    if tail_offset < tail_prefix_len {
        stream_offset.saturating_add(tail_offset)
    } else {
        read_offset.saturating_add(tail_offset - tail_prefix_len)
    }
}

fn record_post_budget_module_name_pair(
    tail: &[u8],
    module_start: usize,
    pattern_start: usize,
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    let Some(module_end) = find_byte_from(tail, module_start, b'\n') else {
        return;
    };
    let name_start = module_end.saturating_add(1);
    let Some(name_end) = find_byte_from(tail, name_start, b'\n') else {
        return;
    };
    if module_start == module_end || name_start == name_end {
        return;
    }
    let Ok(module) = std::str::from_utf8(&tail[module_start..module_end]) else {
        return;
    };
    let Ok(name) = std::str::from_utf8(&tail[name_start..name_end]) else {
        return;
    };
    let Some(severity) = post_budget_global_severity(module, name) else {
        return;
    };
    if !seen.insert((pattern_start, module.to_string(), name.to_string())) {
        return;
    }
    let reduce_proximate = has_reduce_class_byte_nearby(tail, name_end.saturating_add(1));
    matches.push(PostBudgetGlobalMatch {
        module: module.to_string(),
        name: name.to_string(),
        pattern_start,
        reduce_proximate,
        severity,
    });
}

fn record_post_budget_opcode_stream(
    tail: &[u8],
    start_index: usize,
    initial_stack: &[StackValue],
    initial_memo_len: usize,
    resolve_memo_value: &impl Fn(i64) -> Option<StackValue>,
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    let mut stack = initial_stack.to_vec();
    let mut memo_overlay: HashMap<i64, StackValue> = HashMap::new();
    let initial_memo_len = i64::try_from(initial_memo_len).unwrap_or(i64::MAX);
    let mut memo_len = initial_memo_len;
    let mut index = start_index.min(tail.len());
    let mut sink = PostBudgetRecordSink { seen, matches };

    while index < tail.len() {
        let parsed = match parse_opcode(tail, index, tail.len()) {
            Ok(parsed) => parsed,
            Err(error) if error.report_index.is_none() => {
                stack.clear();
                memo_overlay.clear();
                memo_len = initial_memo_len;
                index += 1;
                continue;
            }
            Err(_) => break,
        };

        handle_post_budget_opcode(
            &parsed,
            tail,
            &mut stack,
            &mut memo_overlay,
            &mut memo_len,
            resolve_memo_value,
            &mut sink,
        );

        index = parsed.next;
        if parsed.name == "STOP" {
            break;
        }
    }
}

fn handle_post_budget_opcode(
    opcode: &ParsedOpcode,
    tail: &[u8],
    stack: &mut Vec<StackValue>,
    memo_overlay: &mut HashMap<i64, StackValue>,
    memo_len: &mut i64,
    resolve_memo_value: &impl Fn(i64) -> Option<StackValue>,
    sink: &mut PostBudgetRecordSink<'_>,
) {
    match opcode.name {
        "PROTO" | "FRAME" | "STOP" => {}
        name if is_post_budget_text_opcode(name) => {
            stack.push(stack_value_from_text_arg(&opcode.arg, tail));
        }
        "NONE" => stack.push(StackValue::Primitive {
            type_name: "NoneType",
            repr: "None".to_string(),
        }),
        "NEWTRUE" => stack.push(StackValue::Primitive {
            type_name: "bool",
            repr: "True".to_string(),
        }),
        "NEWFALSE" => stack.push(StackValue::Primitive {
            type_name: "bool",
            repr: "False".to_string(),
        }),
        "BININT" | "BININT1" | "BININT2" | "LONG" | "LONG1" | "LONG4" | "INT" => {
            stack.push(stack_value_from_integer_arg(&opcode.arg, tail));
        }
        "FLOAT" | "BINFLOAT" => stack.push(StackValue::Other),
        "BINBYTES" | "BINBYTES8" | "SHORT_BINBYTES" | "BYTEARRAY8" => {
            if let Some((start, end)) = opcode.arg.byte_span(tail.len()) {
                stack.push(StackValue::Bytes { start, end });
            } else {
                stack.push(StackValue::Bytes { start: 0, end: 0 });
            }
        }
        "NEXT_BUFFER" => stack.push(StackValue::Other),
        "READONLY_BUFFER" => {}
        "MARK" => stack.push(StackValue::Mark),
        "POP" => {
            stack.pop();
        }
        "DUP" => {
            if let Some(value) = stack.last().cloned() {
                stack.push(value);
            }
        }
        "POP_MARK" => {
            pop_to_mark(stack);
        }
        "EMPTY_TUPLE" => stack.push(StackValue::Tuple(Vec::new())),
        "EMPTY_LIST" | "EMPTY_DICT" | "EMPTY_SET" => stack.push(StackValue::Other),
        "TUPLE" => {
            let values = pop_to_mark(stack);
            stack.push(collapse_tuple_values(values));
        }
        "LIST" | "DICT" | "SET" | "FROZENSET" => {
            pop_to_mark(stack);
            stack.push(StackValue::Other);
        }
        "TUPLE1" => collapse_top_n(stack, 1),
        "TUPLE2" => collapse_top_n(stack, 2),
        "TUPLE3" => collapse_top_n(stack, 3),
        "APPEND" | "SETITEM" => {
            pop_value_operand_preserving_mark(stack);
            if opcode.name == "SETITEM" {
                pop_value_operand_preserving_mark(stack);
            }
        }
        "APPENDS" | "SETITEMS" | "ADDITEMS" => {
            pop_to_mark(stack);
        }
        "PUT" | "BINPUT" | "LONG_BINPUT" => {
            if let (Some(index), Some(value)) = (opcode.arg.as_i64(), stack.last().cloned()) {
                if memo_overlay.insert(index, value).is_none()
                    && resolve_memo_value(index).is_none()
                {
                    *memo_len = (*memo_len).saturating_add(1);
                }
            }
        }
        "MEMOIZE" => {
            if let Some(value) = stack.last().cloned() {
                memo_overlay.insert(*memo_len, value);
                *memo_len = (*memo_len).saturating_add(1);
            }
        }
        "GET" | "BINGET" | "LONG_BINGET" => {
            if let Some(index) = opcode.arg.as_i64() {
                let value = memo_overlay
                    .get(&index)
                    .cloned()
                    .or_else(|| resolve_memo_value(index))
                    .unwrap_or(StackValue::Other);
                stack.push(value);
            }
        }
        "GLOBAL" => {
            let (module, name) = opcode.arg.global_parts(tail);
            let reference = GlobalRef {
                module,
                name,
                position: opcode.pos,
                malformed: false,
                memo_index: None,
                memo_read: false,
            };
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, false, opcode.next, tail, sink);
        }
        "STACK_GLOBAL" => {
            let name_value = stack.pop();
            let module_value = stack.pop();
            let reference =
                resolve_post_budget_stack_global(module_value, name_value, opcode.pos, tail);
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, false, opcode.next, tail, sink);
        }
        "EXT1" | "EXT2" | "EXT4" => {
            let extension_code = opcode.arg.as_i64().unwrap_or_default();
            let reference = GlobalRef {
                module: "copyreg.extension".to_string(),
                name: format!("code_{extension_code}"),
                position: opcode.pos,
                malformed: true,
                memo_index: None,
                memo_read: false,
            };
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, false, opcode.next, tail, sink);
        }
        "REDUCE" | "NEWOBJ" => {
            let callable_value = consume_top_operands(stack, 2);
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        "NEWOBJ_EX" => {
            let callable_value = consume_top_operands(stack, 3);
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        "OBJ" => {
            let values = pop_to_mark(stack);
            let callable_value = values.into_iter().next();
            push_constructed_result(stack, callable_value.as_ref());
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        "INST" => {
            pop_to_mark(stack);
            let (module, name) = opcode.arg.global_parts(tail);
            let reference = GlobalRef {
                module,
                name,
                position: opcode.pos,
                malformed: false,
                memo_index: None,
                memo_read: false,
            };
            stack.push(StackValue::Constructed(reference.clone()));
            record_post_budget_global_ref(&reference, true, opcode.next, tail, sink);
        }
        "BUILD" => {
            let callable_value = consume_top_operands(stack, 2);
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        _ => {}
    }
}

fn is_post_budget_text_opcode(name: &str) -> bool {
    matches!(
        name,
        "BINSTRING"
            | "BINUNICODE"
            | "BINUNICODE8"
            | "SHORT_BINSTRING"
            | "SHORT_BINUNICODE"
            | "STRING"
            | "UNICODE"
    )
}

fn resolve_post_budget_stack_global(
    module_value: Option<StackValue>,
    name_value: Option<StackValue>,
    position: usize,
    tail: &[u8],
) -> GlobalRef {
    let module = resolve_global_operand(module_value.as_ref(), tail);
    let name = resolve_global_operand(name_value.as_ref(), tail);
    match (module, name) {
        (Some(module), Some(name)) => GlobalRef {
            module,
            name,
            position,
            malformed: false,
            memo_index: None,
            memo_read: false,
        },
        (module, name) => GlobalRef {
            module: module.unwrap_or_else(|| "__unknown__".to_string()),
            name: name.unwrap_or_else(|| "__unknown__".to_string()),
            position,
            malformed: true,
            memo_index: None,
            memo_read: false,
        },
    }
}

fn record_post_budget_callable_value(
    callable_value: Option<StackValue>,
    proximity_start: usize,
    tail: &[u8],
    sink: &mut PostBudgetRecordSink<'_>,
) {
    let Some(StackValue::Global(reference) | StackValue::Constructed(reference)) = callable_value
    else {
        return;
    };
    if reference.malformed && reference.module != "copyreg.extension" {
        return;
    }
    record_post_budget_global_ref(&reference, true, proximity_start, tail, sink);
}

fn record_post_budget_global_ref(
    reference: &GlobalRef,
    force_reduce_proximate: bool,
    proximity_start: usize,
    tail: &[u8],
    sink: &mut PostBudgetRecordSink<'_>,
) {
    if reference.malformed && reference.module != "copyreg.extension" {
        return;
    }
    let Some(severity) = post_budget_global_severity(&reference.module, &reference.name) else {
        return;
    };
    record_post_budget_global_with_severity(
        PostBudgetGlobalCandidate {
            module: &reference.module,
            name: &reference.name,
            pattern_start: reference.position,
            proximity_start,
            severity,
            force_reduce_proximate,
        },
        tail,
        sink.seen,
        sink.matches,
    );
}

fn pop_value_operand_preserving_mark(stack: &mut Vec<StackValue>) -> Option<StackValue> {
    match stack.pop() {
        Some(StackValue::Mark) => {
            stack.push(StackValue::Mark);
            None
        }
        value => value,
    }
}

fn pop_to_mark(stack: &mut Vec<StackValue>) -> Vec<StackValue> {
    let mut values = Vec::new();
    while let Some(item) = stack.pop() {
        if matches!(item, StackValue::Mark) {
            break;
        }
        values.push(item);
    }
    values.reverse();
    values
}

fn collapse_top_n(stack: &mut Vec<StackValue>, count: usize) {
    if stack.len() < count {
        stack.push(StackValue::Other);
        return;
    }
    let start = stack.len().saturating_sub(count);
    if stack[start..]
        .iter()
        .any(|value| matches!(value, StackValue::Mark))
    {
        stack.push(StackValue::Other);
        return;
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        if let Some(value) = stack.pop() {
            values.push(value);
        }
    }
    values.reverse();
    stack.push(collapse_tuple_values(values));
}

fn consume_top_operands(stack: &mut Vec<StackValue>, operand_count: usize) -> Option<StackValue> {
    if stack.len() < operand_count {
        stack.push(StackValue::Other);
        return None;
    }
    let mut values = Vec::with_capacity(operand_count);
    for _ in 0..operand_count {
        if let Some(value) = stack.pop() {
            values.push(value);
        }
    }
    values.reverse();
    let callable_value = values.into_iter().next();
    push_constructed_result(stack, callable_value.as_ref());
    callable_value
}

fn push_constructed_result(stack: &mut Vec<StackValue>, callable_value: Option<&StackValue>) {
    match callable_value {
        Some(StackValue::Global(reference) | StackValue::Constructed(reference))
            if !reference.malformed =>
        {
            stack.push(StackValue::Constructed(reference.clone()));
        }
        _ => stack.push(StackValue::Other),
    }
}

fn record_post_budget_extension_ref(
    tail: &[u8],
    index: usize,
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    let Some((extension_code, next)) = read_post_budget_extension_code(tail, index) else {
        return;
    };
    record_post_budget_global_with_severity(
        PostBudgetGlobalCandidate {
            module: "copyreg.extension",
            name: &format!("code_{extension_code}"),
            pattern_start: index,
            proximity_start: next,
            severity: "warning",
            force_reduce_proximate: false,
        },
        tail,
        seen,
        matches,
    );
}

fn read_post_budget_extension_code(tail: &[u8], index: usize) -> Option<(u64, usize)> {
    match *tail.get(index)? {
        0x82 => Some((
            *tail.get(index.saturating_add(1))? as u64,
            index.saturating_add(2),
        )),
        0x83 => {
            let start = index.saturating_add(1);
            let end = start.checked_add(2)?;
            Some((
                u16::from_le_bytes(tail.get(start..end)?.try_into().ok()?) as u64,
                end,
            ))
        }
        0x84 => {
            let start = index.saturating_add(1);
            let end = start.checked_add(4)?;
            Some((
                u32::from_le_bytes(tail.get(start..end)?.try_into().ok()?) as u64,
                end,
            ))
        }
        _ => None,
    }
}

fn record_post_budget_global_with_severity(
    candidate: PostBudgetGlobalCandidate<'_>,
    tail: &[u8],
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    if candidate.module.is_empty() || candidate.name.is_empty() {
        return;
    }
    let key = (
        candidate.pattern_start,
        candidate.module.to_string(),
        candidate.name.to_string(),
    );
    let reduce_proximate = candidate.force_reduce_proximate
        || has_reduce_class_byte_nearby(tail, candidate.proximity_start);
    if !seen.insert(key) {
        if reduce_proximate {
            if let Some(existing) = matches.iter_mut().find(|existing| {
                existing.pattern_start == candidate.pattern_start
                    && existing.module == candidate.module
                    && existing.name == candidate.name
            }) {
                existing.reduce_proximate = true;
                existing.severity = stronger_severity(existing.severity, candidate.severity);
            }
        }
        return;
    }
    matches.push(PostBudgetGlobalMatch {
        module: candidate.module.to_string(),
        name: candidate.name.to_string(),
        pattern_start: candidate.pattern_start,
        reduce_proximate,
        severity: candidate.severity,
    });
}

fn stronger_severity(left: &'static str, right: &'static str) -> &'static str {
    if severity_rank(right) > severity_rank(left) {
        right
    } else {
        left
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "warning" => 3,
        "info" => 2,
        _ => 1,
    }
}

fn post_budget_global_severity(module: &str, name: &str) -> Option<&'static str> {
    if module == "__main__" {
        return Some("warning");
    }
    global_severity(module, name)
}

fn has_reduce_class_byte_nearby(tail: &[u8], start: usize) -> bool {
    let end = start
        .saturating_add(POST_BUDGET_REDUCE_PROXIMITY_BYTES)
        .min(tail.len());
    tail[start..end]
        .iter()
        .any(|byte| POST_BUDGET_REDUCE_BYTES.contains(byte))
}

fn find_byte_from(haystack: &[u8], start: usize, needle: u8) -> Option<usize> {
    haystack
        .get(start..)?
        .iter()
        .position(|byte| *byte == needle)
        .map(|offset| start + offset)
}

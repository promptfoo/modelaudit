use std::collections::{hash_map::Entry, HashMap};

use crate::opcode::{parse_opcode, ArgValue, ParsedOpcode, STACK_GLOBAL_STRING_OPCODES};
use crate::policy::global_severity;
use crate::stack::{stack_value_from_text_arg, GlobalRef, StackValue};

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

#[derive(Default)]
struct PostBudgetMatches {
    slots: HashMap<(usize, Box<str>, Box<str>), usize>,
    matches: Vec<PostBudgetGlobalMatch>,
}

impl PostBudgetMatches {
    fn get_or_insert(
        &mut self,
        module: &str,
        name: &str,
        position: usize,
        severity: &'static str,
    ) -> (&mut PostBudgetGlobalMatch, bool) {
        let index = match self.slots.entry((position, module.into(), name.into())) {
            Entry::Occupied(slot) => return (&mut self.matches[*slot.get()], false),
            Entry::Vacant(slot) => *slot.insert(self.matches.len()),
        };
        self.matches.push(PostBudgetGlobalMatch {
            module: module.to_owned(),
            name: name.to_owned(),
            pattern_start: position,
            reduce_proximate: false,
            severity,
        });
        (&mut self.matches[index], true)
    }
}

pub(crate) fn post_budget_global_matches(
    tail: &[u8],
    payload: &[u8],
    initial_stack: &[StackValue],
    initial_memo: &HashMap<i64, StackValue>,
) -> Vec<PostBudgetGlobalMatch> {
    let mut sink = PostBudgetMatches::default();
    record_post_budget_opcode_stream(tail, payload, initial_stack, initial_memo, &mut sink);

    for index in 0..tail.len() {
        match tail[index..] {
            [b'c' | b'i', ..] => record_post_budget_module_name_pair(tail, index + 1, &mut sink),
            [0x82, _, ..] | [0x83, _, _, ..] | [0x84, _, _, _, _, ..] => {
                record_post_budget_extension_ref(tail, index, &mut sink)
            }
            _ => {}
        }
    }

    sink.matches
}

fn record_post_budget_module_name_pair(
    tail: &[u8],
    module_start: usize,
    sink: &mut PostBudgetMatches,
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
    let (found, inserted) = sink.get_or_insert(module, name, module_start, severity);
    if inserted {
        // The raw sweep leaves the structured match's proximity unchanged on a duplicate.
        found.reduce_proximate = has_reduce_class_byte_nearby(tail, name_end.saturating_add(1));
    }
}

fn post_budget_owned_stack_value(value: &StackValue, payload: &[u8]) -> StackValue {
    match value {
        StackValue::TextSpan { start, end, .. } if start <= end && *end <= payload.len() => {
            StackValue::Text {
                value: String::from_utf8_lossy(&payload[*start..*end]).to_string(),
                memo_read: false,
            }
        }
        StackValue::Global(reference) | StackValue::Constructed { reference, .. } => {
            StackValue::Global(reference.clone())
        }
        StackValue::Text { .. } | StackValue::Mark => value.clone(),
        _ => StackValue::Other,
    }
}

fn record_post_budget_opcode_stream(
    tail: &[u8],
    payload: &[u8],
    initial_stack: &[StackValue],
    initial_memo: &HashMap<i64, StackValue>,
    sink: &mut PostBudgetMatches,
) {
    let mut stack: Vec<_> = initial_stack
        .iter()
        .map(|value| post_budget_owned_stack_value(value, payload))
        .collect();
    let initial_memo: HashMap<_, _> = initial_memo
        .iter()
        .map(|(index, value)| (*index, post_budget_owned_stack_value(value, payload)))
        .collect();
    let mut memo_overlay: HashMap<i64, StackValue> = HashMap::new();
    let initial_memo_len = i64::try_from(initial_memo.len()).unwrap_or(i64::MAX);
    let mut memo_len = initial_memo_len;
    let mut index = 0;

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
            &initial_memo,
            sink,
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
    initial_memo: &HashMap<i64, StackValue>,
    sink: &mut PostBudgetMatches,
) {
    match opcode.name {
        "PROTO" | "FRAME" | "STOP" => {}
        name if STACK_GLOBAL_STRING_OPCODES.contains(&name) => {
            stack.push(stack_value_from_text_arg(&opcode.arg, tail));
        }
        // Only text operands and callable references need their values in this pass.
        "NONE" | "NEWTRUE" | "NEWFALSE" | "BININT" | "BININT1" | "BININT2" | "LONG" | "LONG1"
        | "LONG4" | "INT" | "FLOAT" | "BINFLOAT" | "BINBYTES" | "BINBYTES8" | "SHORT_BINBYTES"
        | "BYTEARRAY8" | "NEXT_BUFFER" | "EMPTY_TUPLE" | "EMPTY_LIST" | "EMPTY_DICT"
        | "EMPTY_SET" => stack.push(StackValue::Other),
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
        "TUPLE" | "LIST" | "DICT" | "SET" | "FROZENSET" => {
            pop_to_mark(stack);
            stack.push(StackValue::Other);
        }
        "TUPLE1" => collapse_top_n(stack, 1),
        "TUPLE2" => collapse_top_n(stack, 2),
        "TUPLE3" => collapse_top_n(stack, 3),
        "APPEND" | "SETITEM" => {
            discard_value_operand_preserving_mark(stack);
            if opcode.name == "SETITEM" {
                discard_value_operand_preserving_mark(stack);
            }
        }
        "APPENDS" | "SETITEMS" | "ADDITEMS" => {
            pop_to_mark(stack);
        }
        "PUT" | "BINPUT" | "LONG_BINPUT" => {
            if let (Some(index), Some(value)) = (opcode.arg.as_i64(), stack.last().cloned()) {
                if memo_overlay.insert(index, value).is_none() && !initial_memo.contains_key(&index)
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
                    .or_else(|| initial_memo.get(&index).cloned())
                    .unwrap_or(StackValue::Other);
                stack.push(value);
            }
        }
        "GLOBAL" | "INST" => {
            let is_inst = opcode.name == "INST";
            if is_inst {
                pop_to_mark(stack);
            }
            let (module, name) = opcode.arg.global_parts();
            let reference = GlobalRef::new(module, name, opcode.pos);
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, is_inst, opcode.next, tail, sink);
        }
        "STACK_GLOBAL" => {
            let reference = {
                let name_value = stack.pop();
                let module_value = stack.pop();
                GlobalRef::from_stack_operands(
                    module_value.as_ref(),
                    name_value.as_ref(),
                    tail,
                    opcode.pos,
                )
            };
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, false, opcode.next, tail, sink);
        }
        "EXT1" | "EXT2" | "EXT4" => {
            let extension_code = opcode.arg.as_i64().unwrap_or_default();
            let reference = GlobalRef::extension(extension_code, opcode.pos);
            stack.push(StackValue::Global(reference.clone()));
            record_post_budget_global_ref(&reference, false, opcode.next, tail, sink);
        }
        "REDUCE" | "NEWOBJ" | "BUILD" => {
            let callable_value = consume_top_operands(stack, 2);
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        "NEWOBJ_EX" => {
            let callable_value = consume_top_operands(stack, 3);
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        "OBJ" => {
            let callable_value = pop_to_mark(stack);
            push_constructed_result(stack, callable_value.as_ref());
            record_post_budget_callable_value(callable_value, opcode.next, tail, sink);
        }
        _ => {}
    }
}

fn record_post_budget_callable_value(
    callable_value: Option<StackValue>,
    proximity_start: usize,
    tail: &[u8],
    sink: &mut PostBudgetMatches,
) {
    let Some(StackValue::Global(reference)) = callable_value else {
        return;
    };
    record_post_budget_global_ref(&reference, true, proximity_start, tail, sink);
}

fn record_post_budget_global_ref(
    reference: &GlobalRef,
    force_reduce_proximate: bool,
    proximity_start: usize,
    tail: &[u8],
    sink: &mut PostBudgetMatches,
) {
    if reference.malformed && reference.module != "copyreg.extension" {
        return;
    }
    let Some(severity) = post_budget_global_severity(&reference.module, &reference.name) else {
        return;
    };
    if reference.module.is_empty() || reference.name.is_empty() {
        return;
    }
    let (found, _) = sink.get_or_insert(
        &reference.module,
        &reference.name,
        reference.position,
        severity,
    );
    found.reduce_proximate |=
        force_reduce_proximate || has_reduce_class_byte_nearby(tail, proximity_start);
}

fn discard_value_operand_preserving_mark(stack: &mut Vec<StackValue>) {
    if !matches!(stack.last(), Some(StackValue::Mark)) {
        stack.pop();
    }
}

fn pop_to_mark(stack: &mut Vec<StackValue>) -> Option<StackValue> {
    let mut first = None;
    while let Some(item) = stack.pop() {
        if matches!(item, StackValue::Mark) {
            break;
        }
        first = Some(item);
    }
    first
}

fn collapse_top_n(stack: &mut Vec<StackValue>, count: usize) {
    if let Some(start) = stack.len().checked_sub(count) {
        if !stack[start..]
            .iter()
            .any(|value| matches!(value, StackValue::Mark))
        {
            stack.truncate(start);
        }
    }
    stack.push(StackValue::Other);
}

fn consume_top_operands(stack: &mut Vec<StackValue>, operand_count: usize) -> Option<StackValue> {
    if stack.len() < operand_count {
        stack.push(StackValue::Other);
        return None;
    }
    let callable_value = stack.drain(stack.len() - operand_count..).next();
    push_constructed_result(stack, callable_value.as_ref());
    callable_value
}

fn push_constructed_result(stack: &mut Vec<StackValue>, callable_value: Option<&StackValue>) {
    match callable_value {
        Some(StackValue::Global(reference)) if !reference.malformed => {
            stack.push(StackValue::Global(reference.clone()));
        }
        _ => stack.push(StackValue::Other),
    }
}

fn record_post_budget_extension_ref(tail: &[u8], index: usize, sink: &mut PostBudgetMatches) {
    let Ok(ParsedOpcode {
        arg: ArgValue::Int(extension_code),
        next,
        ..
    }) = parse_opcode(tail, index, tail.len())
    else {
        return;
    };
    let (found, _) = sink.get_or_insert(
        "copyreg.extension",
        &format!("code_{extension_code}"),
        index,
        "warning",
    );
    found.reduce_proximate |= has_reduce_class_byte_nearby(tail, next);
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

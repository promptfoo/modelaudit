use crate::opcode::{parse_opcode, ParsedOpcode};
use crate::report::DetailValue;

const EXPANSION_EVENT_WINDOW: usize = 6;
const EXPANSION_GROWTH_BUILDERS: &[&str] = &[
    "APPEND", "APPENDS", "LIST", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
];
const EXPANSION_DUP_COUNT_THRESHOLD: usize = 128;
const EXPANSION_DUP_DENSITY_THRESHOLD: f64 = 0.10;
const EXPANSION_GET_PUT_RATIO_THRESHOLD: f64 = 32.0;
const EXPANSION_GET_PUT_MIN_READS: usize = 128;
const EXPANSION_MEMO_GROWTH_MIN_WRITES: usize = 64;
const EXPANSION_MEMO_GROWTH_STEPS_THRESHOLD: usize = 32;
const EXPANSION_RATIO_SUPPORTING_DUP_THRESHOLD: usize = 64;
const EXPANSION_RATIO_SUPPORTING_GROWTH_THRESHOLD: usize = 16;

#[derive(Clone)]
enum ExpansionEvent {
    Op(&'static str),
    Read(i64),
}

#[derive(Clone, Default)]
pub(crate) struct ExpansionHeuristicState {
    stream_id: usize,
    opcode_count: usize,
    memo_reads: usize,
    memo_writes: usize,
    dup_count: usize,
    memo_growth_steps: usize,
    max_memo_index: i64,
    next_memo_index: i64,
    last_written_index: Option<i64>,
    last_position: usize,
    event_window: Vec<ExpansionEvent>,
}

#[derive(Clone)]
pub(crate) struct ExpansionHeuristicFinding {
    pub(crate) stream_id: usize,
    pub(crate) position: usize,
    pub(crate) opcode_count: usize,
    pub(crate) memo_reads: usize,
    pub(crate) memo_writes: usize,
    pub(crate) get_put_ratio: f64,
    pub(crate) dup_count: usize,
    pub(crate) dup_density: f64,
    pub(crate) memo_growth_steps: usize,
    pub(crate) memo_slots_used: usize,
    pub(crate) triggers: Vec<&'static str>,
}

impl ExpansionHeuristicState {
    pub(crate) fn new(stream_id: usize) -> Self {
        Self {
            stream_id,
            max_memo_index: -1,
            ..Self::default()
        }
    }
}

pub(crate) fn record_expansion_state_opcode(
    state: &mut ExpansionHeuristicState,
    opcode: &ParsedOpcode,
    position: usize,
) -> bool {
    state.opcode_count += 1;
    state.last_position = position;

    if opcode.name == "DUP" {
        state.dup_count += 1;
    }

    let is_memo_read = is_memo_read_opcode(opcode.name);
    if is_memo_read {
        state.memo_reads += 1;
    } else if is_memo_write_opcode(opcode.name) {
        state.memo_writes += 1;
        let memo_index = if opcode.name == "MEMOIZE" {
            let index = state.next_memo_index;
            state.next_memo_index += 1;
            Some(index)
        } else {
            let index = opcode.arg.as_i64();
            if let Some(index) = index {
                state.next_memo_index = state.next_memo_index.max(index.saturating_add(1));
            }
            index
        };

        let previous_memo_index = state.last_written_index;
        let repeated_previous_read = previous_memo_index.is_some_and(|index| {
            state
                .event_window
                .iter()
                .filter(|event| {
                    matches!(event, ExpansionEvent::Read(read_index) if *read_index == index)
                })
                .count()
                >= 2
        });
        let has_growth_builder = state.event_window.iter().any(|event| {
            matches!(event, ExpansionEvent::Op(op_name) if EXPANSION_GROWTH_BUILDERS.contains(op_name))
        });
        let is_sequential_growth = previous_memo_index
            .zip(memo_index)
            .is_some_and(|(previous, current)| current == previous.saturating_add(1));
        if is_sequential_growth && repeated_previous_read && has_growth_builder {
            state.memo_growth_steps += 1;
        }

        if let Some(index) = memo_index {
            state.max_memo_index = state.max_memo_index.max(index);
            state.last_written_index = Some(index);
        }
    }

    if is_memo_read {
        state
            .event_window
            .push(ExpansionEvent::Read(opcode.arg.as_i64().unwrap_or(-1)));
    } else {
        state.event_window.push(ExpansionEvent::Op(opcode.name));
    }
    if state.event_window.len() > EXPANSION_EVENT_WINDOW {
        state.event_window.remove(0);
    }

    opcode.name == "STOP"
}

pub(crate) fn flush_expansion_state(
    state: &mut ExpansionHeuristicState,
    findings: &mut Vec<ExpansionHeuristicFinding>,
) {
    let next_stream_id = state.stream_id.saturating_add(1);
    if let Some(finding) = build_expansion_heuristic_finding(state) {
        findings.push(finding);
    }
    *state = ExpansionHeuristicState::new(next_stream_id);
}

pub(crate) fn detect_expansion_findings_in_tail(
    tail: &[u8],
    stream_offset: usize,
    read_offset: usize,
    tail_prefix_len: usize,
    position_offset: usize,
) -> Vec<ExpansionHeuristicFinding> {
    let mut findings = Vec::new();
    let mut state = ExpansionHeuristicState::new(0);
    let mut index = 0usize;
    while index < tail.len() {
        let parsed = match parse_opcode(tail, index, tail.len()) {
            Ok(opcode) => opcode,
            Err(_) => break,
        };
        let local_position = if parsed.pos < tail_prefix_len {
            stream_offset.saturating_add(parsed.pos)
        } else {
            read_offset.saturating_add(parsed.pos - tail_prefix_len)
        };
        let should_finish_stream = record_expansion_state_opcode(
            &mut state,
            &parsed,
            position_offset.saturating_add(local_position),
        );
        index = parsed.next;
        if should_finish_stream {
            flush_expansion_state(&mut state, &mut findings);
        }
    }
    flush_expansion_state(&mut state, &mut findings);
    findings
}

pub(crate) fn expansion_finding_to_detail(finding: &ExpansionHeuristicFinding) -> DetailValue {
    DetailValue::Dict(vec![
        (
            "stream_id".to_string(),
            DetailValue::UInt(finding.stream_id as u64),
        ),
        (
            "position".to_string(),
            DetailValue::UInt(finding.position as u64),
        ),
        (
            "opcode_count".to_string(),
            DetailValue::UInt(finding.opcode_count as u64),
        ),
        (
            "memo_reads".to_string(),
            DetailValue::UInt(finding.memo_reads as u64),
        ),
        (
            "memo_writes".to_string(),
            DetailValue::UInt(finding.memo_writes as u64),
        ),
        (
            "get_put_ratio".to_string(),
            DetailValue::Float(finding.get_put_ratio),
        ),
        (
            "dup_count".to_string(),
            DetailValue::UInt(finding.dup_count as u64),
        ),
        (
            "dup_density".to_string(),
            DetailValue::Float(finding.dup_density),
        ),
        (
            "memo_growth_steps".to_string(),
            DetailValue::UInt(finding.memo_growth_steps as u64),
        ),
        (
            "memo_slots_used".to_string(),
            DetailValue::UInt(finding.memo_slots_used as u64),
        ),
        (
            "triggers".to_string(),
            DetailValue::List(
                finding
                    .triggers
                    .iter()
                    .map(|trigger| DetailValue::String((*trigger).to_string()))
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn expansion_trigger_label(trigger: &str) -> &str {
    match trigger {
        "suspicious_get_put_ratio" => "high memo GET/PUT ratio",
        "excessive_dup_usage" => "dense DUP usage",
        "memo_growth_chain" => "iterative memo growth chain",
        _ => trigger,
    }
}

fn build_expansion_heuristic_finding(
    state: &ExpansionHeuristicState,
) -> Option<ExpansionHeuristicFinding> {
    if state.opcode_count == 0 {
        return None;
    }

    let get_put_ratio = if state.memo_writes == 0 {
        0.0
    } else {
        state.memo_reads as f64 / state.memo_writes as f64
    };
    let dup_density = state.dup_count as f64 / state.opcode_count as f64;

    let mut triggers = Vec::new();
    if state.memo_writes >= EXPANSION_MEMO_GROWTH_MIN_WRITES
        && state.memo_growth_steps >= EXPANSION_MEMO_GROWTH_STEPS_THRESHOLD
    {
        triggers.push("memo_growth_chain");
    }
    if state.dup_count >= EXPANSION_DUP_COUNT_THRESHOLD
        && dup_density >= EXPANSION_DUP_DENSITY_THRESHOLD
    {
        triggers.push("excessive_dup_usage");
    }
    if state.memo_reads >= EXPANSION_GET_PUT_MIN_READS
        && get_put_ratio >= EXPANSION_GET_PUT_RATIO_THRESHOLD
        && (state.dup_count >= EXPANSION_RATIO_SUPPORTING_DUP_THRESHOLD
            || state.memo_growth_steps >= EXPANSION_RATIO_SUPPORTING_GROWTH_THRESHOLD)
    {
        triggers.push("suspicious_get_put_ratio");
    }
    if triggers.is_empty() {
        return None;
    }

    let memo_slots_used = if state.max_memo_index >= 0 {
        usize::try_from(state.max_memo_index.saturating_add(1)).unwrap_or(usize::MAX)
    } else {
        0
    };

    Some(ExpansionHeuristicFinding {
        stream_id: state.stream_id,
        position: state.last_position,
        opcode_count: state.opcode_count,
        memo_reads: state.memo_reads,
        memo_writes: state.memo_writes,
        get_put_ratio: round_float(get_put_ratio, 100.0),
        dup_count: state.dup_count,
        dup_density: round_float(dup_density, 10_000.0),
        memo_growth_steps: state.memo_growth_steps,
        memo_slots_used,
        triggers,
    })
}

fn is_memo_read_opcode(name: &str) -> bool {
    matches!(name, "GET" | "BINGET" | "LONG_BINGET")
}

fn is_memo_write_opcode(name: &str) -> bool {
    matches!(name, "PUT" | "BINPUT" | "LONG_BINPUT" | "MEMOIZE")
}

fn round_float(value: f64, factor: f64) -> f64 {
    (value * factor).round() / factor
}

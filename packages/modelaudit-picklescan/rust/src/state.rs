use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use crate::expansion::{
    detect_expansion_findings_in_tail, expansion_finding_to_detail, expansion_trigger_label,
    flush_expansion_state, record_expansion_state_opcode, ExpansionHeuristicFinding,
    ExpansionHeuristicState,
};
use crate::nested::{
    decode_possible_encoded_pickle, detect_oversized_encoded_pickle_prefixes,
    encoded_literal_may_contain_pickle, encoded_nested_literal_probe_coverage_incomplete,
    encoded_nested_literal_probe_windows, encoded_nested_window_char_limit, has_execution_opcode,
    has_pickle_prefix, looks_like_pickle_payload, nested_pickle_probe_offsets,
    pickle_payload_extent, truncated_pickle_prefix_requires_fail_closed, MAX_NESTED_PAYLOAD_PROBES,
};
use crate::nested_surface::{
    encoded_nested_payload_finding, is_allowlisted_nested_constructor_ref,
    nested_rule_code_for_encoding, raw_nested_payload_finding, NestedPayloadFinding,
    NestedSurfaceOutcome,
};
use crate::opcode::{parse_opcode, ArgValue, ParseError, ParsedOpcode};
use crate::options::{deadline_from_timeout, ScanOptions};
use crate::policy::{callable_severity, global_severity};
use crate::post_budget::{post_budget_absolute_position, post_budget_global_matches};
use crate::report::{
    detail_string, detail_usize, notice_to_detail_value, scan_error_to_detail_value, DetailValue,
    Finding, FindingDedupeKey, Notice, NoticeDedupeKey, ScanError,
};
use crate::stack::{
    collapse_tuple_values, operand_preview, pytorch_storage_descriptor_ref, pytorch_storage_key,
    resolve_global_operand, stack_value_from_integer_arg, stack_value_from_text_arg,
    stack_value_preview, stack_value_string, FutureCallbacks, GlobalRef, RegexScannerRule,
    StackValue,
};
use crate::strings::{
    is_repeated_single_byte, is_suspicious_magic_method, suspicious_string_matches,
};

const MIN_SUSPICIOUS_LITERAL_SCAN_WINDOW_CHARS: usize = 8192;
const SUSPICIOUS_LITERAL_SCAN_OVERLAP_CHARS: usize = 4096;
const MAX_STR_FORMAT_FIELD_NESTING: usize = 4;
static RUNTIME_PYTHON_MINOR_VERSION: AtomicU8 = AtomicU8::new(13);
const STR_FORMAT_DECIMAL_ZERO_CODEPOINTS: &[u32] = &[
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16B50,
    0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];
const PYTHON_3_12_PLUS_STR_FORMAT_DECIMAL_ZERO_CODEPOINTS: &[u32] = &[0x11F50, 0x16AC0, 0x1E4F0];

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormatFieldNumbering {
    Unset,
    Auto,
    Manual,
}

enum StrFormatRootItemLookup {
    Invalid,
    Path(Vec<Option<String>>),
}
const TIME_CHECK_INTERVAL_OPCODES: usize = 4096;
const MAX_IMPORT_REFERENCES: usize = 10_000;
const MAX_TRACKED_DICT_UNKNOWN_KEY_VALUES: usize = 16;
const MAX_TRACKED_STR_JOIN_RESULT_BYTES: usize = 4096;

const STACK_GLOBAL_STRING_OPCODES: &[&str] = &[
    "BINSTRING",
    "BINUNICODE",
    "BINUNICODE8",
    "SHORT_BINSTRING",
    "SHORT_BINUNICODE",
    "STRING",
    "UNICODE",
];
const REDUCE_OPCODES: &[&str] = &["REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST", "BUILD"];

#[derive(Clone, Copy)]
enum CallbackDispatchGuard {
    Always,
    NonEmptyIterable {
        arg_index: usize,
    },
    LiteralRegexMatch {
        pattern_arg_index: usize,
        input_arg_index: usize,
        flags_arg_index: Option<usize>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegexLiteralInputMatch {
    Matches,
    DoesNotMatch,
    Unknown,
}

struct RegexPatternSpec {
    pattern: String,
    flags: Option<isize>,
}

const REGEX_FLAG_IGNORECASE: isize = 2;
const REGEX_FLAG_MULTILINE: isize = 8;
const REGEX_FLAG_DOTALL: isize = 16;

const EXACT_ARITY_STDLIB_EAGER_ITERABLE_CONSUMERS: &[(&str, &str, usize, usize)] = &[
    ("array", "array", 2, 1),
    ("collections", "Counter", 1, 0),
    ("collections", "OrderedDict", 1, 0),
    ("collections", "UserDict", 1, 0),
    ("collections", "UserList", 1, 0),
    ("heapq", "nlargest", 2, 1),
    ("heapq", "nlargest", 3, 1),
    ("heapq", "nsmallest", 2, 1),
    ("heapq", "nsmallest", 3, 1),
    ("math", "fsum", 1, 0),
    ("math", "prod", 1, 0),
    ("statistics", "fmean", 1, 0),
    ("statistics", "fmean", 2, 0),
    ("statistics", "fmean", 2, 1),
    ("statistics", "geometric_mean", 1, 0),
    ("statistics", "harmonic_mean", 1, 0),
    ("statistics", "harmonic_mean", 2, 0),
    ("statistics", "harmonic_mean", 2, 1),
    ("statistics", "mean", 1, 0),
    ("statistics", "median", 1, 0),
    ("statistics", "median_grouped", 1, 0),
    ("statistics", "median_grouped", 2, 0),
    ("statistics", "median_high", 1, 0),
    ("statistics", "median_low", 1, 0),
    ("statistics", "mode", 1, 0),
    ("statistics", "multimode", 1, 0),
    ("statistics", "quantiles", 1, 0),
    ("statistics", "pstdev", 1, 0),
    ("statistics", "pstdev", 2, 0),
    ("statistics", "pvariance", 1, 0),
    ("statistics", "pvariance", 2, 0),
    ("statistics", "stdev", 1, 0),
    ("statistics", "stdev", 2, 0),
    ("statistics", "variance", 1, 0),
    ("statistics", "variance", 2, 0),
    ("weakref", "WeakKeyDictionary", 1, 0),
    ("weakref", "WeakSet", 1, 0),
    ("weakref", "WeakValueDictionary", 1, 0),
];

const EXACT_ARITY_CALLBACK_DISPATCH_CONSUMERS: &[(
    &str,
    &str,
    usize,
    usize,
    usize,
    CallbackDispatchGuard,
)] = &[
    (
        "heapq",
        "nlargest",
        3,
        2,
        1,
        CallbackDispatchGuard::NonEmptyIterable { arg_index: 1 },
    ),
    (
        "heapq",
        "nsmallest",
        3,
        2,
        1,
        CallbackDispatchGuard::NonEmptyIterable { arg_index: 1 },
    ),
    (
        "re",
        "sub",
        3,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    ("weakref", "ref", 2, 1, 1, CallbackDispatchGuard::Always),
    ("weakref", "proxy", 2, 1, 1, CallbackDispatchGuard::Always),
    (
        "weakref",
        "WeakMethod",
        2,
        1,
        1,
        CallbackDispatchGuard::Always,
    ),
    (
        "tokenize",
        "tokenize",
        1,
        0,
        0,
        CallbackDispatchGuard::Always,
    ),
    (
        "re",
        "sub",
        4,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "sub",
        5,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: Some(4),
        },
    ),
    (
        "re",
        "subn",
        3,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "subn",
        4,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "subn",
        5,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: Some(4),
        },
    ),
    (
        "re",
        "Pattern.sub",
        3,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "Pattern.sub",
        4,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "Pattern.subn",
        3,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
    (
        "re",
        "Pattern.subn",
        4,
        1,
        1,
        CallbackDispatchGuard::LiteralRegexMatch {
            pattern_arg_index: 0,
            input_arg_index: 2,
            flags_arg_index: None,
        },
    ),
];

const EXACT_ARITY_LAZY_ZERO_ARG_CALLBACK_ITERABLES: &[(&str, &str, usize, usize)] =
    &[("tokenize", "generate_tokens", 1, 0)];

const EXACT_ARITY_ITERABLE_DESCRIPTOR_CONSUMERS: &[(&str, &str, usize, usize)] = &[
    ("array", "array.extend", 2, 1),
    ("builtins", "bytearray.__init__", 2, 1),
    ("builtins", "bytearray.extend", 2, 1),
    ("builtins", "dict.__init__", 2, 1),
    ("builtins", "dict.fromkeys", 1, 0),
    ("builtins", "dict.fromkeys", 2, 0),
    ("builtins", "dict.update", 2, 1),
    ("builtins", "list.__init__", 2, 1),
    ("builtins", "list.extend", 2, 1),
    ("builtins", "set.__init__", 2, 1),
    ("collections", "ChainMap.update", 2, 1),
    ("collections", "Counter.__init__", 2, 1),
    ("collections", "Counter.subtract", 2, 1),
    ("collections", "Counter.update", 2, 1),
    ("collections", "defaultdict.__init__", 3, 2),
    ("collections", "defaultdict.update", 2, 1),
    ("collections", "deque.__init__", 2, 1),
    ("collections", "deque.extend", 2, 1),
    ("collections", "deque.extendleft", 2, 1),
    ("collections", "OrderedDict.__init__", 2, 1),
    ("collections", "OrderedDict.update", 2, 1),
    ("collections", "UserDict.__init__", 2, 1),
    ("collections", "UserDict.update", 2, 1),
    ("collections", "UserList.__init__", 2, 1),
    ("collections", "UserList.extend", 2, 1),
    ("weakref", "WeakKeyDictionary.update", 2, 1),
    ("weakref", "WeakSet.update", 2, 1),
    ("weakref", "WeakValueDictionary.update", 2, 1),
];

enum LimitError {
    OpcodeBudgetExceeded,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanStatus {
    Complete,
    Inconclusive,
    Error,
}

impl ScanStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Inconclusive => "inconclusive",
            Self::Error => "error",
        }
    }

    fn is_complete(self) -> bool {
        self == Self::Complete
    }
}

impl PartialEq<&str> for ScanStatus {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl ScanVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        }
    }
}

impl PartialEq<&str> for ScanVerdict {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

fn global_ref_details(
    reference: &GlobalRef,
    symbol: &str,
    op_name: &'static str,
) -> Vec<(String, DetailValue)> {
    vec![
        (
            "opcode".to_string(),
            DetailValue::String(op_name.to_string()),
        ),
        (
            "module".to_string(),
            DetailValue::String(reference.module.clone()),
        ),
        (
            "name".to_string(),
            DetailValue::String(reference.name.clone()),
        ),
        (
            "import_reference".to_string(),
            DetailValue::String(symbol.to_string()),
        ),
        (
            "position".to_string(),
            DetailValue::UInt(reference.position as u64),
        ),
    ]
}

type GlobalReferenceDedupeKey = (String, String, usize, &'static str, bool);
type CallableInvocationDedupeKey = (String, String, Option<usize>);

#[derive(Clone)]
struct CallableInvocation {
    reference: GlobalRef,
    op_name: &'static str,
    opcode_position: usize,
    positional_arg_count: Option<usize>,
    args: Vec<StackValue>,
}

struct DynamicTypeCallableAttribute {
    attribute_name: Option<String>,
    callable: Option<GlobalRef>,
    unknown_key_values_overflowed: bool,
}

enum MappingLookup<'a> {
    Found(&'a GlobalRef),
    Shadowed,
}

pub(crate) struct ScanState<'a> {
    source: String,
    payload: &'a [u8],
    options: &'a ScanOptions,
    bytes_total: Option<usize>,
    position_offset: usize,
    nested_depth: usize,
    deadline: Instant,
    stack: Vec<StackValue>,
    memo: HashMap<i64, StackValue>,
    findings: Vec<Finding>,
    notices: Vec<Notice>,
    errors: Vec<ScanError>,
    protocols: Vec<i64>,
    import_references: Vec<Vec<(String, DetailValue)>>,
    callable_invocations: Vec<Vec<(String, DetailValue)>>,
    callable_invocation_keys: HashSet<CallableInvocationDedupeKey>,
    opcode_count: usize,
    opcode_counts: HashMap<&'static str, usize>,
    global_count: usize,
    bytes_scanned: usize,
    first_pickle_end_pos: Option<usize>,
    stream_start_offset: usize,
    stream_opcode_count: usize,
    stream_proto_version: Option<i64>,
    expansion_state: ExpansionHeuristicState,
    expansion_findings: Vec<ExpansionHeuristicFinding>,
    next_buffer_count: usize,
    readonly_buffer_count: usize,
    readonly_buffer_empty_stack_count: usize,
    first_buffer_opcode_position: Option<usize>,
    persistent_id_count: usize,
    first_persistent_id_position: Option<usize>,
    status: ScanStatus,
    verdict: ScanVerdict,
    seen_finding_keys: HashSet<FindingDedupeKey>,
    seen_notice_keys: HashSet<NoticeDedupeKey>,
    seen_global_reference_keys: HashSet<GlobalReferenceDedupeKey>,
    import_references_truncated: bool,
    callable_invocations_truncated: bool,
}

impl<'a> ScanState<'a> {
    pub(crate) fn set_runtime_python_minor_version(minor: u8) {
        RUNTIME_PYTHON_MINOR_VERSION.store(minor, Ordering::Relaxed);
    }

    pub(crate) fn new(
        source: String,
        payload: &'a [u8],
        options: &'a ScanOptions,
        bytes_total: Option<usize>,
        position_offset: usize,
        nested_depth: usize,
        deadline: Option<Instant>,
    ) -> Self {
        let deadline = deadline.unwrap_or_else(|| deadline_from_timeout(options.timeout_s));
        Self {
            source,
            payload,
            options,
            bytes_total,
            position_offset,
            nested_depth,
            deadline,
            stack: Vec::new(),
            memo: HashMap::new(),
            findings: Vec::new(),
            notices: Vec::new(),
            errors: Vec::new(),
            protocols: Vec::new(),
            import_references: Vec::new(),
            callable_invocations: Vec::new(),
            callable_invocation_keys: HashSet::new(),
            opcode_count: 0,
            opcode_counts: HashMap::new(),
            global_count: 0,
            bytes_scanned: 0,
            first_pickle_end_pos: None,
            stream_start_offset: position_offset,
            stream_opcode_count: 0,
            stream_proto_version: None,
            expansion_state: ExpansionHeuristicState::new(0),
            expansion_findings: Vec::new(),
            next_buffer_count: 0,
            readonly_buffer_count: 0,
            readonly_buffer_empty_stack_count: 0,
            first_buffer_opcode_position: None,
            persistent_id_count: 0,
            first_persistent_id_position: None,
            status: ScanStatus::Complete,
            verdict: ScanVerdict::Clean,
            seen_finding_keys: HashSet::new(),
            seen_notice_keys: HashSet::new(),
            seen_global_reference_keys: HashSet::new(),
            import_references_truncated: false,
            callable_invocations_truncated: false,
        }
    }

    pub(crate) fn run(&mut self) {
        let scan_limit = self.scan_limit();
        if self.bytes_total == Some(0) || scan_limit == 0 {
            if self.bytes_total.is_some() && self.bytes_total != Some(0) {
                self.record_short_read();
            } else {
                self.record_empty_input_error();
            }
            self.finish_analysis();
            return;
        }

        let mut index = 0usize;
        while index < scan_limit {
            let stream_start = index;
            let mut parsed_opcode = false;
            let mut saw_stop = false;
            self.stream_start_offset = self.position_offset + stream_start;
            self.stream_opcode_count = 0;
            self.stream_proto_version = None;

            loop {
                if index >= scan_limit {
                    break;
                }
                let parsed = match parse_opcode(self.payload, index, scan_limit) {
                    Ok(opcode) => opcode,
                    Err(error) => {
                        self.handle_parse_error(error, index);
                        self.scan_follow_on_pickle_streams(index);
                        self.finish_analysis();
                        return;
                    }
                };

                if let Err(limit_error) = self.check_limits(&parsed) {
                    self.status = ScanStatus::Inconclusive;
                    match limit_error {
                        LimitError::OpcodeBudgetExceeded => {
                            self.add_notice(Notice {
                                message: format!(
                                    "Opcode analysis stopped after reaching max_opcodes={}",
                                    self.options.max_opcodes
                                ),
                                severity: "info",
                                location: Some(self.source.clone()),
                                code: Some("opcode_budget"),
                                details: vec![
                                    (
                                        "opcode_count".to_string(),
                                        DetailValue::UInt(self.opcode_count as u64),
                                    ),
                                    (
                                        "max_opcodes".to_string(),
                                        DetailValue::UInt(self.options.max_opcodes as u64),
                                    ),
                                    ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                                ],
                            });
                            self.scan_post_budget_tail(parsed.pos);
                        }
                        LimitError::Timeout => {
                            self.add_notice(Notice {
                                message: format!(
                                    "Opcode analysis timed out after {:.3} seconds",
                                    self.options.timeout_s
                                ),
                                severity: "info",
                                location: Some(self.source.clone()),
                                code: Some("timeout"),
                                details: vec![
                                    (
                                        "opcode_count".to_string(),
                                        DetailValue::UInt(self.opcode_count as u64),
                                    ),
                                    (
                                        "timeout_s".to_string(),
                                        DetailValue::Float(self.options.timeout_s),
                                    ),
                                    ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                                ],
                            });
                            self.scan_post_budget_tail(parsed.pos);
                        }
                    }
                    self.finish_analysis();
                    return;
                }

                parsed_opcode = true;
                let position = self.position_offset + parsed.pos;
                self.bytes_scanned = self.bytes_scanned.max(parsed.next);
                self.opcode_count += 1;
                *self.opcode_counts.entry(parsed.name).or_insert(0) += 1;
                index = parsed.next;
                self.record_structural_opcode(&parsed, position);
                self.record_expansion_opcode(&parsed, position);
                self.handle_opcode(&parsed, position);

                if parsed.name == "STOP" {
                    saw_stop = true;
                    if self.first_pickle_end_pos.is_none() {
                        self.first_pickle_end_pos = Some(self.position_offset + index);
                    }
                    self.stack.clear();
                    self.memo.clear();
                    break;
                }
            }

            if !parsed_opcode {
                if self.opcode_count == 0 && self.findings.is_empty() {
                    self.record_empty_input_error();
                }
                break;
            }

            if !saw_stop && index >= scan_limit {
                self.handle_parse_error(
                    ParseError::new("pickle exhausted before seeing STOP").at(index),
                    index,
                );
                self.finish_analysis();
                return;
            }

            if index <= stream_start {
                break;
            }
        }

        if self.status.is_complete()
            && matches!(self.bytes_total, Some(bytes_total) if self.payload.len() < bytes_total)
        {
            self.record_short_read();
        }

        self.finish_analysis();
    }

    fn scan_limit(&self) -> usize {
        match self.bytes_total {
            Some(total) => total.min(self.payload.len()),
            None => self.payload.len(),
        }
    }

    fn check_limits(&self, _opcode: &ParsedOpcode) -> Result<(), LimitError> {
        if self.opcode_count >= self.options.max_opcodes {
            return Err(LimitError::OpcodeBudgetExceeded);
        }
        if self.opcode_count % TIME_CHECK_INTERVAL_OPCODES == 0 && Instant::now() > self.deadline {
            return Err(LimitError::Timeout);
        }
        Ok(())
    }

    fn handle_parse_error(&mut self, error: ParseError, index: usize) {
        let report_index = error.report_index.unwrap_or(index);
        if self.opcode_count == 0 && self.findings.is_empty() {
            self.status = ScanStatus::Error;
            self.errors.push(ScanError {
                message: format!("Could not parse pickle stream: {}", error.message),
                category: "parse_error",
                location: Some(format!(
                    "{} (pos {})",
                    self.source,
                    self.position_offset + report_index
                )),
                exception_type: Some(error.exception_type),
                details: vec![(
                    "opcode_count".to_string(),
                    DetailValue::UInt(self.opcode_count as u64),
                )],
            });
        } else {
            self.status = ScanStatus::Inconclusive;
            self.add_notice(Notice {
                message: format!(
                    "Pickle parsing stopped before the stream was fully consumed: {}",
                    error.exception_type
                ),
                severity: "info",
                location: Some(format!(
                    "{} (pos {})",
                    self.source,
                    self.position_offset + report_index
                )),
                code: Some("parse_incomplete"),
                details: vec![
                    (
                        "opcode_count".to_string(),
                        DetailValue::UInt(self.opcode_count as u64),
                    ),
                    ("exception".to_string(), DetailValue::String(error.message)),
                    (
                        "exception_type".to_string(),
                        DetailValue::String(error.exception_type.to_string()),
                    ),
                    ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                ],
            });
        }
    }

    fn record_empty_input_error(&mut self) {
        self.status = ScanStatus::Error;
        self.verdict = ScanVerdict::Unknown;
        self.errors.push(ScanError {
            message: "Input is empty and does not contain a pickle stream".to_string(),
            category: "empty_input",
            location: Some(self.source.clone()),
            exception_type: None,
            details: Vec::new(),
        });
    }

    fn record_short_read(&mut self) {
        let Some(expected_size) = self.bytes_total else {
            return;
        };
        self.status = ScanStatus::Error;
        self.bytes_scanned = self.bytes_scanned.max(self.payload.len());
        self.errors.push(ScanError {
            message: format!(
                "Could not read requested pickle stream size: expected {} bytes, got {}",
                expected_size,
                self.payload.len()
            ),
            category: "short_read",
            location: Some(self.source.clone()),
            exception_type: None,
            details: vec![
                (
                    "expected_size".to_string(),
                    DetailValue::UInt(expected_size as u64),
                ),
                (
                    "bytes_read".to_string(),
                    DetailValue::UInt(self.payload.len() as u64),
                ),
                (
                    "position_offset".to_string(),
                    DetailValue::UInt(self.position_offset as u64),
                ),
            ],
        });
    }

    fn handle_opcode(&mut self, opcode: &ParsedOpcode, position: usize) {
        match opcode.name {
            "PROTO" => {
                if let ArgValue::Int(value) = opcode.arg {
                    self.protocols.push(value);
                }
            }
            name if STACK_GLOBAL_STRING_OPCODES.contains(&name) => {
                let value = opcode.arg.text(self.payload);
                if !self.is_large_uninteresting_repeated_literal(&value) {
                    let suppress_hex_escape = contains_escaped_hex_marker(&value)
                        && self.is_data_only_encoded_nested_pickle_literal(&value);
                    self.scan_string_literal(&value, opcode.name, position, suppress_hex_escape);
                    self.scan_encoded_nested_pickle_literal(&value, position);
                }
                match opcode.name {
                    "BINSTRING" | "SHORT_BINSTRING" => {
                        if let Some((start, end)) = opcode.arg.byte_span(self.payload.len()) {
                            let bytes = &self.payload[start..end];
                            self.scan_raw_nested_pickle_bytes(bytes, self.position_offset + start);
                        }
                    }
                    "STRING" => {
                        if let Some(bytes) = opcode.arg.raw_bytes(self.payload) {
                            self.scan_raw_nested_pickle_bytes(bytes.as_ref(), position);
                        }
                    }
                    _ => {}
                }
                self.stack
                    .push(stack_value_from_text_arg(&opcode.arg, self.payload));
            }
            "NONE" => self.stack.push(StackValue::Primitive {
                type_name: "NoneType",
                repr: "None".to_string(),
            }),
            "NEWTRUE" => self.stack.push(StackValue::Primitive {
                type_name: "bool",
                repr: "True".to_string(),
            }),
            "NEWFALSE" => self.stack.push(StackValue::Primitive {
                type_name: "bool",
                repr: "False".to_string(),
            }),
            "BININT" | "BININT1" | "BININT2" | "LONG" | "LONG1" | "LONG4" | "INT" => {
                self.stack
                    .push(stack_value_from_integer_arg(&opcode.arg, self.payload));
            }
            "FLOAT" | "BINFLOAT" => self.stack.push(StackValue::Other),
            "BINBYTES" | "BINBYTES8" | "SHORT_BINBYTES" | "BYTEARRAY8" => {
                if let Some((start, end)) = opcode.arg.byte_span(self.payload.len()) {
                    let bytes = &self.payload[start..end];
                    self.scan_raw_nested_pickle_bytes(bytes, self.position_offset + start);
                    self.stack.push(StackValue::Bytes { start, end });
                } else {
                    self.stack.push(StackValue::Bytes { start: 0, end: 0 });
                }
            }
            "NEXT_BUFFER" => {
                self.record_buffer_opcode(opcode.name, position, false);
                self.stack.push(StackValue::Other);
            }
            "READONLY_BUFFER" => {
                self.record_buffer_opcode(opcode.name, position, self.stack.is_empty());
            }
            "MARK" => self.stack.push(StackValue::Mark),
            "POP" => {
                self.stack.pop();
            }
            "DUP" => {
                if let Some(value) = self.stack.last().cloned() {
                    self.stack.push(value);
                }
            }
            "POP_MARK" => {
                self.pop_to_mark();
            }
            "EMPTY_TUPLE" => {
                self.stack.push(StackValue::Tuple(Vec::new()));
            }
            "EMPTY_LIST" => {
                self.stack.push(StackValue::Primitive {
                    type_name: "list",
                    repr: "[]".to_string(),
                });
            }
            "EMPTY_DICT" => {
                self.stack.push(StackValue::TrackedDict {
                    entries: Vec::new(),
                    unknown_key_values: Vec::new(),
                    unknown_key_values_overflowed: false,
                    memo_index: None,
                });
            }
            "EMPTY_SET" => {
                self.stack.push(StackValue::Primitive {
                    type_name: "set",
                    repr: "set()".to_string(),
                });
            }
            "TUPLE" => {
                let values = self.pop_to_mark();
                self.stack.push(self.collapse_stack_values(values));
            }
            "DICT" => {
                let values = self.pop_to_mark();
                self.stack.push(self.tracked_dict_from_values(&values));
            }
            "LIST" | "SET" | "FROZENSET" => {
                let _ = self.pop_to_mark();
                self.stack.push(StackValue::Other);
            }
            "TUPLE1" => self.collapse_top_n(1),
            "TUPLE2" => self.collapse_top_n(2),
            "TUPLE3" => self.collapse_top_n(3),
            "APPEND" => {
                self.pop_value_operand_preserving_mark();
            }
            "SETITEM" => self.apply_setitem(),
            "APPENDS" | "SETITEMS" | "ADDITEMS" => {
                let values = self.pop_to_mark();
                if opcode.name == "SETITEMS" {
                    self.apply_setitems(&values);
                }
            }
            "PUT" | "BINPUT" | "LONG_BINPUT" => {
                if let Some(value) = self.stack.last().cloned() {
                    if let Some(index) = opcode.arg.as_i64() {
                        let value = Self::with_memo_index(value, index);
                        if let Some(top) = self.stack.last_mut() {
                            *top = value.clone();
                        }
                        self.memo.insert(index, value);
                    }
                }
            }
            "MEMOIZE" => {
                if let Some(value) = self.stack.last().cloned() {
                    let index = self.memo.len() as i64;
                    let value = Self::with_memo_index(value, index);
                    if let Some(top) = self.stack.last_mut() {
                        *top = value.clone();
                    }
                    self.memo.insert(index, value);
                }
            }
            "GET" | "BINGET" | "LONG_BINGET" => {
                if let Some(index) = opcode.arg.as_i64() {
                    if let Some(value) = self.memo.get(&index).cloned() {
                        self.stack.push(value);
                    } else {
                        self.stack.push(StackValue::Other);
                    }
                }
            }
            "GLOBAL" => {
                let (module, name) = opcode.arg.global_parts(self.payload);
                let reference = GlobalRef {
                    module,
                    name,
                    position,
                    malformed: false,
                };
                self.stack.push(StackValue::Global(reference.clone()));
                self.record_global_ref(&reference, opcode.name);
            }
            "STACK_GLOBAL" => {
                let name_value = self.stack.pop();
                let module_value = self.stack.pop();
                let reference = self.resolve_stack_global(module_value, name_value, position);
                self.stack.push(StackValue::Global(reference.clone()));
                self.record_global_ref(&reference, opcode.name);
            }
            "EXT1" | "EXT2" | "EXT4" => {
                let extension_code = opcode.arg.as_i64().unwrap_or_default();
                let reference = GlobalRef {
                    module: "copyreg.extension".to_string(),
                    name: format!("code_{}", extension_code),
                    position,
                    malformed: true,
                };
                self.stack.push(StackValue::Global(reference.clone()));
                self.add_finding(Finding {
                    message: format!(
                        "Encountered {} extension reference {}; extension resolution is opaque",
                        opcode.name, reference.name
                    ),
                    severity: "warning",
                    location: Some(format!("{} (pos {})", self.source, position)),
                    rule_code: Some("EXTENSION_REF"),
                    details: vec![
                        ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                        ("extension_code".to_string(), DetailValue::Int(extension_code)),
                        ("symbol".to_string(), DetailValue::String(reference.symbol())),
                    ],
                    why: Some(
                        "Pickle extension opcodes resolve through a process-global registry and can obscure call targets.",
                    ),
                });
            }
            name if REDUCE_OPCODES.contains(&name) => {
                let invocations = self.consume_callable_opcode(opcode, position);
                for invocation in &invocations {
                    self.push_callable_invocation(invocation);
                }
                if let Some(primary_invocation) = invocations.first() {
                    let callable_ref = &primary_invocation.reference;
                    if callable_ref.module == "copyreg.extension" {
                        self.add_finding(Finding {
                            message: format!(
                                "Found {} opcode invoking opaque copyreg extension: {}",
                                opcode.name,
                                callable_ref.symbol()
                            ),
                            severity: "critical",
                            location: Some(format!("{} (pos {})", self.source, position)),
                            rule_code: Some("DANGEROUS_CALL"),
                            details: vec![
                                ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                                (
                                    "module".to_string(),
                                    DetailValue::String(callable_ref.module.clone()),
                                ),
                                ("name".to_string(), DetailValue::String(callable_ref.name.clone())),
                                (
                                    "import_reference".to_string(),
                                    DetailValue::String(callable_ref.symbol()),
                                ),
                                (
                                    "global_position".to_string(),
                                    DetailValue::UInt(callable_ref.position as u64),
                                ),
                                ("opaque_extension".to_string(), DetailValue::Bool(true)),
                            ],
                            why: Some(
                                "Copyreg extension opcodes resolve through process-local state and become executable when consumed by REDUCE-like opcodes.",
                            ),
                        });
                    } else if callable_ref.module == "__main__" {
                        self.add_finding(Finding {
                            message: format!(
                                "Found {} opcode invoking __main__ global: {}",
                                opcode.name,
                                callable_ref.symbol()
                            ),
                            severity: "critical",
                            location: Some(format!("{} (pos {})", self.source, position)),
                            rule_code: Some("DANGEROUS_CALL"),
                            details: vec![
                                ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                                (
                                    "module".to_string(),
                                    DetailValue::String(callable_ref.module.clone()),
                                ),
                                ("name".to_string(), DetailValue::String(callable_ref.name.clone())),
                                (
                                    "import_reference".to_string(),
                                    DetailValue::String(callable_ref.symbol()),
                                ),
                                (
                                    "global_position".to_string(),
                                    DetailValue::UInt(callable_ref.position as u64),
                                ),
                            ],
                            why: Some(
                                "__main__ references depend on arbitrary application code and become executable when consumed by REDUCE-like opcodes.",
                            ),
                        });
                    } else if let Some(mutation_target) =
                        sensitive_mutator_invocation_target(callable_ref, &primary_invocation.args)
                    {
                        self.add_finding(Finding {
                            message: format!(
                                "Found {} opcode mutating process-global state: {}",
                                opcode.name,
                                callable_ref.symbol()
                            ),
                            severity: "critical",
                            location: Some(format!("{} (pos {})", self.source, position)),
                            rule_code: Some("DANGEROUS_CALL"),
                            details: vec![
                                ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                                (
                                    "module".to_string(),
                                    DetailValue::String(callable_ref.module.clone()),
                                ),
                                ("name".to_string(), DetailValue::String(callable_ref.name.clone())),
                                (
                                    "import_reference".to_string(),
                                    DetailValue::String(callable_ref.symbol()),
                                ),
                                (
                                    "global_position".to_string(),
                                    DetailValue::UInt(callable_ref.position as u64),
                                ),
                                (
                                    "mutation_target".to_string(),
                                    DetailValue::String(mutation_target.to_string()),
                                ),
                            ],
                            why: Some(
                                "This pickle opcode mutates process-global registries or diagnostic policy during deserialization.",
                            ),
                        });
                    } else if let Some(protocol_target) =
                        operator_mutator_protocol_target(callable_ref, &primary_invocation.args)
                    {
                        self.add_finding(Finding {
                            message: format!(
                                "Found {} opcode invoking object mutation protocol: {}",
                                opcode.name,
                                callable_ref.symbol()
                            ),
                            severity: "critical",
                            location: Some(format!("{} (pos {})", self.source, position)),
                            rule_code: Some("DANGEROUS_CALL"),
                            details: vec![
                                ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                                (
                                    "module".to_string(),
                                    DetailValue::String(callable_ref.module.clone()),
                                ),
                                ("name".to_string(), DetailValue::String(callable_ref.name.clone())),
                                (
                                    "import_reference".to_string(),
                                    DetailValue::String(callable_ref.symbol()),
                                ),
                                (
                                    "global_position".to_string(),
                                    DetailValue::UInt(callable_ref.position as u64),
                                ),
                                (
                                    "mutation_target".to_string(),
                                    DetailValue::String(protocol_target.to_string()),
                                ),
                            ],
                            why: Some(
                                "Operator mutators dispatch to target object protocol methods, which can execute attacker-controlled methods during deserialization.",
                            ),
                        });
                    } else if let Some(severity) =
                        callable_severity(&callable_ref.module, &callable_ref.name)
                    {
                        self.add_finding(Finding {
                            message: format!(
                                "Found {} opcode invoking dangerous global: {}",
                                opcode.name,
                                callable_ref.symbol()
                            ),
                            severity,
                            location: Some(format!("{} (pos {})", self.source, position)),
                            rule_code: Some("DANGEROUS_CALL"),
                            details: vec![
                                ("opcode".to_string(), DetailValue::String(opcode.name.to_string())),
                                (
                                    "module".to_string(),
                                    DetailValue::String(callable_ref.module.clone()),
                                ),
                                ("name".to_string(), DetailValue::String(callable_ref.name.clone())),
                                (
                                    "import_reference".to_string(),
                                    DetailValue::String(callable_ref.symbol()),
                                ),
                                (
                                    "global_position".to_string(),
                                    DetailValue::UInt(callable_ref.position as u64),
                                ),
                            ],
                            why: Some(
                                "This pickle opcode can invoke attacker-controlled callables during deserialization.",
                            ),
                        });
                    }
                }
            }
            "PERSID" | "BINPERSID" => {
                self.record_persistent_id(opcode, position);
            }
            "FRAME" | "STOP" => {}
            _ => {}
        }
    }

    fn record_buffer_opcode(&mut self, op_name: &'static str, position: usize, empty_stack: bool) {
        if self.first_buffer_opcode_position.is_none() {
            self.first_buffer_opcode_position = Some(position);
        }
        match op_name {
            "NEXT_BUFFER" => self.next_buffer_count += 1,
            "READONLY_BUFFER" => {
                self.readonly_buffer_count += 1;
                if empty_stack {
                    self.readonly_buffer_empty_stack_count += 1;
                }
            }
            _ => {}
        }
    }

    fn emit_buffer_opcode_notice(&mut self) {
        let buffer_opcode_count = self.next_buffer_count + self.readonly_buffer_count;
        if buffer_opcode_count == 0 {
            return;
        }
        let position = self.first_buffer_opcode_position.unwrap_or(0);
        self.add_notice(Notice {
            message: format!(
                "Encountered {buffer_opcode_count} protocol 5 buffer opcode(s); external buffer context is opaque"
            ),
            severity: "info",
            location: Some(format!("{} (pos {})", self.source, position)),
            code: Some("buffer_opcode"),
            details: vec![
                (
                    "buffer_opcode_count".to_string(),
                    DetailValue::UInt(buffer_opcode_count as u64),
                ),
                (
                    "next_buffer_count".to_string(),
                    DetailValue::UInt(self.next_buffer_count as u64),
                ),
                (
                    "readonly_buffer_count".to_string(),
                    DetailValue::UInt(self.readonly_buffer_count as u64),
                ),
                (
                    "readonly_buffer_empty_stack_count".to_string(),
                    DetailValue::UInt(self.readonly_buffer_empty_stack_count as u64),
                ),
                (
                    "requires_external_buffer_context".to_string(),
                    DetailValue::Bool(true),
                ),
            ],
        });
    }

    fn pop_value_operand_preserving_mark(&mut self) -> Option<StackValue> {
        match self.stack.pop() {
            Some(StackValue::Mark) => {
                self.stack.push(StackValue::Mark);
                None
            }
            value => value,
        }
    }

    fn pop_to_mark(&mut self) -> Vec<StackValue> {
        let mut values = Vec::new();
        while let Some(item) = self.stack.pop() {
            if matches!(item, StackValue::Mark) {
                break;
            }
            values.push(item);
        }
        values.reverse();
        values
    }

    fn apply_setitem(&mut self) {
        let value = self.pop_value_operand_preserving_mark();
        let key = self.pop_value_operand_preserving_mark();
        let key = key
            .as_ref()
            .and_then(|value| stack_value_string(value, self.payload));
        if let Some(value) = value {
            if let Some(key) = key {
                self.record_top_tracked_dict_entry(key.as_ref(), value);
            } else {
                self.record_top_tracked_dict_unknown_key_value(value);
            }
        }
    }

    fn apply_setitems(&mut self, values: &[StackValue]) {
        for pair in values.chunks_exact(2) {
            let key = pair
                .first()
                .and_then(|value| stack_value_string(value, self.payload));
            if let Some(value) = pair.get(1) {
                if let Some(key) = key {
                    self.record_top_tracked_dict_entry(key.as_ref(), value.clone());
                } else {
                    self.record_top_tracked_dict_unknown_key_value(value.clone());
                }
            }
        }
    }

    fn tracked_dict_from_values(&self, values: &[StackValue]) -> StackValue {
        let mut entries = Vec::new();
        let mut unknown_key_values = Vec::new();
        let mut unknown_key_values_overflowed = false;
        for pair in values.chunks_exact(2) {
            let key = pair
                .first()
                .and_then(|value| stack_value_string(value, self.payload));
            if let Some(value) = pair.get(1) {
                if let Some(key) = key {
                    Self::insert_tracked_dict_entry(&mut entries, key, value.clone());
                } else {
                    Self::insert_tracked_dict_unknown_key_value(
                        &mut unknown_key_values,
                        &mut unknown_key_values_overflowed,
                        value.clone(),
                    );
                }
            }
        }
        StackValue::TrackedDict {
            entries,
            unknown_key_values,
            unknown_key_values_overflowed,
            memo_index: None,
        }
    }

    fn record_top_tracked_dict_entry(&mut self, key: &str, value: StackValue) {
        let memo_index = match self.stack.last_mut() {
            Some(StackValue::TrackedDict {
                entries,
                memo_index,
                ..
            }) => {
                Self::insert_tracked_dict_entry(entries, key.to_string(), value.clone());
                *memo_index
            }
            _ => None,
        };
        if let Some(memo_index) = memo_index {
            if let Some(StackValue::TrackedDict { entries, .. }) = self.memo.get_mut(&memo_index) {
                Self::insert_tracked_dict_entry(entries, key.to_string(), value);
            }
        }
    }

    fn record_top_tracked_dict_unknown_key_value(&mut self, value: StackValue) {
        let memo_index = match self.stack.last_mut() {
            Some(StackValue::TrackedDict {
                unknown_key_values,
                unknown_key_values_overflowed,
                memo_index,
                ..
            }) => {
                Self::insert_tracked_dict_unknown_key_value(
                    unknown_key_values,
                    unknown_key_values_overflowed,
                    value.clone(),
                );
                *memo_index
            }
            _ => None,
        };
        if let Some(memo_index) = memo_index {
            if let Some(StackValue::TrackedDict {
                unknown_key_values,
                unknown_key_values_overflowed,
                ..
            }) = self.memo.get_mut(&memo_index)
            {
                Self::insert_tracked_dict_unknown_key_value(
                    unknown_key_values,
                    unknown_key_values_overflowed,
                    value,
                );
            }
        }
    }

    fn insert_tracked_dict_entry(
        entries: &mut Vec<(String, StackValue)>,
        key: String,
        value: StackValue,
    ) {
        if let Some((_, existing_value)) = entries
            .iter_mut()
            .find(|(existing_key, _)| existing_key == &key)
        {
            *existing_value = value;
        } else {
            entries.push((key, value));
        }
    }

    fn insert_tracked_dict_unknown_key_value(
        unknown_key_values: &mut Vec<StackValue>,
        unknown_key_values_overflowed: &mut bool,
        value: StackValue,
    ) {
        if unknown_key_values.len() < MAX_TRACKED_DICT_UNKNOWN_KEY_VALUES {
            unknown_key_values.push(value);
        } else {
            *unknown_key_values_overflowed = true;
        }
    }

    fn collapse_top_n(&mut self, count: usize) {
        if self.stack.len() < count {
            self.stack.push(StackValue::Other);
            return;
        }
        let start = self.stack.len().saturating_sub(count);
        if self.stack[start..]
            .iter()
            .any(|value| matches!(value, StackValue::Mark))
        {
            self.stack.push(StackValue::Other);
            return;
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(value) = self.stack.pop() {
                values.push(value);
            }
        }
        values.reverse();
        self.stack.push(self.collapse_stack_values(values));
    }

    fn collapse_stack_values(&self, values: Vec<StackValue>) -> StackValue {
        if let Some(rules) = self.regex_scanner_lexicon_rules(&values) {
            return StackValue::RegexScannerLexicon { rules };
        }
        collapse_tuple_values(values)
    }

    fn regex_scanner_lexicon_rules(&self, values: &[StackValue]) -> Option<Vec<RegexScannerRule>> {
        let mut rules = Vec::new();
        let mut saw_scanner_rule_shape = false;
        for value in values {
            let StackValue::Tuple(items) = value else {
                return None;
            };
            let [pattern_value, action_value] = items.as_slice() else {
                return None;
            };
            let pattern = stack_value_string(pattern_value, self.payload)?;
            saw_scanner_rule_shape = true;
            if let Some(action) = Self::callable_reference_from_value(Some(action_value)) {
                rules.push(RegexScannerRule { pattern, action });
            }
        }
        if saw_scanner_rule_shape && !rules.is_empty() {
            Some(rules)
        } else {
            None
        }
    }

    fn consume_callable_opcode(
        &mut self,
        opcode: &ParsedOpcode,
        position: usize,
    ) -> Vec<CallableInvocation> {
        let (callable_value, positional_arg_count, argument_values) = match opcode.name {
            "REDUCE" | "NEWOBJ" => {
                let Some(values) = self.consume_top_operand_values(2) else {
                    return Vec::new();
                };
                (
                    values.first().cloned(),
                    Self::tuple_positional_arg_count(values.get(1)),
                    Self::tuple_argument_values(values.get(1)),
                )
            }
            "NEWOBJ_EX" => {
                let Some(values) = self.consume_top_operand_values(3) else {
                    return Vec::new();
                };
                (
                    values.first().cloned(),
                    Self::tuple_positional_arg_count(values.get(1)),
                    Self::tuple_argument_values(values.get(1)),
                )
            }
            "OBJ" => {
                let values = self.pop_to_mark();
                let positional_arg_count = values.len().checked_sub(1);
                let callable_value = values.first().cloned();
                let argument_values = values.get(1..).map(|items| items.to_vec());
                self.push_constructed_result(callable_value.as_ref());
                (callable_value, positional_arg_count, argument_values)
            }
            "INST" => {
                let values = self.pop_to_mark();
                let (module, name) = opcode.arg.global_parts(self.payload);
                let reference = GlobalRef {
                    module,
                    name,
                    position,
                    malformed: false,
                };
                self.record_global_ref(&reference, opcode.name);
                self.stack.push(StackValue::Constructed(reference.clone()));
                (
                    Some(StackValue::Global(reference)),
                    Some(values.len()),
                    Some(values),
                )
            }
            "BUILD" => (self.consume_top_operands(2), None, None),
            _ => (None, None, None),
        };

        self.record_dynamic_type_callable_attribute_finding(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        );

        let mut invocations = Vec::new();
        if let Some(invocation) = Self::callable_invocation_for_value(
            callable_value.as_ref(),
            opcode.name,
            position,
            positional_arg_count,
            argument_values.as_deref(),
        ) {
            invocations.push(invocation);
        }
        invocations.extend(self.protocol_dispatch_invocations(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        ));
        invocations.extend(self.callback_dispatch_invocations(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        ));
        invocations.extend(self.future_callback_invocations(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        ));
        invocations.extend(Self::call_iterator_consumption_invocations(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        ));
        invocations.extend(self.defaultdict_factory_invocations(
            callable_value.as_ref(),
            argument_values.as_deref(),
            opcode.name,
            position,
        ));
        invocations
    }

    fn callable_invocation_for_value(
        callable_value: Option<&StackValue>,
        op_name: &'static str,
        position: usize,
        positional_arg_count: Option<usize>,
        args: Option<&[StackValue]>,
    ) -> Option<CallableInvocation> {
        match callable_value {
            Some(StackValue::Global(reference)) if !reference.malformed => {
                if Self::suppress_plain_constructor_invocation(reference, op_name) {
                    return None;
                }
                Some(CallableInvocation {
                    reference: reference.clone(),
                    op_name,
                    opcode_position: position,
                    positional_arg_count,
                    args: args.unwrap_or_default().to_vec(),
                })
            }
            Some(StackValue::Constructed(reference)) if !reference.malformed => {
                let reference = match op_name {
                    "REDUCE" | "OBJ" => Self::constructed_callable_reference(reference),
                    _ => reference.clone(),
                };
                Some(CallableInvocation {
                    reference,
                    op_name,
                    opcode_position: position,
                    positional_arg_count,
                    args: args.unwrap_or_default().to_vec(),
                })
            }
            Some(StackValue::Global(reference) | StackValue::Constructed(reference))
                if reference.module == "copyreg.extension" =>
            {
                Some(CallableInvocation {
                    reference: reference.clone(),
                    op_name,
                    opcode_position: position,
                    positional_arg_count,
                    args: args.unwrap_or_default().to_vec(),
                })
            }
            _ => None,
        }
    }

    fn suppress_plain_constructor_invocation(reference: &GlobalRef, op_name: &'static str) -> bool {
        matches!(op_name, "REDUCE" | "OBJ")
            && reference.module == "re"
            && reference.name == "Scanner"
    }

    fn record_dynamic_type_callable_attribute_finding(
        &mut self,
        callable_value: Option<&StackValue>,
        arguments: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) {
        let Some(arguments) = arguments else {
            return;
        };
        let Some(arguments) = Self::dynamic_type_constructor_arguments(callable_value, arguments)
        else {
            return;
        };
        let [type_name_value, _, namespace] = arguments else {
            return;
        };
        let attributes = self.dynamic_type_callable_attributes(namespace);
        if attributes.is_empty() {
            return;
        }

        let type_name = stack_value_string(type_name_value, self.payload);
        for attribute in attributes {
            let dynamic_attribute_name = attribute.attribute_name.is_none();
            let attribute_name = attribute
                .attribute_name
                .unwrap_or_else(|| "__dynamic__".to_string());
            let callable_module = attribute
                .callable
                .as_ref()
                .map_or(DetailValue::None, |callable| {
                    DetailValue::String(callable.module.clone())
                });
            let callable_name = attribute
                .callable
                .as_ref()
                .map_or(DetailValue::None, |callable| {
                    DetailValue::String(callable.name.clone())
                });
            let callable_import_reference = attribute
                .callable
                .as_ref()
                .map_or(DetailValue::None, |callable| {
                    DetailValue::String(callable.symbol())
                });
            let global_position = attribute
                .callable
                .as_ref()
                .map_or(DetailValue::None, |callable| {
                    DetailValue::UInt(callable.position as u64)
                });
            self.add_finding(Finding {
                message: format!(
                    "Found {op_name} opcode constructing a dynamic type with callable attribute: {attribute_name}"
                ),
                severity: "warning",
                location: Some(format!("{} (pos {})", self.source, position)),
                rule_code: Some("DYNAMIC_TYPE_CALLABLE_ATTRIBUTE"),
                details: vec![
                    ("opcode".to_string(), DetailValue::String(op_name.to_string())),
                    (
                        "type_name".to_string(),
                        type_name
                            .clone()
                            .map_or(DetailValue::None, DetailValue::String),
                    ),
                    (
                        "attribute_name".to_string(),
                        DetailValue::String(attribute_name),
                    ),
                    (
                        "dynamic_attribute_name".to_string(),
                        DetailValue::Bool(dynamic_attribute_name),
                    ),
                    ("callable_module".to_string(), callable_module),
                    ("callable_name".to_string(), callable_name),
                    (
                        "callable_import_reference".to_string(),
                        callable_import_reference,
                    ),
                    ("global_position".to_string(), global_position),
                    (
                        "tracked_dynamic_key_value_overflow".to_string(),
                        DetailValue::Bool(attribute.unknown_key_values_overflowed),
                    ),
                ],
                why: Some(
                    "Dynamically constructed classes can install attacker-controlled protocol hooks such as __del__ or __repr__; those hooks may execute during or after deserialization.",
                ),
            });
        }
    }

    fn dynamic_type_constructor_arguments<'args>(
        callable_value: Option<&StackValue>,
        arguments: &'args [StackValue],
    ) -> Option<&'args [StackValue]> {
        let Some(StackValue::Global(reference)) = callable_value else {
            return None;
        };
        if reference.malformed
            || !matches!(
                reference.module.as_str(),
                "builtins" | "__builtin__" | "__builtins__"
            )
        {
            return None;
        }
        if reference.name == "type" && arguments.len() == 3 {
            return Some(arguments);
        }
        if reference.name == "type.__new__"
            && arguments.len() == 4
            && Self::is_builtin_type_value(arguments.first())
        {
            return Some(&arguments[1..]);
        }
        None
    }

    fn is_builtin_type_value(value: Option<&StackValue>) -> bool {
        let Some(StackValue::Global(reference)) = value else {
            return false;
        };
        !reference.malformed
            && matches!(
                (reference.module.as_str(), reference.name.as_str()),
                ("builtins" | "__builtin__" | "__builtins__", "type")
            )
    }

    fn dynamic_type_callable_attributes(
        &self,
        namespace: &StackValue,
    ) -> Vec<DynamicTypeCallableAttribute> {
        let StackValue::TrackedDict {
            entries,
            unknown_key_values,
            unknown_key_values_overflowed,
            memo_index,
        } = namespace
        else {
            return Vec::new();
        };

        let mut attributes = Vec::new();
        for (key, value) in self.current_tracked_dict_entries(entries, *memo_index) {
            let key = key.to_ascii_lowercase();
            if !is_suspicious_magic_method(&key) {
                continue;
            }
            if let Some(callable) = Self::callable_reference_from_value(Some(value)) {
                attributes.push(DynamicTypeCallableAttribute {
                    attribute_name: Some(key),
                    callable: Some(callable),
                    unknown_key_values_overflowed: false,
                });
            }
        }
        for value in self.current_tracked_dict_unknown_key_values(unknown_key_values, *memo_index) {
            if let Some(callable) = Self::callable_reference_from_value(Some(value)) {
                attributes.push(DynamicTypeCallableAttribute {
                    attribute_name: None,
                    callable: Some(callable),
                    unknown_key_values_overflowed: false,
                });
            }
        }
        if self.current_tracked_dict_unknown_key_values_overflowed(
            *unknown_key_values_overflowed,
            *memo_index,
        ) {
            attributes.push(DynamicTypeCallableAttribute {
                attribute_name: None,
                callable: None,
                unknown_key_values_overflowed: true,
            });
        }
        attributes
    }

    fn protocol_dispatch_invocations(
        &self,
        callable_value: Option<&StackValue>,
        argument_values: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !matches!(op_name, "REDUCE" | "OBJ") {
            return Vec::new();
        }
        let Some(StackValue::Global(callable_reference)) = callable_value else {
            return Vec::new();
        };
        if callable_reference.malformed {
            return Vec::new();
        }
        let Some(arguments) = argument_values else {
            return Vec::new();
        };
        match (
            callable_reference.module.as_str(),
            callable_reference.name.as_str(),
        ) {
            ("builtins", "format") => {
                Self::builtins_format_invocations(arguments, op_name, position)
            }
            ("builtins", "str.format") => self.str_format_invocations(arguments, op_name, position),
            ("builtins", "str.format_map") => {
                self.str_format_map_invocations(arguments, op_name, position)
            }
            ("operator", "mod" | "imod") => {
                self.operator_mod_invocations(arguments, op_name, position)
            }
            ("string", "Formatter.vformat") => {
                self.formatter_vformat_invocations(arguments, op_name, position)
            }
            ("string", "Formatter._vformat") => {
                self.formatter_private_vformat_invocations(arguments, op_name, position)
            }
            ("string", "Template.substitute" | "Template.safe_substitute") => {
                self.template_substitute_invocations(arguments, op_name, position)
            }
            _ => Vec::new(),
        }
    }

    fn callback_dispatch_invocations(
        &self,
        callable_value: Option<&StackValue>,
        argument_values: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !matches!(op_name, "REDUCE" | "OBJ") {
            return Vec::new();
        }
        let Some(StackValue::Global(callable_reference)) = callable_value else {
            return Vec::new();
        };
        if callable_reference.malformed {
            return Vec::new();
        }
        let Some(arguments) = argument_values else {
            return Vec::new();
        };
        if let Some(invocation) = self.regex_scanner_scan_invocation(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
            op_name,
            position,
        ) {
            return vec![invocation];
        }
        let Some((_, _, _, callback_arg_index, callback_arg_count, guard)) =
            EXACT_ARITY_CALLBACK_DISPATCH_CONSUMERS.iter().find(
                |(consumer_module, consumer_name, arity, _, _, _)| {
                    Self::consumer_module_matches(&callable_reference.module, consumer_module)
                        && *consumer_name == callable_reference.name
                        && *arity == arguments.len()
                },
            )
        else {
            return Vec::new();
        };
        if !self.callback_dispatch_guard_is_satisfied(*guard, arguments) {
            return Vec::new();
        }
        let Some(reference) =
            Self::callable_reference_from_value(arguments.get(*callback_arg_index))
        else {
            return Vec::new();
        };
        vec![Self::callable_invocation(
            reference,
            op_name,
            position,
            Some(*callback_arg_count),
        )]
    }

    fn callback_dispatch_guard_is_satisfied(
        &self,
        guard: CallbackDispatchGuard,
        arguments: &[StackValue],
    ) -> bool {
        match guard {
            CallbackDispatchGuard::Always => true,
            CallbackDispatchGuard::NonEmptyIterable { arg_index } => {
                Self::is_definitely_non_empty_iterable_argument(arguments.get(arg_index))
            }
            CallbackDispatchGuard::LiteralRegexMatch {
                pattern_arg_index,
                input_arg_index,
                flags_arg_index,
            } => self.literal_regex_pattern_matches_argument(
                arguments.get(pattern_arg_index),
                arguments.get(input_arg_index),
                flags_arg_index.and_then(|arg_index| arguments.get(arg_index)),
            ),
        }
    }

    fn future_callback_invocations(
        &mut self,
        callable_value: Option<&StackValue>,
        argument_values: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !matches!(op_name, "REDUCE" | "OBJ") {
            return Vec::new();
        }
        let Some(StackValue::Global(callable_reference)) = callable_value else {
            return Vec::new();
        };
        if callable_reference.malformed {
            return Vec::new();
        }
        let Some(arguments) = argument_values else {
            return Vec::new();
        };
        if Self::is_concurrent_future_symbol(callable_reference, "Future.add_done_callback")
            && arguments.len() == 2
        {
            return self.future_add_done_callback_invocations(arguments, op_name, position);
        }
        if Self::is_concurrent_future_completion_method(callable_reference, arguments.len()) {
            return self.future_completion_invocations(arguments, op_name, position);
        }
        Vec::new()
    }

    fn future_add_done_callback_invocations(
        &mut self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        let Some(StackValue::FutureCallbacks(receiver)) = arguments.first() else {
            return Vec::new();
        };
        let Some(callback) = Self::callable_reference_from_value(arguments.get(1)) else {
            return Vec::new();
        };
        if receiver.done {
            return vec![Self::callable_invocation(
                callback,
                op_name,
                position,
                Some(1),
            )];
        }
        if let Some(memo_index) = receiver.memo_index {
            self.memoized_future_add_callback(memo_index, callback);
        }
        Vec::new()
    }

    fn future_completion_invocations(
        &mut self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        let Some(StackValue::FutureCallbacks(receiver)) = arguments.first() else {
            return Vec::new();
        };
        let callbacks = receiver.callbacks.clone();
        if let Some(memo_index) = receiver.memo_index {
            self.memoized_future_mark_done(memo_index);
        }
        callbacks
            .into_iter()
            .map(|callback| Self::callable_invocation(callback, op_name, position, Some(1)))
            .collect()
    }

    fn is_concurrent_future_symbol(reference: &GlobalRef, name: &str) -> bool {
        matches!(
            reference.module.as_str(),
            "concurrent.futures" | "concurrent.futures._base"
        ) && reference.name == name
    }

    fn is_concurrent_future_completion_method(reference: &GlobalRef, arity: usize) -> bool {
        matches!(
            (reference.module.as_str(), reference.name.as_str(), arity),
            (
                "concurrent.futures" | "concurrent.futures._base",
                "Future.set_result" | "Future.set_exception",
                2
            ) | (
                "concurrent.futures" | "concurrent.futures._base",
                "Future.cancel",
                1
            )
        )
    }

    fn literal_regex_pattern_matches_argument(
        &self,
        pattern_value: Option<&StackValue>,
        input_value: Option<&StackValue>,
        flags_value: Option<&StackValue>,
    ) -> bool {
        let Some(mut pattern) = self.regex_pattern_from_value(pattern_value) else {
            return false;
        };
        if flags_value.is_some() {
            pattern.flags = flags_value.and_then(Self::stack_value_integer);
        }
        let Some(input) = input_value.and_then(|value| stack_value_string(value, self.payload))
        else {
            return false;
        };
        Self::regex_pattern_matches_literal_input(&pattern.pattern, &input, pattern.flags)
    }

    fn regex_scanner_scan_invocation(
        &self,
        module: &str,
        name: &str,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Option<CallableInvocation> {
        if module != "re" || name != "Scanner.scan" || arguments.len() != 2 {
            return None;
        }
        let Some(StackValue::RegexScanner { rules, flags }) = arguments.first() else {
            return None;
        };
        let input = arguments
            .get(1)
            .and_then(|value| stack_value_string(value, self.payload))?;
        rules
            .iter()
            .find(|rule| Self::regex_pattern_matches_literal_input(&rule.pattern, &input, *flags))
            .map(|rule| Self::callable_invocation(rule.action.clone(), op_name, position, Some(2)))
    }

    fn regex_pattern_from_value(&self, value: Option<&StackValue>) -> Option<RegexPatternSpec> {
        match value {
            Some(StackValue::RegexPattern { pattern, flags }) => Some(RegexPatternSpec {
                pattern: pattern.clone(),
                flags: *flags,
            }),
            Some(value) => {
                stack_value_string(value, self.payload).map(|pattern| RegexPatternSpec {
                    pattern,
                    flags: Some(0),
                })
            }
            None => None,
        }
    }

    fn is_regex_metacharacter(character: char) -> bool {
        matches!(
            character,
            '.' | '^' | '$' | '*' | '+' | '?' | '{' | '}' | '[' | ']' | '\\' | '|' | '(' | ')'
        )
    }

    fn is_plain_regex_literal(pattern: &str) -> bool {
        !pattern.chars().any(Self::is_regex_metacharacter)
    }

    fn regex_flags_may_enable(flags: Option<isize>, flag: isize) -> bool {
        flags.is_none_or(|bits| bits & flag != 0)
    }

    fn regex_any_line_matches(input: &str, predicate: impl Fn(&str) -> bool) -> bool {
        input.split('\n').any(predicate)
    }

    fn plain_regex_literal_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> bool {
        pattern.is_empty()
            || input.contains(pattern)
            || (Self::regex_flags_may_enable(flags, REGEX_FLAG_IGNORECASE)
                && input.to_lowercase().contains(&pattern.to_lowercase()))
    }

    fn regex_pattern_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> bool {
        !matches!(
            Self::classify_regex_pattern_literal_input(pattern, input, flags),
            RegexLiteralInputMatch::DoesNotMatch
        )
    }

    fn classify_regex_pattern_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> RegexLiteralInputMatch {
        if let Some(match_result) =
            Self::simple_regex_alternative_matches_literal_input(pattern, input, flags)
        {
            return match_result;
        }
        if let Some(match_result) =
            Self::simple_regex_anchor_matches_literal_input(pattern, input, flags)
        {
            return match_result;
        }
        if let Some(match_result) =
            Self::simple_regex_char_class_matches_literal_input(pattern, input, flags)
        {
            return match_result;
        }
        if let Some(match_result) =
            Self::simple_regex_dot_matches_literal_input(pattern, input, flags)
        {
            return match_result;
        }
        if let Some(match_result) =
            Self::simple_regex_single_char_quantifier_matches_literal_input(pattern, input, flags)
        {
            return match_result;
        }
        if Self::is_plain_regex_literal(pattern) {
            return if Self::plain_regex_literal_matches_literal_input(pattern, input, flags) {
                RegexLiteralInputMatch::Matches
            } else {
                RegexLiteralInputMatch::DoesNotMatch
            };
        }
        RegexLiteralInputMatch::Unknown
    }

    fn simple_regex_alternative_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> Option<RegexLiteralInputMatch> {
        if !pattern.contains('|') {
            return None;
        }
        if pattern.contains('\\') || pattern.contains('(') || pattern.contains(')') {
            return Some(RegexLiteralInputMatch::Unknown);
        }
        let mut saw_unknown = false;
        for branch in pattern.split('|') {
            match Self::classify_regex_pattern_literal_input(branch, input, flags) {
                RegexLiteralInputMatch::Matches => return Some(RegexLiteralInputMatch::Matches),
                RegexLiteralInputMatch::DoesNotMatch => {}
                RegexLiteralInputMatch::Unknown => saw_unknown = true,
            }
        }
        Some(if saw_unknown {
            RegexLiteralInputMatch::Unknown
        } else {
            RegexLiteralInputMatch::DoesNotMatch
        })
    }

    fn simple_regex_anchor_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> Option<RegexLiteralInputMatch> {
        if let Some(inner) = pattern
            .strip_prefix('^')
            .and_then(|remaining| remaining.strip_suffix('$'))
        {
            if Self::is_plain_regex_literal(inner) {
                let matches = input == inner
                    || input
                        .strip_suffix('\n')
                        .is_some_and(|without_final_newline| without_final_newline == inner)
                    || (Self::regex_flags_may_enable(flags, REGEX_FLAG_MULTILINE)
                        && Self::regex_any_line_matches(input, |line| line == inner));
                return Some(if matches {
                    RegexLiteralInputMatch::Matches
                } else {
                    RegexLiteralInputMatch::DoesNotMatch
                });
            }
        }
        if let Some(inner) = pattern.strip_prefix('^') {
            if Self::is_plain_regex_literal(inner) {
                let matches = input.starts_with(inner)
                    || (Self::regex_flags_may_enable(flags, REGEX_FLAG_MULTILINE)
                        && Self::regex_any_line_matches(input, |line| line.starts_with(inner)));
                return Some(if matches {
                    RegexLiteralInputMatch::Matches
                } else {
                    RegexLiteralInputMatch::DoesNotMatch
                });
            }
        }
        if let Some(inner) = pattern.strip_suffix('$') {
            if Self::is_plain_regex_literal(inner) {
                let matches = input.ends_with(inner)
                    || input
                        .strip_suffix('\n')
                        .is_some_and(|without_final_newline| {
                            without_final_newline.ends_with(inner)
                        })
                    || (Self::regex_flags_may_enable(flags, REGEX_FLAG_MULTILINE)
                        && Self::regex_any_line_matches(input, |line| line.ends_with(inner)));
                return Some(if matches {
                    RegexLiteralInputMatch::Matches
                } else {
                    RegexLiteralInputMatch::DoesNotMatch
                });
            }
        }
        None
    }

    fn simple_regex_char_class_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> Option<RegexLiteralInputMatch> {
        let inner = pattern.strip_prefix('[')?.strip_suffix(']')?;
        let (negated, characters) = inner
            .strip_prefix('^')
            .map_or((false, inner), |characters| (true, characters));
        if characters.is_empty()
            || characters
                .chars()
                .any(|character| matches!(character, '[' | ']' | '\\' | '-'))
        {
            return Some(RegexLiteralInputMatch::Unknown);
        }
        let matches = input.chars().any(|character| {
            let contains = characters.chars().any(|candidate| {
                candidate == character
                    || (Self::regex_flags_may_enable(flags, REGEX_FLAG_IGNORECASE)
                        && candidate.to_lowercase().to_string()
                            == character.to_lowercase().to_string())
            });
            if negated {
                !contains
            } else {
                contains
            }
        });
        Some(if matches {
            RegexLiteralInputMatch::Matches
        } else {
            RegexLiteralInputMatch::DoesNotMatch
        })
    }

    fn simple_regex_dot_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> Option<RegexLiteralInputMatch> {
        match pattern {
            "." | ".+" | ".+?" => Some(Self::dot_regex_atom_matches_literal_input(input, flags)),
            ".*" | ".*?" | ".?" | ".??" => Some(RegexLiteralInputMatch::Matches),
            _ => None,
        }
    }

    fn dot_regex_atom_matches_literal_input(
        input: &str,
        flags: Option<isize>,
    ) -> RegexLiteralInputMatch {
        if input.chars().any(|character| {
            character != '\n' || Self::regex_flags_may_enable(flags, REGEX_FLAG_DOTALL)
        }) {
            RegexLiteralInputMatch::Matches
        } else {
            RegexLiteralInputMatch::DoesNotMatch
        }
    }

    fn simple_regex_single_char_quantifier_matches_literal_input(
        pattern: &str,
        input: &str,
        flags: Option<isize>,
    ) -> Option<RegexLiteralInputMatch> {
        let mut characters = pattern.chars();
        let atom = characters.next()?;
        let quantifier = characters.next()?;
        if characters.next().is_some()
            || Self::is_regex_metacharacter(atom)
            || !matches!(quantifier, '*' | '+' | '?')
        {
            return None;
        }
        Some(match quantifier {
            '*' | '?' => RegexLiteralInputMatch::Matches,
            '+' => {
                if input.chars().any(|character| {
                    character == atom
                        || (Self::regex_flags_may_enable(flags, REGEX_FLAG_IGNORECASE)
                            && atom.to_lowercase().to_string()
                                == character.to_lowercase().to_string())
                }) {
                    RegexLiteralInputMatch::Matches
                } else {
                    RegexLiteralInputMatch::DoesNotMatch
                }
            }
            _ => RegexLiteralInputMatch::Unknown,
        })
    }

    fn builtins_format_invocations(
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !(1..=2).contains(&arguments.len()) {
            return Vec::new();
        }
        let Some(StackValue::Constructed(receiver_reference)) = arguments.first() else {
            return Vec::new();
        };
        Self::format_invocation(receiver_reference, op_name, position)
            .into_iter()
            .collect()
    }

    fn str_format_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if arguments.len() < 2 || !self.brace_format_string_may_use_field(arguments.first()) {
            return Vec::new();
        }
        let mut invocations: Vec<CallableInvocation> = arguments
            .iter()
            .skip(1)
            .filter_map(|argument| match argument {
                StackValue::Constructed(reference) => {
                    Self::format_invocation(reference, op_name, position)
                }
                _ => None,
            })
            .collect();

        let Some(format_string) = resolve_global_operand(arguments.first(), self.payload) else {
            return invocations;
        };
        let lookups = Self::str_format_positional_lookups(&format_string);

        for (index, path) in lookups {
            invocations.extend(self.mapping_lookup_path_invocations(
                arguments.get(index + 1),
                &path,
                op_name,
                position,
            ));
        }
        invocations
    }

    fn str_format_positional_lookups(format_string: &str) -> Vec<(usize, Vec<Option<String>>)> {
        let mut numbering = FormatFieldNumbering::Unset;
        let mut next_auto_index = 0;
        let mut lookups = Vec::new();
        let _ = Self::collect_str_format_lookup_indices(
            format_string,
            0,
            &mut numbering,
            &mut next_auto_index,
            &mut lookups,
        );
        lookups
    }

    fn collect_str_format_lookup_indices(
        format_string: &str,
        depth: usize,
        numbering: &mut FormatFieldNumbering,
        next_auto_index: &mut usize,
        lookups: &mut Vec<(usize, Vec<Option<String>>)>,
    ) -> Option<()> {
        if depth > MAX_STR_FORMAT_FIELD_NESTING {
            return Some(());
        }

        let bytes = format_string.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                    cursor += 2;
                }
                b'{' => {
                    let (field, next_cursor) =
                        Self::extract_str_format_field(format_string, cursor + 1)?;
                    Self::collect_str_format_field_lookup_indices(
                        field,
                        depth,
                        numbering,
                        next_auto_index,
                        lookups,
                    )?;
                    cursor = next_cursor;
                }
                b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                    cursor += 2;
                }
                b'}' => return None,
                _ => cursor += 1,
            }
        }
        Some(())
    }

    fn extract_str_format_field(format_string: &str, start: usize) -> Option<(&str, usize)> {
        let bytes = format_string.as_bytes();
        let mut cursor = start;
        let mut nested_depth = 0usize;

        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                    cursor += 2;
                }
                b'{' => {
                    nested_depth += 1;
                    cursor += 1;
                }
                b'}' if nested_depth == 0 => {
                    return Some((&format_string[start..cursor], cursor + 1));
                }
                b'}' => {
                    nested_depth -= 1;
                    cursor += 1;
                }
                _ => cursor += 1,
            }
        }
        None
    }

    fn collect_str_format_field_lookup_indices(
        field: &str,
        depth: usize,
        numbering: &mut FormatFieldNumbering,
        next_auto_index: &mut usize,
        lookups: &mut Vec<(usize, Vec<Option<String>>)>,
    ) -> Option<()> {
        let (field_name, format_spec_index) = Self::str_format_field_name_and_spec(field);
        let root_end = field_name.find(['[', '.']).unwrap_or(field_name.len());
        let root = &field_name[..root_end];
        let has_item_lookup = field_name[root_end..].contains('[');

        let positional_index = if root.is_empty() {
            if *numbering == FormatFieldNumbering::Manual {
                return None;
            }
            *numbering = FormatFieldNumbering::Auto;
            let index = *next_auto_index;
            *next_auto_index += 1;
            Some(index)
        } else if let Some(index) = Self::parse_str_format_decimal_index(root) {
            if *numbering == FormatFieldNumbering::Auto {
                return None;
            }
            *numbering = FormatFieldNumbering::Manual;
            Some(index)
        } else {
            None
        };

        if has_item_lookup {
            if let Some(index) = positional_index {
                if let StrFormatRootItemLookup::Path(path) =
                    Self::str_format_root_item_key(field_name, root_end)
                {
                    lookups.push((index, path));
                }
            }
        }

        if let Some(spec_start) = format_spec_index {
            Self::collect_str_format_lookup_indices(
                &field[spec_start..],
                depth + 1,
                numbering,
                next_auto_index,
                lookups,
            )?;
        }
        Some(())
    }

    fn str_format_field_name_and_spec(field: &str) -> (&str, Option<usize>) {
        let bytes = field.as_bytes();
        let mut delimiter_index = bytes.len();
        let mut format_spec_index = None;
        let mut item_depth = 0usize;
        for (index, byte) in bytes.iter().enumerate() {
            match byte {
                b'[' => item_depth += 1,
                b']' if item_depth > 0 => item_depth -= 1,
                b'!' | b':' if item_depth == 0 => {
                    if delimiter_index == bytes.len() {
                        delimiter_index = index;
                    }
                    if *byte == b':' {
                        format_spec_index = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }

        (&field[..delimiter_index], format_spec_index)
    }

    fn str_format_root_item_key(field_name: &str, root_end: usize) -> StrFormatRootItemLookup {
        let Some(suffix) = field_name.get(root_end..) else {
            return StrFormatRootItemLookup::Invalid;
        };
        let mut remaining = suffix;
        let mut path = Vec::new();

        while !remaining.is_empty() {
            if remaining.starts_with('.') {
                break;
            }
            let Some(after_open) = remaining.strip_prefix('[') else {
                return StrFormatRootItemLookup::Invalid;
            };
            let Some((key, after_close)) = after_open.split_once(']') else {
                return StrFormatRootItemLookup::Invalid;
            };
            if key.is_empty() {
                path.push(None);
            } else if Self::is_str_format_decimal_syntax(key) {
                if Self::parse_str_format_decimal_index(key).is_some() {
                    path.push(None);
                } else {
                    return StrFormatRootItemLookup::Invalid;
                }
            } else {
                path.push(Some(key.to_string()));
            }
            remaining = after_close;
        }

        if path.is_empty() {
            StrFormatRootItemLookup::Invalid
        } else {
            StrFormatRootItemLookup::Path(path)
        }
    }

    fn parse_str_format_decimal_index(value: &str) -> Option<usize> {
        let mut chars = value.chars();
        let first = chars.next()?;
        let mut index = usize::try_from(Self::str_format_decimal_digit_value(first)?).ok()?;
        for ch in chars {
            let digit = usize::try_from(Self::str_format_decimal_digit_value(ch)?).ok()?;
            index = index.checked_mul(10)?.checked_add(digit)?;
        }
        (index <= isize::MAX as usize).then_some(index)
    }

    fn is_str_format_decimal_syntax(value: &str) -> bool {
        !value.is_empty()
            && value
                .chars()
                .all(|ch| Self::str_format_decimal_digit_value(ch).is_some())
    }

    fn str_format_decimal_digit_value(ch: char) -> Option<u32> {
        let codepoint = ch as u32;
        Self::str_format_decimal_digit_value_in_ranges(
            codepoint,
            STR_FORMAT_DECIMAL_ZERO_CODEPOINTS,
        )
        .or_else(|| {
            (RUNTIME_PYTHON_MINOR_VERSION.load(Ordering::Relaxed) >= 12)
                .then(|| {
                    Self::str_format_decimal_digit_value_in_ranges(
                        codepoint,
                        PYTHON_3_12_PLUS_STR_FORMAT_DECIMAL_ZERO_CODEPOINTS,
                    )
                })
                .flatten()
        })
    }

    fn str_format_decimal_digit_value_in_ranges(
        codepoint: u32,
        zero_codepoints: &[u32],
    ) -> Option<u32> {
        zero_codepoints.iter().find_map(|zero| {
            (codepoint >= *zero && codepoint < *zero + 10).then_some(codepoint - *zero)
        })
    }

    fn str_format_map_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if arguments.len() != 2 || !self.brace_format_string_may_use_field(arguments.first()) {
            return Vec::new();
        }
        let Some(format_string) = resolve_global_operand(arguments.first(), self.payload) else {
            return self.mapping_lookup_invocations(arguments.get(1), None, op_name, position);
        };
        Self::str_format_named_lookups(&format_string)
            .into_iter()
            .flat_map(|path| {
                self.mapping_lookup_path_invocations(arguments.get(1), &path, op_name, position)
            })
            .collect()
    }

    fn str_format_named_lookups(format_string: &str) -> Vec<Vec<Option<String>>> {
        let mut lookups = Vec::new();
        let _ = Self::collect_str_format_named_lookup_paths(format_string, 0, &mut lookups);
        lookups
    }

    fn collect_str_format_named_lookup_paths(
        format_string: &str,
        depth: usize,
        lookups: &mut Vec<Vec<Option<String>>>,
    ) -> Option<()> {
        if depth > MAX_STR_FORMAT_FIELD_NESTING {
            return Some(());
        }

        let bytes = format_string.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                    cursor += 2;
                }
                b'{' => {
                    let (field, next_cursor) =
                        Self::extract_str_format_field(format_string, cursor + 1)?;
                    Self::collect_str_format_field_named_lookup_paths(field, depth, lookups)?;
                    cursor = next_cursor;
                }
                b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                    cursor += 2;
                }
                b'}' => return None,
                _ => cursor += 1,
            }
        }
        Some(())
    }

    fn collect_str_format_field_named_lookup_paths(
        field: &str,
        depth: usize,
        lookups: &mut Vec<Vec<Option<String>>>,
    ) -> Option<()> {
        let (field_name, format_spec_index) = Self::str_format_field_name_and_spec(field);
        let root_end = field_name.find(['[', '.']).unwrap_or(field_name.len());
        let root = &field_name[..root_end];
        if !root.is_empty() && Self::parse_str_format_decimal_index(root).is_none() {
            let mut path = vec![Some(root.to_string())];
            if field_name[root_end..].contains('[') {
                if let StrFormatRootItemLookup::Path(item_path) =
                    Self::str_format_root_item_key(field_name, root_end)
                {
                    path.extend(item_path);
                }
            }
            lookups.push(path);
        }

        if let Some(spec_start) = format_spec_index {
            Self::collect_str_format_named_lookup_paths(&field[spec_start..], depth + 1, lookups)?;
        }
        Some(())
    }

    fn operator_mod_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if arguments.len() != 2
            || !self.percent_format_string_may_use_mapping_key(arguments.first())
        {
            return Vec::new();
        }
        self.mapping_lookup_invocations(arguments.get(1), None, op_name, position)
    }

    fn mapping_lookup_invocations(
        &self,
        mapping: Option<&StackValue>,
        key: Option<&str>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        let Some(MappingLookup::Found(default_factory)) =
            self.mapping_lookup_default_factory(mapping, key)
        else {
            return Vec::new();
        };
        vec![Self::zero_arg_invocation(
            default_factory,
            op_name,
            position,
        )]
    }

    fn mapping_lookup_path_invocations(
        &self,
        mapping: Option<&StackValue>,
        path: &[Option<String>],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        let Some(MappingLookup::Found(default_factory)) =
            self.mapping_lookup_default_factory_path(mapping, path)
        else {
            return Vec::new();
        };
        vec![Self::zero_arg_invocation(
            default_factory,
            op_name,
            position,
        )]
    }

    fn mapping_lookup_default_factory<'b>(
        &'b self,
        mapping: Option<&'b StackValue>,
        key: Option<&str>,
    ) -> Option<MappingLookup<'b>> {
        self.mapping_lookup_default_factory_inner(mapping?, key)
    }

    fn mapping_lookup_default_factory_path<'b>(
        &'b self,
        mapping: Option<&'b StackValue>,
        path: &[Option<String>],
    ) -> Option<MappingLookup<'b>> {
        self.mapping_lookup_default_factory_path_inner(mapping?, path)
    }

    fn mapping_lookup_default_factory_inner<'b>(
        &'b self,
        mapping: &'b StackValue,
        key: Option<&str>,
    ) -> Option<MappingLookup<'b>> {
        match mapping {
            StackValue::DefaultDict { default_factory } => {
                Some(MappingLookup::Found(default_factory))
            }
            StackValue::TrackedDict {
                entries,
                memo_index,
                ..
            } => {
                let entries = self.current_tracked_dict_entries(entries, *memo_index);
                if key.is_some_and(|key| entries.iter().any(|(candidate, _)| candidate == key)) {
                    Some(MappingLookup::Shadowed)
                } else {
                    None
                }
            }
            StackValue::MappingWrapper {
                reference,
                mappings,
            } if reference.module == "collections" && reference.name == "ChainMap" => {
                for mapping in mappings {
                    match self.mapping_lookup_default_factory_inner(mapping, key) {
                        Some(MappingLookup::Found(default_factory)) => {
                            return Some(MappingLookup::Found(default_factory));
                        }
                        Some(MappingLookup::Shadowed) => return Some(MappingLookup::Shadowed),
                        None => {}
                    }
                }
                None
            }
            StackValue::MappingWrapper {
                reference,
                mappings,
            } if reference.module == "types" && reference.name == "MappingProxyType" => mappings
                .first()
                .and_then(|mapping| self.mapping_lookup_default_factory_inner(mapping, key)),
            _ => None,
        }
    }

    fn mapping_lookup_default_factory_path_inner<'b>(
        &'b self,
        mapping: &'b StackValue,
        path: &[Option<String>],
    ) -> Option<MappingLookup<'b>> {
        match mapping {
            StackValue::DefaultDict { default_factory } => {
                Some(MappingLookup::Found(default_factory))
            }
            StackValue::TrackedDict {
                entries,
                memo_index,
                ..
            } => {
                let entries = self.current_tracked_dict_entries(entries, *memo_index);
                let (key, remaining_path) = path.split_first()?;
                let key = key.as_deref()?;
                let (_, value) = entries.iter().find(|(candidate, _)| candidate == key)?;
                if remaining_path.is_empty() {
                    Some(MappingLookup::Shadowed)
                } else {
                    self.mapping_lookup_default_factory_path_inner(value, remaining_path)
                }
            }
            StackValue::MappingWrapper {
                reference,
                mappings,
            } if reference.module == "collections" && reference.name == "ChainMap" => {
                for mapping in mappings {
                    match self.mapping_lookup_default_factory_path_inner(mapping, path) {
                        Some(MappingLookup::Found(default_factory)) => {
                            return Some(MappingLookup::Found(default_factory));
                        }
                        Some(MappingLookup::Shadowed) => return Some(MappingLookup::Shadowed),
                        None => {}
                    }
                }
                None
            }
            StackValue::MappingWrapper {
                reference,
                mappings,
            } if reference.module == "types" && reference.name == "MappingProxyType" => mappings
                .first()
                .and_then(|mapping| self.mapping_lookup_default_factory_path_inner(mapping, path)),
            _ => None,
        }
    }

    fn current_tracked_dict_entries<'b>(
        &'b self,
        entries: &'b [(String, StackValue)],
        memo_index: Option<i64>,
    ) -> &'b [(String, StackValue)] {
        memo_index
            .and_then(|index| self.memo.get(&index))
            .and_then(|value| match value {
                StackValue::TrackedDict { entries, .. } => Some(entries.as_slice()),
                _ => None,
            })
            .unwrap_or(entries)
    }

    fn current_tracked_dict_unknown_key_values<'b>(
        &'b self,
        unknown_key_values: &'b [StackValue],
        memo_index: Option<i64>,
    ) -> &'b [StackValue] {
        memo_index
            .and_then(|index| self.memo.get(&index))
            .and_then(|value| match value {
                StackValue::TrackedDict {
                    unknown_key_values, ..
                } => Some(unknown_key_values.as_slice()),
                _ => None,
            })
            .unwrap_or(unknown_key_values)
    }

    fn current_tracked_dict_unknown_key_values_overflowed(
        &self,
        unknown_key_values_overflowed: bool,
        memo_index: Option<i64>,
    ) -> bool {
        memo_index
            .and_then(|index| self.memo.get(&index))
            .and_then(|value| match value {
                StackValue::TrackedDict {
                    unknown_key_values_overflowed,
                    ..
                } => Some(*unknown_key_values_overflowed),
                _ => None,
            })
            .unwrap_or(unknown_key_values_overflowed)
    }

    fn formatter_vformat_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        self.formatter_defaultdict_kwargs_invocations(arguments, &[4], op_name, position)
    }

    fn formatter_private_vformat_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        self.formatter_defaultdict_kwargs_invocations(arguments, &[6, 7], op_name, position)
    }

    fn formatter_defaultdict_kwargs_invocations(
        &self,
        arguments: &[StackValue],
        expected_arg_counts: &[usize],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !expected_arg_counts.contains(&arguments.len())
            || !self.brace_format_string_may_use_field(arguments.get(1))
        {
            return Vec::new();
        }
        let Some(format_string) = resolve_global_operand(arguments.get(1), self.payload) else {
            return self.mapping_lookup_invocations(arguments.get(3), None, op_name, position);
        };
        Self::str_format_named_lookups(&format_string)
            .into_iter()
            .flat_map(|path| {
                self.mapping_lookup_path_invocations(arguments.get(3), &path, op_name, position)
            })
            .collect()
    }

    fn template_substitute_invocations(
        &self,
        arguments: &[StackValue],
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if arguments.len() != 2 || !Self::string_template_may_lookup(arguments.first()) {
            return Vec::new();
        }
        self.mapping_lookup_invocations(arguments.get(1), None, op_name, position)
    }

    fn string_template_may_lookup(value: Option<&StackValue>) -> bool {
        let Some(StackValue::StringTemplate { template }) = value else {
            return false;
        };
        Self::template_literal_contains_placeholder(template)
    }

    fn template_literal_contains_placeholder(template: &str) -> bool {
        let mut chars = template.chars().peekable();
        while let Some(character) = chars.next() {
            if character != '$' {
                continue;
            }
            match chars.peek() {
                Some('$') => {
                    chars.next();
                }
                Some(_) => return true,
                None => {}
            }
        }
        false
    }

    fn brace_format_string_may_use_field(&self, value: Option<&StackValue>) -> bool {
        if !Self::is_format_string_argument(value) {
            return false;
        }
        let Some(format_string) = value.and_then(|value| stack_value_string(value, self.payload))
        else {
            return false;
        };
        Self::brace_format_literal_contains_field(&format_string)
    }

    fn brace_format_literal_contains_field(format_string: &str) -> bool {
        let mut chars = format_string.chars().peekable();
        while let Some(character) = chars.next() {
            if character != '{' {
                continue;
            }
            if chars.peek() == Some(&'{') {
                chars.next();
                continue;
            }
            return true;
        }
        false
    }

    fn percent_format_string_may_use_mapping_key(&self, value: Option<&StackValue>) -> bool {
        let Some(format_string) = value.and_then(|value| stack_value_string(value, self.payload))
        else {
            return false;
        };
        Self::percent_format_literal_contains_mapping_key(&format_string)
    }

    fn percent_format_literal_contains_mapping_key(format_string: &str) -> bool {
        let mut chars = format_string.chars().peekable();
        while let Some(character) = chars.next() {
            if character != '%' {
                continue;
            }
            match chars.peek() {
                Some('%') => {
                    chars.next();
                }
                Some('(') => return true,
                _ => {}
            }
        }
        false
    }

    fn is_format_string_argument(value: Option<&StackValue>) -> bool {
        matches!(
            value,
            Some(StackValue::Text(_) | StackValue::TextSpan { .. })
        )
    }

    fn is_definitely_non_empty_iterable_argument(value: Option<&StackValue>) -> bool {
        match value {
            Some(StackValue::Tuple(items)) => !items.is_empty(),
            Some(StackValue::Text(value)) => !value.is_empty(),
            Some(StackValue::TextSpan { start, end }) | Some(StackValue::Bytes { start, end }) => {
                start < end
            }
            _ => false,
        }
    }

    fn format_invocation(
        receiver_reference: &GlobalRef,
        op_name: &'static str,
        position: usize,
    ) -> Option<CallableInvocation> {
        if receiver_reference.malformed {
            return None;
        }
        Some(CallableInvocation {
            reference: Self::constructed_protocol_method_reference(
                receiver_reference,
                "__format__",
            ),
            op_name,
            opcode_position: position,
            positional_arg_count: Some(1),
            args: Vec::new(),
        })
    }

    fn call_iterator_consumption_invocations(
        callable_value: Option<&StackValue>,
        argument_values: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !matches!(op_name, "REDUCE" | "OBJ") {
            return Vec::new();
        }
        let Some(StackValue::Global(callable_reference)) = callable_value else {
            return Vec::new();
        };
        if callable_reference.malformed {
            return Vec::new();
        }

        let Some(arguments) = argument_values else {
            return Vec::new();
        };
        if let Some(callable) = Self::eager_call_iterator_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::itertools_eager_call_iterator_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::stdlib_eager_call_iterator_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::builtin_iterable_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::method_descriptor_iterable_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::operator_sequence_search_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }
        if let Some(callable) = Self::operator_protocol_consumed_callable(
            &callable_reference.module,
            &callable_reference.name,
            arguments,
        ) {
            return vec![Self::zero_arg_invocation(callable, op_name, position)];
        }

        if !Self::is_next_call_iterator_consumer(
            &callable_reference.module,
            &callable_reference.name,
        ) || !(1..=2).contains(&arguments.len())
        {
            return Vec::new();
        }
        let Some(StackValue::CallIterator { callable }) = arguments.first() else {
            return Vec::new();
        };
        vec![Self::zero_arg_invocation(callable, op_name, position)]
    }

    fn eager_call_iterator_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if Self::is_single_arg_eager_call_iterator_consumer(module, name) {
            let [StackValue::CallIterator { callable }] = arguments else {
                return None;
            };
            return Some(callable);
        }
        if !Self::is_deque_call_iterator_consumer(module, name)
            || !(1..=2).contains(&arguments.len())
        {
            return None;
        }
        match arguments.first() {
            Some(StackValue::CallIterator { callable }) => Some(callable),
            _ => None,
        }
    }

    fn is_single_arg_eager_call_iterator_consumer(module: &str, name: &str) -> bool {
        matches!(
            (module, name),
            (
                "builtins" | "__builtin__" | "__builtins__",
                "dict" | "frozenset" | "list" | "set" | "tuple"
            )
        )
    }

    fn is_deque_call_iterator_consumer(module: &str, name: &str) -> bool {
        matches!((module, name), ("collections", "deque"))
    }

    fn itertools_eager_call_iterator_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if module != "itertools" {
            return None;
        }
        match name {
            "product" if !arguments.is_empty() => {
                arguments.iter().find_map(Self::call_iterator_callable_ref)
            }
            "permutations" if (1..=2).contains(&arguments.len()) => {
                arguments.first().and_then(Self::call_iterator_callable_ref)
            }
            "combinations" | "combinations_with_replacement" if arguments.len() == 2 => {
                arguments.first().and_then(Self::call_iterator_callable_ref)
            }
            _ => None,
        }
    }

    fn stdlib_eager_call_iterator_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        Self::exact_arity_consumed_callable(
            EXACT_ARITY_STDLIB_EAGER_ITERABLE_CONSUMERS,
            module,
            name,
            arguments,
        )
    }

    fn builtin_iterable_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if !matches!(module, "builtins" | "__builtin__" | "__builtins__") {
            return None;
        }
        if Self::builtin_iterable_consumer_arity_matches(name, arguments.len()) {
            if let Some(StackValue::CallIterator { callable }) = arguments.first() {
                return Some(callable);
            }
        }
        Self::builtin_join_consumed_callable(name, arguments)
    }

    fn method_descriptor_iterable_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if let Some(callable) = Self::exact_arity_consumed_callable(
            EXACT_ARITY_ITERABLE_DESCRIPTOR_CONSUMERS,
            module,
            name,
            arguments,
        ) {
            return Some(callable);
        }
        match (module, name) {
            (
                "builtins" | "__builtin__" | "__builtins__",
                "frozenset.difference"
                | "frozenset.intersection"
                | "frozenset.isdisjoint"
                | "frozenset.symmetric_difference"
                | "frozenset.union"
                | "set.difference"
                | "set.difference_update"
                | "set.intersection"
                | "set.intersection_update"
                | "set.isdisjoint"
                | "set.symmetric_difference"
                | "set.symmetric_difference_update"
                | "set.union"
                | "set.update",
            ) if arguments.len() >= 2 => arguments
                .iter()
                .skip(1)
                .find_map(Self::call_iterator_callable_ref),
            _ => None,
        }
    }

    fn exact_arity_consumed_callable<'b>(
        consumers: &[(&str, &str, usize, usize)],
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        consumers
            .iter()
            .filter(|(consumer_module, consumer_name, arity, _)| {
                Self::consumer_module_matches(module, consumer_module)
                    && *consumer_name == name
                    && *arity == arguments.len()
            })
            .find_map(|(_, _, _, consumed_arg_index)| {
                arguments
                    .get(*consumed_arg_index)
                    .and_then(Self::call_iterator_callable_ref)
            })
    }

    fn consumer_module_matches(module: &str, expected: &str) -> bool {
        if expected == "builtins" {
            matches!(module, "builtins" | "__builtin__" | "__builtins__")
        } else {
            module == expected
        }
    }

    fn operator_sequence_search_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if !matches!(module, "operator" | "_operator")
            || !matches!(name, "contains" | "countOf" | "indexOf")
            || arguments.len() != 2
        {
            return None;
        }
        arguments.first().and_then(Self::call_iterator_callable_ref)
    }

    fn operator_protocol_consumed_callable<'b>(
        module: &str,
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if !matches!(module, "operator" | "_operator") {
            return None;
        }
        match name {
            "iadd" if arguments.len() == 2 => {
                if !Self::is_operator_sequence_add_receiver(arguments.first()) {
                    return None;
                }
                arguments.get(1).and_then(Self::call_iterator_callable_ref)
            }
            "iconcat" if arguments.len() == 2 => {
                if !Self::is_operator_sequence_concat_receiver(arguments.first()) {
                    return None;
                }
                arguments.get(1).and_then(Self::call_iterator_callable_ref)
            }
            "ior" if arguments.len() == 2 => {
                if !Self::is_operator_mapping_update_receiver(arguments.first()) {
                    return None;
                }
                arguments.get(1).and_then(Self::call_iterator_callable_ref)
            }
            "setitem" if arguments.len() == 3 => {
                if !Self::is_operator_slice_assignment_receiver(arguments.first())
                    || !Self::is_constructed_builtin_instance(arguments.get(1), "slice")
                {
                    return None;
                }
                arguments.get(2).and_then(Self::call_iterator_callable_ref)
            }
            _ => None,
        }
    }

    fn builtin_iterable_consumer_arity_matches(name: &str, argument_count: usize) -> bool {
        match name {
            "all" | "any" | "max" | "min" | "sorted" => argument_count == 1,
            "bytearray" | "bytes" => argument_count == 1,
            "sum" => (1..=2).contains(&argument_count),
            _ => false,
        }
    }

    fn builtin_join_consumed_callable<'b>(
        name: &str,
        arguments: &'b [StackValue],
    ) -> Option<&'b GlobalRef> {
        if arguments.len() != 2 {
            return None;
        }
        let receiver = arguments.first();
        let receiver_matches = match name {
            "str.join" => Self::is_format_string_argument(receiver),
            "bytes.join" => Self::is_bytes_like_argument(receiver),
            "bytearray.join" => Self::is_constructed_builtin_instance(receiver, "bytearray"),
            _ => false,
        };
        if !receiver_matches {
            return None;
        }
        match arguments.get(1) {
            Some(StackValue::CallIterator { callable }) => Some(callable),
            _ => None,
        }
    }

    fn is_bytes_like_argument(value: Option<&StackValue>) -> bool {
        matches!(value, Some(StackValue::Bytes { .. }))
            || Self::is_constructed_builtin_instance(value, "bytes")
    }

    fn is_constructed_builtin_instance(value: Option<&StackValue>, name: &str) -> bool {
        match value {
            Some(StackValue::Constructed(reference)) if !reference.malformed => {
                matches!(
                    reference.module.as_str(),
                    "builtins" | "__builtin__" | "__builtins__"
                ) && reference.name == name
            }
            _ => false,
        }
    }

    fn is_builtin_container_argument(value: Option<&StackValue>, name: &str) -> bool {
        matches!(
            value,
            Some(StackValue::Primitive { type_name, .. }) if *type_name == name
        ) || (name == "dict" && matches!(value, Some(StackValue::TrackedDict { .. })))
            || Self::is_constructed_builtin_instance(value, name)
    }

    fn is_constructed_stdlib_instance(
        value: Option<&StackValue>,
        module: &str,
        name: &str,
    ) -> bool {
        match value {
            Some(
                StackValue::Constructed(reference) | StackValue::MappingWrapper { reference, .. },
            ) if !reference.malformed => reference.module == module && reference.name == name,
            _ => false,
        }
    }

    fn is_operator_sequence_add_receiver(value: Option<&StackValue>) -> bool {
        Self::is_builtin_container_argument(value, "list")
            || Self::is_constructed_stdlib_instance(value, "collections", "deque")
            || Self::is_constructed_stdlib_instance(value, "collections", "UserList")
    }

    fn is_operator_sequence_concat_receiver(value: Option<&StackValue>) -> bool {
        Self::is_builtin_container_argument(value, "list")
            || Self::is_constructed_stdlib_instance(value, "collections", "deque")
    }

    fn is_operator_slice_assignment_receiver(value: Option<&StackValue>) -> bool {
        Self::is_builtin_container_argument(value, "list")
            || Self::is_constructed_builtin_instance(value, "bytearray")
            || Self::is_constructed_stdlib_instance(value, "collections", "UserList")
    }

    fn is_operator_mapping_update_receiver(value: Option<&StackValue>) -> bool {
        Self::is_builtin_container_argument(value, "dict")
            || Self::is_constructed_stdlib_instance(value, "collections", "ChainMap")
            || Self::is_constructed_stdlib_instance(value, "collections", "defaultdict")
            || Self::is_constructed_stdlib_instance(value, "collections", "OrderedDict")
            || Self::is_constructed_stdlib_instance(value, "collections", "UserDict")
    }

    fn is_next_call_iterator_consumer(module: &str, name: &str) -> bool {
        matches!(
            (module, name),
            ("builtins" | "__builtin__" | "__builtins__", "next")
        )
    }

    fn defaultdict_factory_invocations(
        &self,
        callable_value: Option<&StackValue>,
        argument_values: Option<&[StackValue]>,
        op_name: &'static str,
        position: usize,
    ) -> Vec<CallableInvocation> {
        if !matches!(op_name, "REDUCE" | "OBJ") {
            return Vec::new();
        }
        let Some(StackValue::Global(callable_reference)) = callable_value else {
            return Vec::new();
        };
        if callable_reference.malformed
            || !Self::is_defaultdict_factory_lookup(
                &callable_reference.module,
                &callable_reference.name,
            )
        {
            return Vec::new();
        }
        let Some(argument_values) = argument_values else {
            return Vec::new();
        };
        let key = argument_values
            .get(1)
            .and_then(|value| stack_value_string(value, self.payload));
        let Some(MappingLookup::Found(default_factory)) =
            self.mapping_lookup_default_factory(argument_values.first(), key.as_deref())
        else {
            return Vec::new();
        };
        vec![Self::zero_arg_invocation(
            default_factory,
            op_name,
            position,
        )]
    }

    fn is_defaultdict_factory_lookup(module: &str, name: &str) -> bool {
        matches!(
            (module, name),
            ("operator", "getitem")
                | (
                    "collections",
                    "defaultdict.__getitem__" | "defaultdict.__missing__"
                )
                | (
                    "builtins" | "__builtin__" | "__builtins__",
                    "dict.__getitem__"
                )
        )
    }

    fn zero_arg_invocation(
        reference: &GlobalRef,
        op_name: &'static str,
        position: usize,
    ) -> CallableInvocation {
        Self::callable_invocation(reference.clone(), op_name, position, Some(0))
    }

    fn callable_invocation(
        reference: GlobalRef,
        op_name: &'static str,
        position: usize,
        positional_arg_count: Option<usize>,
    ) -> CallableInvocation {
        CallableInvocation {
            reference,
            op_name,
            opcode_position: position,
            positional_arg_count,
            args: Vec::new(),
        }
    }

    fn constructed_callable_reference(reference: &GlobalRef) -> GlobalRef {
        Self::constructed_protocol_method_reference(reference, "__call__")
    }

    fn constructed_protocol_method_reference(
        reference: &GlobalRef,
        method_name: &str,
    ) -> GlobalRef {
        GlobalRef {
            module: reference.module.clone(),
            name: format!("{}.{}", reference.name, method_name),
            position: reference.position,
            malformed: reference.malformed,
        }
    }

    fn tuple_argument_values(value: Option<&StackValue>) -> Option<Vec<StackValue>> {
        match value {
            Some(StackValue::Tuple(values)) => Some(values.clone()),
            _ => None,
        }
    }

    fn tuple_positional_arg_count(value: Option<&StackValue>) -> Option<usize> {
        match value {
            Some(StackValue::Tuple(values)) => Some(values.len()),
            _ => None,
        }
    }

    fn with_memo_index(value: StackValue, index: i64) -> StackValue {
        match value {
            StackValue::FutureCallbacks(mut callbacks) => {
                callbacks.memo_index = Some(index);
                StackValue::FutureCallbacks(callbacks)
            }
            StackValue::TrackedDict {
                entries,
                unknown_key_values,
                unknown_key_values_overflowed,
                ..
            } => StackValue::TrackedDict {
                entries,
                unknown_key_values,
                unknown_key_values_overflowed,
                memo_index: Some(index),
            },
            value => value,
        }
    }

    fn memoized_future_add_callback(&mut self, memo_index: i64, callback: GlobalRef) {
        if let Some(StackValue::FutureCallbacks(callbacks)) = self.memo.get_mut(&memo_index) {
            callbacks.callbacks.push(callback);
        }
    }

    fn memoized_future_mark_done(&mut self, memo_index: i64) {
        if let Some(StackValue::FutureCallbacks(callbacks)) = self.memo.get_mut(&memo_index) {
            callbacks.done = true;
        }
    }

    fn consume_top_operands(&mut self, operand_count: usize) -> Option<StackValue> {
        self.consume_top_operand_values(operand_count)
            .and_then(|values| values.into_iter().next())
    }

    fn consume_top_operand_values(&mut self, operand_count: usize) -> Option<Vec<StackValue>> {
        if self.stack.len() < operand_count {
            self.stack.push(StackValue::Other);
            return None;
        }
        let mut values = Vec::with_capacity(operand_count);
        for _ in 0..operand_count {
            if let Some(value) = self.stack.pop() {
                values.push(value);
            }
        }
        values.reverse();
        self.push_reducer_result(&values);
        Some(values)
    }

    fn push_reducer_result(&mut self, values: &[StackValue]) {
        if let Some(call_iterator) = Self::call_iterator_result(values) {
            self.stack.push(call_iterator);
            return;
        }
        if let Some(call_iterator) = Self::lazy_zero_arg_callback_iterable_result(values) {
            self.stack.push(call_iterator);
            return;
        }
        if let Some(call_iterator) = Self::lazy_call_iterator_wrapper_result(values) {
            self.stack.push(call_iterator);
            return;
        }
        if let Some(call_iterator_tuple) = Self::call_iterator_tuple_wrapper_result(values) {
            self.stack.push(call_iterator_tuple);
            return;
        }
        if let Some(defaultdict) = Self::defaultdict_result(values) {
            self.stack.push(defaultdict);
            return;
        }
        if let Some(mapping_wrapper) = self.mapping_wrapper_result(values) {
            self.stack.push(mapping_wrapper);
            return;
        }
        if let Some(template) = self.string_template_result(values) {
            self.stack.push(template);
            return;
        }
        if let Some(tuple_item) = Self::tuple_getitem_result(values) {
            self.stack.push(tuple_item);
            return;
        }
        if let Some(joined) = self.str_join_result(values) {
            self.stack.push(joined);
            return;
        }
        if let Some(regex_pattern) = self.regex_pattern_result(values) {
            self.stack.push(regex_pattern);
            return;
        }
        if let Some(regex_scanner) = Self::regex_scanner_result(values) {
            self.stack.push(regex_scanner);
            return;
        }
        if let Some(future) = Self::future_callbacks_result(values) {
            self.stack.push(future);
            return;
        }
        self.push_constructed_result(values.first());
    }

    fn call_iterator_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || !matches!(
                (
                    callable_reference.module.as_str(),
                    callable_reference.name.as_str()
                ),
                ("builtins" | "__builtin__" | "__builtins__", "iter")
            )
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if arguments.len() != 2 {
            return None;
        }
        let callable = Self::callable_reference_from_value(arguments.first())?;
        Some(StackValue::CallIterator { callable })
    }

    fn regex_pattern_result(&self, values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "re"
            || callable_reference.name != "compile"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if !(1..=2).contains(&arguments.len()) {
            return None;
        }
        let pattern = arguments
            .first()
            .and_then(|value| stack_value_string(value, self.payload))?;
        let flags = arguments.get(1).map_or(Some(0), Self::stack_value_integer);
        Some(StackValue::RegexPattern { pattern, flags })
    }

    fn regex_scanner_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "re"
            || callable_reference.name != "Scanner"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if !(1..=2).contains(&arguments.len()) {
            return None;
        }
        let Some(StackValue::RegexScannerLexicon { rules }) = arguments.first() else {
            return None;
        };
        let flags = arguments.get(1).map_or(Some(0), Self::stack_value_integer);
        Some(StackValue::RegexScanner {
            rules: rules.clone(),
            flags,
        })
    }

    fn future_callbacks_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || !Self::is_concurrent_future_symbol(callable_reference, "Future")
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if !arguments.is_empty() {
            return None;
        }
        Some(StackValue::FutureCallbacks(FutureCallbacks {
            callbacks: Vec::new(),
            done: false,
            memo_index: None,
        }))
    }

    fn string_template_result(&self, values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "string"
            || callable_reference.name != "Template"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if arguments.len() != 1 {
            return None;
        }
        let template = arguments
            .first()
            .and_then(|value| stack_value_string(value, self.payload))?;
        Some(StackValue::StringTemplate { template })
    }

    fn lazy_zero_arg_callback_iterable_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        let (_, _, _, callback_arg_index) = EXACT_ARITY_LAZY_ZERO_ARG_CALLBACK_ITERABLES
            .iter()
            .find(|(consumer_module, consumer_name, arity, _)| {
                Self::consumer_module_matches(&callable_reference.module, consumer_module)
                    && *consumer_name == callable_reference.name
                    && *arity == arguments.len()
            })?;
        let callable = Self::callable_reference_from_value(arguments.get(*callback_arg_index))?;
        Some(StackValue::CallIterator { callable })
    }

    fn lazy_call_iterator_wrapper_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        let callable = match callable_reference.module.as_str() {
            "builtins" | "__builtin__" | "__builtins__" => {
                Self::builtins_lazy_call_iterator_wrapper_callable(
                    &callable_reference.name,
                    arguments,
                )
            }
            "itertools" => Self::itertools_lazy_call_iterator_wrapper_callable(
                &callable_reference.name,
                arguments,
            ),
            "heapq" => {
                Self::heapq_lazy_call_iterator_wrapper_callable(&callable_reference.name, arguments)
            }
            _ => None,
        }?;
        Some(StackValue::CallIterator { callable })
    }

    fn builtins_lazy_call_iterator_wrapper_callable(
        name: &str,
        arguments: &[StackValue],
    ) -> Option<GlobalRef> {
        match name {
            "iter" if arguments.len() == 1 => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "enumerate" if (1..=2).contains(&arguments.len()) => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "zip" => arguments.iter().find_map(Self::call_iterator_callable),
            _ => None,
        }
    }

    fn itertools_lazy_call_iterator_wrapper_callable(
        name: &str,
        arguments: &[StackValue],
    ) -> Option<GlobalRef> {
        match name {
            "batched" if (2..=3).contains(&arguments.len()) => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "chain" => arguments.iter().find_map(Self::call_iterator_callable),
            "compress" if arguments.len() == 2 => {
                arguments.iter().find_map(Self::call_iterator_callable)
            }
            "cycle" if arguments.len() == 1 => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "islice" if (2..=4).contains(&arguments.len()) => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "pairwise" if arguments.len() == 1 => {
                arguments.first().and_then(Self::call_iterator_callable)
            }
            "zip_longest" if !arguments.is_empty() => {
                arguments.iter().find_map(Self::call_iterator_callable)
            }
            "chain.from_iterable" if arguments.len() == 1 => arguments
                .first()
                .and_then(Self::call_iterator_callable_or_tuple_item),
            _ => None,
        }
    }

    fn heapq_lazy_call_iterator_wrapper_callable(
        name: &str,
        arguments: &[StackValue],
    ) -> Option<GlobalRef> {
        match name {
            "merge" if !arguments.is_empty() => {
                arguments.iter().find_map(Self::call_iterator_callable)
            }
            _ => None,
        }
    }

    fn call_iterator_callable(value: &StackValue) -> Option<GlobalRef> {
        match value {
            StackValue::CallIterator { callable } => Some(callable.clone()),
            StackValue::CallIteratorTuple { callable, .. } => Some(callable.clone()),
            _ => None,
        }
    }

    fn call_iterator_callable_ref(value: &StackValue) -> Option<&GlobalRef> {
        match value {
            StackValue::CallIterator { callable }
            | StackValue::CallIteratorTuple { callable, .. } => Some(callable),
            _ => None,
        }
    }

    fn call_iterator_callable_or_tuple_item(value: &StackValue) -> Option<GlobalRef> {
        Self::call_iterator_callable(value).or_else(|| match value {
            StackValue::Tuple(items) => items.iter().find_map(Self::call_iterator_callable),
            _ => None,
        })
    }

    fn call_iterator_tuple_wrapper_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "itertools"
            || callable_reference.name != "tee"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if !(1..=2).contains(&arguments.len()) {
            return None;
        }
        let callable = arguments.first().and_then(Self::call_iterator_callable)?;
        Some(StackValue::CallIteratorTuple {
            callable,
            item_count: Self::tee_item_count(arguments),
        })
    }

    fn tee_item_count(arguments: &[StackValue]) -> Option<usize> {
        let Some(count_value) = arguments.get(1) else {
            return Some(2);
        };
        Self::stack_value_nonnegative_index(count_value)
    }

    fn tuple_getitem_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "operator"
            || callable_reference.name != "getitem"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        let [container, index_value] = arguments.as_slice() else {
            return None;
        };
        match container {
            StackValue::Tuple(items) => {
                let index = Self::stack_value_tuple_index(index_value, items.len())?;
                items.get(index).cloned()
            }
            StackValue::CallIteratorTuple {
                callable,
                item_count,
            } => {
                let index = Self::stack_value_nonnegative_index(index_value)?;
                if item_count.is_none_or(|count| index < count) {
                    Some(StackValue::CallIterator {
                        callable: callable.clone(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn str_join_result(&self, values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || !matches!(
                callable_reference.module.as_str(),
                "builtins" | "__builtin__" | "__builtins__"
            )
            || callable_reference.name != "str.join"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        let [separator, iterable] = arguments.as_slice() else {
            return None;
        };
        let separator = stack_value_string(separator, self.payload)?;
        let StackValue::Tuple(items) = iterable else {
            return None;
        };

        let mut result = String::new();
        for (index, item) in items.iter().enumerate() {
            let item = stack_value_string(item, self.payload)?;
            let separator_len = if index > 0 { separator.len() } else { 0 };
            let additional_len = separator_len.saturating_add(item.len());
            if result.len().saturating_add(additional_len) > MAX_TRACKED_STR_JOIN_RESULT_BYTES {
                return None;
            }
            if index > 0 {
                result.push_str(&separator);
            }
            result.push_str(&item);
        }
        Some(StackValue::Text(result))
    }

    fn stack_value_tuple_index(value: &StackValue, len: usize) -> Option<usize> {
        let index = Self::stack_value_integer(value)?;
        let len = isize::try_from(len).ok()?;
        let adjusted = if index < 0 { len + index } else { index };
        if (0..len).contains(&adjusted) {
            usize::try_from(adjusted).ok()
        } else {
            None
        }
    }

    fn stack_value_nonnegative_index(value: &StackValue) -> Option<usize> {
        let index = Self::stack_value_integer(value)?;
        usize::try_from(index).ok()
    }

    fn stack_value_integer(value: &StackValue) -> Option<isize> {
        match value {
            StackValue::Primitive {
                type_name: "int",
                repr,
            } => repr.parse().ok(),
            _ => None,
        }
    }

    fn defaultdict_result(values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed
            || callable_reference.module != "collections"
            || callable_reference.name != "defaultdict"
        {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };
        if arguments.len() != 1 {
            return None;
        }
        let default_factory = Self::callable_reference_from_value(arguments.first())?;
        Some(StackValue::DefaultDict { default_factory })
    }

    fn mapping_wrapper_result(&self, values: &[StackValue]) -> Option<StackValue> {
        let Some(StackValue::Global(callable_reference)) = values.first() else {
            return None;
        };
        if callable_reference.malformed {
            return None;
        }
        let Some(StackValue::Tuple(arguments)) = values.get(1) else {
            return None;
        };

        let mappings = match (
            callable_reference.module.as_str(),
            callable_reference.name.as_str(),
        ) {
            ("collections", "ChainMap") if !arguments.is_empty() => arguments.clone(),
            ("types", "MappingProxyType") if arguments.len() == 1 => {
                vec![arguments[0].clone()]
            }
            _ => return None,
        };

        if mappings
            .iter()
            .all(|mapping| !self.mapping_may_contain_default_factory(mapping))
        {
            return None;
        }

        Some(StackValue::MappingWrapper {
            reference: callable_reference.clone(),
            mappings,
        })
    }

    fn mapping_may_contain_default_factory(&self, mapping: &StackValue) -> bool {
        match mapping {
            StackValue::DefaultDict { .. } => true,
            StackValue::TrackedDict {
                entries,
                memo_index,
                ..
            } => self
                .current_tracked_dict_entries(entries, *memo_index)
                .iter()
                .any(|(_, value)| self.mapping_may_contain_default_factory(value)),
            StackValue::MappingWrapper { mappings, .. } => mappings
                .iter()
                .any(|mapping| self.mapping_may_contain_default_factory(mapping)),
            _ => false,
        }
    }

    fn callable_reference_from_value(value: Option<&StackValue>) -> Option<GlobalRef> {
        match value {
            Some(StackValue::Global(reference)) if !reference.malformed => Some(reference.clone()),
            Some(StackValue::Constructed(reference)) if !reference.malformed => {
                Some(Self::constructed_callable_reference(reference))
            }
            Some(StackValue::Global(reference) | StackValue::Constructed(reference))
                if reference.module == "copyreg.extension" =>
            {
                Some(reference.clone())
            }
            _ => None,
        }
    }

    fn push_constructed_result(&mut self, callable_value: Option<&StackValue>) {
        match callable_value {
            Some(StackValue::Global(reference) | StackValue::Constructed(reference))
                if !reference.malformed =>
            {
                self.stack.push(StackValue::Constructed(reference.clone()));
            }
            _ => self.stack.push(StackValue::Other),
        }
    }

    fn resolve_stack_global(
        &mut self,
        module_value: Option<StackValue>,
        name_value: Option<StackValue>,
        position: usize,
    ) -> GlobalRef {
        let module = resolve_global_operand(module_value.as_ref(), self.payload);
        let name = resolve_global_operand(name_value.as_ref(), self.payload);

        match (module, name) {
            (Some(module), Some(name)) => GlobalRef {
                module,
                name,
                position,
                malformed: false,
            },
            (module, name) => {
                let malformed = GlobalRef {
                    module: module.unwrap_or_else(|| "__unknown__".to_string()),
                    name: name.unwrap_or_else(|| "__unknown__".to_string()),
                    position,
                    malformed: true,
                };
                self.add_finding(Finding {
                    message: "Malformed STACK_GLOBAL operands prevent reliable callable resolution"
                        .to_string(),
                    severity: "critical",
                    location: Some(format!("{} (pos {})", self.source, position)),
                    rule_code: Some("MALFORMED_STACK_GLOBAL"),
                    details: vec![
                        (
                            "module_operand".to_string(),
                            DetailValue::String(operand_preview(module_value.as_ref())),
                        ),
                        (
                            "name_operand".to_string(),
                            DetailValue::String(operand_preview(name_value.as_ref())),
                        ),
                    ],
                    why: Some(
                        "Malformed STACK_GLOBAL operands can be used to bypass scanners that assume string-only operands.",
                    ),
                });
                malformed
            }
        }
    }

    fn scan_string_literal(
        &mut self,
        value: &str,
        op_name: &'static str,
        position: usize,
        suppress_hex_escape: bool,
    ) {
        let max_chars = self.options.max_string_literal_scan_chars;
        if max_chars == 0 {
            if !value.is_empty() {
                self.record_literal_scan_truncated(
                    "string",
                    value.chars().count(),
                    op_name,
                    position,
                );
            }
            return;
        }
        if value.len() <= max_chars {
            self.scan_string_literal_candidate(value, op_name, position, suppress_hex_escape);
            return;
        }

        let value_len = string_char_len(value);
        if value_len <= max_chars {
            self.scan_string_literal_candidate(value, op_name, position, suppress_hex_escape);
            return;
        }

        self.record_literal_scan_truncated("string", value_len, op_name, position);
        let suspicious_window_chars = max_chars.max(MIN_SUSPICIOUS_LITERAL_SCAN_WINDOW_CHARS);
        let overlap_chars = suspicious_window_chars
            .saturating_sub(1)
            .min(SUSPICIOUS_LITERAL_SCAN_OVERLAP_CHARS);
        let step_chars = suspicious_window_chars.saturating_sub(overlap_chars).max(1);
        let mut window_start = 0usize;
        loop {
            let window_end = advance_chars_from(value, window_start, suspicious_window_chars);
            self.scan_string_literal_candidate(
                &value[window_start..window_end],
                op_name,
                position,
                suppress_hex_escape,
            );
            if window_end >= value.len() {
                break;
            }
            let next_window_start = advance_chars_from(value, window_start, step_chars);
            if next_window_start <= window_start {
                break;
            }
            window_start = next_window_start;
        }
    }

    fn scan_string_literal_candidate(
        &mut self,
        value: &str,
        op_name: &'static str,
        position: usize,
        suppress_hex_escape: bool,
    ) {
        for matched_pattern in suspicious_string_matches(value) {
            if suppress_hex_escape && matched_pattern == "hex escape" {
                continue;
            }
            self.add_finding(Finding {
                message: format!(
                    "Suspicious string literal contains code execution pattern: {}",
                    matched_pattern
                ),
                severity: "warning",
                location: Some(format!("{} (pos {})", self.source, position)),
                rule_code: Some("SUSPICIOUS_STRING"),
                details: vec![
                    ("opcode".to_string(), DetailValue::String(op_name.to_string())),
                    ("pattern".to_string(), DetailValue::String(matched_pattern)),
                ],
                why: Some(
                    "Suspicious code-like strings embedded in pickle payloads can be used by downstream loaders or helper code during deserialization workflows.",
                ),
            });
        }
    }

    fn scan_raw_nested_pickle_bytes(&mut self, value: &[u8], position: usize) {
        let mut skip_offsets_before = 0usize;
        let probe_offsets = nested_pickle_probe_offsets(value);
        let limit_exceeded = probe_offsets.limit_exceeded;
        for offset in probe_offsets.offsets {
            if offset < skip_offsets_before {
                continue;
            }
            let remaining_len = value.len().saturating_sub(offset);
            let end = value
                .len()
                .min(offset.saturating_add(self.options.max_nested_pickle_bytes));
            let probe = &value[offset..end];
            if let Some(payload_len) =
                pickle_payload_extent(probe, self.options.max_nested_pickle_bytes)
            {
                let candidate = &probe[..payload_len];
                let nested_has_execution_opcode = has_execution_opcode(candidate);
                let surface_outcome =
                    self.surface_nested_pickle_findings(candidate, "raw", position + offset);
                self.add_nested_payload_finding(
                    raw_nested_payload_finding(
                        candidate.len(),
                        position + offset,
                        false,
                        nested_has_execution_opcode,
                    ),
                    surface_outcome.promote_complete_payload(nested_has_execution_opcode),
                );
                if surface_outcome.should_stop_raw_probe_scan(nested_has_execution_opcode) {
                    return;
                }
                skip_offsets_before = offset.saturating_add(payload_len);
                continue;
            }
            if has_pickle_prefix(probe) && has_execution_opcode(probe) {
                let surface_outcome =
                    self.surface_nested_pickle_findings(probe, "raw", position + offset);
                self.add_nested_payload_finding(
                    raw_nested_payload_finding(probe.len(), position + offset, true, true),
                    true,
                );
                if surface_outcome.should_stop_raw_probe_scan(true) {
                    return;
                }
                return;
            }
            let candidate_truncated = remaining_len > self.options.max_nested_pickle_bytes;
            if candidate_truncated && truncated_pickle_prefix_requires_fail_closed(probe) {
                self.add_nested_payload_finding(
                    raw_nested_payload_finding(remaining_len, position + offset, true, false),
                    true,
                );
                self.record_raw_nested_payload_truncated(remaining_len, position + offset);
                return;
            }
        }
        if limit_exceeded {
            self.record_nested_probe_limit_exceeded("raw", value.len(), position);
        }
    }

    fn is_data_only_encoded_nested_pickle_literal(&self, value: &str) -> bool {
        decode_possible_encoded_pickle(value, self.options.max_nested_pickle_bytes)
            .into_iter()
            .any(|(_, decoded)| !has_execution_opcode(&decoded))
    }

    fn is_large_uninteresting_repeated_literal(&self, value: &str) -> bool {
        value.len() >= 1024
            && value.len() <= self.options.max_string_literal_scan_chars
            && is_repeated_single_byte(value.as_bytes())
    }

    fn scan_encoded_nested_pickle_literal(&mut self, value: &str, position: usize) {
        if !encoded_literal_may_contain_pickle(value) {
            return;
        }

        let mut found_candidate = false;
        if value.len() <= self.options.max_string_literal_scan_chars {
            found_candidate |= self.scan_encoded_nested_pickle_candidate(value, position);
        } else {
            let value_len = string_char_len(value);
            if value_len <= self.options.max_string_literal_scan_chars {
                found_candidate |= self.scan_encoded_nested_pickle_candidate(value, position);
            } else {
                self.record_literal_scan_truncated(
                    "string",
                    value_len,
                    "encoded_nested_pickle",
                    position,
                );
            }
        }

        let max_window_chars =
            encoded_nested_window_char_limit(value, self.options.max_nested_pickle_bytes);
        let probe_coverage_incomplete = encoded_nested_literal_probe_coverage_incomplete(value);
        if !found_candidate
            && (value.len() <= max_window_chars || value.chars().count() <= max_window_chars)
        {
            found_candidate |= self.scan_encoded_nested_pickle_candidate(value, position);
        }

        for candidate in encoded_nested_literal_probe_windows(value, max_window_chars) {
            if found_candidate && candidate == value {
                continue;
            }
            found_candidate |= self.scan_encoded_nested_pickle_candidate(&candidate, position);
        }

        if probe_coverage_incomplete {
            self.record_literal_scan_truncated(
                "string",
                string_char_len(value),
                "encoded_nested_pickle",
                position,
            );
        }

        if found_candidate {
            return;
        }

        if probe_coverage_incomplete {
            return;
        }

        if value.len() > self.options.max_string_literal_scan_chars
            && string_char_len(value) > self.options.max_string_literal_scan_chars
        {
            self.record_literal_scan_truncated(
                "string",
                string_char_len(value),
                "encoded_nested_pickle",
                position,
            );
        }
    }

    fn scan_encoded_nested_pickle_candidate(&mut self, value: &str, position: usize) -> bool {
        let mut decoded_payload_found = false;
        for (encoding, decoded) in
            decode_possible_encoded_pickle(value, self.options.max_nested_pickle_bytes)
        {
            decoded_payload_found = true;
            let nested_has_execution_opcode = has_execution_opcode(&decoded);
            let surface_outcome = self.surface_nested_pickle_findings(&decoded, encoding, position);
            self.add_nested_payload_finding(
                encoded_nested_payload_finding(
                    encoding,
                    decoded.len(),
                    position,
                    false,
                    nested_has_execution_opcode,
                ),
                surface_outcome.promote_complete_payload(nested_has_execution_opcode),
            );
        }
        if decoded_payload_found {
            return true;
        }

        let mut oversized_prefix_found = false;
        for (encoding, payload_size) in
            detect_oversized_encoded_pickle_prefixes(value, self.options.max_nested_pickle_bytes)
        {
            oversized_prefix_found = true;
            self.add_nested_payload_finding(
                encoded_nested_payload_finding(encoding, payload_size, position, true, false),
                true,
            );
            self.record_encoded_nested_payload_truncated(encoding, payload_size, position);
        }
        oversized_prefix_found
    }

    fn record_raw_nested_payload_truncated(&mut self, payload_size: usize, position: usize) {
        if self.status.is_complete() {
            self.status = ScanStatus::Inconclusive;
        }
        self.add_notice(Notice {
            message: "Nested pickle payload exceeds configured deep-scan byte limit".to_string(),
            severity: "info",
            location: Some(format!("{} (pos {})", self.source, position)),
            code: Some("nested_payload_truncated"),
            details: vec![
                (
                    "encoding".to_string(),
                    DetailValue::String("raw".to_string()),
                ),
                (
                    "payload_size".to_string(),
                    DetailValue::UInt(payload_size as u64),
                ),
                (
                    "max_nested_pickle_bytes".to_string(),
                    DetailValue::UInt(self.options.max_nested_pickle_bytes as u64),
                ),
                ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
            ],
        });
    }

    fn record_nested_probe_limit_exceeded(
        &mut self,
        encoding: &'static str,
        payload_size: usize,
        position: usize,
    ) {
        if self.status.is_complete() {
            self.status = ScanStatus::Inconclusive;
        }
        let details = vec![
            (
                "encoding".to_string(),
                DetailValue::String(encoding.to_string()),
            ),
            (
                "payload_size".to_string(),
                DetailValue::UInt(payload_size as u64),
            ),
            (
                "max_nested_payload_probes".to_string(),
                DetailValue::UInt(MAX_NESTED_PAYLOAD_PROBES as u64),
            ),
            ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
        ];
        let location = Some(format!("{} (pos {})", self.source, position));
        self.add_finding(Finding {
            message: "Nested pickle probe candidate limit exceeded".to_string(),
            severity: "critical",
            location: location.clone(),
            rule_code: Some(nested_rule_code_for_encoding(encoding)),
            details: details.clone(),
            why: Some(
                "Too many plausible nested pickle starts were found to analyze exhaustively; the payload is treated as unsafe because later nested gadgets may be hidden past the probe budget.",
            ),
        });
        self.add_notice(Notice {
            message: "Nested pickle probe candidate limit exceeded".to_string(),
            severity: "info",
            location,
            code: Some("nested_probe_limit"),
            details,
        });
    }

    fn add_nested_payload_finding(
        &mut self,
        finding: NestedPayloadFinding,
        promote_complete_payload: bool,
    ) {
        let mut details = vec![
            (
                "encoding".to_string(),
                DetailValue::String(finding.encoding.to_string()),
            ),
            (
                "payload_size".to_string(),
                DetailValue::UInt(finding.payload_size as u64),
            ),
        ];
        if finding.analysis_incomplete || finding.include_limit_when_complete {
            details.push((
                "max_nested_pickle_bytes".to_string(),
                DetailValue::UInt(self.options.max_nested_pickle_bytes as u64),
            ));
            details.push((
                "analysis_incomplete".to_string(),
                DetailValue::Bool(finding.analysis_incomplete),
            ));
        }
        details.push((
            "nested_has_execution_opcode".to_string(),
            DetailValue::Bool(finding.nested_has_execution_opcode),
        ));

        let location = Some(format!("{} (pos {})", self.source, finding.position));
        if !finding.analysis_incomplete && !promote_complete_payload {
            self.add_notice(Notice {
                message: finding.complete_message.to_string(),
                severity: "info",
                location,
                code: Some(if finding.encoding == "raw" {
                    "nested_payload_detected"
                } else {
                    "encoded_nested_payload_detected"
                }),
                details,
            });
            return;
        }

        self.add_finding(Finding {
            message: if finding.analysis_incomplete {
                finding.incomplete_message.to_string()
            } else {
                finding.complete_message.to_string()
            },
            severity: "critical",
            location,
            rule_code: Some(finding.rule_code),
            details,
            why: Some(finding.why),
        });
    }

    fn record_encoded_nested_payload_truncated(
        &mut self,
        encoding: &'static str,
        payload_size: usize,
        position: usize,
    ) {
        if self.status.is_complete() {
            self.status = ScanStatus::Inconclusive;
        }
        self.add_notice(Notice {
            message: "Encoded pickle payload exceeds configured deep-scan byte limit".to_string(),
            severity: "info",
            location: Some(format!("{} (pos {})", self.source, position)),
            code: Some("encoded_nested_payload_truncated"),
            details: vec![
                (
                    "encoding".to_string(),
                    DetailValue::String(encoding.to_string()),
                ),
                (
                    "payload_size".to_string(),
                    DetailValue::UInt(payload_size as u64),
                ),
                (
                    "max_nested_pickle_bytes".to_string(),
                    DetailValue::UInt(self.options.max_nested_pickle_bytes as u64),
                ),
                ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
            ],
        });
    }

    fn record_global_ref(&mut self, reference: &GlobalRef, op_name: &'static str) {
        let symbol = reference.symbol();
        let severity = global_severity(&reference.module, &reference.name);
        let is_dangerous = severity.is_some();
        let reference_kind = if reference.malformed {
            "malformed"
        } else if is_dangerous {
            "dangerous"
        } else {
            "observed"
        };
        let key = (
            symbol.clone(),
            op_name.to_string(),
            reference.position,
            reference_kind,
            reference.malformed,
        );

        if reference.malformed {
            self.seen_global_reference_keys.insert(key);
            return;
        }

        self.global_count += 1;
        let details = global_ref_details(reference, &symbol, op_name);
        if self.seen_global_reference_keys.insert(key) {
            let mut import_reference_details = details.clone();
            import_reference_details
                .push(("is_dangerous".to_string(), DetailValue::Bool(is_dangerous)));
            self.push_import_reference(import_reference_details);
        }

        if let Some(global_severity) = severity {
            self.add_finding(Finding {
                message: format!("Found dangerous global reference: {}", symbol),
                severity: global_severity,
                location: Some(format!("{} (pos {})", self.source, reference.position)),
                rule_code: Some("DANGEROUS_GLOBAL"),
                details: details.clone(),
                why: Some(
                    "Dangerous globals can execute code or access sensitive system resources when unpickled.",
                ),
            });
            return;
        }

        if reference.module == "__main__" {
            self.add_finding(Finding {
                message: format!(
                    "Found non-allowlisted __main__ global reference: {}",
                    reference.symbol()
                ),
                severity: "warning",
                location: Some(format!("{} (pos {})", self.source, reference.position)),
                rule_code: Some("S203"),
                details,
                why: Some(
                    "Pickles that instantiate classes from __main__ depend on arbitrary application code and deserve manual review before loading.",
                ),
            });
        }
    }

    fn record_persistent_id(&mut self, opcode: &ParsedOpcode, position: usize) {
        self.persistent_id_count += 1;
        if self.first_persistent_id_position.is_none() {
            self.first_persistent_id_position = Some(position);
        }
        let persistent_id = if opcode.name == "BINPERSID" {
            self.stack.pop()
        } else {
            Some(StackValue::Text(opcode.arg.coerce_text(self.payload)))
        };
        self.stack.push(StackValue::Other);
        let storage_descriptor = persistent_id
            .as_ref()
            .and_then(|value| pytorch_storage_descriptor_ref(value, self.payload).cloned());
        if let Some(descriptor) = storage_descriptor.as_ref() {
            self.mark_pytorch_storage_persistent_id_import_reference(descriptor);
        }
        if self.persistent_id_count > 1 {
            return;
        }

        let mut details = vec![(
            "opcode".to_string(),
            DetailValue::String(opcode.name.to_string()),
        )];
        if let Some(value) = persistent_id.as_ref() {
            details.push((
                "persistent_id_preview".to_string(),
                DetailValue::String(stack_value_preview(value, 0)),
            ));
            if let Some(storage_key) = pytorch_storage_key(value, self.payload) {
                details.push((
                    "pytorch_storage_persistent_id".to_string(),
                    DetailValue::Bool(true),
                ));
                details.push((
                    "pytorch_storage_key".to_string(),
                    DetailValue::String(storage_key),
                ));
            }
        }

        self.add_finding(Finding {
            message: format!("Found pickle persistent ID opcode: {}", opcode.name),
            severity: "warning",
            location: Some(format!("{} (pos {})", self.source, position)),
            rule_code: Some("PERSISTENT_ID"),
            details,
            why: Some(
                "Persistent pickle IDs delegate object resolution to loader-defined callbacks, which can hide external object construction or storage lookups.",
            ),
        });
    }

    fn mark_pytorch_storage_persistent_id_import_reference(&mut self, descriptor: &GlobalRef) {
        for details in &mut self.import_references {
            if detail_usize(details, "position") != Some(descriptor.position) {
                continue;
            }
            if detail_string(details, "module").as_deref() != Some(descriptor.module.as_str())
                || detail_string(details, "name").as_deref() != Some(descriptor.name.as_str())
            {
                continue;
            }
            if !details
                .iter()
                .any(|(key, _)| key == "pytorch_storage_persistent_id")
            {
                details.push((
                    "pytorch_storage_persistent_id".to_string(),
                    DetailValue::Bool(true),
                ));
            }
            break;
        }
    }

    fn emit_persistent_id_notice(&mut self) {
        if self.persistent_id_count <= 1 {
            return;
        }
        self.add_notice(Notice {
            message: "Additional pickle persistent ID opcodes were summarized".to_string(),
            severity: "info",
            location: self
                .first_persistent_id_position
                .map(|position| format!("{} (pos {})", self.source, position)),
            code: Some("persistent_id_summary"),
            details: vec![
                (
                    "persistent_id_count".to_string(),
                    DetailValue::UInt(self.persistent_id_count as u64),
                ),
                (
                    "first_persistent_id_position".to_string(),
                    DetailValue::UInt(self.first_persistent_id_position.unwrap_or_default() as u64),
                ),
            ],
        });
    }

    fn add_finding(&mut self, finding: Finding) {
        if self.seen_finding_keys.insert(finding.dedupe_key()) {
            self.findings.push(finding);
        }
    }

    fn add_notice(&mut self, notice: Notice) {
        if self.seen_notice_keys.insert(notice.dedupe_key()) {
            self.notices.push(notice);
        }
    }

    fn push_import_reference(&mut self, details: Vec<(String, DetailValue)>) {
        if self.import_references.len() < MAX_IMPORT_REFERENCES {
            self.import_references.push(details);
            return;
        }
        if self.import_references_truncated {
            return;
        }
        self.import_references_truncated = true;
        self.add_notice(Notice {
            message: "Import reference metadata exceeded the scanner reporting limit".to_string(),
            severity: "info",
            location: Some(self.source.clone()),
            code: Some("import_references_truncated"),
            details: vec![
                (
                    "max_import_references".to_string(),
                    DetailValue::UInt(MAX_IMPORT_REFERENCES as u64),
                ),
                ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
            ],
        });
    }

    fn push_callable_invocation(&mut self, invocation: &CallableInvocation) {
        if invocation.reference.malformed {
            return;
        }

        let dedupe_key = (
            invocation.reference.module.clone(),
            invocation.reference.name.clone(),
            invocation.positional_arg_count,
        );
        if self.callable_invocation_keys.contains(&dedupe_key) {
            return;
        }
        if self.callable_invocations.len() >= MAX_IMPORT_REFERENCES {
            self.record_callable_invocations_truncated_notice();
            return;
        }
        self.callable_invocation_keys.insert(dedupe_key);

        let symbol = invocation.reference.symbol();
        let mut details = vec![
            (
                "opcode".to_string(),
                DetailValue::String(invocation.op_name.to_string()),
            ),
            (
                "module".to_string(),
                DetailValue::String(invocation.reference.module.clone()),
            ),
            (
                "name".to_string(),
                DetailValue::String(invocation.reference.name.clone()),
            ),
            ("import_reference".to_string(), DetailValue::String(symbol)),
            (
                "global_position".to_string(),
                DetailValue::UInt(invocation.reference.position as u64),
            ),
            (
                "opcode_position".to_string(),
                DetailValue::UInt(invocation.opcode_position as u64),
            ),
        ];
        if let Some(positional_arg_count) = invocation.positional_arg_count {
            details.push((
                "positional_arg_count".to_string(),
                DetailValue::UInt(positional_arg_count as u64),
            ));
        }
        self.callable_invocations.push(details);
    }

    fn record_callable_invocations_truncated_notice(&mut self) {
        if self.callable_invocations_truncated {
            return;
        }
        if self.status.is_complete() {
            self.status = ScanStatus::Inconclusive;
        }
        self.callable_invocations_truncated = true;
        self.add_notice(Notice {
            message: "Callable invocation metadata exceeded the scanner reporting limit"
                .to_string(),
            severity: "info",
            location: Some(self.source.clone()),
            code: Some("callable_invocations_truncated"),
            details: vec![
                (
                    "max_callable_invocations".to_string(),
                    DetailValue::UInt(MAX_IMPORT_REFERENCES as u64),
                ),
                ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
            ],
        });
    }

    fn rebuild_seen_notice_keys(&mut self) {
        self.seen_notice_keys = self.notices.iter().map(Notice::dedupe_key).collect();
    }

    fn record_structural_opcode(&mut self, opcode: &ParsedOpcode, position: usize) {
        self.stream_opcode_count += 1;
        if opcode.name == "FRAME" {
            self.record_oversized_frame_notice(opcode, position);
            return;
        }
        if opcode.name != "PROTO" {
            return;
        }

        let protocol = opcode.arg.as_i64();
        if self.stream_opcode_count > 1 {
            let mut details = vec![
                (
                    "tamper_type".to_string(),
                    DetailValue::String("misplaced_proto".to_string()),
                ),
                ("position".to_string(), DetailValue::UInt(position as u64)),
                (
                    "stream_offset".to_string(),
                    DetailValue::UInt(self.stream_start_offset as u64),
                ),
            ];
            if let Some(protocol) = protocol {
                details.push(("protocol".to_string(), DetailValue::Int(protocol)));
            }
            self.add_finding(Finding {
                message: format!("Misplaced PROTO opcode in pickle stream at byte position {position}"),
                severity: "warning",
                location: Some(format!("{} (pos {})", self.source, position)),
                rule_code: Some("STRUCTURAL_TAMPER"),
                details,
                why: Some(
                    "Binary protocol declarations are expected at the beginning of a stream. A later PROTO opcode indicates structural tampering or malformed serialization.",
                ),
            });
        }

        if let Some(previous_protocol) = self.stream_proto_version {
            let mut details = vec![
                (
                    "tamper_type".to_string(),
                    DetailValue::String("duplicate_proto".to_string()),
                ),
                ("position".to_string(), DetailValue::UInt(position as u64)),
                (
                    "stream_offset".to_string(),
                    DetailValue::UInt(self.stream_start_offset as u64),
                ),
                (
                    "previous_protocol".to_string(),
                    DetailValue::Int(previous_protocol),
                ),
            ];
            if let Some(protocol) = protocol {
                details.push(("protocol".to_string(), DetailValue::Int(protocol)));
            }
            self.add_finding(Finding {
                message: format!(
                    "Duplicate PROTO opcode in pickle stream at byte position {position} (previous={}, current={})",
                    previous_protocol,
                    protocol
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ),
                severity: "warning",
                location: Some(format!("{} (pos {})", self.source, position)),
                rule_code: Some("STRUCTURAL_TAMPER"),
                details,
                why: Some(
                    "Multiple protocol declarations inside one pickle stream are structurally unusual and can be used to probe parser differences between tools.",
                ),
            });
        }

        if let Some(protocol) = protocol {
            self.stream_proto_version = Some(protocol);
        }
    }

    fn record_oversized_frame_notice(&mut self, opcode: &ParsedOpcode, position: usize) {
        let ArgValue::UInt(frame_len) = &opcode.arg else {
            return;
        };
        let remaining_bytes = self.payload.len().saturating_sub(opcode.next);
        let oversized_threshold = remaining_bytes.saturating_add(remaining_bytes / 2);
        if *frame_len <= oversized_threshold {
            return;
        }

        self.add_notice(Notice {
            message: "Pickle FRAME declares more bytes than remain in the stream".to_string(),
            severity: "info",
            location: Some(format!("{} (pos {})", self.source, position)),
            code: Some("oversized_frame"),
            details: vec![
                ("position".to_string(), DetailValue::UInt(position as u64)),
                (
                    "stream_offset".to_string(),
                    DetailValue::UInt(self.stream_start_offset as u64),
                ),
                (
                    "frame_length".to_string(),
                    DetailValue::UInt(*frame_len as u64),
                ),
                (
                    "remaining_bytes".to_string(),
                    DetailValue::UInt(remaining_bytes as u64),
                ),
            ],
        });
    }

    fn record_expansion_opcode(&mut self, opcode: &ParsedOpcode, position: usize) {
        let should_finish_stream =
            record_expansion_state_opcode(&mut self.expansion_state, opcode, position);
        if should_finish_stream {
            flush_expansion_state(&mut self.expansion_state, &mut self.expansion_findings);
        }
    }

    fn finish_analysis(&mut self) {
        flush_expansion_state(&mut self.expansion_state, &mut self.expansion_findings);
        self.emit_collected_expansion_finding();
        self.emit_buffer_opcode_notice();
        self.emit_persistent_id_notice();
        self.rebuild_seen_notice_keys();
        self.coalesce_redundant_global_findings();
        self.finalize_verdict();
    }

    fn emit_collected_expansion_finding(&mut self) {
        if self.expansion_findings.is_empty() {
            return;
        }
        let findings = std::mem::take(&mut self.expansion_findings);
        self.add_expansion_finding(&findings, false);
    }

    fn add_expansion_finding(
        &mut self,
        expansion_findings: &[ExpansionHeuristicFinding],
        post_budget: bool,
    ) {
        let Some(primary_finding) = expansion_findings.first() else {
            return;
        };

        let trigger_labels = primary_finding
            .triggers
            .iter()
            .map(|trigger| expansion_trigger_label(trigger).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let additional_streams = expansion_findings.len().saturating_sub(1);
        let additional_note = if additional_streams > 0 {
            format!(
                " (+{} more stream{})",
                additional_streams,
                if additional_streams == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        };
        let message = if post_budget {
            format!(
                "Suspicious pickle expansion/resource-exhaustion pattern found beyond opcode budget: {}{}",
                trigger_labels, additional_note
            )
        } else {
            format!(
                "Suspicious pickle expansion/resource-exhaustion pattern detected: {}{}",
                trigger_labels, additional_note
            )
        };
        let mut details = vec![
            (
                "findings".to_string(),
                DetailValue::List(
                    expansion_findings
                        .iter()
                        .map(expansion_finding_to_detail)
                        .collect(),
                ),
            ),
            (
                "suspicious_streams".to_string(),
                DetailValue::UInt(expansion_findings.len() as u64),
            ),
        ];
        if post_budget {
            details.push(("post_budget".to_string(), DetailValue::Bool(true)));
        }

        self.add_finding(Finding {
            message,
            severity: "warning",
            location: Some(format!("{} (pos {})", self.source, primary_finding.position)),
            rule_code: Some("PICKLE_EXPANSION"),
            details,
            why: Some(
                "Memo and DUP-heavy pickle streams can cause resource exhaustion when deserialized. Bounded expansion heuristics preserve this signal without materializing expanded objects.",
            ),
        });
    }

    fn record_literal_scan_truncated(
        &mut self,
        literal_type: &'static str,
        literal_length: usize,
        op_name: &'static str,
        position: usize,
    ) {
        if self.status.is_complete() {
            self.status = ScanStatus::Inconclusive;
        }
        self.add_notice(Notice {
            message: format!(
                "{} literal scan truncated at configured limit",
                capitalize(literal_type)
            ),
            severity: "info",
            location: Some(format!("{} (pos {})", self.source, position)),
            code: Some("literal_scan_truncated"),
            details: vec![
                (
                    "opcode".to_string(),
                    DetailValue::String(op_name.to_string()),
                ),
                (
                    "literal_type".to_string(),
                    DetailValue::String(literal_type.to_string()),
                ),
                (
                    "literal_length".to_string(),
                    DetailValue::UInt(literal_length as u64),
                ),
                (
                    "max_string_literal_scan_chars".to_string(),
                    DetailValue::UInt(self.options.max_string_literal_scan_chars as u64),
                ),
                ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
            ],
        });
    }

    fn surface_nested_pickle_findings(
        &mut self,
        payload: &[u8],
        encoding: &'static str,
        position: usize,
    ) -> NestedSurfaceOutcome {
        if self.nested_depth >= self.options.max_nested_depth {
            return NestedSurfaceOutcome {
                depth_limited: true,
                ..NestedSurfaceOutcome::default()
            };
        }

        let nested_source = format!(
            "{} (nested {} pickle at pos {})",
            self.source, encoding, position
        );
        let mut nested_scan = ScanState::new(
            nested_source.clone(),
            payload,
            self.options,
            Some(payload.len()),
            0,
            self.nested_depth + 1,
            Some(self.deadline),
        );
        nested_scan.run();

        let nested_had_findings = !nested_scan.findings.is_empty();
        let mut outcome = NestedSurfaceOutcome {
            incomplete: !nested_scan.status.is_complete(),
            ..NestedSurfaceOutcome::default()
        };
        if !outcome.incomplete
            && !nested_had_findings
            && !nested_scan_has_only_allowlisted_constructor_refs(&nested_scan)
        {
            outcome.has_unclassified_execution = true;
        }
        let nested_incomplete = !nested_scan.status.is_complete();

        for nested_finding in nested_scan.findings {
            if nested_finding.severity == "critical" {
                outcome.has_critical_finding = true;
            }
            let nested_details = nested_finding
                .details
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let mut details = vec![
                (
                    "nested_encoding".to_string(),
                    DetailValue::String(encoding.to_string()),
                ),
                (
                    "nested_source".to_string(),
                    DetailValue::String(nested_source.clone()),
                ),
                (
                    "nested_rule_code".to_string(),
                    match nested_finding.rule_code {
                        Some(rule_code) => DetailValue::String(rule_code.to_string()),
                        None => DetailValue::None,
                    },
                ),
                (
                    "nested_details".to_string(),
                    DetailValue::Dict(nested_details),
                ),
            ];
            for key in ["import_reference", "module", "name", "opcode"] {
                if let Some(value) = detail_string(&nested_finding.details, key) {
                    details.push((key.to_string(), DetailValue::String(value)));
                }
            }
            self.add_finding(Finding {
                message: format!("Nested pickle finding: {}", nested_finding.message),
                severity: nested_finding.severity,
                location: nested_finding.location,
                rule_code: nested_finding.rule_code,
                details,
                why: nested_finding.why,
            });
        }

        if nested_incomplete {
            if self.status.is_complete() {
                self.status = ScanStatus::Inconclusive;
            }
            self.add_finding(Finding {
                message: "Nested pickle analysis did not complete".to_string(),
                severity: "critical",
                location: Some(nested_source.clone()),
                rule_code: Some(nested_rule_code_for_encoding(encoding)),
                details: vec![
                    (
                        "nested_encoding".to_string(),
                        DetailValue::String(encoding.to_string()),
                    ),
                    (
                        "nested_status".to_string(),
                        DetailValue::String(nested_scan.status.as_str().to_string()),
                    ),
                    ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                ],
                why: Some(
                    "Incomplete nested pickle analysis is treated as unsafe because truncated or budget-limited nested payloads can hide deserialization gadgets.",
                ),
            });
            let nested_errors = nested_scan
                .errors
                .iter()
                .map(scan_error_to_detail_value)
                .collect::<Vec<_>>();
            let nested_notices = nested_scan
                .notices
                .iter()
                .map(notice_to_detail_value)
                .collect::<Vec<_>>();
            self.add_notice(Notice {
                message: "Nested pickle analysis did not complete".to_string(),
                severity: "info",
                location: Some(nested_source),
                code: Some("nested_pickle_incomplete"),
                details: vec![
                    (
                        "nested_encoding".to_string(),
                        DetailValue::String(encoding.to_string()),
                    ),
                    (
                        "nested_status".to_string(),
                        DetailValue::String(nested_scan.status.as_str().to_string()),
                    ),
                    (
                        "nested_errors".to_string(),
                        DetailValue::List(nested_errors),
                    ),
                    (
                        "nested_notices".to_string(),
                        DetailValue::List(nested_notices),
                    ),
                    ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                ],
            });
        }
        outcome
    }

    fn scan_post_budget_tail(&mut self, read_offset: usize) {
        if self.options.post_budget_scan_bytes == 0 {
            return;
        }
        let tail_start = read_offset.min(self.payload.len());
        let tail_end = tail_start
            .saturating_add(self.options.post_budget_scan_bytes)
            .min(self.payload.len());
        let tail_prefix_len = 0;
        let tail = &self.payload[tail_start..tail_end];
        self.bytes_scanned = self
            .bytes_scanned
            .max(tail_start.saturating_add(tail.len()));

        let initial_stack = self
            .stack
            .iter()
            .map(|value| post_budget_owned_stack_value(value, self.payload))
            .collect::<Vec<_>>();
        let memo_snapshot = self
            .memo
            .iter()
            .map(|(index, value)| (*index, post_budget_owned_stack_value(value, self.payload)))
            .collect::<HashMap<_, _>>();
        for global_match in post_budget_global_matches(
            tail,
            tail_prefix_len,
            &initial_stack,
            memo_snapshot.len(),
            |memo_index| memo_snapshot.get(&memo_index).cloned(),
        ) {
            let absolute_position = post_budget_absolute_position(
                read_offset,
                read_offset,
                tail_prefix_len,
                global_match.pattern_start,
            );
            let severity = if global_match.reduce_proximate {
                "critical"
            } else {
                global_match.severity
            };
            self.add_finding(Finding {
                message: "Dangerous global-like byte pattern found after analysis limit"
                    .to_string(),
                severity,
                location: Some(format!(
                    "{} (pos {})",
                    self.source,
                    self.position_offset + absolute_position
                )),
                rule_code: Some("POST_BUDGET_GLOBAL"),
                details: vec![
                    (
                        "pattern".to_string(),
                        DetailValue::String(global_match.pattern()),
                    ),
                    (
                        "module".to_string(),
                        DetailValue::String(global_match.module),
                    ),
                    ("name".to_string(), DetailValue::String(global_match.name)),
                    (
                        "position".to_string(),
                        DetailValue::UInt((self.position_offset + absolute_position) as u64),
                    ),
                    (
                        "reduce_proximate".to_string(),
                        DetailValue::Bool(global_match.reduce_proximate),
                    ),
                ],
                why: Some(
                    "Opcode analysis stopped early, but a byte-level tail scan still found dangerous pickle global references.",
                ),
            });
        }

        let expansion_findings = detect_expansion_findings_in_tail(
            tail,
            read_offset,
            read_offset,
            tail_prefix_len,
            self.position_offset,
        );
        if !expansion_findings.is_empty() {
            self.add_expansion_finding(&expansion_findings, true);
        }
    }

    fn scan_follow_on_pickle_streams(&mut self, start_index: usize) {
        if self.options.post_budget_scan_bytes == 0 || start_index >= self.payload.len() {
            return;
        }
        let scan_end = self
            .payload
            .len()
            .min(start_index.saturating_add(self.options.post_budget_scan_bytes));
        let tail = &self.payload[start_index..scan_end];
        let probe_offsets = nested_pickle_probe_offsets(tail);
        for relative_offset in probe_offsets.offsets {
            let absolute_offset = start_index.saturating_add(relative_offset);
            if absolute_offset <= start_index {
                continue;
            }
            let candidate = &self.payload[absolute_offset..scan_end];
            if self.options.max_nested_pickle_bytes == 0 {
                return;
            }
            let candidate_probe_len = candidate.len().min(self.options.max_nested_pickle_bytes);
            if !looks_like_pickle_payload(
                &candidate[..candidate_probe_len],
                self.options.max_nested_pickle_bytes,
            ) {
                continue;
            }
            let nested_source = format!(
                "{} (follow-on pickle stream at pos {})",
                self.source,
                self.position_offset + absolute_offset
            );
            let mut follow_on_scan = ScanState::new(
                nested_source,
                candidate,
                self.options,
                Some(candidate.len()),
                self.position_offset + absolute_offset,
                self.nested_depth,
                Some(self.deadline),
            );
            follow_on_scan.run();
            let had_findings = !follow_on_scan.findings.is_empty();
            for finding in follow_on_scan.findings {
                self.add_finding(finding);
            }
            for reference in follow_on_scan.import_references {
                self.push_import_reference(reference);
            }
            self.merge_follow_on_callable_invocations(
                follow_on_scan.callable_invocations,
                follow_on_scan.callable_invocations_truncated,
            );
            if had_findings {
                self.add_notice(Notice {
                    message: "Follow-on pickle stream detected after malformed padding".to_string(),
                    severity: "info",
                    location: Some(format!(
                        "{} (pos {})",
                        self.source,
                        self.position_offset + absolute_offset
                    )),
                    code: Some("follow_on_stream_detected"),
                    details: vec![
                        (
                            "position".to_string(),
                            DetailValue::UInt((self.position_offset + absolute_offset) as u64),
                        ),
                        ("analysis_incomplete".to_string(), DetailValue::Bool(true)),
                    ],
                });
                return;
            }
        }
    }

    fn merge_follow_on_callable_invocations(
        &mut self,
        follow_on_invocations: Vec<Vec<(String, DetailValue)>>,
        follow_on_invocations_truncated: bool,
    ) {
        if follow_on_invocations_truncated {
            self.record_callable_invocations_truncated_notice();
        }
        for invocation in follow_on_invocations {
            let Some(invocation_key) = Self::callable_invocation_detail_key(&invocation) else {
                continue;
            };
            if self.callable_invocation_keys.contains(&invocation_key) {
                continue;
            }
            if self.callable_invocations.len() >= MAX_IMPORT_REFERENCES {
                self.record_callable_invocations_truncated_notice();
                continue;
            }
            self.callable_invocation_keys.insert(invocation_key);
            self.callable_invocations.push(invocation);
        }
    }

    fn callable_invocation_detail_key(
        details: &[(String, DetailValue)],
    ) -> Option<(String, String, Option<usize>)> {
        let module = detail_string(details, "module").unwrap_or_default();
        let name = detail_string(details, "name").unwrap_or_default();
        if module.is_empty() || name.is_empty() {
            return None;
        }
        let positional_arg_count = detail_usize(details, "positional_arg_count");
        Some((module, name, positional_arg_count))
    }

    fn coalesce_redundant_global_findings(&mut self) {
        let mut called_global_keys = HashSet::new();
        for finding in &self.findings {
            if finding.rule_code != Some("DANGEROUS_CALL") {
                continue;
            }
            let import_reference = detail_string(&finding.details, "import_reference");
            let global_position = detail_usize(&finding.details, "global_position");
            if let (Some(import_reference), Some(global_position)) =
                (import_reference, global_position)
            {
                called_global_keys.insert((import_reference, global_position));
            }
        }
        if called_global_keys.is_empty() {
            return;
        }

        self.findings.retain(|finding| {
            if finding.rule_code != Some("DANGEROUS_GLOBAL") {
                return true;
            }
            let import_reference = detail_string(&finding.details, "import_reference");
            let location_position = detail_usize(&finding.details, "position");
            match (import_reference, location_position) {
                (Some(import_reference), Some(position)) => {
                    !called_global_keys.contains(&(import_reference, position))
                }
                _ => true,
            }
        });
        self.seen_finding_keys = self
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.message.clone(),
                    finding.location.clone(),
                    finding.rule_code,
                )
            })
            .collect();
    }

    fn finalize_verdict(&mut self) {
        if self
            .findings
            .iter()
            .any(|finding| finding.severity == "critical")
        {
            self.verdict = ScanVerdict::Malicious;
        } else if self
            .findings
            .iter()
            .any(|finding| finding.severity == "warning")
        {
            self.verdict = ScanVerdict::Suspicious;
        } else if self.status.is_complete() {
            self.verdict = ScanVerdict::Clean;
        } else {
            self.verdict = ScanVerdict::Unknown;
        }
    }

    pub(crate) fn to_py_report(&self, py: Python<'_>, duration_s: f64) -> PyResult<Py<PyDict>> {
        let report = PyDict::new(py);
        report.set_item("source", &self.source)?;
        report.set_item("status", self.status.as_str())?;
        report.set_item("verdict", self.verdict.as_str())?;

        let findings = PyList::empty(py);
        for finding in &self.findings {
            findings.append(finding.to_py_object(py)?)?;
        }
        report.set_item("findings", findings)?;

        let notices = PyList::empty(py);
        for notice in &self.notices {
            notices.append(notice.to_py_object(py)?)?;
        }
        report.set_item("notices", notices)?;

        let errors = PyList::empty(py);
        for error in &self.errors {
            errors.append(error.to_py_object(py)?)?;
        }
        report.set_item("errors", errors)?;

        let raw_scan_complete = self.status.is_complete()
            && self
                .bytes_total
                .map(|bytes_total| self.bytes_scanned >= bytes_total)
                .unwrap_or(true);
        let coverage = PyDict::new(py);
        coverage.set_item("bytes_scanned", self.bytes_scanned)?;
        coverage.set_item("bytes_total", self.bytes_total)?;
        coverage.set_item("opcode_count", self.opcode_count)?;
        coverage.set_item("raw_scan_complete", raw_scan_complete)?;
        coverage.set_item("opcode_scan_complete", self.status.is_complete())?;
        report.set_item("coverage", coverage)?;

        let metadata = PyDict::new(py);
        metadata.set_item("opcode_count", self.opcode_count)?;
        let opcode_counts = PyDict::new(py);
        for (opcode, count) in &self.opcode_counts {
            opcode_counts.set_item(opcode, count)?;
        }
        metadata.set_item("opcode_counts", opcode_counts)?;
        metadata.set_item("globals_count", self.global_count)?;
        let import_references = PyList::empty(py);
        for reference in &self.import_references {
            import_references.append(DetailValue::Dict(reference.clone()).to_py_object(py)?)?;
        }
        metadata.set_item("import_references", import_references)?;
        let callable_invocations = PyList::empty(py);
        for invocation in &self.callable_invocations {
            callable_invocations.append(DetailValue::Dict(invocation.clone()).to_py_object(py)?)?;
        }
        metadata.set_item("callable_invocations", callable_invocations)?;
        metadata.set_item(
            "callable_invocations_truncated",
            self.callable_invocations_truncated,
        )?;
        if !self.protocols.is_empty() {
            metadata.set_item("protocols", &self.protocols)?;
        }
        if let Some(first_pickle_end_pos) = self.first_pickle_end_pos {
            metadata.set_item("first_pickle_end_pos", first_pickle_end_pos)?;
        }
        report.set_item("metadata", metadata)?;
        report.set_item("duration_s", duration_s)?;
        Ok(report.unbind())
    }
}

fn sensitive_mutator_invocation_target(
    callable_ref: &GlobalRef,
    args: &[StackValue],
) -> Option<&'static str> {
    if !is_container_mutator_callable(callable_ref) {
        return None;
    }
    args.first().and_then(sensitive_mutation_target)
}

fn operator_mutator_protocol_target(
    callable_ref: &GlobalRef,
    args: &[StackValue],
) -> Option<&'static str> {
    if !matches!(callable_ref.module.as_str(), "operator" | "_operator") {
        return None;
    }
    if !matches!(args.first(), Some(StackValue::Constructed(_))) {
        return None;
    }
    match callable_ref.name.as_str() {
        "setitem" => Some("object.__setitem__"),
        _ => None,
    }
}

fn is_container_mutator_callable(callable_ref: &GlobalRef) -> bool {
    match callable_ref.module.as_str() {
        "builtins" | "__builtin__" | "__builtins__" => matches!(
            callable_ref.name.as_str(),
            "dict.__delitem__"
                | "dict.__ior__"
                | "dict.__setitem__"
                | "dict.clear"
                | "dict.pop"
                | "dict.popitem"
                | "dict.setdefault"
                | "dict.update"
                | "list.__delitem__"
                | "list.__iadd__"
                | "list.__imul__"
                | "list.__setitem__"
                | "list.append"
                | "list.clear"
                | "list.extend"
                | "list.insert"
                | "list.pop"
                | "list.remove"
                | "list.reverse"
                | "list.sort"
        ),
        "operator" | "_operator" => matches!(
            callable_ref.name.as_str(),
            "delitem" | "iadd" | "imul" | "ior" | "setitem"
        ),
        _ => false,
    }
}

fn sensitive_mutation_target(value: &StackValue) -> Option<&'static str> {
    let (StackValue::Global(reference) | StackValue::Constructed(reference)) = value else {
        return None;
    };
    match (reference.module.as_str(), reference.name.as_str()) {
        ("copyreg", "dispatch_table") => Some("copyreg.dispatch_table"),
        ("logging", "root.handlers") => Some("logging.root.handlers"),
        ("warnings", "filters") => Some("warnings.filters"),
        _ => None,
    }
}

fn nested_scan_has_only_allowlisted_constructor_refs(scan: &ScanState<'_>) -> bool {
    let mut saw_import_reference = false;
    for details in &scan.import_references {
        let Some(reference) = detail_string(details, "import_reference") else {
            continue;
        };
        saw_import_reference = true;
        if !is_allowlisted_nested_constructor_ref(&reference) {
            return false;
        }
    }
    saw_import_reference
}

fn post_budget_owned_stack_value(value: &StackValue, payload: &[u8]) -> StackValue {
    match value {
        StackValue::TextSpan { start, end } if start <= end && *end <= payload.len() => {
            StackValue::Text(String::from_utf8_lossy(&payload[*start..*end]).to_string())
        }
        StackValue::Bytes { start, end } if start <= end && *end <= payload.len() => {
            StackValue::Bytes {
                start: *start,
                end: *end,
            }
        }
        StackValue::Tuple(values) => StackValue::Tuple(
            values
                .iter()
                .map(|item| post_budget_owned_stack_value(item, payload))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn advance_chars_from(value: &str, start: usize, count: usize) -> usize {
    if count == 0 || start >= value.len() {
        return start;
    }
    if value.is_ascii() {
        return start.saturating_add(count).min(value.len());
    }
    for (chars_seen, (offset, _)) in value[start..].char_indices().enumerate() {
        if chars_seen == count {
            return start + offset;
        }
    }
    value.len()
}

fn string_char_len(value: &str) -> usize {
    if value.is_ascii() {
        value.len()
    } else {
        value.chars().count()
    }
}

fn contains_escaped_hex_marker(value: &str) -> bool {
    value.contains("\\x") || value.contains("\\X")
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::{
        DEFAULT_MAX_NESTED_DEPTH, DEFAULT_MAX_NESTED_PICKLE_BYTES, DEFAULT_MAX_OPCODES,
        DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS, DEFAULT_POST_BUDGET_SCAN_BYTES, DEFAULT_TIMEOUT_S,
    };
    use crate::report::{detail_string, detail_usize};
    use std::time::Duration;

    #[test]
    fn integer_stack_values_preserve_text_and_long_byte_operands() {
        for (arg, expected) in [
            (ArgValue::Text("42".to_string()), "42"),
            (ArgValue::Text("-7L".to_string()), "-7"),
            (ArgValue::Bytes { start: 0, end: 1 }, "-1"),
            (ArgValue::Bytes { start: 1, end: 3 }, "1"),
        ] {
            let payload = [0xff, 0x01, 0x00];
            match stack_value_from_integer_arg(&arg, &payload) {
                StackValue::Primitive { type_name, repr } => {
                    assert_eq!(type_name, "int");
                    assert_eq!(repr, expected);
                }
                _ => panic!("integer operand did not produce primitive stack value"),
            }
        }
    }

    #[test]
    fn str_join_result_counts_separator_bytes_before_appending() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"";
        let scan = ScanState::new(
            "str-join-bound.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );
        let callable = StackValue::Global(GlobalRef {
            module: "builtins".to_string(),
            name: "str.join".to_string(),
            position: 0,
            malformed: false,
        });

        let within_bound = vec![
            callable.clone(),
            StackValue::Tuple(vec![
                StackValue::Text("x".repeat(MAX_TRACKED_STR_JOIN_RESULT_BYTES - 2)),
                StackValue::Tuple(vec![
                    StackValue::Text("a".to_string()),
                    StackValue::Text("b".to_string()),
                ]),
            ]),
        ];
        assert!(matches!(
            scan.str_join_result(&within_bound),
            Some(StackValue::Text(value)) if value.len() == MAX_TRACKED_STR_JOIN_RESULT_BYTES
        ));

        let over_bound = vec![
            callable,
            StackValue::Tuple(vec![
                StackValue::Text("x".repeat(MAX_TRACKED_STR_JOIN_RESULT_BYTES - 1)),
                StackValue::Tuple(vec![
                    StackValue::Text("a".to_string()),
                    StackValue::Text("b".to_string()),
                ]),
            ]),
        ];
        assert!(scan.str_join_result(&over_bound).is_none());
    }

    #[test]
    fn global_reference_dedupe_preserves_malformed_state() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b".";
        let mut scan = ScanState::new(
            "global-dedupe.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );
        let malformed = GlobalRef {
            module: "os".to_string(),
            name: "system".to_string(),
            position: 7,
            malformed: true,
        };
        let well_formed = GlobalRef {
            malformed: false,
            ..malformed.clone()
        };

        scan.record_global_ref(&malformed, "STACK_GLOBAL");
        scan.record_global_ref(&well_formed, "STACK_GLOBAL");
        scan.record_global_ref(&well_formed, "STACK_GLOBAL");

        assert_eq!(scan.seen_global_reference_keys.len(), 2);
        assert_eq!(scan.import_references.len(), 1);
        assert_eq!(scan.global_count, 2);
        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("DANGEROUS_GLOBAL")
                && detail_string(&finding.details, "import_reference").as_deref()
                    == Some("os.system")
        }));
    }

    #[test]
    fn large_repeated_literals_skip_expensive_text_and_encoded_probes_only_when_complete() {
        let mut options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b".";
        let scan = ScanState::new(
            "large-repeated.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        assert!(scan.is_large_uninteresting_repeated_literal(&"A".repeat(1024 * 1024)));
        assert!(!scan.is_large_uninteresting_repeated_literal(&"A".repeat(1023)));
        assert!(!scan.is_large_uninteresting_repeated_literal("AAAos.system('id')AAA"));

        options.max_string_literal_scan_chars = 8;
        let truncated_scan = ScanState::new(
            "large-repeated-truncated.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );
        assert!(!truncated_scan.is_large_uninteresting_repeated_literal(&"A".repeat(1024)));
    }

    #[test]
    fn missing_memo_gets_push_opaque_operands() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };

        for (name, payload) in [
            ("GET", b"g0\n)R.".as_slice()),
            ("BINGET", b"h\x00)R.".as_slice()),
            ("LONG_BINGET", b"j\x00\x00\x00\x00)R.".as_slice()),
        ] {
            let mut scan = ScanState::new(
                format!("missing-memo-{name}.pkl"),
                payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert_eq!(scan.verdict, "clean", "{name} should be opaque");
            assert!(scan.import_references.is_empty(), "{name} import refs");
            assert!(
                scan.findings
                    .iter()
                    .all(|finding| finding.rule_code != Some("MALFORMED_STACK_GLOBAL")),
                "{name} should not synthesize malformed globals"
            );
        }
    }

    #[test]
    fn timeout_checks_are_amortized_by_opcode_interval() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b".";
        let mut scan = ScanState::new(
            "timeout-amortized.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            Instant::now().checked_sub(Duration::from_secs(1)),
        );
        let opcode = ParsedOpcode {
            name: "NONE",
            arg: ArgValue::None,
            pos: 0,
            next: 1,
        };

        scan.opcode_count = TIME_CHECK_INTERVAL_OPCODES - 1;
        assert!(matches!(scan.check_limits(&opcode), Ok(())));

        scan.opcode_count = TIME_CHECK_INTERVAL_OPCODES;
        assert!(matches!(
            scan.check_limits(&opcode),
            Err(LimitError::Timeout)
        ));
    }

    #[test]
    fn global_finding_coalesce_uses_structured_positions_only() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b".";
        let mut scan = ScanState::new(
            "structured-position.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );
        let call_finding = Finding {
            message: "call".to_string(),
            severity: "critical",
            location: Some("structured-position.pkl (pos 9)".to_string()),
            rule_code: Some("DANGEROUS_CALL"),
            details: vec![
                (
                    "import_reference".to_string(),
                    DetailValue::String("os.system".to_string()),
                ),
                ("global_position".to_string(), DetailValue::UInt(4)),
            ],
            why: None,
        };
        let global_without_position = Finding {
            message: "global".to_string(),
            severity: "critical",
            location: Some("source-with-text-(pos 4).pkl (pos 4)".to_string()),
            rule_code: Some("DANGEROUS_GLOBAL"),
            details: vec![(
                "import_reference".to_string(),
                DetailValue::String("os.system".to_string()),
            )],
            why: None,
        };

        scan.findings = vec![call_finding.clone(), global_without_position];
        scan.coalesce_redundant_global_findings();
        assert!(scan
            .findings
            .iter()
            .any(|finding| finding.rule_code == Some("DANGEROUS_GLOBAL")));

        let global_with_position = Finding {
            details: vec![
                (
                    "import_reference".to_string(),
                    DetailValue::String("os.system".to_string()),
                ),
                ("position".to_string(), DetailValue::UInt(4)),
            ],
            ..call_finding.clone()
        };
        scan.findings = vec![
            call_finding,
            Finding {
                message: "global".to_string(),
                rule_code: Some("DANGEROUS_GLOBAL"),
                ..global_with_position
            },
        ];
        scan.coalesce_redundant_global_findings();
        assert!(scan
            .findings
            .iter()
            .all(|finding| finding.rule_code != Some("DANGEROUS_GLOBAL")));
    }

    #[test]
    fn stack_global_rejects_byte_operands_fail_closed() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };

        for (name, payload) in [
            (
                "bytes-module-and-name",
                b"\x80\x04C\x02osC\x06system\x93.".as_slice(),
            ),
            (
                "bytes-module",
                b"\x80\x04C\x02os\x8c\x06system\x93.".as_slice(),
            ),
            (
                "bytes-name",
                b"\x80\x04\x8c\x02osC\x06system\x93.".as_slice(),
            ),
        ] {
            let mut scan = ScanState::new(
                format!("stack-global-{name}.pkl"),
                payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert_eq!(scan.verdict, "malicious", "{name}");
            assert!(
                scan.findings
                    .iter()
                    .any(|finding| finding.rule_code == Some("MALFORMED_STACK_GLOBAL")),
                "{name} should fail closed"
            );
            assert!(
                scan.findings
                    .iter()
                    .all(|finding| finding.rule_code != Some("DANGEROUS_CALL")),
                "{name} should not reinterpret bytes as text globals"
            );
        }
    }

    #[test]
    fn notice_dedupe_state_can_be_rebuilt_after_notice_rewrites() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b".";
        let mut scan = ScanState::new(
            "notice-dedupe.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );
        let old_notice = Notice {
            message: "old notice".to_string(),
            severity: "info",
            location: Some("notice-dedupe.pkl (pos 1)".to_string()),
            code: Some("rewritten_notice"),
            details: Vec::new(),
        };
        let coalesced_notice = Notice {
            message: "coalesced notice".to_string(),
            severity: "info",
            location: Some("notice-dedupe.pkl".to_string()),
            code: Some("rewritten_notice"),
            details: Vec::new(),
        };

        scan.add_notice(old_notice.clone());
        scan.notices.clear();
        scan.notices.push(coalesced_notice.clone());
        scan.rebuild_seen_notice_keys();

        scan.add_notice(old_notice);
        scan.add_notice(coalesced_notice);

        assert_eq!(scan.notices.len(), 2);
        assert_eq!(scan.seen_notice_keys.len(), 2);
    }

    #[test]
    fn inst_dispatch_flags_dangerous_global_calls() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"(ios\nsystem\n.";
        let mut scan = ScanState::new(
            "inst-dispatch.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("DANGEROUS_CALL")
                && detail_string(&finding.details, "opcode").as_deref() == Some("INST")
                && detail_string(&finding.details, "import_reference").as_deref()
                    == Some("os.system")
        }));
    }

    #[test]
    fn obj_dispatch_uses_first_mark_value_as_callable() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"(cos\nsystem\nU\x04echoo.";
        let mut scan = ScanState::new(
            "obj-dispatch.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("DANGEROUS_CALL")
                && detail_string(&finding.details, "opcode").as_deref() == Some("OBJ")
                && detail_string(&finding.details, "import_reference").as_deref()
                    == Some("os.system")
        }));
    }

    #[test]
    fn newobj_ex_dispatch_consumes_callable_args_and_kwargs() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04cos\nsystem\n)}\x92.";
        let mut scan = ScanState::new(
            "newobj-ex-dispatch.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("DANGEROUS_CALL")
                && detail_string(&finding.details, "opcode").as_deref() == Some("NEWOBJ_EX")
                && detail_string(&finding.details, "import_reference").as_deref()
                    == Some("os.system")
        }));
    }

    #[test]
    fn protocol5_buffer_opcodes_create_opaque_stack_context() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x05\x97\x98\x93.";
        let mut scan = ScanState::new(
            "buffer-stack-global.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.verdict, "malicious");
        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("MALFORMED_STACK_GLOBAL"))
            .expect("malformed STACK_GLOBAL finding");
        assert_eq!(
            detail_string(&finding.details, "module_operand").as_deref(),
            Some("NoneType:None")
        );
        assert_eq!(
            detail_string(&finding.details, "name_operand").as_deref(),
            Some("object")
        );
        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("buffer_opcode")));
    }

    #[test]
    fn protocol5_buffer_opcode_notices_are_collapsed() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x05\x97\x97\x98\x97\x98.";
        let mut scan = ScanState::new(
            "many-buffer-opcodes.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let buffer_notices = scan
            .notices
            .iter()
            .filter(|notice| notice.code == Some("buffer_opcode"))
            .collect::<Vec<_>>();
        assert_eq!(buffer_notices.len(), 1);
        let notice = buffer_notices[0];
        assert_eq!(
            detail_usize(&notice.details, "buffer_opcode_count"),
            Some(5)
        );
        assert_eq!(detail_usize(&notice.details, "next_buffer_count"), Some(3));
        assert_eq!(
            detail_usize(&notice.details, "readonly_buffer_count"),
            Some(2)
        );
    }

    #[test]
    fn readonly_buffer_empty_stack_does_not_fabricate_operand() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x05\x98\x93.";
        let mut scan = ScanState::new(
            "readonly-empty-stack.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("MALFORMED_STACK_GLOBAL"))
            .expect("malformed STACK_GLOBAL finding");
        assert_eq!(
            detail_string(&finding.details, "module_operand").as_deref(),
            Some("NoneType:None")
        );
        assert_eq!(
            detail_string(&finding.details, "name_operand").as_deref(),
            Some("NoneType:None")
        );
        let notice = scan
            .notices
            .iter()
            .find(|notice| notice.code == Some("buffer_opcode"))
            .expect("buffer opcode notice");
        assert_eq!(
            detail_usize(&notice.details, "readonly_buffer_empty_stack_count"),
            Some(1)
        );
    }

    #[test]
    fn empty_collection_operands_report_precise_stack_preview_types() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };

        for (opcode, expected_preview) in
            [(b']', "list:[]"), (b'}', "dict:{}"), (b'\x8f', "set:set()")]
        {
            let payload = [
                b"\x80\x04".as_slice(),
                &[opcode],
                b"\x8c\x06system\x94\x93.".as_slice(),
            ]
            .concat();
            let mut scan = ScanState::new(
                format!("empty-operand-{expected_preview}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            let finding = scan
                .findings
                .iter()
                .find(|finding| finding.rule_code == Some("MALFORMED_STACK_GLOBAL"))
                .expect("malformed STACK_GLOBAL finding");
            assert_eq!(
                detail_string(&finding.details, "module_operand").as_deref(),
                Some(expected_preview)
            );
        }
    }

    #[test]
    fn truncated_proto0_nested_payloads_are_not_silently_dropped() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: 4,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let inner = b"cos\nsystem\n.";
        let payload = [
            b"\x80\x04C".as_slice(),
            &[inner.len() as u8],
            inner.as_slice(),
            b".".as_slice(),
        ]
        .concat();
        let mut scan = ScanState::new(
            "truncated-proto0-nested.pkl".to_string(),
            &payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.status, "inconclusive");
        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("S213")
                && finding.details.iter().any(|(key, value)| {
                    key == "analysis_incomplete" && matches!(value, DetailValue::Bool(true))
                })
        }));
        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("nested_payload_truncated")));
    }

    #[test]
    fn callable_operand_underflow_does_not_clear_stack_state() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "operand-underflow.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );
        scan.stack.push(StackValue::Text("survivor".to_string()));

        assert!(scan.consume_top_operands(2).is_none());

        assert_eq!(scan.stack.len(), 2);
        assert_eq!(stack_value_preview(&scan.stack[0], 0), "str:\"survivor\"");
        assert!(matches!(scan.stack[1], StackValue::Other));
    }

    #[test]
    fn tuple_shortcuts_do_not_wrap_mark_sentinels() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "tuple-mark.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );
        scan.stack.push(StackValue::Mark);

        scan.collapse_top_n(1);

        assert_eq!(scan.stack.len(), 2);
        assert!(matches!(scan.stack[0], StackValue::Mark));
        assert!(matches!(scan.stack[1], StackValue::Other));
    }

    #[test]
    fn follow_on_streams_do_not_consume_nested_depth_budget() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: 1,
        };
        let payload = b"padding\x00\x80\x04cos\nsystem\n)R.";
        let mut scan = ScanState::new(
            "follow-on-depth.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            1,
            None,
        );

        scan.scan_follow_on_pickle_streams(0);

        assert!(scan
            .findings
            .iter()
            .any(|finding| finding.rule_code == Some("DANGEROUS_CALL")));
        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("follow_on_stream_detected")));
    }

    #[test]
    fn import_reference_metadata_is_capped_with_notice() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "import-cap.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );

        for index in 0..=MAX_IMPORT_REFERENCES {
            scan.push_import_reference(vec![(
                "position".to_string(),
                DetailValue::UInt(index as u64),
            )]);
        }

        assert_eq!(scan.import_references.len(), MAX_IMPORT_REFERENCES);
        assert_eq!(
            scan.notices
                .iter()
                .filter(|notice| notice.code == Some("import_references_truncated"))
                .count(),
            1
        );
    }

    #[test]
    fn callable_invocation_metadata_is_capped_with_notice() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "callable-invocation-cap.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );

        for index in 0..=MAX_IMPORT_REFERENCES {
            let invocation = ScanState::callable_invocation(
                GlobalRef {
                    module: "module".to_string(),
                    name: format!("call_{index}"),
                    position: index,
                    malformed: false,
                },
                "REDUCE",
                index,
                Some(0),
            );
            scan.push_callable_invocation(&invocation);
        }

        assert_eq!(scan.callable_invocations.len(), MAX_IMPORT_REFERENCES);
        assert_eq!(scan.status, ScanStatus::Inconclusive);
        assert_eq!(
            scan.notices
                .iter()
                .filter(|notice| notice.code == Some("callable_invocations_truncated"))
                .count(),
            1
        );
    }

    #[test]
    fn follow_on_callable_invocation_truncation_is_propagated() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "follow-on-truncated-invocations.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );

        scan.merge_follow_on_callable_invocations(Vec::new(), true);

        assert!(scan.callable_invocations_truncated);
        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("callable_invocations_truncated")));
    }

    #[test]
    fn follow_on_duplicate_callable_invocations_do_not_mark_metadata_truncated() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            "follow-on-duplicate-invocation.pkl".to_string(),
            b"",
            &options,
            Some(0),
            0,
            0,
            None,
        );

        for index in 0..MAX_IMPORT_REFERENCES {
            let invocation = ScanState::callable_invocation(
                GlobalRef {
                    module: "module".to_string(),
                    name: format!("call_{index}"),
                    position: index,
                    malformed: false,
                },
                "REDUCE",
                index,
                Some(0),
            );
            scan.push_callable_invocation(&invocation);
        }

        scan.merge_follow_on_callable_invocations(
            vec![scan.callable_invocations[0].clone()],
            false,
        );

        assert!(!scan.callable_invocations_truncated);
        assert_eq!(scan.status, ScanStatus::Complete);
    }

    #[test]
    fn persistent_id_opcodes_are_flagged() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"Pexternal-storage-key\n.";
        let mut scan = ScanState::new(
            "persistent.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.verdict, "suspicious");
        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("PERSISTENT_ID"))
            .expect("persistent ID finding");
        assert_eq!(
            detail_string(&finding.details, "opcode").as_deref(),
            Some("PERSID")
        );
    }

    #[test]
    fn repeated_persistent_id_opcodes_are_summarized() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"Pa\nPb\nPc\n.";
        let mut scan = ScanState::new(
            "persistent-many.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(
            scan.findings
                .iter()
                .filter(|finding| finding.rule_code == Some("PERSISTENT_ID"))
                .count(),
            1
        );
        let notice = scan
            .notices
            .iter()
            .find(|notice| notice.code == Some("persistent_id_summary"))
            .expect("persistent ID summary notice");
        assert_eq!(
            detail_usize(&notice.details, "persistent_id_count"),
            Some(3)
        );
    }

    #[test]
    fn data_only_nested_payloads_emit_notice_not_finding() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04C\x04\x80\x04}.\x94.";
        let mut scan = ScanState::new(
            "data-only-nested.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.verdict, "clean");
        assert!(scan.findings.is_empty());
        let notice = scan
            .notices
            .iter()
            .find(|notice| notice.code == Some("nested_payload_detected"))
            .expect("data-only nested payload notice");
        assert_eq!(
            detail_string(&notice.details, "encoding").as_deref(),
            Some("raw")
        );
    }

    #[test]
    fn benign_nested_constructor_payloads_emit_notice_not_finding() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let nested_payload = b"ccollections\nOrderedDict\n)R.";
        let mut payload = b"\x80\x04C".to_vec();
        payload.push(nested_payload.len() as u8);
        payload.extend_from_slice(nested_payload);
        payload.extend_from_slice(b"\x94.");
        let mut scan = ScanState::new(
            "benign-constructor-nested.pkl".to_string(),
            &payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.verdict, "clean");
        assert!(scan.findings.is_empty());
        let notice = scan
            .notices
            .iter()
            .find(|notice| notice.code == Some("nested_payload_detected"))
            .expect("benign constructor nested payload notice");
        assert_eq!(
            detail_string(&notice.details, "encoding").as_deref(),
            Some("raw")
        );
        assert!(notice
            .details
            .iter()
            .any(|(key, value)| key == "nested_has_execution_opcode"
                && matches!(value, DetailValue::Bool(true))));
    }

    #[test]
    fn raw_nested_payload_scan_continues_after_data_only_payloads() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let nested_bytes = b"AAAAAA\x80\x04}.BBBBBBcos\nsystem\n)R.CCCC";
        let mut payload = b"\x80\x04B".to_vec();
        payload.extend_from_slice(&(nested_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(nested_bytes);
        payload.push(b'.');
        let mut scan = ScanState::new(
            "raw-nested-benign-before-malicious.pkl".to_string(),
            &payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert_eq!(scan.verdict, "malicious");
        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("nested_payload_detected")));
        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("S213")
                && detail_string(&finding.details, "encoding").as_deref() == Some("raw")
                && detail_usize(&finding.details, "payload_size") == Some(14)
        }));
        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("DANGEROUS_CALL")
                && detail_string(&finding.details, "import_reference").as_deref()
                    == Some("os.system")
        }));
    }

    #[test]
    fn legacy_string_opcodes_scan_raw_nested_payloads() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let nested_bytes = b"AAAAAAcos\nsystem\n)R.BBBB";
        let mut binstring_payload = b"\x80\x02T".to_vec();
        binstring_payload.extend_from_slice(&(nested_bytes.len() as u32).to_le_bytes());
        binstring_payload.extend_from_slice(nested_bytes);
        binstring_payload.push(b'.');
        let mut short_binstring_payload = b"\x80\x02U".to_vec();
        short_binstring_payload.push(nested_bytes.len() as u8);
        short_binstring_payload.extend_from_slice(nested_bytes);
        short_binstring_payload.push(b'.');
        let payloads = [
            ("binstring", binstring_payload),
            ("short-binstring", short_binstring_payload),
            (
                "protocol0-string",
                b"\x80\x02S'AAAAAAcos\\x0asystem\\x0a)R.BBBB'\n.".to_vec(),
            ),
        ];

        for (label, payload) in payloads {
            let mut scan = ScanState::new(
                format!("legacy-string-raw-nested-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert_eq!(scan.verdict, "malicious", "missed {label}");
            assert!(scan.findings.iter().any(|finding| {
                finding.rule_code == Some("S213")
                    && detail_string(&finding.details, "encoding").as_deref() == Some("raw")
                    && detail_usize(&finding.details, "payload_size") == Some(14)
            }));
            assert!(scan.findings.iter().any(|finding| {
                finding.rule_code == Some("DANGEROUS_CALL")
                    && detail_string(&finding.details, "import_reference").as_deref()
                        == Some("os.system")
            }));
        }
    }

    #[test]
    fn oversized_frame_lengths_emit_structural_notice() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04\x95\xfe\xff\xff\xff\xff\xff\xff\xff}.";
        let mut scan = ScanState::new(
            "oversized-frame.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let notice = scan
            .notices
            .iter()
            .find(|notice| notice.code == Some("oversized_frame"))
            .expect("oversized FRAME notice");
        assert_eq!(detail_usize(&notice.details, "position"), Some(2));
        assert_eq!(detail_usize(&notice.details, "remaining_bytes"), Some(2));
        assert_eq!(scan.verdict, "clean");
    }

    #[test]
    fn post_budget_tail_reports_expanded_needles_at_precise_positions() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 1,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04cos\npopen\n.";
        let mut scan = ScanState::new(
            "post-budget.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
            .expect("post-budget global finding");
        assert_eq!(
            detail_string(&finding.details, "pattern").as_deref(),
            Some("os\npopen")
        );
        assert_eq!(detail_usize(&finding.details, "position"), Some(2));
        assert_eq!(finding.location.as_deref(), Some("post-budget.pkl (pos 2)"));
    }

    #[test]
    fn post_budget_tail_detects_policy_dangerous_globals() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 1,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };

        for (module, name) in [
            ("subprocess", "run"),
            ("subprocess", "check_call"),
            ("importlib", "reload"),
            ("ctypes", "CDLL"),
            ("runpy", "run_path"),
            ("__main__", "Evil"),
        ] {
            let mut payload = b"\x80\x04c".to_vec();
            payload.extend_from_slice(module.as_bytes());
            payload.push(b'\n');
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(b"\n.");
            let expected_pattern = format!("{module}\n{name}");
            let mut scan = ScanState::new(
                format!("post-budget-{expected_pattern}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert!(
                scan.findings.iter().any(|finding| {
                    finding.rule_code == Some("POST_BUDGET_GLOBAL")
                        && detail_string(&finding.details, "pattern").as_deref()
                            == Some(expected_pattern.as_str())
                }),
                "missing post-budget pattern {expected_pattern:?}"
            );
        }
    }

    #[test]
    fn post_budget_tail_detects_modern_stack_global_forms() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let forms = [
            (
                "short-binunicode",
                b"\x8c\nsubprocess\x94\x8c\x03run\x94\x93)R.".to_vec(),
            ),
            (
                "protocol0-string",
                b"S'sub\\x70rocess'\nS'run'\n\x93)R.".to_vec(),
            ),
            (
                "protocol0-unicode",
                b"Vsub\\u0070rocess\nVrun\n\x93)R.".to_vec(),
            ),
            ("binunicode", {
                let mut payload = Vec::new();
                payload.push(b'X');
                payload.extend_from_slice(&10u32.to_le_bytes());
                payload.extend_from_slice(b"subprocess\x94X");
                payload.extend_from_slice(&3u32.to_le_bytes());
                payload.extend_from_slice(b"run\x94\x93)R.");
                payload
            }),
            ("binunicode8", {
                let mut payload = Vec::new();
                payload.push(0x8d);
                payload.extend_from_slice(&10u64.to_le_bytes());
                payload.extend_from_slice(b"subprocess\x94\x8d");
                payload.extend_from_slice(&3u64.to_le_bytes());
                payload.extend_from_slice(b"run\x94\x93)R.");
                payload
            }),
        ];

        for (label, tail) in forms {
            let mut payload = b"\x80\x04\x88\x88".to_vec();
            payload.extend_from_slice(&tail);
            let mut scan = ScanState::new(
                format!("post-budget-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            let finding = scan
                .findings
                .iter()
                .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
                .unwrap_or_else(|| panic!("missing post-budget STACK_GLOBAL finding for {label}"));
            assert_eq!(finding.severity, "critical");
            assert_eq!(
                detail_string(&finding.details, "pattern").as_deref(),
                Some("subprocess\nrun")
            );
        }
    }

    #[test]
    fn post_budget_tail_resynchronizes_after_malformed_bytes_before_modern_globals() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04\x88\x88\xff\x8c\nsubprocess\x94\x8c\x03run\x94\x93)R.";
        let mut scan = ScanState::new(
            "post-budget-malformed-modern-global.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
            .expect("post-budget modern global finding after malformed byte");
        assert_eq!(finding.severity, "critical");
        assert_eq!(
            detail_string(&finding.details, "pattern").as_deref(),
            Some("subprocess\nrun")
        );
    }

    #[test]
    fn post_budget_tail_does_not_resolve_tuple_wrapped_globals_after_malformed_bytes() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04\x88\x88\xff\x8c\nsubprocess\x94\x8c\x03run\x94\x86\x93)R.";
        let mut scan = ScanState::new(
            "post-budget-malformed-tuple-wrapped-global.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(
            !scan.findings.iter().any(|finding| {
                finding.rule_code == Some("POST_BUDGET_GLOBAL")
                    && detail_string(&finding.details, "pattern").as_deref()
                        == Some("subprocess\nrun")
            }),
            "tuple-wrapped STACK_GLOBAL operands after malformed bytes should stay unresolved"
        );
    }

    #[test]
    fn post_budget_tail_does_not_resynchronize_inside_truncated_literals() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: 32,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let inert_inner_bytes = b"\x8c\nsubprocess\x94\x8c\x03run\x94\x93)R.";
        let mut payload = b"\x80\x04\x88\x88X".to_vec();
        payload.extend_from_slice(&(64_u32).to_le_bytes());
        payload.extend_from_slice(inert_inner_bytes);
        payload.resize(4 + 1 + 4 + 64, b'A');
        payload.push(b'.');
        let mut scan = ScanState::new(
            "post-budget-truncated-literal.pkl".to_string(),
            &payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(
            !scan.findings.iter().any(|finding| {
                finding.rule_code == Some("POST_BUDGET_GLOBAL")
                    && detail_string(&finding.details, "pattern").as_deref()
                        == Some("subprocess\nrun")
            }),
            "truncated literal bodies must not be reparsed as executable opcodes"
        );
    }

    fn short_binunicode(value: &[u8]) -> Vec<u8> {
        assert!(value.len() <= u8::MAX as usize);
        let mut payload = vec![0x8c, value.len() as u8];
        payload.extend_from_slice(value);
        payload
    }

    fn pre_memoized_post_budget_stack_global_payload(tail: &[u8]) -> Vec<u8> {
        let mut payload = b"\x80\x04".to_vec();
        payload.extend_from_slice(&short_binunicode(b"subprocess"));
        payload.push(0x94);
        payload.extend_from_slice(&short_binunicode(b"run"));
        payload.push(0x94);
        payload.extend_from_slice(b"\x880\x880\x880\x880");
        payload.extend_from_slice(tail);
        payload
    }

    fn post_budget_prememo_options() -> ScanOptions {
        ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 7,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        }
    }

    #[test]
    fn post_budget_tail_resolves_memoized_stack_global_gets() {
        let options = post_budget_prememo_options();
        let variants = [
            ("binget", b"h\x00h\x01\x93)R.".as_slice()),
            (
                "long-binget",
                b"j\x00\x00\x00\x00j\x01\x00\x00\x00\x93)R.".as_slice(),
            ),
            ("get", b"g0\ng1\n\x93)R.".as_slice()),
        ];

        for (label, tail) in variants {
            let payload = pre_memoized_post_budget_stack_global_payload(tail);
            let mut scan = ScanState::new(
                format!("post-budget-prememo-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            let finding = scan
                .findings
                .iter()
                .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
                .unwrap_or_else(|| {
                    panic!("missing memoized post-budget global finding for {label}")
                });
            assert_eq!(finding.severity, "critical");
            assert_eq!(
                detail_string(&finding.details, "pattern").as_deref(),
                Some("subprocess\nrun")
            );
        }
    }

    #[test]
    fn post_budget_tail_detects_mixed_memo_and_inline_stack_global_operands() {
        let options = post_budget_prememo_options();
        let variants = [
            ("memo-module-inline-name", {
                let mut tail = b"h\x00".to_vec();
                tail.extend_from_slice(&short_binunicode(b"run"));
                tail.extend_from_slice(b"\x93)R.");
                tail
            }),
            ("inline-module-memo-name", {
                let mut tail = short_binunicode(b"subprocess");
                tail.extend_from_slice(b"h\x01\x93)R.");
                tail
            }),
            (
                "memo-module-inline-short-binstring-name",
                b"h\x00U\x03run\x93)R.".to_vec(),
            ),
            (
                "memo-module-inline-protocol0-string-name",
                b"h\x00S'run'\n\x93)R.".to_vec(),
            ),
            (
                "inline-protocol0-module-memo-name",
                b"S'subprocess'\nh\x01\x93)R.".to_vec(),
            ),
        ];

        for (label, tail) in variants {
            let payload = pre_memoized_post_budget_stack_global_payload(&tail);
            let mut scan = ScanState::new(
                format!("post-budget-prememo-mixed-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            let finding = scan
                .findings
                .iter()
                .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
                .unwrap_or_else(|| panic!("missing mixed post-budget global finding for {label}"));
            assert_eq!(finding.severity, "critical");
            assert_eq!(
                detail_string(&finding.details, "pattern").as_deref(),
                Some("subprocess\nrun")
            );
        }
    }

    #[test]
    fn post_budget_tail_detects_interleaved_memoized_stack_global_operands() {
        let options = post_budget_prememo_options();
        let variants = [
            ("dup-pop", b"h\x00h\x0120\x93)R.".as_slice()),
            ("mark-pop", b"h\x00(0h\x01\x93)R.".as_slice()),
            ("none-pop", b"h\x00N0h\x01\x93)R.".as_slice()),
        ];

        for (label, tail) in variants {
            let payload = pre_memoized_post_budget_stack_global_payload(tail);
            let mut scan = ScanState::new(
                format!("post-budget-interleaved-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert!(
                scan.findings.iter().any(|finding| {
                    finding.rule_code == Some("POST_BUDGET_GLOBAL")
                        && finding.severity == "critical"
                        && detail_string(&finding.details, "pattern").as_deref()
                            == Some("subprocess\nrun")
                }),
                "missing interleaved post-budget global finding for {label}"
            );
        }
    }

    #[test]
    fn post_budget_tail_treats_tuple_wrapped_stack_global_operands_as_malformed() {
        let options = post_budget_prememo_options();
        let payload = pre_memoized_post_budget_stack_global_payload(b"h\x00h\x01\x86\x93)R.");
        let mut scan = ScanState::new(
            "post-budget-tuple-wrapped-stack-global.pkl".to_string(),
            &payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(
            !scan.findings.iter().any(|finding| {
                finding.rule_code == Some("POST_BUDGET_GLOBAL")
                    && detail_string(&finding.details, "pattern").as_deref()
                        == Some("subprocess\nrun")
            }),
            "tuple-wrapped STACK_GLOBAL operands are malformed and should not be reported as a resolved executable global"
        );
    }

    fn tail_only_post_budget_payload(tail: &[u8]) -> Vec<u8> {
        let mut payload = b"\x80\x04\x88".to_vec();
        payload.extend_from_slice(tail);
        payload
    }

    fn assert_post_budget_subprocess_run_finding(payload: &[u8], label: &str) {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let mut scan = ScanState::new(
            format!("post-budget-tail-local-{label}.pkl"),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        assert!(
            scan.findings.iter().any(|finding| {
                finding.rule_code == Some("POST_BUDGET_GLOBAL")
                    && finding.severity == "critical"
                    && detail_string(&finding.details, "pattern").as_deref()
                        == Some("subprocess\nrun")
            }),
            "missing tail-local memo post-budget global finding for {label}"
        );
    }

    #[test]
    fn post_budget_tail_tracks_tail_local_put_and_get_memos() {
        let variants = [
            ("binput-binget", {
                let mut tail = short_binunicode(b"subprocess");
                tail.extend_from_slice(b"q\x05");
                tail.extend_from_slice(&short_binunicode(b"run"));
                tail.extend_from_slice(b"q\x06h\x05h\x06\x93)R.");
                tail
            }),
            ("put-get", {
                let mut tail = short_binunicode(b"subprocess");
                tail.extend_from_slice(b"p5\n");
                tail.extend_from_slice(&short_binunicode(b"run"));
                tail.extend_from_slice(b"p6\ng5\ng6\n\x93)R.");
                tail
            }),
            ("long-binput-long-binget", {
                let mut tail = short_binunicode(b"subprocess");
                tail.push(b'r');
                tail.extend_from_slice(&5u32.to_le_bytes());
                tail.extend_from_slice(&short_binunicode(b"run"));
                tail.push(b'r');
                tail.extend_from_slice(&6u32.to_le_bytes());
                tail.push(b'j');
                tail.extend_from_slice(&5u32.to_le_bytes());
                tail.push(b'j');
                tail.extend_from_slice(&6u32.to_le_bytes());
                tail.extend_from_slice(b"\x93)R.");
                tail
            }),
            ("memoize-binget", {
                let mut tail = short_binunicode(b"subprocess");
                tail.push(0x94);
                tail.extend_from_slice(&short_binunicode(b"run"));
                tail.push(0x94);
                tail.extend_from_slice(b"h\x00h\x01\x93)R.");
                tail
            }),
        ];

        for (label, tail) in variants {
            let payload = tail_only_post_budget_payload(&tail);
            assert_post_budget_subprocess_run_finding(&payload, label);
        }
    }

    #[test]
    fn post_budget_tail_promotes_memoized_stack_global_reduce_class_opcodes() {
        let options = post_budget_prememo_options();
        let variants = [
            ("reduce", b"h\x00h\x01\x93)R.".as_slice()),
            ("obj", b"h\x00h\x01\x93o.".as_slice()),
            ("newobj", b"h\x00h\x01\x93\x81.".as_slice()),
            ("newobj-ex", b"h\x00h\x01\x93\x92.".as_slice()),
        ];

        for (label, tail) in variants {
            let payload = pre_memoized_post_budget_stack_global_payload(tail);
            let mut scan = ScanState::new(
                format!("post-budget-prememo-{label}.pkl"),
                &payload,
                &options,
                Some(payload.len()),
                0,
                0,
                None,
            );

            scan.run();

            assert!(
                scan.findings.iter().any(|finding| {
                    finding.rule_code == Some("POST_BUDGET_GLOBAL")
                        && finding.severity == "critical"
                        && detail_string(&finding.details, "pattern").as_deref()
                            == Some("subprocess\nrun")
                }),
                "missing critical memoized post-budget finding for {label}"
            );
        }
    }

    #[test]
    fn post_budget_tail_detects_inst_and_extension_refs() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 2,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };

        let inst_payload = b"\x80\x04\x88\x88(isubprocess\nrun\n.".to_vec();
        let mut inst_scan = ScanState::new(
            "post-budget-inst.pkl".to_string(),
            &inst_payload,
            &options,
            Some(inst_payload.len()),
            0,
            0,
            None,
        );
        inst_scan.run();
        assert!(inst_scan.findings.iter().any(|finding| {
            finding.rule_code == Some("POST_BUDGET_GLOBAL")
                && detail_string(&finding.details, "pattern").as_deref() == Some("subprocess\nrun")
        }));

        let ext_payload = b"\x80\x04\x88\x88\x82\x07R.".to_vec();
        let mut ext_scan = ScanState::new(
            "post-budget-ext.pkl".to_string(),
            &ext_payload,
            &options,
            Some(ext_payload.len()),
            0,
            0,
            None,
        );
        ext_scan.run();
        let finding = ext_scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
            .expect("post-budget extension finding");
        assert_eq!(finding.severity, "critical");
        assert_eq!(
            detail_string(&finding.details, "pattern").as_deref(),
            Some("copyreg.extension\ncode_7")
        );
    }

    #[test]
    fn post_budget_tail_promotes_reduce_proximate_globals_to_critical() {
        let options = ScanOptions {
            timeout_s: DEFAULT_TIMEOUT_S,
            max_opcodes: 1,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04cos\npopen\n)R.";
        let mut scan = ScanState::new(
            "post-budget-critical.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            None,
        );

        scan.run();

        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.rule_code == Some("POST_BUDGET_GLOBAL"))
            .expect("post-budget global finding");
        assert_eq!(finding.severity, "critical");
        assert_eq!(
            detail_string(&finding.details, "pattern").as_deref(),
            Some("os\npopen")
        );
    }

    #[test]
    fn timeout_limit_still_scans_post_budget_tail() {
        let options = ScanOptions {
            timeout_s: 0.001,
            max_opcodes: DEFAULT_MAX_OPCODES,
            post_budget_scan_bytes: DEFAULT_POST_BUDGET_SCAN_BYTES,
            max_string_literal_scan_chars: DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            max_nested_pickle_bytes: DEFAULT_MAX_NESTED_PICKLE_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
        };
        let payload = b"\x80\x04csubprocess\nrun\n)R.";
        let mut scan = ScanState::new(
            "post-budget-timeout.pkl".to_string(),
            payload,
            &options,
            Some(payload.len()),
            0,
            0,
            Some(Instant::now() - Duration::from_secs(1)),
        );

        scan.run();

        assert!(scan
            .notices
            .iter()
            .any(|notice| notice.code == Some("timeout")));
        assert!(scan.findings.iter().any(|finding| {
            finding.rule_code == Some("POST_BUDGET_GLOBAL") && finding.severity == "critical"
        }));
    }
}

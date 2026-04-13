use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

mod opcode;
mod policy;
mod report;

use opcode::{parse_opcode, ArgValue, ParseError, ParsedOpcode};
use policy::global_severity;
use report::{
    detail_string, detail_usize, notice_to_detail_value, scan_error_to_detail_value, DetailValue,
    Finding, Notice, ScanError,
};

const DEFAULT_TIMEOUT_S: f64 = 3600.0;
const DEFAULT_MAX_OPCODES: usize = 1_000_000;
const DEFAULT_POST_BUDGET_SCAN_BYTES: usize = 100 * 1024 * 1024;
const DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_NESTED_PICKLE_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_NESTED_DEPTH: usize = 1;
const MAX_TRACKED_TUPLE_ITEMS: usize = 16;

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
const BASE64_LITERAL_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX_LITERAL_CHARS: &[u8] = b"0123456789abcdefABCDEF";
const ENCODED_LITERAL_PROBE_CHARS: usize = 64;
const MAX_NESTED_PAYLOAD_PROBES: usize = 64;

#[derive(Clone)]
struct GlobalRef {
    module: String,
    name: String,
    position: usize,
    malformed: bool,
}

impl GlobalRef {
    fn symbol(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

#[derive(Clone)]
enum StackValue {
    Mark,
    Text(String),
    Bytes(Vec<u8>),
    Global(GlobalRef),
    Constructed(GlobalRef),
    Tuple(Vec<StackValue>),
    Primitive {
        type_name: &'static str,
        repr: String,
    },
    Other,
}

enum LimitError {
    OpcodeBudgetExceeded(Vec<u8>),
    Timeout,
}

struct ScanOptions {
    timeout_s: f64,
    max_opcodes: usize,
    post_budget_scan_bytes: usize,
    max_string_literal_scan_chars: usize,
    max_nested_pickle_bytes: usize,
    max_nested_depth: usize,
}

impl ScanOptions {
    fn from_py(options: &Bound<'_, PyDict>) -> PyResult<Self> {
        Ok(Self {
            timeout_s: option_f64(options, "timeout_s", DEFAULT_TIMEOUT_S)?,
            max_opcodes: option_usize(options, "max_opcodes", DEFAULT_MAX_OPCODES)?,
            post_budget_scan_bytes: option_usize(
                options,
                "post_budget_scan_bytes",
                DEFAULT_POST_BUDGET_SCAN_BYTES,
            )?,
            max_string_literal_scan_chars: option_usize(
                options,
                "max_string_literal_scan_chars",
                DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS,
            )?,
            max_nested_pickle_bytes: option_usize(
                options,
                "max_nested_pickle_bytes",
                DEFAULT_MAX_NESTED_PICKLE_BYTES,
            )?,
            max_nested_depth: option_usize(options, "max_nested_depth", DEFAULT_MAX_NESTED_DEPTH)?,
        })
    }
}

fn option_usize(options: &Bound<'_, PyDict>, key: &str, default: usize) -> PyResult<usize> {
    match options.get_item(key)? {
        Some(value) => value.extract::<usize>(),
        None => Ok(default),
    }
}

fn option_f64(options: &Bound<'_, PyDict>, key: &str, default: f64) -> PyResult<f64> {
    let value = match options.get_item(key)? {
        Some(value) => value.extract::<f64>(),
        None => Ok(default),
    }?;
    if value.is_finite() && value > 0.0 {
        Ok(value)
    } else {
        Err(PyValueError::new_err(format!(
            "{key} must be greater than 0 and finite, got {value:?}"
        )))
    }
}

struct ScanState<'a> {
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
    opcode_count: usize,
    global_count: usize,
    bytes_scanned: usize,
    first_pickle_end_pos: Option<usize>,
    status: &'static str,
    verdict: &'static str,
    seen_finding_keys: HashSet<(String, Option<String>, Option<&'static str>)>,
    seen_notice_keys: HashSet<(Option<&'static str>, Option<String>, String)>,
    seen_global_reference_keys: HashSet<(String, String, usize, &'static str)>,
}

impl<'a> ScanState<'a> {
    fn new(
        source: String,
        payload: &'a [u8],
        options: &'a ScanOptions,
        bytes_total: Option<usize>,
        position_offset: usize,
        nested_depth: usize,
        deadline: Option<Instant>,
    ) -> Self {
        let deadline = deadline.unwrap_or_else(|| {
            Instant::now()
                .checked_add(Duration::from_secs_f64(options.timeout_s))
                .unwrap_or_else(Instant::now)
        });
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
            opcode_count: 0,
            global_count: 0,
            bytes_scanned: 0,
            first_pickle_end_pos: None,
            status: "complete",
            verdict: "clean",
            seen_finding_keys: HashSet::new(),
            seen_notice_keys: HashSet::new(),
            seen_global_reference_keys: HashSet::new(),
        }
    }

    fn run(&mut self) {
        let scan_limit = self.scan_limit();
        if self.bytes_total == Some(0) || scan_limit == 0 {
            if self.bytes_total.is_some() && self.bytes_total != Some(0) {
                self.record_short_read();
            } else {
                self.record_empty_input_error();
            }
            self.finalize_common_metadata();
            self.finalize_verdict();
            return;
        }

        let mut index = 0usize;
        while index < scan_limit {
            let stream_start = index;
            let mut parsed_opcode = false;
            let mut saw_stop = false;

            loop {
                if index >= scan_limit {
                    break;
                }
                let parsed = match parse_opcode(self.payload, index, scan_limit) {
                    Ok(opcode) => opcode,
                    Err(error) => {
                        self.handle_parse_error(error, index);
                        self.finalize_common_metadata();
                        self.coalesce_redundant_global_findings();
                        self.finalize_verdict();
                        return;
                    }
                };

                if let Err(limit_error) = self.check_limits(&parsed) {
                    self.status = "inconclusive";
                    match limit_error {
                        LimitError::OpcodeBudgetExceeded(tail_prefix) => {
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
                            self.scan_post_budget_tail(parsed.pos, parsed.next, tail_prefix);
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
                        }
                    }
                    self.finalize_common_metadata();
                    self.coalesce_redundant_global_findings();
                    self.finalize_verdict();
                    return;
                }

                parsed_opcode = true;
                let position = self.position_offset + parsed.pos;
                self.bytes_scanned = self
                    .bytes_scanned
                    .max(parsed.next)
                    .max(parsed.pos.saturating_add(1));
                self.opcode_count += 1;
                index = parsed.next;
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
                self.finalize_common_metadata();
                self.coalesce_redundant_global_findings();
                self.finalize_verdict();
                return;
            }

            if index <= stream_start {
                break;
            }
        }

        if self.status == "complete"
            && self.bytes_total.is_some()
            && self.payload.len() < self.bytes_total.unwrap()
        {
            self.record_short_read();
        }

        self.finalize_common_metadata();
        self.coalesce_redundant_global_findings();
        self.finalize_verdict();
    }

    fn scan_limit(&self) -> usize {
        match self.bytes_total {
            Some(total) => total.min(self.payload.len()),
            None => self.payload.len(),
        }
    }

    fn check_limits(&self, opcode: &ParsedOpcode) -> Result<(), LimitError> {
        if self.opcode_count >= self.options.max_opcodes {
            return Err(LimitError::OpcodeBudgetExceeded(post_budget_opcode_prefix(
                opcode,
                &self.stack,
            )));
        }
        if Instant::now() > self.deadline {
            return Err(LimitError::Timeout);
        }
        Ok(())
    }

    fn handle_parse_error(&mut self, error: ParseError, index: usize) {
        let report_index = error.report_index.unwrap_or(index);
        if self.opcode_count == 0 && self.findings.is_empty() {
            self.status = "error";
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
            self.status = "inconclusive";
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
        self.status = "error";
        self.verdict = "unknown";
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
        self.status = "error";
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

    fn finalize_common_metadata(&mut self) {
        if !self.protocols.is_empty() {
            // Kept in a side vector and serialized in to_py_report().
        }
    }

    fn handle_opcode(&mut self, opcode: &ParsedOpcode, position: usize) {
        match opcode.name {
            "PROTO" => {
                if let ArgValue::Int(value) = opcode.arg {
                    self.protocols.push(value);
                }
            }
            name if STACK_GLOBAL_STRING_OPCODES.contains(&name) => {
                let value = opcode.arg.coerce_text();
                self.stack.push(StackValue::Text(value.clone()));
                self.scan_string_literal(&value, opcode.name, position);
                self.scan_encoded_nested_pickle_literal(&value, position);
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
                self.stack.push(stack_value_from_integer_arg(&opcode.arg));
            }
            "FLOAT" | "BINFLOAT" => self.stack.push(StackValue::Other),
            "BINBYTES" | "BINBYTES8" | "SHORT_BINBYTES" | "BYTEARRAY8" => {
                let bytes = match &opcode.arg {
                    ArgValue::Bytes(value) => value.clone(),
                    _ => Vec::new(),
                };
                self.stack.push(StackValue::Bytes(bytes.clone()));
                self.scan_raw_nested_pickle_bytes(&bytes, position);
            }
            "NEXT_BUFFER" | "READONLY_BUFFER" => {}
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
            "EMPTY_LIST" | "EMPTY_DICT" | "EMPTY_SET" => {
                self.stack.push(StackValue::Primitive {
                    type_name: "tuple",
                    repr: "()".to_string(),
                });
            }
            "TUPLE" => {
                let values = self.pop_to_mark();
                self.stack.push(collapse_tuple_values(values));
            }
            "LIST" | "DICT" | "SET" | "FROZENSET" => {
                let _ = self.pop_to_mark();
                self.stack.push(StackValue::Other);
            }
            "TUPLE1" => self.collapse_top_n(1),
            "TUPLE2" => self.collapse_top_n(2),
            "TUPLE3" => self.collapse_top_n(3),
            "APPEND" | "SETITEM" => {
                self.stack.pop();
                if opcode.name == "SETITEM" {
                    self.stack.pop();
                }
            }
            "APPENDS" | "SETITEMS" | "ADDITEMS" => {
                self.pop_to_mark();
            }
            "PUT" | "BINPUT" | "LONG_BINPUT" => {
                if let Some(value) = self.stack.last().cloned() {
                    if let Some(index) = opcode.arg.as_i64() {
                        self.memo.insert(index, value);
                    }
                }
            }
            "MEMOIZE" => {
                if let Some(value) = self.stack.last().cloned() {
                    self.memo.insert(self.memo.len() as i64, value);
                }
            }
            "GET" | "BINGET" | "LONG_BINGET" => {
                if let Some(index) = opcode.arg.as_i64() {
                    if let Some(value) = self.memo.get(&index).cloned() {
                        self.stack.push(value);
                    } else {
                        self.stack.push(StackValue::Global(GlobalRef {
                            module: "__unknown__".to_string(),
                            name: format!("memo_{}", index),
                            position,
                            malformed: true,
                        }));
                    }
                }
            }
            "GLOBAL" => {
                let (module, name) = opcode.arg.global_parts();
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
                if let Some(callable_ref) = self.consume_callable_opcode(opcode, position) {
                    if let Some(severity) =
                        global_severity(&callable_ref.module, &callable_ref.name)
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

    fn collapse_top_n(&mut self, count: usize) {
        if self.stack.len() < count {
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
        self.stack.push(collapse_tuple_values(values));
    }

    fn consume_callable_opcode(
        &mut self,
        opcode: &ParsedOpcode,
        position: usize,
    ) -> Option<GlobalRef> {
        let callable_value = match opcode.name {
            "REDUCE" | "NEWOBJ" => self.consume_top_operands(2),
            "NEWOBJ_EX" => self.consume_top_operands(3),
            "OBJ" => {
                let values = self.pop_to_mark();
                let callable_value = values.into_iter().next();
                self.push_constructed_result(callable_value.as_ref());
                callable_value
            }
            "INST" => {
                let _ = self.pop_to_mark();
                let (module, name) = opcode.arg.global_parts();
                let reference = GlobalRef {
                    module,
                    name,
                    position,
                    malformed: false,
                };
                self.record_global_ref(&reference, opcode.name);
                self.stack.push(StackValue::Constructed(reference.clone()));
                Some(StackValue::Global(reference))
            }
            "BUILD" => self.consume_top_operands(2),
            _ => None,
        };

        match callable_value {
            Some(StackValue::Global(reference) | StackValue::Constructed(reference))
                if !reference.malformed =>
            {
                Some(reference)
            }
            _ => None,
        }
    }

    fn consume_top_operands(&mut self, operand_count: usize) -> Option<StackValue> {
        if self.stack.len() < operand_count {
            self.stack.clear();
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
        let callable_value = values.into_iter().next();
        self.push_constructed_result(callable_value.as_ref());
        callable_value
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
        let module = resolve_global_operand(module_value.as_ref());
        let name = resolve_global_operand(name_value.as_ref());

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
                    message: "Malformed STACK_GLOBAL operands prevent reliable callable resolution".to_string(),
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

    fn scan_string_literal(&mut self, value: &str, op_name: &'static str, position: usize) {
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
            self.scan_string_literal_candidate(value, op_name, position);
            return;
        }

        let value_len = value.chars().count();
        if value_len <= max_chars {
            self.scan_string_literal_candidate(value, op_name, position);
            return;
        }

        self.record_literal_scan_truncated("string", value_len, op_name, position);
        let prefix_chars = max_chars / 2;
        let suffix_chars = max_chars - prefix_chars;
        for window in [
            take_chars(value, prefix_chars),
            take_last_chars(value, suffix_chars),
        ] {
            self.scan_string_literal_candidate(&window, op_name, position);
        }
    }

    fn scan_string_literal_candidate(
        &mut self,
        value: &str,
        op_name: &'static str,
        position: usize,
    ) {
        for matched_pattern in suspicious_string_matches(value) {
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
        if value.len() > self.options.max_nested_pickle_bytes {
            for offset in nested_pickle_probe_offsets(value) {
                let end = value
                    .len()
                    .min(offset.saturating_add(self.options.max_nested_pickle_bytes));
                let candidate = &value[offset..end];
                if looks_like_pickle_payload(candidate, self.options.max_nested_pickle_bytes) {
                    self.add_nested_payload_finding("raw", value.len(), position + offset, false);
                    self.surface_nested_pickle_findings(candidate, "raw", position + offset);
                    return;
                }
            }
            if has_pickle_prefix(value) {
                self.add_nested_payload_finding("raw", value.len(), position, true);
                self.record_raw_nested_payload_truncated(value.len(), position);
            }
            return;
        }

        if !looks_like_pickle_payload(value, self.options.max_nested_pickle_bytes) {
            return;
        }

        self.add_nested_payload_finding("raw", value.len(), position, false);
        self.surface_nested_pickle_findings(value, "raw", position);
    }

    fn add_nested_payload_finding(
        &mut self,
        encoding: &'static str,
        payload_size: usize,
        position: usize,
        analysis_incomplete: bool,
    ) {
        self.add_finding(Finding {
            message: if analysis_incomplete {
                "Nested pickle payload exceeds deep-scan byte limit".to_string()
            } else {
                "Nested pickle payload detected".to_string()
            },
            severity: "critical",
            location: Some(format!("{} (pos {})", self.source, position)),
            rule_code: Some("S213"),
            details: vec![
                ("encoding".to_string(), DetailValue::String(encoding.to_string())),
                ("payload_size".to_string(), DetailValue::UInt(payload_size as u64)),
                (
                    "max_nested_pickle_bytes".to_string(),
                    DetailValue::UInt(self.options.max_nested_pickle_bytes as u64),
                ),
                (
                    "analysis_incomplete".to_string(),
                    DetailValue::Bool(analysis_incomplete),
                ),
            ],
            why: Some(
                "This pickle contains another serialized pickle payload inside a byte field. Nested payloads can hide code execution paths from shallow scanners.",
            ),
        });
    }

    fn scan_encoded_nested_pickle_literal(&mut self, value: &str, position: usize) {
        if value.len() <= self.options.max_string_literal_scan_chars {
            self.scan_encoded_nested_pickle_candidate(value, position);
            return;
        }

        let value_len = value.chars().count();
        if value_len <= self.options.max_string_literal_scan_chars {
            self.scan_encoded_nested_pickle_candidate(value, position);
            return;
        }

        {
            self.record_literal_scan_truncated(
                "string",
                value_len,
                "encoded_nested_pickle",
                position,
            );
        }

        let max_window_chars =
            encoded_nested_window_char_limit(value, self.options.max_nested_pickle_bytes);
        if value.len() <= max_window_chars || value.chars().count() <= max_window_chars {
            self.scan_encoded_nested_pickle_candidate(value, position);
        }

        for candidate in encoded_nested_literal_probe_windows(value, max_window_chars) {
            self.scan_encoded_nested_pickle_candidate(&candidate, position);
        }
    }

    fn scan_encoded_nested_pickle_candidate(&mut self, value: &str, position: usize) {
        let mut decoded_payload_found = false;
        for (encoding, decoded) in
            decode_possible_encoded_pickle(value, self.options.max_nested_pickle_bytes)
        {
            decoded_payload_found = true;
            self.add_encoded_nested_payload_finding(encoding, decoded.len(), position, false);
            self.surface_nested_pickle_findings(&decoded, encoding, position);
        }
        if decoded_payload_found {
            return;
        }

        for (encoding, payload_size) in
            detect_oversized_encoded_pickle_prefixes(value, self.options.max_nested_pickle_bytes)
        {
            self.add_encoded_nested_payload_finding(encoding, payload_size, position, true);
            self.record_encoded_nested_payload_truncated(encoding, payload_size, position);
        }
    }

    fn record_raw_nested_payload_truncated(&mut self, payload_size: usize, position: usize) {
        if self.status == "complete" {
            self.status = "inconclusive";
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

    fn add_encoded_nested_payload_finding(
        &mut self,
        encoding: &'static str,
        payload_size: usize,
        position: usize,
        analysis_incomplete: bool,
    ) {
        let mut details = vec![
            (
                "encoding".to_string(),
                DetailValue::String(encoding.to_string()),
            ),
            (
                "payload_size".to_string(),
                DetailValue::UInt(payload_size as u64),
            ),
        ];
        if analysis_incomplete {
            details.push((
                "max_nested_pickle_bytes".to_string(),
                DetailValue::UInt(self.options.max_nested_pickle_bytes as u64),
            ));
            details.push(("analysis_incomplete".to_string(), DetailValue::Bool(true)));
        }

        self.add_finding(Finding {
            message: if analysis_incomplete {
                "Encoded pickle payload exceeds deep-scan byte limit".to_string()
            } else {
                "Encoded pickle payload detected".to_string()
            },
            severity: "critical",
            location: Some(format!("{} (pos {})", self.source, position)),
            rule_code: Some(if encoding == "base64" { "S601" } else { "S602" }),
            details,
            why: Some(
                "Encoded nested pickle payloads can hide deserialization gadgets inside apparently inert metadata strings.",
            ),
        });
    }

    fn record_encoded_nested_payload_truncated(
        &mut self,
        encoding: &'static str,
        payload_size: usize,
        position: usize,
    ) {
        if self.status == "complete" {
            self.status = "inconclusive";
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
        if reference.malformed {
            return;
        }

        self.global_count += 1;
        let severity = global_severity(&reference.module, &reference.name);
        let is_dangerous = severity.is_some();
        let reference_kind = if is_dangerous {
            "dangerous"
        } else {
            "observed"
        };
        let key = (
            reference.symbol(),
            op_name.to_string(),
            reference.position,
            reference_kind,
        );
        if self.seen_global_reference_keys.insert(key) {
            self.import_references.push(vec![
                (
                    "import_reference".to_string(),
                    DetailValue::String(reference.symbol()),
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
                    "opcode".to_string(),
                    DetailValue::String(op_name.to_string()),
                ),
                (
                    "position".to_string(),
                    DetailValue::UInt(reference.position as u64),
                ),
                ("is_dangerous".to_string(), DetailValue::Bool(is_dangerous)),
            ]);
        }

        if let Some(global_severity) = severity {
            self.add_finding(Finding {
                message: format!("Found dangerous global reference: {}", reference.symbol()),
                severity: global_severity,
                location: Some(format!("{} (pos {})", self.source, reference.position)),
                rule_code: Some("DANGEROUS_GLOBAL"),
                details: vec![
                    ("opcode".to_string(), DetailValue::String(op_name.to_string())),
                    ("module".to_string(), DetailValue::String(reference.module.clone())),
                    ("name".to_string(), DetailValue::String(reference.name.clone())),
                    (
                        "import_reference".to_string(),
                        DetailValue::String(reference.symbol()),
                    ),
                ],
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
                details: vec![
                    ("opcode".to_string(), DetailValue::String(op_name.to_string())),
                    ("module".to_string(), DetailValue::String(reference.module.clone())),
                    ("name".to_string(), DetailValue::String(reference.name.clone())),
                    (
                        "import_reference".to_string(),
                        DetailValue::String(reference.symbol()),
                    ),
                ],
                why: Some(
                    "Pickles that instantiate classes from __main__ depend on arbitrary application code and deserve manual review before loading.",
                ),
            });
        }
    }

    fn record_persistent_id(&mut self, opcode: &ParsedOpcode, position: usize) {
        let persistent_id = if opcode.name == "BINPERSID" {
            self.stack.pop()
        } else {
            Some(StackValue::Text(opcode.arg.coerce_text()))
        };

        let mut details = vec![(
            "opcode".to_string(),
            DetailValue::String(opcode.name.to_string()),
        )];
        if let Some(value) = persistent_id.as_ref() {
            details.push((
                "persistent_id_preview".to_string(),
                DetailValue::String(stack_value_preview(value, 0)),
            ));
            if let Some(storage_key) = pytorch_storage_key(value) {
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
        self.stack.push(StackValue::Other);
    }

    fn add_finding(&mut self, finding: Finding) {
        let key = (
            finding.message.clone(),
            finding.location.clone(),
            finding.rule_code,
        );
        if self.seen_finding_keys.insert(key) {
            self.findings.push(finding);
        }
    }

    fn add_notice(&mut self, notice: Notice) {
        let key = (notice.code, notice.location.clone(), notice.message.clone());
        if self.seen_notice_keys.insert(key) {
            self.notices.push(notice);
        }
    }

    fn record_literal_scan_truncated(
        &mut self,
        literal_type: &'static str,
        literal_length: usize,
        op_name: &'static str,
        position: usize,
    ) {
        if self.status == "complete" {
            self.status = "inconclusive";
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
    ) {
        if self.nested_depth >= self.options.max_nested_depth {
            return;
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

        for nested_finding in nested_scan.findings {
            let nested_details = nested_finding
                .details
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            self.add_finding(Finding {
                message: format!("Nested pickle finding: {}", nested_finding.message),
                severity: nested_finding.severity,
                location: nested_finding.location,
                rule_code: nested_finding.rule_code,
                details: vec![
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
                ],
                why: nested_finding.why,
            });
        }

        if nested_scan.status != "complete" {
            if self.status == "complete" {
                self.status = "inconclusive";
            }
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
                        DetailValue::String(nested_scan.status.to_string()),
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
    }

    fn scan_post_budget_tail(
        &mut self,
        stream_offset: usize,
        read_offset: usize,
        tail_prefix: Vec<u8>,
    ) {
        if self.options.post_budget_scan_bytes == 0 {
            return;
        }
        let read_size = self
            .options
            .post_budget_scan_bytes
            .saturating_sub(tail_prefix.len());
        let tail_start = read_offset.min(self.payload.len());
        let tail_end = tail_start.saturating_add(read_size).min(self.payload.len());
        let mut tail = tail_prefix;
        tail.extend_from_slice(&self.payload[tail_start..tail_end]);
        self.bytes_scanned = self
            .bytes_scanned
            .max(stream_offset.saturating_add(tail.len()));

        for needle in [
            b"nt\nsystem".as_slice(),
            b"os\nsystem".as_slice(),
            b"posix\nsystem".as_slice(),
            b"subprocess\nPopen".as_slice(),
            b"builtins\neval".as_slice(),
            b"__builtin__\neval".as_slice(),
        ] {
            if let Some(offset) = find_bytes(&tail, needle) {
                self.add_finding(Finding {
                    message: "Dangerous global-like byte pattern found beyond opcode budget".to_string(),
                    severity: "warning",
                    location: Some(format!(
                        "{} (pos {})",
                        self.source,
                        self.position_offset + stream_offset + offset
                    )),
                    rule_code: Some("POST_BUDGET_GLOBAL"),
                    details: vec![(
                        "pattern".to_string(),
                        DetailValue::String(String::from_utf8_lossy(needle).to_string()),
                    )],
                    why: Some(
                        "Opcode analysis stopped early, but a byte-level tail scan still found suspicious global references.",
                    ),
                });
            }
        }
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
            let location_position = finding.location.as_deref().and_then(location_position);
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
            self.verdict = "malicious";
        } else if self
            .findings
            .iter()
            .any(|finding| finding.severity == "warning")
        {
            self.verdict = "suspicious";
        } else if self.status == "complete" {
            self.verdict = "clean";
        } else {
            self.verdict = "unknown";
        }
    }

    fn to_py_report(&self, py: Python<'_>, duration_s: f64) -> PyResult<Py<PyDict>> {
        let report = PyDict::new(py);
        report.set_item("source", &self.source)?;
        report.set_item("status", self.status)?;
        report.set_item("verdict", self.verdict)?;

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

        let raw_scan_complete = self.status == "complete"
            && self
                .bytes_total
                .map(|bytes_total| self.bytes_scanned >= bytes_total)
                .unwrap_or(true);
        let coverage = PyDict::new(py);
        coverage.set_item("bytes_scanned", self.bytes_scanned)?;
        coverage.set_item("bytes_total", self.bytes_total)?;
        coverage.set_item("opcode_count", self.opcode_count)?;
        coverage.set_item("raw_scan_complete", raw_scan_complete)?;
        coverage.set_item("opcode_scan_complete", self.status == "complete")?;
        report.set_item("coverage", coverage)?;

        let metadata = PyDict::new(py);
        metadata.set_item("opcode_count", self.opcode_count)?;
        metadata.set_item("globals_count", self.global_count)?;
        let import_references = PyList::empty(py);
        for reference in &self.import_references {
            import_references.append(DetailValue::Dict(reference.clone()).to_py_object(py)?)?;
        }
        metadata.set_item("import_references", import_references)?;
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

fn resolve_global_operand(value: Option<&StackValue>) -> Option<String> {
    match value {
        Some(StackValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

fn operand_preview(value: Option<&StackValue>) -> String {
    match value {
        Some(StackValue::Global(reference)) => format!("_GlobalRef({})", reference.symbol()),
        Some(StackValue::Constructed(reference)) => format!("constructed:{}", reference.symbol()),
        Some(StackValue::Bytes(bytes)) => format!("bytes(len={})", bytes.len()),
        Some(StackValue::Mark) => "MARK".to_string(),
        Some(StackValue::Text(value)) => format!("str:{:?}", value),
        Some(StackValue::Tuple(values)) => format!("tuple(len={})", values.len()),
        Some(StackValue::Primitive { type_name, repr }) => format!("{type_name}:{repr}"),
        Some(StackValue::Other) => "object".to_string(),
        None => "NoneType:None".to_string(),
    }
}

fn collapse_tuple_values(values: Vec<StackValue>) -> StackValue {
    if values.len() > MAX_TRACKED_TUPLE_ITEMS
        || values
            .iter()
            .any(|value| matches!(value, StackValue::Tuple(_)))
    {
        StackValue::Other
    } else {
        StackValue::Tuple(values)
    }
}

fn stack_value_preview(value: &StackValue, depth: usize) -> String {
    if depth >= 3 {
        return "...".to_string();
    }

    match value {
        StackValue::Mark => "MARK".to_string(),
        StackValue::Text(value) => format!("str:{:?}", value),
        StackValue::Bytes(bytes) => format!("bytes(len={})", bytes.len()),
        StackValue::Global(reference) => format!("global:{}", reference.symbol()),
        StackValue::Constructed(reference) => format!("constructed:{}", reference.symbol()),
        StackValue::Tuple(values) => {
            let mut parts: Vec<String> = values
                .iter()
                .take(6)
                .map(|item| stack_value_preview(item, depth + 1))
                .collect();
            if values.len() > 6 {
                parts.push("...".to_string());
            }
            format!("tuple({})", parts.join(", "))
        }
        StackValue::Primitive { type_name, repr } => format!("{type_name}:{repr}"),
        StackValue::Other => "object".to_string(),
    }
}

fn stack_value_text(value: &StackValue) -> Option<&str> {
    match value {
        StackValue::Text(text) => Some(text),
        StackValue::Primitive { repr, .. } => Some(repr),
        _ => None,
    }
}

fn stack_value_string(value: &StackValue) -> Option<String> {
    match value {
        StackValue::Text(text) => Some(text.clone()),
        StackValue::Primitive { repr, .. } => Some(repr.clone()),
        StackValue::Bytes(bytes) => std::str::from_utf8(bytes).ok().map(str::to_string),
        _ => None,
    }
}

fn pytorch_storage_key(value: &StackValue) -> Option<String> {
    let StackValue::Tuple(items) = value else {
        return None;
    };
    if items.len() < 4 || stack_value_text(&items[0]) != Some("storage") {
        return None;
    }
    if !is_pytorch_storage_descriptor(&items[1]) {
        return None;
    }
    stack_value_string(&items[2])
}

fn is_pytorch_storage_descriptor(value: &StackValue) -> bool {
    match value {
        StackValue::Global(reference) => {
            reference.module == "torch" && reference.name.ends_with("Storage")
        }
        StackValue::Text(text) => text.starts_with("torch.") && text.ends_with("Storage"),
        _ => false,
    }
}

fn stack_value_from_integer_arg(arg: &ArgValue) -> StackValue {
    match arg {
        ArgValue::Int(value) => StackValue::Primitive {
            type_name: "int",
            repr: value.to_string(),
        },
        ArgValue::UInt(value) => StackValue::Primitive {
            type_name: "int",
            repr: value.to_string(),
        },
        _ => StackValue::Other,
    }
}

fn post_budget_opcode_prefix(opcode: &ParsedOpcode, stack: &[StackValue]) -> Vec<u8> {
    if opcode.name == "STACK_GLOBAL" && stack.len() >= 2 {
        if let (StackValue::Text(module), StackValue::Text(name)) =
            (&stack[stack.len() - 2], &stack[stack.len() - 1])
        {
            let mut prefix = module.as_bytes().to_vec();
            prefix.push(b'\n');
            prefix.extend_from_slice(name.as_bytes());
            return prefix;
        }
    }

    if !matches!(opcode.name, "GLOBAL" | "INST") {
        return Vec::new();
    }

    let (module, name) = opcode.arg.global_parts();
    if module.is_empty() || name.is_empty() {
        return Vec::new();
    }
    let mut prefix = Vec::new();
    prefix.push(if opcode.name == "GLOBAL" { b'c' } else { b'i' });
    prefix.extend_from_slice(module.as_bytes());
    prefix.push(b'\n');
    prefix.extend_from_slice(name.as_bytes());
    prefix.push(b'\n');
    prefix
}

fn suspicious_string_matches(value: &str) -> Vec<String> {
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
    if contains_import_statement(&lower) {
        matches.push("import statement".to_string());
    }
    if lower.contains("importlib") {
        matches.push("importlib".to_string());
    }
    if contains_call_like(&lower, "__import__") {
        matches.push("__import__(".to_string());
    }
    if contains_hex_escape(value) {
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
    lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| window[0] == "import" && !window[1].is_empty())
}

fn contains_hex_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).any(|window| {
        window[0] == b'\\' && window[1] == b'x' && is_hex_byte(window[2]) && is_hex_byte(window[3])
    })
}

fn decode_possible_encoded_pickle(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<(&'static str, Vec<u8>)> {
    let stripped = value.trim();
    if stripped.len() < 16 {
        return Vec::new();
    }

    let mut decoded_values = Vec::new();
    let max_base64_nested_pickle_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_hex_nested_pickle_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_nested_pickle_chars = max_nested_pickle_bytes * 4;

    if base64_prefix_has_pickle_prefix(stripped) && is_base64_candidate(stripped) {
        let bounded = take_bytes_str(stripped, max_base64_nested_pickle_chars);
        let padded = pad_base64(&bounded);
        if let Some(decoded) = decode_base64(&padded) {
            if looks_like_pickle_payload(&decoded, max_nested_pickle_bytes) {
                decoded_values.push(("base64", decoded));
            }
        }
    }

    if hex_prefix_has_pickle_prefix(stripped) {
        let hex_candidate =
            take_bytes_str(stripped, max_escaped_hex_nested_pickle_chars).replace("\\x", "");
        if hex_candidate.len() >= 16
            && hex_candidate.len() % 2 == 0
            && is_hex_candidate(&hex_candidate)
            && !is_repeated_single_char(&hex_candidate)
        {
            let bounded_hex_candidate = take_bytes_str(&hex_candidate, max_hex_nested_pickle_chars);
            if let Some(decoded) = decode_hex(&bounded_hex_candidate) {
                if looks_like_pickle_payload(&decoded, max_nested_pickle_bytes) {
                    decoded_values.push(("hex", decoded));
                }
            }
        }
    }

    decoded_values
}

fn detect_oversized_encoded_pickle_prefixes(
    value: &str,
    max_nested_pickle_bytes: usize,
) -> Vec<(&'static str, usize)> {
    let stripped = value.trim();
    if stripped.len() < 16 {
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
        let max_hex_probe_chars = (probe_decoded_bytes * 4).max(16);
        let mut hex_candidate = take_bytes_str(stripped, max_hex_probe_chars).replace("\\x", "");
        if hex_candidate.len() % 2 == 1 {
            hex_candidate.pop();
        }
        if hex_candidate.len() >= 16
            && is_hex_candidate(&hex_candidate)
            && !is_repeated_single_char(&hex_candidate)
        {
            if let Some(decoded) = decode_hex(&hex_candidate) {
                if decoded.len() > max_nested_pickle_bytes && has_pickle_prefix(&decoded) {
                    detected.push(("hex", estimate_hex_decoded_size(stripped)));
                }
            }
        }
    }

    detected
}

fn looks_like_pickle_payload(value: &[u8], max_bytes: usize) -> bool {
    if value.len() < 2 || value.len() > max_bytes || !has_pickle_prefix(value) {
        return false;
    }
    let mut index = 0usize;
    let mut stack_depth = 0usize;
    let mut mark_depths: Vec<usize> = Vec::new();
    while index < value.len() {
        let parsed = match parse_opcode(value, index, value.len()) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        index = parsed.next;
        if !validate_pickle_stack_effect(&parsed, &mut stack_depth, &mut mark_depths) {
            return false;
        }
        if parsed.name == "STOP" {
            return stack_depth > 0;
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
            if mark_depths.last().copied() == Some(*stack_depth) || *stack_depth == 0 {
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
        "TUPLE" | "LIST" | "DICT" | "SET" | "FROZENSET" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth + 1;
                true
            }
            None => false,
        },
        "APPENDS" | "SETITEMS" | "ADDITEMS" => match mark_depths.pop() {
            Some(mark_depth) => {
                *stack_depth = mark_depth + 1;
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
        "NEXT_BUFFER" | "READONLY_BUFFER" => true,
        _ => {
            *stack_depth += 1;
            true
        }
    }
}

fn has_pickle_prefix(value: &[u8]) -> bool {
    if value.len() < 2 {
        return false;
    }
    value[0] == 0x80
        || matches!(
            value[0],
            b'(' | b'c' | b'd' | b'l' | b'i' | b'I' | b'S' | b'V'
        )
}

fn nested_pickle_probe_offsets(value: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    for index in 0..value.len().saturating_sub(1) {
        if has_pickle_prefix(&value[index..]) {
            offsets.push(index);
            if offsets.len() >= MAX_NESTED_PAYLOAD_PROBES {
                break;
            }
        }
    }
    offsets
}

fn encoded_nested_literal_probe_windows(value: &str, max_window_chars: usize) -> Vec<String> {
    let mut windows = Vec::new();
    push_unique_window(&mut windows, take_chars(value, max_window_chars));
    push_unique_window(&mut windows, take_last_chars(value, max_window_chars));

    let bytes = value.as_bytes();
    let patterns: [&[u8]; 3] = [b"gA", b"800", b"\\x80"];
    for index in 0..bytes.len() {
        if windows.len() >= MAX_NESTED_PAYLOAD_PROBES {
            break;
        }
        if !patterns
            .iter()
            .any(|pattern| bytes[index..].starts_with(pattern))
        {
            continue;
        }
        if !value.is_char_boundary(index) {
            continue;
        }
        push_unique_window(
            &mut windows,
            take_bytes_str(&value[index..], max_window_chars),
        );
    }

    windows
}

fn push_unique_window(windows: &mut Vec<String>, candidate: String) {
    if candidate.is_empty() || windows.iter().any(|window| window == &candidate) {
        return;
    }
    windows.push(candidate);
}

fn encoded_nested_window_char_limit(value: &str, max_nested_pickle_bytes: usize) -> usize {
    let max_base64_chars = max_nested_pickle_bytes.div_ceil(3) * 4;
    let max_plain_hex_chars = max_nested_pickle_bytes * 2;
    let max_escaped_hex_chars = max_nested_pickle_bytes * 4;
    let probe = encoded_literal_probe(value);
    if probe.contains("\\x") {
        return 16.max(max_escaped_hex_chars);
    }
    if chars_are_in_alphabet(probe.as_bytes(), HEX_LITERAL_CHARS) {
        return 16.max(max_plain_hex_chars);
    }
    if chars_are_in_alphabet(probe.as_bytes(), BASE64_LITERAL_CHARS) {
        return 16.max(max_base64_chars);
    }
    16
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
    let prefix = take_bytes_str(value, value.len().min(24));
    let padded = pad_base64(&prefix);
    decode_base64(&padded)
        .map(|decoded| has_pickle_prefix(&decoded))
        .unwrap_or(false)
}

fn hex_prefix_has_pickle_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut decoded = [0u8; 2];
    let mut decoded_len = 0usize;
    let mut high_nibble: Option<u8> = None;
    let mut index = 0usize;

    while index < bytes.len() && decoded_len < decoded.len() {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'x') {
            index += 2;
            continue;
        }

        let Some(nibble) = hex_value(bytes[index]) else {
            return false;
        };
        if let Some(high) = high_nibble {
            decoded[decoded_len] = (high << 4) | nibble;
            decoded_len += 1;
            high_nibble = None;
        } else {
            high_nibble = Some(nibble);
        }
        index += 1;
    }

    decoded_len == decoded.len() && high_nibble.is_none() && has_pickle_prefix(&decoded)
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
    value.replace("\\x", "").len() / 2
}

fn take_chars(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

fn take_last_chars(value: &str, count: usize) -> String {
    let len = value.chars().count();
    value.chars().skip(len.saturating_sub(count)).collect()
}

fn take_bytes_str(value: &str, count: usize) -> String {
    value.bytes().take(count).map(char::from).collect()
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn location_position(location: &str) -> Option<usize> {
    let marker = "(pos ";
    let start = location.rfind(marker)? + marker.len();
    let end = location[start..].strip_suffix(')')?;
    end.parse::<usize>().ok()
}

#[pyfunction]
#[pyo3(signature = (payload, source, options, bytes_total=None, position_offset=0, nested_depth=0))]
fn scan_bytes(
    py: Python<'_>,
    payload: &[u8],
    source: &str,
    options: &Bound<'_, PyDict>,
    bytes_total: Option<usize>,
    position_offset: usize,
    nested_depth: usize,
) -> PyResult<Py<PyDict>> {
    let options = ScanOptions::from_py(options)?;
    let started_at = Instant::now();
    let mut scan = ScanState::new(
        source.to_string(),
        payload,
        &options,
        bytes_total,
        position_offset,
        nested_depth,
        None,
    );
    scan.run();
    scan.to_py_report(py, started_at.elapsed().as_secs_f64())
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
    fn encoded_prefix_gates_recognize_pickle_prefixes() {
        assert!(base64_prefix_has_pickle_prefix("gAR9Lg=="));
        assert!(hex_prefix_has_pickle_prefix("80047d2e"));
        assert!(hex_prefix_has_pickle_prefix(r"\x80\x04\x7d\x2e"));
    }

    #[test]
    fn encoded_prefix_gates_reject_benign_repeated_literals() {
        assert!(!base64_prefix_has_pickle_prefix("AAAAAAAAAAAAAAAA"));
        assert!(!hex_prefix_has_pickle_prefix("4141414141414141"));
        assert!(
            decode_possible_encoded_pickle(&"A".repeat(1024), DEFAULT_MAX_NESTED_PICKLE_BYTES)
                .is_empty()
        );
        assert!(detect_oversized_encoded_pickle_prefixes(
            &"A".repeat(1024),
            DEFAULT_MAX_NESTED_PICKLE_BYTES
        )
        .is_empty());
    }

    #[test]
    fn protocol5_buffer_opcodes_do_not_create_stack_operands() {
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
            Some("NoneType:None")
        );
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
}

#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_bytes, m)?)?;
    Ok(())
}

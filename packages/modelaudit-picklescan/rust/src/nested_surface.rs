#[derive(Clone)]
pub(crate) struct NestedPayloadFinding {
    pub(crate) encoding: &'static str,
    pub(crate) payload_size: usize,
    pub(crate) position: usize,
    pub(crate) analysis_incomplete: bool,
    pub(crate) nested_has_execution_opcode: bool,
    pub(crate) rule_code: &'static str,
    pub(crate) complete_message: &'static str,
    pub(crate) incomplete_message: &'static str,
    pub(crate) why: &'static str,
    pub(crate) include_limit_when_complete: bool,
}

#[derive(Default)]
pub(crate) struct NestedSurfaceOutcome {
    pub(crate) has_critical_finding: bool,
    pub(crate) has_unclassified_execution: bool,
    pub(crate) incomplete: bool,
    pub(crate) depth_limited: bool,
}

impl NestedSurfaceOutcome {
    pub(crate) fn promote_complete_payload(&self, nested_has_execution_opcode: bool) -> bool {
        self.has_critical_finding
            || self.incomplete
            || (self.has_unclassified_execution && nested_has_execution_opcode)
            || (self.depth_limited && nested_has_execution_opcode)
    }

    pub(crate) fn should_stop_raw_probe_scan(&self, nested_has_execution_opcode: bool) -> bool {
        self.has_critical_finding
            || self.incomplete
            || (self.depth_limited && nested_has_execution_opcode)
    }
}

pub(crate) fn raw_nested_payload_finding(
    payload_size: usize,
    position: usize,
    analysis_incomplete: bool,
    nested_has_execution_opcode: bool,
) -> NestedPayloadFinding {
    NestedPayloadFinding {
        encoding: "raw",
        payload_size,
        position,
        analysis_incomplete,
        nested_has_execution_opcode,
        rule_code: "S213",
        complete_message: "Nested pickle payload detected",
        incomplete_message: "Nested pickle payload exceeds deep-scan byte limit",
        why: "This pickle contains another serialized pickle payload inside a byte field. Nested payloads can hide code execution paths from shallow scanners.",
        include_limit_when_complete: true,
    }
}

pub(crate) fn encoded_nested_payload_finding(
    encoding: &'static str,
    payload_size: usize,
    position: usize,
    analysis_incomplete: bool,
    nested_has_execution_opcode: bool,
) -> NestedPayloadFinding {
    NestedPayloadFinding {
        encoding,
        payload_size,
        position,
        analysis_incomplete,
        nested_has_execution_opcode,
        rule_code: if encoding == "base64" { "S601" } else { "S602" },
        complete_message: "Encoded pickle payload detected",
        incomplete_message: "Encoded pickle payload exceeds deep-scan byte limit",
        why: "Encoded nested pickle payloads can hide deserialization gadgets inside apparently inert metadata strings.",
        include_limit_when_complete: false,
    }
}

pub(crate) fn nested_rule_code_for_encoding(encoding: &'static str) -> &'static str {
    match encoding {
        "raw" => "S213",
        "base64" => "S601",
        _ => "S602",
    }
}

pub(crate) fn is_allowlisted_nested_constructor_ref(reference: &str) -> bool {
    matches!(
        reference,
        "builtins.range"
            | "builtins.slice"
            | "__builtin__.range"
            | "__builtin__.slice"
            | "__builtins__.range"
            | "__builtins__.slice"
            | "collections.Counter"
            | "collections.OrderedDict"
            | "collections.defaultdict"
            | "datetime.date"
            | "datetime.datetime"
            | "datetime.time"
            | "datetime.timedelta"
            | "decimal.Decimal"
            | "pathlib.PurePath"
            | "pathlib.PurePosixPath"
            | "pathlib.PureWindowsPath"
            | "pathlib.PosixPath"
            | "pathlib.WindowsPath"
            | "re._compile"
            | "uuid.UUID"
    )
}

use std::borrow::Cow;

use crate::opcode::ArgValue;

const MAX_TRACKED_TUPLE_ITEMS: usize = 16;
const MAX_TRACKED_TUPLE_DEPTH: usize = 2;
const MAX_STACK_BYTES_PREVIEW: usize = 4096;

#[derive(Clone)]
pub(crate) struct GlobalRef {
    pub(crate) module: String,
    pub(crate) name: String,
    pub(crate) position: usize,
    pub(crate) malformed: bool,
}

impl GlobalRef {
    pub(crate) fn symbol(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

#[derive(Clone)]
pub(crate) struct RegexScannerRule {
    pub(crate) pattern: String,
    pub(crate) action: GlobalRef,
}

#[derive(Clone)]
pub(crate) enum StackValue {
    Mark,
    Text(String),
    TextSpan {
        start: usize,
        end: usize,
    },
    Bytes {
        start: usize,
        end: usize,
    },
    Global(GlobalRef),
    Constructed(GlobalRef),
    CallIterator {
        callable: GlobalRef,
    },
    CallIteratorTuple {
        callable: GlobalRef,
        item_count: Option<usize>,
    },
    DefaultDict {
        default_factory: GlobalRef,
    },
    RegexPattern {
        pattern: String,
    },
    RegexScannerLexicon {
        rules: Vec<RegexScannerRule>,
    },
    RegexScanner {
        rules: Vec<RegexScannerRule>,
    },
    Tuple(Vec<StackValue>),
    Primitive {
        type_name: &'static str,
        repr: String,
    },
    Other,
}

pub(crate) fn resolve_global_operand(value: Option<&StackValue>, payload: &[u8]) -> Option<String> {
    match value {
        Some(StackValue::Text(value)) => Some(value.clone()),
        Some(StackValue::TextSpan { start, end }) if start <= end && *end <= payload.len() => {
            Some(String::from_utf8_lossy(&payload[*start..*end]).to_string())
        }
        _ => None,
    }
}

pub(crate) fn operand_preview(value: Option<&StackValue>) -> String {
    match value {
        Some(StackValue::Global(reference)) => format!("_GlobalRef({})", reference.symbol()),
        Some(StackValue::Constructed(reference)) => format!("constructed:{}", reference.symbol()),
        Some(StackValue::CallIterator { callable }) => {
            format!("call_iterator:{}", callable.symbol())
        }
        Some(StackValue::CallIteratorTuple {
            callable,
            item_count,
        }) => format!(
            "call_iterator_tuple(callable={}, len={})",
            callable.symbol(),
            item_count.map_or_else(|| "unknown".to_string(), |count| count.to_string())
        ),
        Some(StackValue::DefaultDict { default_factory }) => {
            format!("defaultdict(factory={})", default_factory.symbol())
        }
        Some(StackValue::RegexPattern { pattern }) => format!("regex_pattern:{pattern:?}"),
        Some(StackValue::RegexScannerLexicon { rules }) => {
            format!("regex_scanner_lexicon(rules={})", rules.len())
        }
        Some(StackValue::RegexScanner { rules }) => {
            format!("regex_scanner(rules={})", rules.len())
        }
        Some(StackValue::TextSpan { start, end }) => {
            format!("str_span(len={})", end.saturating_sub(*start))
        }
        Some(StackValue::Bytes { start, end }) => {
            format!("bytes(len={})", end.saturating_sub(*start))
        }
        Some(StackValue::Mark) => "MARK".to_string(),
        Some(StackValue::Text(value)) => format!("str:{:?}", value),
        Some(StackValue::Tuple(values)) => format!("tuple(len={})", values.len()),
        Some(StackValue::Primitive { type_name, repr }) => format!("{type_name}:{repr}"),
        Some(StackValue::Other) => "object".to_string(),
        None => "NoneType:None".to_string(),
    }
}

pub(crate) fn collapse_tuple_values(values: Vec<StackValue>) -> StackValue {
    if values.len() > MAX_TRACKED_TUPLE_ITEMS
        || tuple_depth_for_values(&values) > MAX_TRACKED_TUPLE_DEPTH
    {
        StackValue::Other
    } else {
        StackValue::Tuple(values)
    }
}

fn tuple_depth_for_values(values: &[StackValue]) -> usize {
    1 + values
        .iter()
        .map(stack_value_tuple_depth)
        .max()
        .unwrap_or(0)
}

fn stack_value_tuple_depth(value: &StackValue) -> usize {
    match value {
        StackValue::Tuple(values) => tuple_depth_for_values(values),
        _ => 0,
    }
}

pub(crate) fn stack_value_preview(value: &StackValue, depth: usize) -> String {
    if depth >= 3 {
        return "...".to_string();
    }

    match value {
        StackValue::Mark => "MARK".to_string(),
        StackValue::Text(value) => format!("str:{:?}", value),
        StackValue::TextSpan { start, end } => {
            format!("str_span(len={})", end.saturating_sub(*start))
        }
        StackValue::Bytes { start, end } => format!("bytes(len={})", end.saturating_sub(*start)),
        StackValue::Global(reference) => format!("global:{}", reference.symbol()),
        StackValue::Constructed(reference) => format!("constructed:{}", reference.symbol()),
        StackValue::CallIterator { callable } => {
            format!("call_iterator:{}", callable.symbol())
        }
        StackValue::CallIteratorTuple {
            callable,
            item_count,
        } => format!(
            "call_iterator_tuple(callable={}, len={})",
            callable.symbol(),
            item_count.map_or_else(|| "unknown".to_string(), |count| count.to_string())
        ),
        StackValue::DefaultDict { default_factory } => {
            format!("defaultdict(factory={})", default_factory.symbol())
        }
        StackValue::RegexPattern { pattern } => format!("regex_pattern:{pattern:?}"),
        StackValue::RegexScannerLexicon { rules } => {
            format!("regex_scanner_lexicon(rules={})", rules.len())
        }
        StackValue::RegexScanner { rules } => format!("regex_scanner(rules={})", rules.len()),
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

pub(crate) fn stack_value_string(value: &StackValue, payload: &[u8]) -> Option<String> {
    stack_value_text(value, payload).map(Cow::into_owned)
}

pub(crate) fn pytorch_storage_key(value: &StackValue, payload: &[u8]) -> Option<String> {
    let StackValue::Tuple(items) = value else {
        return None;
    };
    if items.len() < 4 || stack_value_text(&items[0], payload).as_deref() != Some("storage") {
        return None;
    }
    if !is_pytorch_storage_descriptor(&items[1], payload) {
        return None;
    }
    stack_value_string(&items[2], payload)
}

pub(crate) fn stack_value_from_integer_arg(arg: &ArgValue, payload: &[u8]) -> StackValue {
    match arg {
        ArgValue::Int(value) => StackValue::Primitive {
            type_name: "int",
            repr: value.to_string(),
        },
        ArgValue::UInt(value) => StackValue::Primitive {
            type_name: "int",
            repr: value.to_string(),
        },
        ArgValue::Text(value) | ArgValue::DecodedString { text: value, .. } => {
            integer_text_repr(value).map_or(StackValue::Other, |repr| StackValue::Primitive {
                type_name: "int",
                repr,
            })
        }
        ArgValue::Bytes { start, end } if start <= end && *end <= payload.len() => {
            little_endian_signed_integer_repr(&payload[*start..*end]).map_or(
                StackValue::Other,
                |repr| StackValue::Primitive {
                    type_name: "int",
                    repr,
                },
            )
        }
        _ => StackValue::Other,
    }
}

pub(crate) fn stack_value_from_text_arg(arg: &ArgValue, payload: &[u8]) -> StackValue {
    match arg {
        ArgValue::Text(value) | ArgValue::DecodedString { text: value, .. } => {
            StackValue::Text(value.clone())
        }
        ArgValue::TextSpan { start, end } | ArgValue::Bytes { start, end }
            if start <= end && *end <= payload.len() =>
        {
            StackValue::TextSpan {
                start: *start,
                end: *end,
            }
        }
        _ => StackValue::Text(arg.coerce_text(payload)),
    }
}

fn stack_value_text<'payload>(
    value: &'payload StackValue,
    payload: &'payload [u8],
) -> Option<Cow<'payload, str>> {
    match value {
        StackValue::Text(text) => Some(Cow::Borrowed(text)),
        StackValue::TextSpan { start, end } if start <= end && *end <= payload.len() => {
            Some(String::from_utf8_lossy(&payload[*start..*end]))
        }
        StackValue::Primitive { repr, .. } => Some(Cow::Borrowed(repr)),
        StackValue::Bytes { start, end }
            if start <= end
                && *end <= payload.len()
                && end.saturating_sub(*start) <= MAX_STACK_BYTES_PREVIEW =>
        {
            std::str::from_utf8(&payload[*start..*end])
                .ok()
                .map(Cow::Borrowed)
        }
        _ => None,
    }
}

fn is_pytorch_storage_descriptor(value: &StackValue, payload: &[u8]) -> bool {
    match value {
        StackValue::Global(reference) => {
            reference.module == "torch" && reference.name.ends_with("Storage")
        }
        StackValue::Text(text) => text.starts_with("torch.") && text.ends_with("Storage"),
        StackValue::TextSpan { start, end } if start <= end && *end <= payload.len() => {
            let text = String::from_utf8_lossy(&payload[*start..*end]);
            text.starts_with("torch.") && text.ends_with("Storage")
        }
        _ => false,
    }
}

fn integer_text_repr(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_suffix('L').unwrap_or(trimmed);
    if trimmed.parse::<i64>().is_ok() {
        return Some(trimmed.to_string());
    }
    None
}

fn little_endian_signed_integer_repr(value: &[u8]) -> Option<String> {
    if value.len() > 16 {
        return None;
    }
    if value.is_empty() {
        return Some("0".to_string());
    }

    let sign_extend = value.last().is_some_and(|byte| byte & 0x80 != 0);
    let mut buffer = if sign_extend { [0xffu8; 16] } else { [0u8; 16] };
    buffer[..value.len()].copy_from_slice(value);
    Some(i128::from_le_bytes(buffer).to_string())
}

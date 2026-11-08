use std::borrow::Cow;

use crate::opcode::ArgValue;

const MAX_TRACKED_TUPLE_ITEMS: usize = 16;
const MAX_TRACKED_TUPLE_DEPTH: usize = 4;
const MAX_STACK_BYTES_PREVIEW: usize = 4096;

#[derive(Clone)]
pub(crate) struct GlobalRef {
    pub(crate) module: String,
    pub(crate) name: String,
    pub(crate) position: usize,
    pub(crate) malformed: bool,
    pub(crate) memo_index: Option<i64>,
    pub(crate) memo_read: bool,
}

impl GlobalRef {
    pub(crate) fn new(module: String, name: String, position: usize) -> Self {
        Self {
            module,
            name,
            position,
            malformed: false,
            memo_index: None,
            memo_read: false,
        }
    }

    pub(crate) fn from_stack_operands(
        module: Option<&StackValue>,
        name: Option<&StackValue>,
        payload: &[u8],
        position: usize,
    ) -> Self {
        let module = resolve_global_operand(module, payload);
        let name = resolve_global_operand(name, payload);
        Self {
            malformed: module.is_none() || name.is_none(),
            ..Self::new(
                module.unwrap_or_else(|| "__unknown__".to_owned()),
                name.unwrap_or_else(|| "__unknown__".to_owned()),
                position,
            )
        }
    }

    pub(crate) fn extension(code: i64, position: usize) -> Self {
        let name = format!("code_{code}");
        Self {
            malformed: true,
            ..Self::new("copyreg.extension".to_owned(), name, position)
        }
    }

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
pub(crate) struct FutureCallbacks {
    pub(crate) callbacks: Vec<GlobalRef>,
    pub(crate) done: bool,
    pub(crate) memo_index: Option<i64>,
}

#[derive(Clone)]
pub(crate) enum StackValue {
    Mark,
    Text {
        value: String,
        memo_read: bool,
    },
    TextSpan {
        start: usize,
        end: usize,
        memo_read: bool,
    },
    Bytes {
        start: usize,
        end: usize,
    },
    ExternalBuffer,
    Global(GlobalRef),
    Constructed {
        reference: GlobalRef,
        // Constructor provenance only; generic instance dispatch stays unchanged.
        defaultdict_without_factory: bool,
    },
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
    DynamicType {
        type_name: Option<String>,
        memo_index: Option<i64>,
    },
    TrackedDict {
        entries: Vec<(String, StackValue)>,
        unknown_key_values: Vec<StackValue>,
        unknown_key_values_overflowed: bool,
        memo_index: Option<i64>,
    },
    MappingWrapper {
        reference: GlobalRef,
        mappings: Vec<StackValue>,
    },
    StringTemplate {
        template: String,
    },
    RegexPattern {
        pattern: String,
        flags: Option<isize>,
    },
    RegexScannerLexicon {
        rules: Vec<RegexScannerRule>,
    },
    RegexScanner {
        rules: Vec<RegexScannerRule>,
        flags: Option<isize>,
    },
    FutureCallbacks(FutureCallbacks),
    Tuple(Vec<StackValue>),
    Primitive {
        type_name: &'static str,
        repr: String,
    },
    Other,
}

pub(crate) fn resolve_global_operand(value: Option<&StackValue>, payload: &[u8]) -> Option<String> {
    match value {
        Some(StackValue::Text { value, .. }) => Some(value.clone()),
        Some(StackValue::TextSpan { start, end, .. }) if start <= end && *end <= payload.len() => {
            Some(String::from_utf8_lossy(&payload[*start..*end]).to_string())
        }
        _ => None,
    }
}

pub(crate) fn operand_preview(value: Option<&StackValue>) -> String {
    match value {
        Some(StackValue::Global(reference)) => format!("_GlobalRef({})", reference.symbol()),
        Some(StackValue::Constructed { reference, .. }) => {
            format!("constructed:{}", reference.symbol())
        }
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
        Some(StackValue::DynamicType {
            type_name,
            memo_index,
        }) => format!(
            "dynamic_type(name={}, memo={})",
            type_name.as_deref().unwrap_or("unknown"),
            memo_index.map_or_else(|| "none".to_string(), |index| index.to_string())
        ),
        Some(StackValue::TrackedDict {
            entries,
            unknown_key_values,
            ..
        }) if entries.is_empty() && unknown_key_values.is_empty() => "dict:{}".to_string(),
        Some(StackValue::TrackedDict {
            entries,
            unknown_key_values,
            unknown_key_values_overflowed,
            ..
        }) => {
            let overflow = if *unknown_key_values_overflowed {
                "+overflow"
            } else {
                ""
            };
            format!(
                "dict(keys={}, dynamic_keys={}{})",
                entries.len(),
                unknown_key_values.len(),
                overflow
            )
        }
        Some(StackValue::MappingWrapper {
            reference,
            mappings,
        }) => format!(
            "mapping_wrapper:{}(mappings={})",
            reference.symbol(),
            mappings.len()
        ),
        Some(StackValue::StringTemplate { template }) => {
            format!("string_template:{template:?}")
        }
        Some(StackValue::RegexPattern { pattern, flags }) => {
            format!(
                "regex_pattern:{pattern:?},flags={}",
                regex_flags_preview(*flags)
            )
        }
        Some(StackValue::RegexScannerLexicon { rules }) => {
            format!("regex_scanner_lexicon(rules={})", rules.len())
        }
        Some(StackValue::RegexScanner { rules, flags }) => {
            format!(
                "regex_scanner(rules={}, flags={})",
                rules.len(),
                regex_flags_preview(*flags)
            )
        }
        Some(StackValue::FutureCallbacks(callbacks)) => format!(
            "future_callbacks(callbacks={}, done={}, memo={})",
            callbacks.callbacks.len(),
            callbacks.done,
            callbacks
                .memo_index
                .map_or_else(|| "none".to_string(), |index| index.to_string())
        ),
        Some(StackValue::TextSpan { start, end, .. }) => {
            format!("str_span(len={})", end.saturating_sub(*start))
        }
        Some(StackValue::Bytes { start, end }) => {
            format!("bytes(len={})", end.saturating_sub(*start))
        }
        Some(StackValue::ExternalBuffer) => "external_buffer".to_string(),
        Some(StackValue::Mark) => "MARK".to_string(),
        Some(StackValue::Text { value, .. }) => format!("str:{:?}", value),
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
        StackValue::Global(reference) => format!("global:{}", reference.symbol()),
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
        _ => operand_preview(Some(value)),
    }
}

fn regex_flags_preview(flags: Option<isize>) -> String {
    flags.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

pub(crate) fn stack_value_string(value: &StackValue, payload: &[u8]) -> Option<String> {
    stack_value_text(value, payload).map(Cow::into_owned)
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
        ArgValue::Text(value) | ArgValue::DecodedString { text: value, .. } => StackValue::Text {
            value: value.clone(),
            memo_read: false,
        },
        ArgValue::TextSpan { start, end } | ArgValue::Bytes { start, end }
            if start <= end && *end <= payload.len() =>
        {
            StackValue::TextSpan {
                start: *start,
                end: *end,
                memo_read: false,
            }
        }
        _ => StackValue::Text {
            value: arg.coerce_text(payload),
            memo_read: false,
        },
    }
}

fn stack_value_text<'payload>(
    value: &'payload StackValue,
    payload: &'payload [u8],
) -> Option<Cow<'payload, str>> {
    match value {
        StackValue::Text { value, .. } => Some(Cow::Borrowed(value)),
        StackValue::TextSpan { start, end, .. } if start <= end && *end <= payload.len() => {
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

pub(crate) struct PytorchStorageId<'a> {
    pub(crate) descriptor: Option<&'a GlobalRef>,
    pub(crate) key: Cow<'a, str>,
}

pub(crate) fn pytorch_storage_persistent_id<'a>(
    value: &'a StackValue,
    payload: &'a [u8],
) -> Option<PytorchStorageId<'a>> {
    let StackValue::Tuple(items) = value else {
        return None;
    };
    let [tag, descriptor, key, location, size] = items.as_slice() else {
        return None;
    };
    if stack_value_text(tag, payload).as_deref() != Some("storage") {
        return None;
    }
    let descriptor = match descriptor {
        StackValue::Global(reference)
            if is_known_pytorch_storage_global(&reference.module, &reference.name) =>
        {
            Some(reference)
        }
        StackValue::Text { .. } | StackValue::TextSpan { .. }
            if is_known_pytorch_storage_reference_text(&stack_value_text(descriptor, payload)?) =>
        {
            None
        }
        _ => return None,
    };
    let key = stack_value_text(key, payload)?;
    stack_value_text(location, payload)?;
    match size {
        StackValue::Primitive {
            type_name: "int",
            repr,
        } if repr.parse::<u64>().is_ok() => Some(PytorchStorageId { descriptor, key }),
        _ => None,
    }
}

fn is_known_pytorch_storage_name(name: &str) -> bool {
    matches!(
        name,
        "BFloat16Storage"
            | "BoolStorage"
            | "ByteStorage"
            | "CharStorage"
            | "ComplexDoubleStorage"
            | "ComplexFloatStorage"
            | "DoubleStorage"
            | "FloatStorage"
            | "HalfStorage"
            | "IntStorage"
            | "LongStorage"
            | "QInt32Storage"
            | "QInt8Storage"
            | "QUInt8Storage"
            | "QUInt4x2Storage"
            | "QUInt2x4Storage"
            | "ShortStorage"
            | "UntypedStorage"
    )
}

pub(crate) fn is_known_pytorch_storage_global(module: &str, name: &str) -> bool {
    matches!(module, "torch" | "torch.storage") && is_known_pytorch_storage_name(name)
}

fn is_known_pytorch_storage_reference_text(text: &str) -> bool {
    text.strip_prefix("torch.storage.")
        .or_else(|| text.strip_prefix("torch."))
        .is_some_and(is_known_pytorch_storage_name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_previews_preserve_recursive_format_and_limits() {
        let global = StackValue::Global(GlobalRef {
            module: "os".to_string(),
            name: "system".to_string(),
            position: 0,
            malformed: false,
            memo_index: None,
            memo_read: false,
        });
        let nested = StackValue::Tuple(vec![StackValue::Tuple(vec![global.clone()])]);
        for (value, depth, expected) in [
            (global.clone(), 0, "global:os.system"),
            (global.clone(), 2, "global:os.system"),
            (global, 3, "..."),
            (nested.clone(), 0, "tuple(tuple(global:os.system))"),
            (nested, 1, "tuple(tuple(...))"),
            (StackValue::Other, 2, "object"),
            (StackValue::Other, 3, "..."),
            (StackValue::Tuple(vec![]), 3, "..."),
            (
                StackValue::Tuple(vec![StackValue::Other; 6]),
                0,
                "tuple(object, object, object, object, object, object)",
            ),
            (
                StackValue::Tuple(vec![StackValue::Other; 7]),
                0,
                "tuple(object, object, object, object, object, object, ...)",
            ),
        ] {
            assert_eq!(stack_value_preview(&value, depth), expected);
        }
    }
}

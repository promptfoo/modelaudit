use std::borrow::Cow;
use std::collections::HashSet;

use crate::opcode::{decode_raw_unicode_escape, parse_pickle_string_literal};
use crate::policy::global_severity;

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
}

pub(crate) fn post_budget_global_matches(
    tail: &[u8],
    tail_prefix_len: usize,
    resolve_memo_string: impl Fn(i64) -> Option<String>,
) -> Vec<PostBudgetGlobalMatch> {
    let mut matches = Vec::new();
    let mut seen = HashSet::new();

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
        record_post_budget_stack_global_pattern(
            tail,
            index,
            &resolve_memo_string,
            &mut seen,
            &mut matches,
        );
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

fn record_post_budget_stack_global_pattern(
    tail: &[u8],
    index: usize,
    resolve_memo_string: &impl Fn(i64) -> Option<String>,
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    let Some((module, after_module)) =
        read_post_budget_stack_global_operand(tail, index, resolve_memo_string)
    else {
        return;
    };
    let name_start = skip_post_budget_memoize(tail, after_module);
    let Some((name, after_name)) =
        read_post_budget_stack_global_operand(tail, name_start, resolve_memo_string)
    else {
        return;
    };
    let stack_global_position = skip_post_budget_memoize(tail, after_name);
    if tail.get(stack_global_position) != Some(&0x93) {
        return;
    }
    record_post_budget_global(
        &module,
        &name,
        index,
        stack_global_position.saturating_add(1),
        tail,
        seen,
        matches,
    );
}

fn read_post_budget_stack_global_operand<'a>(
    tail: &'a [u8],
    index: usize,
    resolve_memo_string: &impl Fn(i64) -> Option<String>,
) -> Option<(Cow<'a, str>, usize)> {
    if let Some((text, next)) = read_post_budget_text_operand(tail, index) {
        return Some((text, next));
    }

    let (memo_index, next) = read_post_budget_memo_read(tail, index)?;
    resolve_memo_string(memo_index).map(|value| (Cow::Owned(value), next))
}

fn read_post_budget_memo_read(tail: &[u8], index: usize) -> Option<(i64, usize)> {
    match *tail.get(index)? {
        b'g' => {
            let digits_start = index.saturating_add(1);
            let digits_end = find_byte_from(tail, digits_start, b'\n')?;
            let digits = std::str::from_utf8(tail.get(digits_start..digits_end)?).ok()?;
            let memo_index = digits.parse::<i64>().ok()?;
            Some((memo_index, digits_end.saturating_add(1)))
        }
        b'h' => Some((
            i64::from(*tail.get(index.saturating_add(1))?),
            index.saturating_add(2),
        )),
        b'j' => {
            let start = index.saturating_add(1);
            let end = start.checked_add(4)?;
            let memo_index = u32::from_le_bytes(tail.get(start..end)?.try_into().ok()?);
            Some((i64::from(memo_index), end))
        }
        _ => None,
    }
}

fn read_post_budget_text_operand(tail: &[u8], index: usize) -> Option<(Cow<'_, str>, usize)> {
    let opcode = *tail.get(index)?;
    let (start, end) = match opcode {
        b'S' => {
            let start = index.saturating_add(1);
            let end = find_byte_from(tail, start, b'\n')?;
            return Some((
                Cow::Owned(parse_pickle_string_literal(tail.get(start..end)?)),
                end.saturating_add(1),
            ));
        }
        b'U' | 0x8c => {
            let len = *tail.get(index.saturating_add(1))? as usize;
            let start = index.saturating_add(2);
            (start, start.checked_add(len)?)
        }
        b'T' | b'X' => {
            let len_start = index.saturating_add(1);
            let len_end = len_start.checked_add(4)?;
            let len = usize::try_from(u32::from_le_bytes(
                tail.get(len_start..len_end)?.try_into().ok()?,
            ))
            .ok()?;
            let start = len_end;
            (start, start.checked_add(len)?)
        }
        0x8d => {
            let len_start = index.saturating_add(1);
            let len_end = len_start.checked_add(8)?;
            let len = usize::try_from(u64::from_le_bytes(
                tail.get(len_start..len_end)?.try_into().ok()?,
            ))
            .ok()?;
            let start = len_end;
            (start, start.checked_add(len)?)
        }
        b'V' => {
            let start = index.saturating_add(1);
            let end = find_byte_from(tail, start, b'\n')?;
            return Some((
                Cow::Owned(decode_raw_unicode_escape(tail.get(start..end)?)),
                end.saturating_add(1),
            ));
        }
        _ => return None,
    };
    let value = std::str::from_utf8(tail.get(start..end)?).ok()?;
    Some((Cow::Borrowed(value), end))
}

fn skip_post_budget_memoize(tail: &[u8], mut index: usize) -> usize {
    while tail.get(index) == Some(&0x94) {
        index = index.saturating_add(1);
    }
    index
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

fn record_post_budget_global(
    module: &str,
    name: &str,
    pattern_start: usize,
    proximity_start: usize,
    tail: &[u8],
    seen: &mut HashSet<(usize, String, String)>,
    matches: &mut Vec<PostBudgetGlobalMatch>,
) {
    let Some(severity) = post_budget_global_severity(module, name) else {
        return;
    };
    record_post_budget_global_with_severity(
        PostBudgetGlobalCandidate {
            module,
            name,
            pattern_start,
            proximity_start,
            severity,
        },
        tail,
        seen,
        matches,
    );
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
    if !seen.insert((
        candidate.pattern_start,
        candidate.module.to_string(),
        candidate.name.to_string(),
    )) {
        return;
    }
    let reduce_proximate = has_reduce_class_byte_nearby(tail, candidate.proximity_start);
    matches.push(PostBudgetGlobalMatch {
        module: candidate.module.to_string(),
        name: candidate.name.to_string(),
        pattern_start: candidate.pattern_start,
        reduce_proximate,
        severity: candidate.severity,
    });
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

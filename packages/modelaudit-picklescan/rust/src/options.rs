use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_TIMEOUT_S: f64 = 3600.0;
const MAX_TIMEOUT_S: f64 = 86_400.0;
pub(crate) const DEFAULT_MAX_OPCODES: usize = 1_000_000;
pub(crate) const DEFAULT_POST_BUDGET_SCAN_BYTES: usize = 100 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS: usize = 8 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_NESTED_PICKLE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_NESTED_DEPTH: usize = 2;

pub(crate) struct ScanOptions {
    pub(crate) timeout_s: f64,
    pub(crate) max_opcodes: usize,
    pub(crate) post_budget_scan_bytes: usize,
    pub(crate) max_string_literal_scan_chars: usize,
    pub(crate) max_nested_pickle_bytes: usize,
    pub(crate) max_nested_depth: usize,
}

impl ScanOptions {
    pub(crate) fn from_py(options: &Bound<'_, PyDict>) -> PyResult<Self> {
        Ok(Self {
            timeout_s: clamp_timeout_s(option_f64(options, "timeout_s", DEFAULT_TIMEOUT_S)?),
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
            )
            .and_then(|value| require_minimum_usize(value, "max_nested_pickle_bytes", 2))?,
            max_nested_depth: option_usize(options, "max_nested_depth", DEFAULT_MAX_NESTED_DEPTH)?,
        })
    }
}

fn clamp_timeout_s(timeout_s: f64) -> f64 {
    timeout_s.min(MAX_TIMEOUT_S)
}

fn timeout_duration(timeout_s: f64) -> Duration {
    if timeout_s.is_finite() && timeout_s > 0.0 {
        Duration::from_secs_f64(clamp_timeout_s(timeout_s))
    } else {
        Duration::from_secs_f64(DEFAULT_TIMEOUT_S)
    }
}

pub(crate) fn deadline_from_timeout(timeout_s: f64) -> Instant {
    let now = Instant::now();
    let duration = timeout_duration(timeout_s);
    now.checked_add(duration).unwrap_or_else(|| {
        now.checked_add(Duration::from_secs_f64(DEFAULT_TIMEOUT_S))
            .unwrap_or_else(|| now + Duration::from_secs(1))
    })
}

fn option_usize(options: &Bound<'_, PyDict>, key: &str, default: usize) -> PyResult<usize> {
    match options.get_item(key)? {
        Some(value) => value.extract::<usize>(),
        None => Ok(default),
    }
}

fn require_minimum_usize(value: usize, key: &str, minimum: usize) -> PyResult<usize> {
    if value < minimum {
        return Err(PyValueError::new_err(format!(
            "{key} must be at least {minimum}"
        )));
    }
    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_duration_clamps_excessive_values() {
        assert_eq!(clamp_timeout_s(1.0e18), MAX_TIMEOUT_S);
        assert_eq!(timeout_duration(1.0e18), Duration::from_secs(86_400));
        assert_eq!(timeout_duration(f64::NAN), Duration::from_secs(3600));
    }
}

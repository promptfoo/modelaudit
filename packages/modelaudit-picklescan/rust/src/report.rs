use pyo3::conversion::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::borrow::Cow;

#[derive(Clone)]
pub(crate) enum DetailValue {
    String(String),
    Int(i64),
    UInt(u64),
    Float(f64),
    Bool(bool),
    List(Vec<DetailValue>),
    Dict(Vec<(String, DetailValue)>),
    None,
}

impl DetailValue {
    fn to_py_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            DetailValue::String(value) => value.into_py_any(py),
            DetailValue::Int(value) => (*value).into_py_any(py),
            DetailValue::UInt(value) => (*value).into_py_any(py),
            DetailValue::Float(value) => (*value).into_py_any(py),
            DetailValue::Bool(value) => (*value).into_py_any(py),
            DetailValue::None => Ok(py.None()),
            DetailValue::List(values) => {
                let list = PyList::empty(py);
                for value in values {
                    list.append(value.to_py_object(py)?)?;
                }
                Ok(list.into_any().unbind())
            }
            DetailValue::Dict(values) => Ok(detail_dict_to_py(py, values)?.into_any().unbind()),
        }
    }
}

#[derive(Clone, IntoPyObjectRef)]
pub(crate) struct Finding {
    pub(crate) message: String,
    pub(crate) severity: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) rule_code: Option<&'static str>,
    #[pyo3(into_py_with = detail_field_to_py)]
    pub(crate) details: Vec<(String, DetailValue)>,
    pub(crate) why: Option<&'static str>,
}

pub(crate) type FindingDedupeKey = (String, Option<String>, Option<&'static str>);

impl Finding {
    pub(crate) fn dedupe_key(&self) -> FindingDedupeKey {
        (self.message.clone(), self.location.clone(), self.rule_code)
    }
}

#[derive(Clone, IntoPyObjectRef)]
pub(crate) struct Notice {
    pub(crate) message: String,
    pub(crate) severity: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) code: Option<&'static str>,
    #[pyo3(into_py_with = detail_field_to_py)]
    pub(crate) details: Vec<(String, DetailValue)>,
}

pub(crate) type NoticeDedupeKey = (Option<&'static str>, Option<String>, String);

impl Notice {
    pub(crate) fn dedupe_key(&self) -> NoticeDedupeKey {
        (self.code, self.location.clone(), self.message.clone())
    }
}

#[derive(Clone, IntoPyObjectRef)]
pub(crate) struct ScanError {
    pub(crate) message: String,
    pub(crate) category: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) exception_type: Option<&'static str>,
    #[pyo3(into_py_with = detail_field_to_py)]
    pub(crate) details: Vec<(String, DetailValue)>,
}

pub(crate) fn detail_string(details: &[(String, DetailValue)], key: &str) -> Option<String> {
    details.iter().find_map(|(detail_key, value)| {
        if detail_key == key {
            if let DetailValue::String(value) = value {
                return Some(value.clone());
            }
        }
        None
    })
}

pub(crate) fn detail_usize(details: &[(String, DetailValue)], key: &str) -> Option<usize> {
    details.iter().find_map(|(detail_key, value)| {
        if detail_key == key {
            match value {
                DetailValue::UInt(value) => return Some(*value as usize),
                DetailValue::Int(value) if *value >= 0 => return Some(*value as usize),
                _ => {}
            }
        }
        None
    })
}

pub(crate) fn text_field(key: &str, value: Option<impl Into<String>>) -> (String, DetailValue) {
    (
        key.to_string(),
        value.map_or(DetailValue::None, |s| DetailValue::String(s.into())),
    )
}

pub(crate) fn scan_error_to_detail_value(error: ScanError) -> DetailValue {
    DetailValue::Dict(vec![
        text_field("message", Some(error.message)),
        text_field("category", Some(error.category)),
        text_field("location", error.location),
        text_field("exception_type", error.exception_type),
        ("details".to_string(), DetailValue::Dict(error.details)),
    ])
}

pub(crate) fn notice_to_detail_value(notice: Notice) -> DetailValue {
    DetailValue::Dict(vec![
        text_field("message", Some(notice.message)),
        text_field("severity", Some(notice.severity)),
        text_field("location", notice.location),
        text_field("code", notice.code),
        ("details".to_string(), DetailValue::Dict(notice.details)),
    ])
}

fn detail_field_to_py<'py>(
    details: Cow<'_, [(String, DetailValue)]>,
    py: Python<'py>,
) -> PyResult<Bound<'py, PyAny>> {
    Ok(detail_dict_to_py(py, &details)?.into_any())
}

pub(crate) fn detail_dict_to_py<'py>(
    py: Python<'py>,
    details: &[(String, DetailValue)],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in details {
        dict.set_item(key, value.to_py_object(py)?)?;
    }
    Ok(dict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_accessors_extract_typed_values() {
        let details = vec![
            (
                "import_reference".to_string(),
                DetailValue::String("os.system".to_string()),
            ),
            ("position".to_string(), DetailValue::UInt(42)),
            ("signed_position".to_string(), DetailValue::Int(7)),
            ("negative".to_string(), DetailValue::Int(-1)),
        ];

        assert_eq!(
            detail_string(&details, "import_reference").as_deref(),
            Some("os.system")
        );
        assert_eq!(detail_usize(&details, "position"), Some(42));
        assert_eq!(detail_usize(&details, "signed_position"), Some(7));
        assert_eq!(detail_usize(&details, "negative"), None);
    }

    #[test]
    fn notice_and_error_detail_values_preserve_contract_fields() {
        let notice = Notice {
            message: "partial".to_string(),
            severity: "info",
            location: Some("nested.pkl".to_string()),
            code: Some("parse_incomplete"),
            details: vec![("analysis_incomplete".to_string(), DetailValue::Bool(true))],
        };
        let error = ScanError {
            message: "bad opcode".to_string(),
            category: "parse_error",
            location: None,
            exception_type: Some("ValueError"),
            details: vec![("position".to_string(), DetailValue::UInt(3))],
        };

        match notice_to_detail_value(notice) {
            DetailValue::Dict(details) => {
                assert_eq!(
                    detail_string(&details, "message").as_deref(),
                    Some("partial")
                );
                assert_eq!(
                    detail_string(&details, "code").as_deref(),
                    Some("parse_incomplete")
                );
            }
            _ => panic!("notice detail should be a dict"),
        }
        match scan_error_to_detail_value(error) {
            DetailValue::Dict(details) => {
                assert_eq!(
                    detail_string(&details, "message").as_deref(),
                    Some("bad opcode")
                );
                assert_eq!(
                    detail_string(&details, "exception_type").as_deref(),
                    Some("ValueError")
                );
            }
            _ => panic!("error detail should be a dict"),
        }
    }
}

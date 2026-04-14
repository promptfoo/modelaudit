use pyo3::conversion::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

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
    pub(crate) fn to_py_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            DetailValue::String(value) => value.clone().into_py_any(py),
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
            DetailValue::Dict(values) => {
                let dict = PyDict::new(py);
                for (key, value) in values {
                    dict.set_item(key, value.to_py_object(py)?)?;
                }
                Ok(dict.into_any().unbind())
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct Finding {
    pub(crate) message: String,
    pub(crate) severity: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) rule_code: Option<&'static str>,
    pub(crate) details: Vec<(String, DetailValue)>,
    pub(crate) why: Option<&'static str>,
}

pub(crate) type FindingDedupeKey = (String, Option<String>, Option<&'static str>);

impl Finding {
    pub(crate) fn dedupe_key(&self) -> FindingDedupeKey {
        (self.message.clone(), self.location.clone(), self.rule_code)
    }

    pub(crate) fn to_py_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        dict.set_item("message", &self.message)?;
        dict.set_item("severity", self.severity)?;
        dict.set_item("location", self.location.clone())?;
        dict.set_item("rule_code", self.rule_code)?;
        dict.set_item("details", detail_dict_to_py(py, &self.details)?)?;
        dict.set_item("why", self.why)?;
        Ok(dict.into_any().unbind())
    }
}

#[derive(Clone)]
pub(crate) struct Notice {
    pub(crate) message: String,
    pub(crate) severity: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) code: Option<&'static str>,
    pub(crate) details: Vec<(String, DetailValue)>,
}

pub(crate) type NoticeDedupeKey = (Option<&'static str>, Option<String>, String);

impl Notice {
    pub(crate) fn dedupe_key(&self) -> NoticeDedupeKey {
        (self.code, self.location.clone(), self.message.clone())
    }

    pub(crate) fn to_py_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        dict.set_item("message", &self.message)?;
        dict.set_item("severity", self.severity)?;
        dict.set_item("location", self.location.clone())?;
        dict.set_item("code", self.code)?;
        dict.set_item("details", detail_dict_to_py(py, &self.details)?)?;
        Ok(dict.into_any().unbind())
    }
}

#[derive(Clone)]
pub(crate) struct ScanError {
    pub(crate) message: String,
    pub(crate) category: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) exception_type: Option<&'static str>,
    pub(crate) details: Vec<(String, DetailValue)>,
}

impl ScanError {
    pub(crate) fn to_py_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        dict.set_item("message", &self.message)?;
        dict.set_item("category", self.category)?;
        dict.set_item("location", self.location.clone())?;
        dict.set_item("exception_type", self.exception_type)?;
        dict.set_item("details", detail_dict_to_py(py, &self.details)?)?;
        Ok(dict.into_any().unbind())
    }
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

pub(crate) fn scan_error_to_detail_value(error: &ScanError) -> DetailValue {
    DetailValue::Dict(vec![
        (
            "message".to_string(),
            DetailValue::String(error.message.clone()),
        ),
        (
            "category".to_string(),
            DetailValue::String(error.category.to_string()),
        ),
        (
            "location".to_string(),
            error
                .location
                .clone()
                .map(DetailValue::String)
                .unwrap_or(DetailValue::None),
        ),
        (
            "exception_type".to_string(),
            error
                .exception_type
                .map(|value| DetailValue::String(value.to_string()))
                .unwrap_or(DetailValue::None),
        ),
        (
            "details".to_string(),
            DetailValue::Dict(error.details.clone()),
        ),
    ])
}

pub(crate) fn notice_to_detail_value(notice: &Notice) -> DetailValue {
    DetailValue::Dict(vec![
        (
            "message".to_string(),
            DetailValue::String(notice.message.clone()),
        ),
        (
            "severity".to_string(),
            DetailValue::String(notice.severity.to_string()),
        ),
        (
            "location".to_string(),
            notice
                .location
                .clone()
                .map(DetailValue::String)
                .unwrap_or(DetailValue::None),
        ),
        (
            "code".to_string(),
            notice
                .code
                .map(|value| DetailValue::String(value.to_string()))
                .unwrap_or(DetailValue::None),
        ),
        (
            "details".to_string(),
            DetailValue::Dict(notice.details.clone()),
        ),
    ])
}

fn detail_dict_to_py(py: Python<'_>, details: &[(String, DetailValue)]) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in details {
        dict.set_item(key, value.to_py_object(py)?)?;
    }
    Ok(dict.unbind())
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

        match notice_to_detail_value(&notice) {
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
        match scan_error_to_detail_value(&error) {
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

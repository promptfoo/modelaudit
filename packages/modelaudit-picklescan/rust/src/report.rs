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

impl Finding {
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

impl Notice {
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

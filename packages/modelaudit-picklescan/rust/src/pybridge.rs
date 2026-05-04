use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyDict;
use std::time::Instant;

use crate::options::ScanOptions;
use crate::state::ScanState;

#[pyfunction]
#[pyo3(signature = (payload, source, options, bytes_total=None, position_offset=0, nested_depth=0))]
pub(crate) fn scan_bytes(
    py: Python<'_>,
    payload: PyBackedBytes,
    source: &str,
    options: &Bound<'_, PyDict>,
    bytes_total: Option<usize>,
    position_offset: usize,
    nested_depth: usize,
) -> PyResult<Py<PyDict>> {
    let options = ScanOptions::from_py(options)?;
    let source = source.to_string();
    let started_at = Instant::now();
    ScanState::set_runtime_python_minor_version(py.version_info().minor);
    let mut scan = ScanState::new(
        source,
        payload.as_ref(),
        &options,
        bytes_total,
        position_offset,
        nested_depth,
        None,
    );
    py.detach(|| scan.run());
    scan.to_py_report(py, started_at.elapsed().as_secs_f64())
}

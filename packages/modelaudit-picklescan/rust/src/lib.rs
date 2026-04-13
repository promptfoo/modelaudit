use pyo3::prelude::*;

mod nested;
mod opcode;
mod policy;
mod pybridge;
mod report;
mod state;
mod strings;

#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pybridge::scan_bytes, m)?)?;
    Ok(())
}

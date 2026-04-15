use pyo3::prelude::*;

mod expansion;
mod nested;
mod nested_surface;
mod opcode;
mod options;
mod policy;
mod post_budget;
mod pybridge;
mod report;
mod stack;
mod state;
mod strings;
mod strings_policy;

#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pybridge::scan_bytes, m)?)?;
    Ok(())
}

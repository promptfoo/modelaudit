# Scripts Directory

This directory contains utility scripts for development, testing, and comparison purposes. These scripts are not part of the main ModelAudit package and are not published to PyPI.

## Files

### `comprehensive_modelscan_test.py`

A comprehensive testing script that compares ModelAudit vs modelscan across various model categories and formats. This script:

- Tests multiple model categories (ONNX, GGUF, PyTorch, etc.)
- Runs both tools on the same models for comparison
- Generates detailed comparison reports
- Identifies blind spots and detection gaps

**Usage:**

```bash
# Test a specific category
python scripts/comprehensive_modelscan_test.py ONNX_BLIND_SPOTS

# Test all categories (shows detailed time estimates)
python scripts/comprehensive_modelscan_test.py
```

**Features:**

- Detailed time estimates based on model count (≈2 min per model)
- Progress tracking with category/model counts
- Intermediate results saved as JSON for recovery
- Automatic cleanup of temporary files on completion

**Requirements:**

- ModelAudit installed (`rye sync --features all`)
- modelscan installed (`pip install modelscan`)
- Sufficient disk space for model downloads

**Output:**

- Generates `comprehensive_comparison_report.md` with detailed results
- Console output with real-time comparison results
- Evidence for security gap analysis

## Development Use Only

These scripts are intended for:

- Internal testing and validation
- Competitive analysis and benchmarking
- Research and development purposes
- Generating documentation and evidence

They should not be used in production environments.

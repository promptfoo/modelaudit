# ModelAudit Test Suite

This directory contains comprehensive tests for the ModelAudit security scanning system.

## Test Structure

### Core Tests
- **`test_asset_scan.py`** - Basic tests for individual asset scanning with expected exit codes
- **`test_asset_integration.py`** - Comprehensive integration tests for end-to-end functionality
- **`test_performance_benchmarks.py`** - Performance and benchmarking tests

### Test Assets
- **`assets/`** - Directory containing both malicious and safe test assets
  - Malicious examples: `evil_pickle.pkl`, `malicious_keras.h5`, `malicious_pytorch.pt`, etc.
  - Safe examples: `safe_pickle.pkl`, `safe_keras.h5`, `safe_pytorch.pt`, etc.
  - **`generate_assets.py`** - Script to regenerate test assets if needed

## Running Tests

### Basic Asset Tests
```bash
# Run basic asset scanning tests
pytest tests/test_asset_scan.py -v

# Test specific asset type
pytest tests/test_asset_scan.py::test_asset_scan_exit_codes[evil_pickle.pkl-1] -v
```

### Integration Tests
```bash
# Run all integration tests
pytest tests/test_asset_integration.py -v

# Run specific integration test categories
pytest tests/test_asset_integration.py::TestAssetIntegration::test_end_to_end_malicious_detection -v
pytest tests/test_asset_integration.py::TestAssetIntegration::test_cli_integration_malicious_directory -v
pytest tests/test_asset_integration.py::TestAssetIntegration::test_mixed_directory_scanning -v
```

### Performance Tests
```bash
# Run performance benchmarks (faster tests)
pytest tests/test_performance_benchmarks.py -v

# Run stress tests (slower)
pytest tests/test_performance_benchmarks.py -v -m slow

# Run specific performance tests
pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_single_file_performance -v
pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_concurrent_performance -v
```

### All Tests
```bash
# Run entire test suite
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=modelaudit --cov-report=html
```

## Test Categories

### 1. Asset Validation Tests
- **Purpose**: Ensure malicious assets are detected and safe assets pass validation
- **Coverage**: All supported ML model formats (PyTorch, TensorFlow, Keras, Pickle, ZIP, JSON)
- **Key Tests**:
  - `test_end_to_end_malicious_detection` - Validates all malicious assets trigger security warnings
  - `test_end_to_end_safe_validation` - Ensures safe assets don't trigger false positives
  - `test_regression_no_false_positives` - Regression test for false positive patterns

### 2. CLI Integration Tests
- **Purpose**: Test command-line interface functionality
- **Coverage**: Text and JSON output formats, directory vs file scanning, error handling
- **Key Tests**:
  - `test_cli_integration_malicious_directory` - CLI scanning of malicious content
  - `test_cli_integration_safe_directory` - CLI scanning of safe content
  - `test_output_format_consistency` - Consistency between API and CLI results

### 3. Performance & Scalability Tests
- **Purpose**: Ensure scanning performance meets requirements and scales appropriately
- **Coverage**: Single files, directories, concurrent scanning, memory usage
- **Key Tests**:
  - `test_single_file_performance` - Individual file scanning benchmarks
  - `test_directory_scanning_performance` - Directory scanning benchmarks
  - `test_scaling_performance` - Performance scaling with file count
  - `test_concurrent_performance` - Multi-threaded scanning performance
  - `test_memory_usage_stability` - Memory leak detection

### 4. Error Handling Tests
- **Purpose**: Validate proper error handling and exit codes
- **Coverage**: File not found, permission errors, timeout handling
- **Key Tests**:
  - `test_error_handling_integration` - Various error scenarios
  - `test_timeout_handling` - Timeout mechanism validation

### 5. Consistency & Regression Tests
- **Purpose**: Ensure consistent results across runs and prevent regressions
- **Coverage**: Repeated scans, format consistency, asset completeness
- **Key Tests**:
  - `test_repeated_scanning_consistency` - Results consistency across multiple runs
  - `test_asset_completeness` - Validates all expected test assets exist

## Performance Thresholds

The performance tests include configurable thresholds:

```python
performance_thresholds = {
    "single_file_scan_max_time": 5.0,    # seconds
    "directory_scan_max_time": 30.0,     # seconds  
    "memory_growth_max_mb": 100,         # MB
    "files_per_second_min": 1.0,         # files/second minimum
    "bytes_per_second_min": 1024,        # bytes/second minimum
}
```

## Test Assets

### Malicious Assets
- **`evil_pickle.pkl`** - Pickle with `__reduce__` calling `os.system`
- **`malicious_keras.h5`** - Keras model with Lambda layer executing code
- **`malicious_pytorch.pt`** - PyTorch ZIP with malicious pickle
- **`malicious_tf/`** - TensorFlow SavedModel with PyFunc node
- **`malicious_manifest.json`** - JSON with leaked API keys/URLs
- **`malicious_zip.zip`** - ZIP with directory traversal + malicious content

### Safe Assets
- **`safe_pickle.pkl`** - Simple dictionary pickle (no code execution)
- **`safe_keras.h5`** - Basic Sequential Keras model
- **`safe_pytorch.pt`** - PyTorch ZIP with benign pickle data
- **`safe_tf/`** - SavedModel with only constant operations
- **`safe_manifest.json`** - Benign configuration manifest
- **`safe_zip.zip`** - ZIP with harmless text file

## Regenerating Test Assets

If you need to recreate the test assets:

```bash
cd tests/assets/
python generate_assets.py
```

This will regenerate all test assets with known malicious and safe patterns.

## CI/CD Integration

These tests are designed for CI/CD integration:

```yaml
# Example GitHub Actions integration
- name: Run Security Tests
  run: pytest tests/test_asset_scan.py tests/test_asset_integration.py -v

- name: Run Performance Tests  
  run: pytest tests/test_performance_benchmarks.py -v --tb=short

- name: Generate Coverage Report
  run: pytest tests/ --cov=modelaudit --cov-report=xml
```

## Adding New Tests

### For New Model Formats
1. Add test assets to `assets/` directory (both safe and malicious versions)
2. Update `generate_assets.py` to include asset generation code
3. Add entries to `ASSETS` list in `test_asset_scan.py`
4. Update integration tests to include new format

### For New Security Checks
1. Create specific test assets that trigger the new security check
2. Add integration tests to validate detection
3. Add performance tests if the new check impacts scanning speed
4. Update regression tests to prevent false positives

## Troubleshooting

### Common Issues

**Missing Dependencies**: Some tests require optional dependencies:
```bash
pip install psutil  # For memory usage tests
pip install tensorflow  # For TensorFlow model tests (optional)
```

**Asset Generation Failures**: Ensure you have all required dependencies:
```bash
pip install h5py torch  # Required for asset generation
```

**Performance Test Failures**: Performance thresholds may need adjustment for different hardware:
- Modify thresholds in `test_performance_benchmarks.py`
- Consider system load when running performance tests

**Permission Errors**: Some error handling tests create temporary files with restricted permissions:
- These tests may behave differently on different operating systems
- Tests are designed to handle platform differences gracefully 
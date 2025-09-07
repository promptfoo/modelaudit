# Mock Improvements Migration Guide

This guide shows how to migrate existing tests to use the new fast mocking utilities for improved performance.

## Quick Start

The fastest way to speed up tests is to use the provided fixtures:

```python
# Before: Slow test with real file I/O
def test_scanner(tmp_path):
    model_file = tmp_path / "model.pkl"
    model_file.write_bytes(pickle.dumps({"data": "test"}))

    scanner = MyScanner()
    result = scanner.scan(str(model_file))
    assert result.success

# After: Fast test with mocked I/O
def test_scanner(fast_file_operations):
    fast_file_operations.add_file('/tmp/model.pkl', pickle.dumps({"data": "test"}))

    scanner = MyScanner()
    result = scanner.scan('/tmp/model.pkl')
    assert result.success
```

## Available Fixtures

### Core Performance Fixtures

- `fast_filesystem` - In-memory filesystem for file operations
- `fast_test_env` - Complete mocked environment (files, network, ML libs)
- `no_sleep` - Mock time.sleep to prevent delays
- `fast_tempfiles` - Mock temporary file creation
- `mock_subprocess` - Mock subprocess calls
- `fast_network_calls` - Mock all network requests

### ML-Specific Fixtures

- `mock_heavy_ml_libs` - Mock PyTorch, TensorFlow, NumPy, etc.
- `fast_scanner_result` - Pre-built mock scanner results

### Specialized Performance Fixtures

- `fast_crypto` - Mock cryptographic operations (hashlib, etc.)
- `fast_compression` - Mock compression operations (zipfile, tarfile)
- `fast_cache` - In-memory cache for caching operations
- `no_logging` - Disable logging for performance
- `ultra_fast_env` - ALL performance mocks enabled
- `fast_secure_hasher` - Mock SecureFileHasher class

## Migration Patterns

### 1. File I/O Operations

```python
# BEFORE: Real file operations
def test_pickle_scanning(tmp_path):
    pickle_file = tmp_path / "test.pkl"
    with open(pickle_file, 'wb') as f:
        pickle.dump(malicious_data, f)

    scanner = PickleScanner()
    result = scanner.scan(str(pickle_file))

# AFTER: Fast mocked file operations
def test_pickle_scanning(fast_file_operations):
    fast_file_operations.add_file('/tmp/test.pkl', pickle.dumps(malicious_data))

    scanner = PickleScanner()
    result = scanner.scan('/tmp/test.pkl')
```

### 2. Network Operations

```python
# BEFORE: Mocked network calls (slow setup)
@patch('requests.get')
def test_download(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b'model data'
    mock_get.return_value = mock_response

    result = download_model('https://example.com/model.pt')

# AFTER: Fast network mocking
def test_download(fast_network_calls):
    # Network calls are automatically mocked with sensible defaults
    result = download_model('https://example.com/model.pt')
    assert result is not None
```

### 3. Heavy ML Dependencies

```python
# BEFORE: Real imports (slow)
def test_tensorflow_model():
    import tensorflow as tf  # Slow import
    model = tf.keras.models.Sequential()
    # ... test logic

# AFTER: Mocked ML libraries
def test_tensorflow_model(mock_heavy_ml_libs):
    import tensorflow as tf  # Fast mock import
    model = tf.keras.models.Sequential()
    # ... test logic works with mocks
```

### 4. Time-Based Operations

```python
# BEFORE: Real delays
def test_timeout_handling():
    start = time.time()
    with pytest.raises(TimeoutError):
        slow_operation(timeout=0.1)
    duration = time.time() - start
    assert duration >= 0.1  # Actual wait

# AFTER: No delays
def test_timeout_handling(no_sleep):
    start = time.time()
    with pytest.raises(TimeoutError):
        slow_operation(timeout=0.1)
    # Test completes instantly
```

### 5. Cryptographic Operations

```python
# BEFORE: Real hashing (CPU intensive)
def test_file_hashing():
    import hashlib
    hasher = hashlib.sha256()
    hasher.update(large_file_content)  # Slow for large files
    file_hash = hasher.hexdigest()

# AFTER: Fast crypto mocking
def test_file_hashing(fast_crypto):
    import hashlib
    hasher = hashlib.sha256()
    hasher.update(large_file_content)  # Instant with mocking
    file_hash = hasher.hexdigest()  # Returns 'fake_hex_digest'
```

### 6. Compression Operations

```python
# BEFORE: Real zip operations (I/O intensive)
def test_zip_scanning(tmp_path):
    zip_file = tmp_path / "model.zip"
    # Create real zip file...
    with zipfile.ZipFile(zip_file, 'r') as zf:
        files = zf.namelist()

# AFTER: Fast compression mocking
def test_zip_scanning(fast_compression):
    with zipfile.ZipFile('/fake/model.zip', 'r') as zf:
        files = zf.namelist()  # Instant, returns mock file list
```

### 7. Cache Operations

```python
# BEFORE: Real cache with potential I/O
def test_caching(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = RealCacheImplementation(cache_dir)
    cache.set("key", "value")

# AFTER: Fast in-memory cache
def test_caching(fast_cache):
    fast_cache.set("key", "value")  # Instant in-memory operation
    assert fast_cache.get("key") == "value"
```

### 8. Ultra-Fast Environment

For tests that need everything mocked:

```python
# BEFORE: Multiple fixture usage
def test_complex_workflow(fast_file_operations, fast_crypto, fast_compression, no_logging, no_sleep):
    # Setup multiple mocks manually...

# AFTER: Single ultra-fast fixture
def test_complex_workflow(ultra_fast_env):
    with ultra_fast_env as env:
        # ALL operations are now ultra-fast:
        # - File I/O uses in-memory filesystem
        # - Network calls return instant responses
        # - ML library imports are mocked
        # - Crypto operations are instant
        # - Compression operations are mocked
        # - Logging is disabled
        # - time.sleep is disabled
        # - Subprocess calls are mocked

        env.add_file('/tmp/model.pkl', b'model data')
        result = complex_model_processing_workflow('/tmp/model.pkl')
        assert result.success
```

### 9. Complete Fast Environment (Legacy)

Standard fast environment without specialized mocks:

```python
def test_standard_workflow():
    with setup_fast_test_environment() as env:
        # Basic fast operations only
        env.add_file('/tmp/model.pkl', b'model data')
        result = basic_model_processing('/tmp/model.pkl')
        assert result.success
```

## Performance Gains

Expected speedups with the new mocking:

### Core Operations

- **File I/O**: 5-50x faster (depends on file size)
- **Network calls**: 100-1000x faster
- **ML library imports**: 10-100x faster
- **Time-based operations**: Instant vs real delays

### Specialized Operations

- **Cryptographic hashing**: 50-500x faster (depends on data size)
- **Compression operations**: 20-100x faster (no real compression/decompression)
- **Cache operations**: 10-50x faster (in-memory vs disk-based)
- **Logging operations**: 5-20x faster (disabled vs formatted output)
- **Serialization**: 10-100x faster (mocked vs real JSON/YAML parsing)

### Combined Impact

- **Individual tests**: 2-50x faster (depending on operations used)
- **Overall test suite**: 3-15x faster (compound effect)
- **CI/CD pipelines**: 2-10x faster (reduced I/O wait times)

## Best Practices

### Use the Right Fixture

- `fast_file_operations` - For tests with file I/O
- `mock_heavy_ml_libs` - For tests importing ML libraries
- `fast_network_calls` - For tests with HTTP requests
- `fast_test_env` - For integration tests needing everything

### Fixture Combinations

Combine fixtures for maximum speed:

```python
def test_comprehensive(mock_heavy_ml_libs, fast_file_operations, no_sleep):
    # All slow operations are now mocked
    pass
```

### Gradual Migration

Start with the slowest tests first:

1. Identify slow tests: `rye run pytest --durations=10`
2. Add appropriate fixtures to the slowest tests
3. Measure improvement: `rye run pytest tests/test_slow_one.py --durations=0`
4. Repeat for remaining slow tests

### When NOT to Use Fast Mocking

- Integration tests that need real I/O behavior
- Tests specifically testing file system edge cases
- Performance benchmarks measuring real operation speeds
- Tests marked with `@pytest.mark.integration`

Use test markers to selectively enable/disable mocking:

```python
@pytest.mark.integration  # Skip fast mocking for integration tests
def test_real_file_behavior(tmp_path):
    # Use real file operations for integration testing
    pass

@pytest.mark.unit  # Use fast mocking for unit tests
def test_scanner_logic(fast_file_operations):
    # Use mocked operations for fast unit testing
    pass
```

## Measuring Improvements

Before and after performance comparison:

```bash
# Measure before migration
rye run pytest tests/test_my_module.py --durations=0

# Migrate tests using this guide

# Measure after migration
rye run pytest tests/test_my_module.py --durations=0

# Compare results - should see significant speedup
```

## Troubleshooting

### Mock Not Working

Make sure fixture is used correctly:

```python
# WRONG: Fixture not used
def test_something():
    fast_filesystem = FastFileSystem()  # Won't affect test

# RIGHT: Fixture injected
def test_something(fast_filesystem):
    # Fixture is active during test
```

### Missing Attributes

If mocks are missing attributes, extend them:

```python
def test_custom_mock(mock_heavy_ml_libs):
    torch = mock_heavy_ml_libs['torch']
    torch.cuda.is_available.return_value = True  # Add missing method
```

### Test Failures After Migration

Check if test logic depends on real file system behavior:

```python
# This might fail with mocks if test expects real file attributes
def test_file_stats(tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_text("content")
    stat = file_path.stat()
    assert stat.st_size == 7  # Real stat

# Solution: Use real files for tests that need real stat behavior
# Or mock stat() to return expected values
```


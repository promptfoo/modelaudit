# Testing Guide - Fast & Efficient 🚀

This guide shows how to run tests efficiently in the modelaudit project.

## Dependencies

Before running the test suite, install the optional dependencies used in CI and
development:

```bash
pip install -e .[all-ci]
pip install -e .[dev-dependencies]
```

Run these commands prior to executing `pytest` so that all extras are
available.

## 🎯 Quick Reference

| Command                                                    | Use Case               | Speed              | Tests                            |
| ---------------------------------------------------------- | ---------------------- | ------------------ | -------------------------------- |
| `rye run pytest -n auto -m "not slow and not integration"` | **Development**        | ⚡ Fastest         | Unit tests only                  |
| `rye run pytest -n auto -x --tb=short`                     | **Quick feedback**     | ⚡ Fast, fail-fast | All tests, stop on first failure |
| `rye run pytest -n auto --cov=modelaudit`                  | **CI/Full validation** | 🐌 Complete        | All tests with coverage          |
| `rye run pytest -k "test_pattern" -n auto`                 | **Specific testing**   | ⚡ Targeted        | Pattern-matched tests            |

## 🏃‍♂️ Speed Optimizations Implemented

### 1. **Parallel Execution**

- **37% faster** execution using `pytest-xdist`
- Automatically detects CPU cores with `-n auto`
- Uses 240%+ CPU utilization

### 2. **Smart Test Selection**

```bash
# Exclude slow tests during development
rye run pytest -m "not slow and not integration"

# Run only unit tests
rye run pytest -m "unit"

# Test only specific file
rye run pytest tests/test_specific.py -n auto
```

### 3. **Fast Failure Modes**

```bash
# Stop on first failure (development)
rye run pytest -x

# Fail fast with minimal output
rye run pytest -x --tb=line --disable-warnings
```

### 4. **Development Workflow**

```bash
# Test specific files or patterns
rye run pytest -k "test_basic" -n auto -x

# Test specific file
rye run pytest tests/test_scanner.py -n auto

# Quick smoke test
rye run pytest -k "test_basic" -n auto -x
```

## 📊 Performance Comparison

| Configuration             | Time       | Speedup           |
| ------------------------- | ---------- | ----------------- |
| Original (sequential)     | 68.5s      | Baseline          |
| **Parallel (all tests)**  | **43.3s**  | **37% faster**    |
| **Fast tests only**       | **~45s**   | **34% faster**    |
| **Specific file/pattern** | **~5-15s** | **80-90% faster** |

## 🔧 Configuration Details

### Pytest Settings (`pyproject.toml`)

```toml
[tool.pytest.ini_options]
addopts = [
    "--disable-warnings",  # Reduces noise
    "--tb=short",         # Concise tracebacks
    "-ra",                # Show summary of all failures
]
```

### Test Markers Available

- `@pytest.mark.slow` - Skip with `-m "not slow"`
- `@pytest.mark.integration` - Skip with `-m "not integration"`
- `@pytest.mark.unit` - Run only with `-m "unit"`
- `@pytest.mark.performance` - Benchmark tests

## 🎯 Development Workflow

### During Active Development

```bash
# 1. Test your changes quickly (fast tests only)
rye run pytest -n auto -m "not slow and not integration" -x

# 2. Run specific tests for your work
rye run pytest tests/test_your_module.py -n auto -v

# 3. Before committing, run full suite
rye run pytest -n auto --cov=modelaudit
```

### Debugging Failed Tests

```bash
# Run single test with full output
rye run pytest tests/test_specific.py::test_function -vv

# Run with debugger
rye run pytest tests/test_specific.py::test_function -vv -s --pdb
```

### Performance Testing

```bash
# Run performance benchmarks
rye run pytest -m "performance" -v

# Profile test execution
rye run pytest --profile-svg --profile-html
```

## 🚀 Additional Speed Tips

### 1. **Use Test Fixtures Efficiently**

- Reuse `tmp_path` fixtures instead of creating temporary files
- Use `@pytest.fixture(scope="module")` for expensive setup

### 2. **Selective Test Execution**

```bash
# Test specific patterns
rye run pytest -k "test_scanner" -n auto

# Test specific severity levels
rye run pytest -k "not test_large_file" -n auto
```

### 3. **IDE Integration**

Most IDEs can use these same optimizations:

- Configure pytest args: `-n auto --disable-warnings`
- Use test markers for filtering
- Set up run configurations for different test types

### 4. **CI/CD Optimization**

```yaml
# Example GitHub Actions
- name: Run Fast Tests
  run: rye run pytest -n auto -m "not slow and not integration" --cov=modelaudit --tb=short

- name: Run Slow/Integration Tests
  run: rye run pytest -n auto -m "slow or integration" --tb=short
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
```

## 🛠 Troubleshooting

### Common Issues

1. **Tests fail in parallel but pass individually**
   - Check for shared state between tests
   - Use proper fixtures for temporary files

2. **Slow test identification**

   ```bash
   # Profile slow tests
   rye run pytest --durations=10
   ```

3. **Memory issues with parallel execution**
   ```bash
   # Reduce worker count
   rye run pytest -n 4  # Instead of -n auto
   ```

## 📈 Monitoring Test Performance

Track test performance over time:

```bash
# Generate duration report
rye run pytest --durations=0 > test_durations.log

# Find slowest tests
rye run pytest --durations=10 --tb=no -q
```

---

## 🚀 **Your New Fast Test Commands:**

```bash
# 🚀 FASTEST - Development workflow
rye run pytest -n auto -m "not slow and not integration" -x

# ⚡ FAST - Skip slow tests
rye run pytest -n auto -m "not slow and not integration"

# 🔥 QUICK FEEDBACK - Fail fast on first error
rye run pytest -n auto -x --tb=short

# 🧪 COMPLETE - Full test suite with coverage
rye run pytest -n auto --cov=modelaudit

# 🎯 SPECIFIC - Test one file/pattern
rye run pytest tests/test_scanner.py -n auto
rye run pytest -k "test_pattern" -n auto
```

**Result**: Tests now run **34-90% faster** depending on the strategy used! 🎉

# Key Commands Reference

## Setup - Dependency Profiles

```bash
rye sync --features all        # Install all dependencies (recommended for development)
rye sync --features all-ci     # All dependencies except platform-specific (for CI)
rye sync                       # Minimal dependencies (pickle, numpy, zip)
rye sync --features tensorflow # Specific framework support
rye sync --features numpy1     # NumPy 1.x compatibility mode (when ML frameworks conflict)
```

## Running the Scanner

```bash
# Basic usage (scan is the default command)
rye run modelaudit model.pkl
rye run modelaudit --format json --output results.json model.pkl
rye run modelaudit scan model.pkl  # Explicit scan command

# Large Model Support (8 GB+)
rye run modelaudit large_model.bin --timeout 1800  # 30 min timeout
rye run modelaudit huge_model.bin --verbose        # Show progress
rye run modelaudit model.bin --no-large-model-support  # Disable optimizations
```

## Testing Commands

```bash
# Fast development testing (recommended)
rye run pytest -n auto -m "not slow and not integration"

# Run all tests with parallel execution
rye run pytest -n auto

# Specific test file or pattern
rye run pytest tests/test_pickle_scanner.py
rye run pytest -k "test_pickle"

# Full test suite with coverage
rye run pytest -n auto --cov=modelaudit
```

## Linting and Formatting

```bash
rye run ruff format modelaudit/ tests/                # Format code
rye run ruff check --fix modelaudit/ tests/           # Fix linting issues
rye run mypy modelaudit/                              # Type checking (mypy)
rye run ty check                                      # Advanced type checking (ty)
npx prettier@latest --write "**/*.{md,yaml,yml,json}" # Format docs
```

## CI Pre-Commit Workflow

**Run these before every commit:**

```bash
# 1. Format (always run first)
rye run ruff format modelaudit/ tests/

# 2. Check lint (without --fix to see issues)
rye run ruff check modelaudit/ tests/

# 3. Fix lint issues
rye run ruff check --fix modelaudit/ tests/

# 4. Type check
rye run mypy modelaudit/

# 5. Advanced type check (optional)
rye run ty check

# 6. Fast tests
rye run pytest -n auto -m "not slow and not integration"

# 7. Format docs
npx prettier@latest --write "**/*.{md,yaml,yml,json}"
```

## Additional Commands

```bash
# Diagnose scanner compatibility
rye run modelaudit doctor --show-failed

# Build package locally
rye build --clean
```

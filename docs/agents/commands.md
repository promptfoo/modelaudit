# Key Commands Reference

## Setup - Dependency Profiles

```bash
uv sync --extra all        # Install all dependencies (recommended for development)
uv sync --extra all-ci     # All dependencies except platform-specific (for CI)
uv sync                    # Minimal dependencies (pickle, numpy, zip)
uv sync --extra tensorflow # Specific framework support
uv sync --extra numpy1     # NumPy 1.x compatibility mode (when ML frameworks conflict)
```

## Running the Scanner

```bash
# Basic usage (scan is the default command)
uv run modelaudit model.pkl
uv run modelaudit --format json --output results.json model.pkl
uv run modelaudit scan model.pkl  # Explicit scan command

# Large Model Support (8 GB+)
uv run modelaudit large_model.bin --timeout 1800  # 30 min timeout
uv run modelaudit huge_model.bin --verbose        # Show progress
uv run modelaudit model.bin --no-large-model-support  # Disable optimizations
```

## Testing Commands

```bash
# Fast development testing (recommended)
uv run pytest -n auto -m "not slow and not integration"

# Run all tests with parallel execution
uv run pytest -n auto

# Specific test file or pattern
uv run pytest tests/test_pickle_scanner.py
uv run pytest -k "test_pickle"

# Full test suite with coverage
uv run pytest -n auto --cov=modelaudit
```

## Linting and Formatting

```bash
uv run ruff format modelaudit/ tests/                # Format code
uv run ruff check --fix modelaudit/ tests/           # Fix linting issues
uv run mypy modelaudit/                              # Type checking (mypy)
uv run ty check                                      # Advanced type checking (ty)
npm ci --ignore-scripts && npx prettier --write "**/*.{md,yaml,yml,json}" # Format docs
```

## CI Pre-Commit Workflow

**Run these before every commit:**

```bash
# 1. Format (always run first)
uv run ruff format modelaudit/ tests/

# 2. Check lint (without --fix to see issues)
uv run ruff check modelaudit/ tests/

# 3. Fix lint issues
uv run ruff check --fix modelaudit/ tests/

# 4. Type check
uv run mypy modelaudit/

# 5. Advanced type check (optional)
uv run ty check

# 6. Fast tests
uv run pytest -n auto -m "not slow and not integration"

# 7. Format docs
npm ci --ignore-scripts && npx prettier --write "**/*.{md,yaml,yml,json}"
```

## Additional Commands

```bash
# Diagnose scanner compatibility
uv run modelaudit doctor --show-failed

# Build package locally
uv build
```

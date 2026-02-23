# Contributing to ModelAudit

Thank you for your interest in contributing to ModelAudit! This guide will help you get started with development and contributing to the project.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- uv (recommended) or pip
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with uv (recommended)
uv sync --extra all

# Windows (lighter optional set)
uv sync --extra all-ci-windows

# Or with pip
pip install -e .[all]
```

### Testing with Development Version

**Install and test your local development version:**

```bash
# Option 1: Install in development mode with pip
pip install -e .[all]

# Then test the CLI directly
modelaudit scan test_model.pkl

# Option 2: Use uv (recommended)
uv sync --extra all

# Test with uv run (no shell activation needed)
uv run modelaudit scan test_model.pkl

# Test with Python import
uv run python -c "from modelaudit.core import scan_file; print(scan_file('test_model.pkl'))"
```

**Create test models for development:**

```bash
# Create a simple test pickle file
python -c "import pickle; pickle.dump({'test': 'data'}, open('test_model.pkl', 'wb'))"

# Test scanning it
modelaudit scan test_model.pkl
```

### Running Tests - Fast & Efficient

This project uses optimized parallel test execution for faster development:

#### Quick Reference

| Command                                                   | Use Case               | Speed           | Tests                            |
| --------------------------------------------------------- | ---------------------- | --------------- | -------------------------------- |
| `uv run pytest -n auto -m "not slow and not integration"` | **Development**        | Fast            | Unit tests only                  |
| `uv run pytest -n auto -x --tb=short`                     | **Quick feedback**     | Fast, fail-fast | All tests, stop on first failure |
| `uv run pytest -n auto --cov=modelaudit`                  | **CI/Full validation** | Complete        | All tests with coverage          |
| `uv run pytest -k "test_pattern" -n auto`                 | **Specific testing**   | Targeted        | Pattern-matched tests            |

#### Common Test Commands

```bash
# FAST - Development testing (excludes slow tests)
uv run pytest -n auto -m "not slow and not integration"

# QUICK FEEDBACK - Fail fast on first error
uv run pytest -n auto -x --tb=short

# COMPLETE - Full test suite with coverage
uv run pytest -n auto --cov=modelaudit

# SPECIFIC - Test individual files or patterns
uv run pytest tests/test_pickle_scanner.py -n auto -v
uv run pytest -k "test_scanner" -n auto

# PERFORMANCE - Profile slow tests
uv run pytest --durations=10 --tb=no
```

#### Speed Optimizations Implemented

**Parallel Execution:**

- **37% faster** execution using `pytest-xdist`
- Automatically detects CPU cores with `-n auto`
- Uses 240%+ CPU utilization

**Smart Test Selection:**

- Exclude slow tests during development: `-m "not slow and not integration"`
- Run only unit tests: `-m "unit"`
- Test specific files: `pytest tests/test_specific.py -n auto`

**Performance Comparison:**
| Configuration | Time | Speedup |
|--------------|------|---------|
| Original (sequential) | 68.5s | Baseline |
| **Parallel (all tests)** | **43.3s** | **37% faster** |
| **Fast tests only** | **~45s** | **34% faster** |
| **Specific file/pattern** | **~5-15s** | **80-90% faster** |

**Test Markers Available:**

- `@pytest.mark.slow` - Skip with `-m "not slow"`
- `@pytest.mark.integration` - Skip with `-m "not integration"`
- `@pytest.mark.unit` - Run only with `-m "unit"`
- `@pytest.mark.performance` - Benchmark tests

### Development Workflow

```bash
# Run linting and formatting with Ruff
uv run ruff check .          # Check entire codebase (including tests)
uv run ruff check --fix .    # Automatically fix lint issues
uv run ruff format .         # Format code

# Type checking
uv run mypy modelaudit/

# Build package
uv build

# The generated distribution contains only the `modelaudit` code and metadata.
# Unnecessary files like tests and Docker configurations are excluded via
# `MANIFEST.in`.

# Publish (maintainers only)
uv publish
```

**Code Quality Tools:**

This project uses modern Python tooling for maintaining code quality:

- **[Ruff](https://docs.astral.sh/ruff/)**: Ultra-fast Python linter and formatter (replaces Black, isort, flake8)
- **[MyPy](https://mypy.readthedocs.io/)**: Static type checker
- **[Prettier](https://prettier.io/)**: Fast formatter for JSON and YAML files

**File Formatting with Prettier:**

```bash
# Format JSON and YAML files
npx prettier --write .

# Check formatting (for CI)
npx prettier --check .
```

## Contributing Guidelines

### Getting Started

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make your changes...
git add .
git commit -m "feat: description"
git push origin feature/your-feature-name
```

**Pull Request Guidelines:**

- Create PR against `main` branch
- Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, etc.)
- All PRs are squash-merged with a conventional commit message
- Keep changes small and focused
- Add tests for new functionality
- Update documentation as needed

### Reporting False Positives / False Negatives

Detection quality reports are high priority and should be reproducible.

Include the following:

- ModelAudit version and Python version
- Exact command used (including flags)
- Expected result vs actual result
- Minimal reproducible sample (or a redacted/synthetic equivalent)
- Why the behavior is a false positive or false negative

If sharing a model artifact is not possible, include:

- File format and extension
- Relevant metadata/layout details
- Representative snippets (redacted) that trigger or evade detection

For sensitive security bypass details, use the private disclosure process in `SECURITY.md` instead of a public issue.

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation updates
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### Project Structure

```
modelaudit/
├── modelaudit/
│   ├── scanners/          # Model format scanners
│   │   ├── base.py                    # Base scanner class
│   │   ├── pickle_scanner.py          # Pickle/joblib security scanner
│   │   ├── tf_savedmodel_scanner.py   # TensorFlow SavedModel scanner
│   │   ├── keras_h5_scanner.py        # Keras H5 model scanner
│   │   ├── pytorch_zip_scanner.py     # PyTorch ZIP format scanner
│   │   ├── pytorch_binary_scanner.py  # PyTorch binary format scanner
│   │   ├── safetensors_scanner.py     # SafeTensors format scanner
│   │   ├── weight_distribution_scanner.py # Weight analysis scanner
│   │   ├── zip_scanner.py             # ZIP archive scanner
│   │   └── manifest_scanner.py        # Config/manifest scanner
│   ├── utils/             # Utility modules
│   ├── auth/              # Authentication modules
│   ├── name_policies/     # Name policy modules
│   ├── cli.py            # Command-line interface
│   └── core.py           # Core scanning logic
├── tests/                # Test suite
├── .github/              # GitHub Actions workflows
└── README.md             # User documentation
```

### Adding New Scanners

When adding a new scanner for a model format:

1. Create a new scanner file in `modelaudit/scanners/`
2. Implement the scanner class following existing patterns
3. Add appropriate tests in `tests/`
4. Update documentation
5. Add any new dependencies to `pyproject.toml`

For the security-focused implementation checklist, see `docs/agents/new-scanner-quickstart.md`.

### Code Style

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write descriptive docstrings
- Keep functions focused and small
- Add comments for complex logic

### Testing

- Write tests for all new functionality
- Ensure tests pass locally before submitting PR
- Include both unit tests and integration tests
- Test with different model formats and edge cases

## Development Tasks

### Common Development Tasks

```bash
# Run full test suite with coverage (optimized parallel execution)
uv run pytest -n auto --cov=modelaudit --cov-report=html

# Check for type errors
uv run mypy modelaudit/

# Format and lint code
uv run ruff format .
uv run ruff check --fix .

# Quick development test cycle
uv run pytest -n auto -m "not slow and not integration" -x

# Build documentation (if applicable)
# Add documentation build commands here

# Create test models for specific formats
python -c "import torch; torch.save({'model': 'data'}, 'test.pt')"
python -c "import pickle; pickle.dump({'test': 'malicious'}, open('malicious.pkl', 'wb'))"
```

The curated model regression corpus is documented in `docs/agents/model-test-corpus.md`.

### Release Process (Maintainers)

Releases are fully automated via [release-please](https://github.com/googleapis/release-please) and GitHub Actions. When conventional commits land on `main`, release-please opens (or updates) a release PR. Merging that PR triggers the build, publish to PyPI, SBOM generation, and provenance attestation pipeline.

See `docs/agents/release-process.md` for the full workflow details.

## Reporting Issues

When reporting issues:

- Use the GitHub issue templates
- Include ModelAudit version and Python version
- Provide minimal reproduction steps
- Include error messages and stack traces
- Mention the model format and size if applicable

## Feature Requests

For feature requests:

- Check existing issues first
- Describe the use case clearly
- Explain why it would benefit users
- Consider proposing an implementation approach

## Getting Help

- GitHub Issues: For bugs and feature requests
- GitHub Discussions: For questions and general discussion
- Email: For security issues or private matters

Thank you for contributing to ModelAudit!

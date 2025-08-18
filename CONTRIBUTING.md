# Contributing to ModelAudit

Thank you for your interest in contributing to ModelAudit! This guide will help you get started with development and contributing to the project.

## 🛠️ Development Setup

### Prerequisites

- Python 3.9 or higher
- Rye (recommended) or pip
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with Rye (recommended)
rye sync --features all

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

# Option 2: Use Rye (recommended)
rye sync --features all

# Test with Rye run (no shell activation needed)
rye run modelaudit scan test_model.pkl

# Test with Python import
rye run python -c "from modelaudit.core import scan_file; print(scan_file('test_model.pkl'))"
```

**Create test models for development:**

```bash
# Create a simple test pickle file
python -c "import pickle; pickle.dump({'test': 'data'}, open('test_model.pkl', 'wb'))"

# Test scanning it
modelaudit scan test_model.pkl
```

### Running Tests

This project uses optimized parallel test execution for faster development:

```bash
# 🚀 FAST - Development testing (excludes slow tests)
rye run pytest -n auto -m "not slow and not integration"

# ⚡ QUICK FEEDBACK - Fail fast on first error
rye run pytest -n auto -x --tb=short

# 🧪 COMPLETE - Full test suite with coverage
rye run pytest -n auto --cov=modelaudit

# 🎯 SPECIFIC - Test individual files or patterns
rye run pytest tests/test_pickle_scanner.py -n auto -v
rye run pytest -k "test_scanner" -n auto

# 📊 PERFORMANCE - Profile slow tests
rye run pytest --durations=10 --tb=no
```

**Test Speed Optimizations:**

- Parallel execution with `-n auto` (37% faster)
- Smart test markers: `slow`, `integration`, `unit`, `performance`
- Optimized pytest configuration in `pyproject.toml`

### Development Workflow

```bash
# Run linting and formatting with Ruff
rye run ruff check .          # Check entire codebase (including tests)
rye run ruff check --fix .    # Automatically fix lint issues
rye run ruff format .         # Format code

# Type checking
rye run mypy modelaudit/

# Build package
rye build

# The generated distribution contains only the `modelaudit` code and metadata.
# Unnecessary files like tests and Docker configurations are excluded via
# `MANIFEST.in`.

# Publish (maintainers only)
rye publish
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

## 🤝 Contributing Guidelines

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

## 📋 Development Tasks

### Common Development Tasks

```bash
# Run full test suite with coverage (optimized parallel execution)
rye run pytest -n auto --cov=modelaudit --cov-report=html

# Check for type errors
rye run mypy modelaudit/

# Format and lint code
rye run ruff format .
rye run ruff check --fix .

# Quick development test cycle
rye run pytest -n auto -m "not slow and not integration" -x

# Build documentation (if applicable)
# Add documentation build commands here

# Create test models for specific formats
python -c "import torch; torch.save({'model': 'data'}, 'test.pt')"
python -c "import pickle; pickle.dump({'test': 'malicious'}, open('malicious.pkl', 'wb'))"
```

### Release Process (Maintainers)

1. Update version in `pyproject.toml`
2. Create release PR
3. After merge, create GitHub release
4. Package will automatically publish to PyPI via GitHub Actions

## 🐛 Reporting Issues

When reporting issues:

- Use the GitHub issue templates
- Include ModelAudit version and Python version
- Provide minimal reproduction steps
- Include error messages and stack traces
- Mention the model format and size if applicable

## 💡 Feature Requests

For feature requests:

- Check existing issues first
- Describe the use case clearly
- Explain why it would benefit users
- Consider proposing an implementation approach

## 📞 Getting Help

- GitHub Issues: For bugs and feature requests
- GitHub Discussions: For questions and general discussion
- Email: For security issues or private matters

Thank you for contributing to ModelAudit! 🚀

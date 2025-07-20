# Contributing to ModelAudit

Thank you for your interest in contributing to ModelAudit! This guide will help you get started with the development process, including how to set up your environment, make changes, and handle releases.

## Table of Contents

- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Release Process](#release-process)
- [Version Management](#version-management)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Project Structure](#project-structure)

## 🛠️ Development Setup

### Prerequisites

- Python 3.9 or higher
- [Rye](https://rye-up.com/) (recommended) or pip
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

## Making Changes

### Development Workflow

1. **Create a feature branch:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes and test them:**

   ```bash
   # Run tests
   rye run pytest -n auto -m "not slow and not integration"

   # Run linting
   rye run ruff check .
   rye run ruff format .

   # Run type checking
   rye run mypy modelaudit/
   ```

3. **Commit your changes:**

   ```bash
   git add .
   git commit -m "feat: description of your changes"
   ```

4. **Push and create a pull request:**
   ```bash
   git push origin feature/your-feature-name
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

### Development Quality Checks

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
```

**Code Quality Tools:**

This project uses modern Python tooling for maintaining code quality:

- **[Ruff](https://docs.astral.sh/ruff/)**: Ultra-fast Python linter and formatter (replaces Black, isort, flake8)
- **[MyPy](https://mypy.readthedocs.io/)**: Static type checker
- **[Biome](https://biomejs.dev/)**: Fast formatter for JSON and YAML files

**File Formatting with Biome:**

```bash
# Format JSON and YAML files
npx @biomejs/biome format --write .

# Check formatting (for CI)
npx @biomejs/biome ci .
```

## Release Process

### Overview

ModelAudit uses an automated release process with GitHub Actions:

1. **Automatic Tagging**: When you push a version change to `main`, a git tag and GitHub release are automatically created
2. **PyPI Publishing**: When you publish a GitHub release, the package is automatically published to PyPI

### Step-by-Step Release Instructions

#### 1. Prepare for Release

**Update version in `pyproject.toml`:**

```bash
# For patch releases (0.1.1 -> 0.1.2)
rye version patch

# For minor releases (0.1.1 -> 0.2.0) 
rye version minor

# For major releases (0.1.1 -> 1.0.0)
rye version major

# Or set a specific version manually in pyproject.toml
```

**Verify the version change:**

```bash
rye version
```

#### 2. Update Documentation (if needed)

Update any version references in:

- `README.md` (installation examples, etc.)
- Documentation files
- Configuration examples

#### 3. Commit and Push Version Change

```bash
git add pyproject.toml
git commit -m "chore: bump version to $(rye version)"
git push origin main
```

**What happens next:**

- The [auto-tag workflow](.github/workflows/tag.yml) will automatically:
  - Detect the version change in `pyproject.toml`
  - Create a git tag (e.g., `v0.2.0`)
  - Create a draft GitHub release with changelog

#### 4. Publish the Release

1. **Go to the [GitHub Releases page](https://github.com/promptfoo/modelaudit/releases)**
2. **Find the automatically created draft release**
3. **Edit the release notes** (the auto-generated content is a template)
4. **Add release notes** describing the changes:

   ```markdown
   ## 🚀 What's New

   - New feature: Enhanced security scanning for XYZ models
   - Improvement: Faster scanning performance
   - Fix: Resolved issue with large file handling

   ## 🐛 Bug Fixes

   - Fixed memory leak in pickle scanner
   - Resolved crash when scanning corrupted files

   ## 📚 Documentation

   - Updated installation instructions
   - Added examples for new scanners

   ## 🔧 Under the Hood

   - Updated dependencies
   - Improved test coverage
   ```

5. **Publish the release** (not draft)

**What happens next:**

- The [release workflow](.github/workflows/release.yml) will automatically:
  - Run the full test suite
  - Build the package
  - Publish to PyPI using trusted publishing

#### 5. Verify the Release

**Check PyPI:**

- Visit https://pypi.org/project/modelaudit/
- Verify the new version is available

**Test installation:**

```bash
pip install --upgrade modelaudit
modelaudit --version
```

## Version Management

### Semantic Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backwards compatible
- **PATCH** (0.0.1): Bug fixes, backwards compatible

### Rye Version Commands

```bash
# Show current version
rye version

# Bump versions
rye version patch    # 0.1.0 -> 0.1.1
rye version minor    # 0.1.0 -> 0.2.0
rye version major    # 0.1.0 -> 1.0.0

# Pre-release versions can be set manually in pyproject.toml
```

## Testing

### Writing Tests

- Place tests in the `tests/` directory
- Follow the naming convention: `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases
- Test edge cases and error conditions

## Code Style

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation updates
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### Pre-commit Setup (Optional)

```bash
# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install
```

## Pull Request Guidelines

### Before Submitting

1. **Ensure all tests pass:**

   ```bash
   rye run pytest -n auto
   ```

2. **Check code style:**

   ```bash
   rye run ruff check .
   rye run ruff format --check .
   rye run mypy modelaudit/
   ```

3. **Update documentation** if you've changed APIs or added features

4. **Add tests** for new functionality

### 🤝 Contributing Guidelines

**Pull Request Guidelines:**

- Create PR against `main` branch
- Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, etc.)
- All PRs are squash-merged with a conventional commit message
- Keep changes small and focused
- Add tests for new functionality
- Update documentation as needed

### PR Requirements

- **Title**: Use conventional commit format (`feat:`, `fix:`, etc.)
- **Description**: Clearly describe what changes you made and why
- **Tests**: Include tests for new functionality
- **Documentation**: Update docs if needed
- **Breaking Changes**: Clearly mark any breaking changes

### Review Process

- All PRs require at least one approval
- CI/CD must pass (tests, linting, type checking)
- PRs are squash-merged with conventional commit messages
- Maintain a clean, linear git history

## Project Structure

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

### Code Style Guidelines

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write descriptive docstrings
- Keep functions focused and small
- Add comments for complex logic

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

# Create test models for specific formats
python -c "import torch; torch.save({'model': 'data'}, 'test.pt')"
python -c "import pickle; pickle.dump({'test': 'malicious'}, open('malicious.pkl', 'wb'))"
```

### Release Process (Maintainers)

1. Update version in `pyproject.toml`
2. Create release PR
3. After merge, create GitHub release
4. Package will automatically publish to PyPI via GitHub Actions

## Getting Help

- **Issues**: Create a GitHub issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Security**: For security issues, please email the maintainers privately

## Release Checklist

Use this checklist when preparing releases:

### Pre-Release

- [ ] All tests pass locally
- [ ] Documentation is up to date
- [ ] Version bumped in `pyproject.toml`
- [ ] CHANGELOG updated (if maintaining one)
- [ ] No outstanding security vulnerabilities

### Release

- [ ] Version change committed and pushed to `main`
- [ ] Auto-generated GitHub release is published
- [ ] PyPI package published successfully
- [ ] New version available on PyPI
- [ ] Installation tested with new version

### Post-Release

- [ ] GitHub release notes are complete and accurate
- [ ] Documentation sites updated (if applicable)
- [ ] Community notified (social media, forums, etc.)

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

---

Thank you for contributing to ModelAudit! 🚀
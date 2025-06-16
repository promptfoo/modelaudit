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

## Development Setup

### Prerequisites

- Python 3.9 or higher
- [Poetry](https://python-poetry.org/) for dependency management
- Git

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies with all extras
poetry install --all-extras

# Verify installation
poetry run modelaudit --help
```

### Development Environment

```bash
# Activate the virtual environment
poetry shell

# Or run commands without activating the shell
poetry run modelaudit scan test_model.pkl
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
   poetry run pytest

   # Run linting
   poetry run ruff check .
   poetry run ruff format .

   # Run type checking
   poetry run mypy modelaudit/
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

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

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
poetry version patch

# For minor releases (0.1.1 -> 0.2.0)
poetry version minor

# For major releases (0.1.1 -> 1.0.0)
poetry version major

# Or set a specific version
poetry version 0.2.0
```

**Verify the version change:**

```bash
poetry version --short
```

#### 2. Update Documentation (if needed)

Update any version references in:

- `README.md` (installation examples, etc.)
- Documentation files
- Configuration examples

#### 3. Commit and Push Version Change

```bash
git add pyproject.toml
git commit -m "chore: bump version to $(poetry version --short)"
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

### Poetry Version Commands

```bash
# Show current version
poetry version

# Bump versions
poetry version patch    # 0.1.0 -> 0.1.1
poetry version minor    # 0.1.0 -> 0.2.0
poetry version major    # 0.1.0 -> 1.0.0

# Set specific version
poetry version 1.2.3

# Pre-release versions
poetry version prerelease  # 0.1.0 -> 0.1.1a0
poetry version prepatch    # 0.1.0 -> 0.1.1a0
poetry version preminor    # 0.1.0 -> 0.2.0a0
poetry version premajor    # 0.1.0 -> 1.0.0a0
```

## Testing

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=modelaudit

# Run specific test files
poetry run pytest tests/test_pickle_scanner.py -v

# Run tests for specific Python versions (requires tox)
poetry run tox
```

### Writing Tests

- Place tests in the `tests/` directory
- Follow the naming convention: `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases
- Test edge cases and error conditions

## Code Style

### Formatting and Linting

We use [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting:

```bash
# Check for lint issues
poetry run ruff check .

# Auto-fix lint issues
poetry run ruff check --fix .

# Format code
poetry run ruff format .

# Check formatting without changing files
poetry run ruff format --check .
```

### Type Checking

We use [MyPy](https://mypy.readthedocs.io/) for type checking:

```bash
# Run type checking
poetry run mypy modelaudit/
```

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
   poetry run pytest
   ```

2. **Check code style:**

   ```bash
   poetry run ruff check .
   poetry run ruff format --check .
   poetry run mypy modelaudit/
   ```

3. **Update documentation** if you've changed APIs or added features

4. **Add tests** for new functionality

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

---

Thank you for contributing to ModelAudit! 🚀

# Migration Guide: Poetry to Rye

This document outlines the migration of the ModelAudit project from Poetry to Rye for dependency management and project tooling.

## Overview

We've migrated from Poetry to Rye to take advantage of:
- **Faster performance**: Rye is built on top of modern Python packaging tools
- **Better standards compliance**: Uses standard PEP 621 project metadata
- **Simplified workflow**: Unified toolchain for Python version management and dependencies
- **Modern tooling**: Built by the same team behind Ruff, ensuring excellent integration

## What Changed

### Project Configuration

- **`pyproject.toml`**: Converted from Poetry format to standard PEP 621 format
- **Lock files**: Replaced `poetry.lock` with Rye's lock files
- **Build system**: Now uses Hatchling instead of Poetry's build system
- **Dependencies**: Moved to standard `[project.dependencies]` and `[project.optional-dependencies]`

### Scripts and Commands

| Old (Poetry) | New (Rye) |
|-------------|-----------|
| `poetry install --extras all` | `rye sync --features all` |
| `poetry run modelaudit` | `rye run modelaudit` |
| `poetry run pytest` | `rye run pytest` |
| `poetry run ruff check` | `rye run ruff check` |
| `poetry run mypy` | `rye run mypy` |
| `poetry build` | `rye build` |
| `poetry publish` | `rye publish` |
| `poetry shell` | `rye shell` |
| `poetry add package` | `rye add package` |
| `poetry add --group dev package` | `rye add --dev package` |

### Setup Commands

- **Old**: `./setup-poetry.sh`
- **New**: `rye sync --features all` (simple and direct)

## Installation & Setup

### 1. Install Rye

```bash
# Install Rye
curl -sSf https://rye-up.com/get | bash
source ~/.profile  # or restart your terminal
```

### 2. Initialize Project

```bash
# Clone the repo if you haven't already
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install dependencies with all features
rye sync --features all
```

### 3. Verify Installation

```bash
# Test the CLI
rye run modelaudit --help

# Run tests
rye run pytest

# Check formatting
rye run ruff check modelaudit/
```

## Development Workflow

### Daily Commands

```bash
# Install dependencies
rye sync

# Add a new dependency
rye add requests

# Add a development dependency
rye add --dev pytest-mock

# Run the application
rye run modelaudit scan model.pkl

# Run tests
rye run pytest

# Format code
rye run ruff format

# Check linting
rye run ruff check --fix

# Type checking
rye run mypy modelaudit/
```

### Working with Optional Dependencies

```bash
# Install specific feature sets
rye sync --features tensorflow
rye sync --features pytorch
rye sync --features h5
rye sync --features yaml
rye sync --features all

# Install for development with all features
rye sync --features all
```

## CI/CD Changes

### GitHub Actions

The GitHub Actions workflow has been updated to use Rye:

```yaml
- name: Install Rye
  uses: eifinger/setup-rye@v3
  with:
    enable-cache: true

- name: Sync dependencies
  run: rye sync --features all

- name: Run tests
  run: rye run pytest
```

### Docker

All Dockerfiles have been updated to follow **Rye best practices**:

```dockerfile
# Copy requirements lock file and install dependencies
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

# Copy source code and install application
COPY . .
RUN pip install --no-cache-dir .[all]
```

**Key changes:**
- **No Rye installation** in containers (following official recommendations)
- Use `requirements.lock` + `pip install` for faster, smaller builds  
- Added comprehensive `.dockerignore` file
- Simpler, more reliable container builds

## Compatibility

### What Stays the Same

- **Python version requirements**: Still supports Python 3.9+
- **Optional dependencies**: Same extras (tensorflow, pytorch, h5, yaml, all)
- **CLI interface**: `modelaudit` command works exactly the same
- **Package structure**: No changes to the Python code itself
- **Testing**: Same pytest configuration and test files

### What's Different

- **Lock file format**: Uses standard pip-tools format instead of Poetry's proprietary format
- **Virtual environment**: Rye manages the virtual environment automatically
- **Dependency specification**: Uses standard `>=` instead of Poetry's `^` by default
- **Build system**: Uses Hatchling for building packages

## Troubleshooting

### Common Issues

1. **Rye not found**: Make sure to restart your terminal after installation
2. **Old lock files**: Delete any remaining `poetry.lock` files
3. **Virtual environment conflicts**: Run `rye sync` to recreate the environment

### Getting Help

```bash
# Show Rye help
rye --help

# Show available commands
rye

# Show project info
rye show

# List dependencies
rye list
```

## FAQ

**Q: Why migrate from Poetry to Rye?**
A: Rye offers better performance, standards compliance, and is built by the team behind Ruff. It provides a more modern Python development experience.

**Q: Can I still use Poetry?**
A: While the project now uses Rye by default, you can still use Poetry if needed. However, you'll need to maintain the Poetry configuration yourself.

**Q: Are there any breaking changes?**
A: No breaking changes to the actual ModelAudit functionality. Only the development and build tooling has changed.

**Q: What about existing Poetry environments?**
A: You can safely delete old Poetry virtual environments. Rye will create new ones as needed.

## Migration Checklist

For existing developers:

- [ ] Install Rye: `curl -sSf https://rye-up.com/get | bash`
- [ ] Update your terminal: `source ~/.profile` or restart
- [ ] Pull latest changes: `git pull`
- [ ] Initialize project: `rye sync --features all`
- [ ] Test setup: `rye run pytest`
- [ ] Update bookmarks/scripts that reference Poetry commands
- [ ] Delete old Poetry virtual environments (optional)

## Additional Resources

- [Rye Documentation](https://rye-up.com/)
- [PEP 621 - Project Metadata](https://peps.python.org/pep-0621/)
- [Migration Discussion](https://github.com/promptfoo/modelaudit/discussions)

---

For questions or issues with the migration, please open an issue or discussion on the GitHub repository. 
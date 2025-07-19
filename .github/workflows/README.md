# GitHub Actions CI Workflows

This directory contains GitHub Actions workflows that automate testing, building, and validation for the ModelAudit project.

## Workflow Overview

### 1. **Python CI** (`test.yml`)

Main testing workflow for Python code.

**Triggers:**

- Pull requests (except documentation-only changes)
- Pushes to main branch
- Manual workflow dispatch

**Features:**

- **Smart path filtering**: Only runs when Python files, dependencies, or workflows change
- **Conditional job execution**: Jobs depend on what files changed
- **Optimized matrix testing**:
  - PRs: Test on Python 3.9 and 3.12 only (min/max versions)
  - Main branch: Test on all supported versions (3.9, 3.10, 3.11, 3.12)
- **Job dependencies**: Type checking only runs if linting passes
- **NumPy compatibility testing**: Reduced matrix for PRs

### 2. **Documentation Check** (`docs-check.yml`)

Lightweight workflow for documentation-only changes.

**Triggers:**

- Changes to `*.md`, `*.txt`, `*.rst`, or `LICENSE` files

**Features:**

- Fast execution (5-minute timeout)
- Prettier formatting check
- Markdown link validation (with smart ignore patterns)
- No Python environment setup needed

### 3. **Docker Image CI** (`docker-image-test.yml`)

Tests Docker image builds.

**Triggers:**

- Changes to Dockerfiles, Python code, or dependencies
- Manual workflow dispatch
- PR label: `test-full-image`

**Features:**

- **Conditional full image testing**:
  - Full image only builds if explicitly requested or Dockerfile.full changes
  - Saves significant CI time on most PRs
- **Increased timeouts**: 60 minutes for full image (was 45)
- **Smart caching**: Uses GitHub Actions cache for faster builds
- **Comprehensive testing**: Validates actual scanning functionality

### 4. **Validate PR Title** (`validate-pr-title.yml`)

Ensures PR titles follow conventional commit format.

**Features:**

- Validates semantic PR titles (feat, fix, docs, etc.)
- Checks subject doesn't start with uppercase
- Skips validation for documentation-only changes

## CI Optimization Strategies

### 1. Path-Based Filtering

- Documentation changes don't trigger full test suite
- Docker workflows only run when Docker-related files change
- NumPy compatibility tests only run when dependencies change

### 2. Conditional Matrix Strategy

- PRs test fewer Python versions (3.9, 3.12) to save time
- Main branch tests all versions for comprehensive coverage
- NumPy tests use reduced matrix on PRs

### 3. Job Dependencies

- Type checking only runs after linting passes
- Build job requires both lint and type-check to pass
- Prevents wasting CI time on code that won't pass basic checks

### 4. Timeout Optimization

- Documentation checks: 5 minutes
- Linting/type checking: 10 minutes
- Python tests: 30 minutes
- Docker lightweight: 20 minutes
- Docker full image: 60 minutes

### 5. Smart Caching

- Python dependencies cached by OS and Python version
- Docker layers cached using GitHub Actions cache
- Rye package manager cache enabled

## Running Workflows Locally

To test workflows locally before pushing:

```bash
# Install act (GitHub Actions local runner)
brew install act  # macOS
# or see https://github.com/nektos/act for other platforms

# Run specific workflow
act -W .github/workflows/test.yml

# Run with specific event
act pull_request -W .github/workflows/test.yml
```

## Adding New Workflows

When adding new workflows, consider:

1. **Path filters**: Only run when relevant files change
2. **Timeouts**: Set appropriate timeouts for each job
3. **Dependencies**: Use job dependencies to fail fast
4. **Matrix strategy**: Consider different strategies for PRs vs main
5. **Caching**: Cache dependencies and build artifacts

## Workflow Permissions

All workflows use minimal permissions:

- `pull-requests: read` for PR validation
- Default permissions for other operations

## Debugging CI Failures

1. Check the workflow logs in the Actions tab
2. Look for timeout issues (may need to increase limits)
3. Verify path filters aren't excluding necessary files
4. Check if conditional logic is working as expected
5. For Docker issues, try building locally first

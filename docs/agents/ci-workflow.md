# CI/CD Workflow

## Pre-Push Validation (Essential)

**The Golden Rule**: Validate locally before pushing (~30 seconds vs 3-5 minutes in CI).

```bash
set -e  # Exit on first error

# 1. Format check
rye run ruff format --check modelaudit/ tests/ || {
    echo "Format check failed - running formatter..."
    rye run ruff format modelaudit/ tests/
}

# 2. Lint check
rye run ruff check modelaudit/ tests/ || exit 1

# 3. Type checking
rye run mypy modelaudit/ || exit 1

# 4. Quick tests
rye run pytest -n auto -m "not slow and not integration" --maxfail=1

# 5. Documentation formatting (if changed)
npx prettier@latest --write "**/*.{md,yaml,yml,json}"
```

## Branch Hygiene

```bash
# Before making changes - get latest main
git fetch origin main
git merge --no-edit origin/main

# After changes - validate before pushing
git push origin your-branch-name
```

## CI Status Monitoring

```bash
# Check only failed/in-progress checks
gh pr view <PR_NUMBER> --json statusCheckRollup --jq '
  .statusCheckRollup[] |
  select(.status == "IN_PROGRESS" or .conclusion == "FAILURE") |
  {name: .name, status: .status, conclusion: .conclusion}
'

# Quick overall status
gh pr view <PR_NUMBER> --json statusCheckRollup --jq '
  [.statusCheckRollup[] | select(.conclusion == "SUCCESS")] | length
' && echo "checks passing"
```

## CI/CD Integration

ModelAudit automatically adapts its output for CI environments:

- **TTY Detection**: Spinners disabled when not a terminal
- **Color Control**: Respects `NO_COLOR` environment variable
- **Recommended for CI**: Use `--format json` for machine-readable output
- **Exit Codes**: 0 (no issues), 1 (issues found), 2 (scan errors)

Example CI usage:

```bash
# JSON output for parsing (recommended)
modelaudit model.pkl --format json --output results.json

# Text output with automatic CI detection
modelaudit model.pkl | tee results.txt

# Explicitly disable colors
NO_COLOR=1 modelaudit model.pkl
```

## Performance Tips

- **Local validation takes ~30 seconds vs 3-5 minutes in CI**
- **Target specific test files** instead of full suite during development
- **Use `--maxfail=1`** with pytest to exit on first test failure
- **Keep branches clean** - merge main regularly to avoid conflicts

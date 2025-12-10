# AGENTS.md - AI Agent Guide for ModelAudit

Guide for AI coding agents working with this security scanner for AI/ML model files.

## Quick Reference

```bash
# Setup
rye sync --features all-ci

# Pre-commit workflow (MUST run before every commit)
rye run ruff format modelaudit/ tests/
rye run ruff check --fix modelaudit/ tests/
rye run mypy modelaudit/
rye run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Branch Workflow

```bash
# 1. Start from clean main
git fetch origin main && git checkout main && git merge --no-edit origin/main

# 2. Create feature branch
git checkout -b feat/your-feature-name  # or fix/, chore/, test/

# 3. Make changes, run pre-commit checks

# 4. Commit with conventional format
git commit -m "feat: add scanner for XYZ format

Description here.

Co-Authored-By: Claude <noreply@anthropic.com>"

# 5. Push and create PR
git push -u origin feat/your-feature-name
gh pr create --title "feat: descriptive title" --body "Brief description"
```

## CI Compliance Requirements

**MUST pass before creating any PR:**

```bash
rye run ruff check modelaudit/ tests/          # Lint (no errors)
rye run ruff format --check modelaudit/ tests/ # Format (no changes)
rye run mypy modelaudit/                       # Types (no errors)
rye run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Common CI Failure Fixes

| Issue               | Fix                                                      |
| ------------------- | -------------------------------------------------------- |
| Import organization | `rye run ruff check --fix --select I modelaudit/ tests/` |
| Format issues       | `rye run ruff format modelaudit/ tests/`                 |
| Type errors         | Fix manually, re-run `mypy`                              |
| Test failures       | Check output, fix issues, re-run tests                   |

## When Modifying Scanners

1. **Preserve security focus** - Don't weaken detection
2. **Test both safe and malicious samples**
3. **Follow the `BaseScanner` pattern** - See `docs/agents/architecture.md`
4. **Add comprehensive tests** - Include edge cases
5. **Run full CI compliance** before committing

## When Adding Features

1. **Handle missing dependencies gracefully**
2. **Update `SCANNER_REGISTRY`** if adding scanners
3. **Follow existing code patterns**
4. **Ensure tests pass across Python 3.10-3.13**

## Non-Interactive Commands

To keep automation reliable:

- Use flags to avoid editors/prompts: `git merge --no-edit`, `git commit -m`
- Run one command per invocation (avoid long `&&` chains)
- If `.git/index.lock` appears and no git process is running, remove it
- Only `git add` intended paths; avoid committing artifacts
- Prefer `gh run rerun <run-id>` over force-pushing to trigger CI

## Project Structure

```
modelaudit/
├── modelaudit/           # Main package
│   ├── scanners/        # Scanner implementations
│   ├── utils/           # Utility modules
│   ├── cli.py           # CLI interface
│   └── core.py          # Core scanning logic
├── tests/               # Test suite
├── docs/agents/         # Detailed documentation
└── CLAUDE.md            # Claude-specific guidance
```

## Detailed Documentation

| Topic           | File                             |
| --------------- | -------------------------------- |
| Commands        | `docs/agents/commands.md`        |
| Testing         | `docs/agents/testing.md`         |
| Security Checks | `docs/agents/security-checks.md` |
| Architecture    | `docs/agents/architecture.md`    |
| CI/CD           | `docs/agents/ci-workflow.md`     |
| Release Process | `docs/agents/release-process.md` |
| Dependencies    | `docs/agents/dependencies.md`    |

## Code Style

- **Python Version**: 3.10+ (supports 3.10-3.13)
- **Classes**: PascalCase (`PickleScanner`)
- **Functions/Variables**: snake_case (`scan_model`)
- **Constants**: UPPER_SNAKE_CASE (`DANGEROUS_OPCODES`)
- **Type hints**: Always use for function signatures

## Exit Codes

- 0: No security issues
- 1: Security issues detected
- 2: Scan errors

## Key Principle

**Always run CI compliance checks before pushing.** Local validation takes ~30 seconds vs 3-5 minutes in CI.

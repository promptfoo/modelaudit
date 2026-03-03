# AGENTS.md — ModelAudit (Canonical Agent Guide)

This is the single source of truth for all AI coding agents (Claude, Gemini, others) working on ModelAudit, a security scanner for AI/ML model files. Follow it exactly and keep instructions concise through progressive disclosure—share only the minimum needed context and iterate.

## Stateless Onboarding

- Agents start with zero context; use this file to bootstrap each session with the essentials: what (stack/project map), why (security-focused scanner), and how (workflow + validation below).
- Prefer pointers over payloads: read the specific docs in `docs/agents/` when needed instead of inlining here.
- Keep instructions universal and minimal; lean on deterministic tools (ruff, mypy, pytest, prettier) rather than embedding style rules.
- When unsure, ask or fetch targeted context instead of expanding instructions.

## Mission & Principles

- **Security first:** Never weaken detections or bypass safeguards.
- **Match the codebase:** Follow existing patterns, architecture, and naming; never add dependencies without approval.
- **Progressive disclosure:** Be concise, reveal details as needed, and prefer short, scoped messages.
- **Iterative refinement:** Share a plan for non-trivial work, execute incrementally, and verify after each change.
- **Ask when unclear:** Confirm scope before risky or ambiguous actions.
- **Proactive completion:** Provide tests and follow-up steps without waiting to be asked.

## Quick Start Commands

```bash
# Setup
uv sync --extra all-ci

# Pre-commit workflow (MUST run before every commit)
uv run ruff format modelaudit/ tests/
uv run ruff check --fix modelaudit/ tests/
uv run mypy modelaudit/
uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Standard Workflow

1. **Understand:** Read nearby code, tests, and docs (`docs/agents/*.md`) before editing.
2. **Plan:** For anything non-trivial, present a short multi-step plan; refine iteratively.
3. **Implement:** Preserve security focus, follow `BaseScanner` patterns (see `docs/agents/architecture.md`), handle missing deps gracefully, and update `SCANNER_REGISTRY` when adding scanners.
4. **Verify:** Run the validation commands above. Format/linters must be clean. Use targeted `pytest` when appropriate.
5. **Report:** Summarize changes with file references and note residual risks or follow-ups.

## Branch & Git Hygiene

**NEVER commit or push directly to `main`.** All changes must go through pull requests.

```bash
# Start clean
git fetch origin main
git checkout main
git merge --no-edit origin/main

# Work on a branch (REQUIRED - never commit to main)
git checkout -b feat/your-feature-name  # or fix/, chore/, test/

# Commit (conventional)
git commit -m "feat: add scanner for XYZ format

Description here.

Co-Authored-By: Claude <noreply@anthropic.com>"

# PR (after validation) - ALL changes go through PRs
git push -u origin feat/your-feature-name
gh pr create --title "feat: descriptive title" --body "Brief description"
```

- Use non-interactive flags (`--no-edit`, `-m`). One command per invocation; avoid long `&&` chains.
- If `.git/index.lock` exists and no git process is running, remove the lock file.
- Add only intended paths; avoid committing artifacts. Prefer `gh run rerun <run-id>` over force-pushing to rerun CI.
- Keep CHANGELOG entries in `[Unreleased]` when adding user-visible changes (Keep a Changelog format).

## CI Compliance Requirements

```bash
uv run ruff check modelaudit/ tests/          # Lint (no errors)
uv run ruff format --check modelaudit/ tests/ # Format (no changes)
uv run mypy modelaudit/                       # Types (no errors)
uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

| Issue               | Fix                                                     |
| ------------------- | ------------------------------------------------------- |
| Import organization | `uv run ruff check --fix --select I modelaudit/ tests/` |
| Format issues       | `uv run ruff format modelaudit/ tests/`                 |
| Type errors         | Fix manually, re-run `mypy`                             |
| Test failures       | Check output, fix issues, re-run tests                  |

## Dependency Management

- ModelAudit supports both NumPy 1.x (Python 3.10) and 2.x (Python 3.11+) via environment markers in `pyproject.toml`. See `docs/agents/dependencies.md` for the full strategy, vendored proto guide, and rules for adding dependencies.
- When adding dependencies, check compatibility with both NumPy versions and add environment markers if needed.

## Coding & Style Guardrails

- **Python:** 3.10–3.13 supported. Classes PascalCase, functions/vars snake_case, constants UPPER_SNAKE_CASE, always type hints.
- **Comments:** Use sparingly to explain intent, not mechanics.
- **Docs/Markdown:** Keep concise; when formatting markdown/json/yaml, use `npm ci --ignore-scripts && npx prettier --write "**/*.{md,yaml,yml,json}"` if instructed or if formatting drifts.
- **Dependencies:** Do not add new packages without explicit approval and updating `pyproject.toml`/locks.
- **Performance & safety:** Prefer safe defaults; avoid destructive commands.

## Scanner/Feature Changes Checklist

- Preserve or strengthen detections; test both benign and malicious samples.
- Follow existing scanner patterns and update registries, CLI wiring, and docs as needed.
- Add comprehensive tests, including edge cases and regression coverage.
- Ensure compatibility across Python 3.10–3.13 and handle missing optional deps gracefully.

## CVE Detection Checklist

When adding CVE detections to existing scanners, follow these rules distilled from recurring review feedback across 13 CVE implementations.

### Detection Logic

- **Doc/comment guards:** Use majority-line analysis (>50% doc lines via `_is_primarily_documentation()`), not substring checks — `"#" in content` is trivially bypassable by embedding a comment token in a payload.
- **`STACK_GLOBAL` handling:** These opcodes have `arg=None` in pickletools; reconstruct `module.class` by walking backwards to find preceding `SHORT_BINUNICODE`/`BINUNICODE` ops.
- **Dict short-circuit scope:** Track which op produces the `SETITEM` target — an unrelated `EMPTY_DICT` in the lookback window must not suppress detection of a `SETITEM` targeting a `REDUCE`/`NEWOBJ` result.
- **Version comparison:** Handle PEP 440 prerelease tags (`a`, `b`, `rc`, `dev`) — `2.10.0a0` is still vulnerable, not the fix.
- **Bounded reads:** Cap archive member reads for metadata validation (10 MB) to prevent memory spikes on large pickles.
- **Pattern registration:** New CVE pattern lists must be added to `validate_patterns()` in `suspicious_symbols.py`.

### CVE Attribution Consistency

- Always include `cve_id`, `cvss`, `cwe`, `description`, `remediation` in the `details` dict.
- Include context fields (e.g., `layer_name` for Keras, `installed_pytorch_version` for PyTorch) — keep consistent across scanner variants (H5 vs ZIP).
- Use `except Exception` (not `except ImportError`) when importing frameworks for version checks, since mocked/broken modules may raise other errors.

### Testing

- Assert the actual signal — never `assert result is not None` alone; verify specific check names, issue messages, or detail fields.
- For "fixed version" tests: also verify the vulnerable version test produces a failed check (prevents silent regression).
- Test bypass prevention: verify that embedding a single comment token in a malicious payload does NOT suppress detection.
- Deterministic fixtures only — never reference host paths like `/etc/passwd`; create all targets under `tmp_path`.
- Type hints: `-> None` on all test methods, `tmp_path: Path` / `monkeypatch: pytest.MonkeyPatch` on parameters.
- Use pathlib (`tmp_path / "file.ext"`) instead of `os.path.join`.

### Registration

- Add new test files to `allowed_test_files` in `tests/conftest.py` (Python 3.10/3.12/3.13 CI allowlist).
- Add CVE explanation functions to `modelaudit/config/explanations.py`.
- Add CHANGELOG entry under the existing `[Unreleased]` section (never create a second one).

For the full multi-file workflow, see `docs/agents/new-scanner-quickstart.md` § "Adding CVE Detections to Existing Scanners".

## Project Map & References

```bash
modelaudit/
├── modelaudit/           # Main package
│   ├── analysis/         # Semantic and integrated analysis
│   ├── auth/             # API authentication and config
│   ├── cache/            # Scan result caching
│   ├── config/           # Blocklists and configuration
│   ├── detectors/        # Security detectors (secrets, JIT, network)
│   ├── integrations/     # SARIF, JFrog, license checking
│   ├── progress/         # Progress tracking subsystem
│   ├── protos/           # Vendored TensorFlow protobuf stubs
│   ├── scanners/         # Scanner implementations (30+)
│   ├── utils/            # File detection, helpers, streaming
│   ├── whitelists/       # HuggingFace/model whitelists
│   ├── cli.py            # CLI interface
│   ├── core.py           # Core scanning orchestration
│   ├── models.py         # Pydantic result models
│   └── telemetry.py      # Anonymous usage telemetry
├── tests/                # Test suite
├── docs/agents/          # Agent documentation
├── docs/maintainers/     # Release, CVE, dependency docs
├── docs/user/            # User-facing guides
└── CHANGELOG.md          # Keep a Changelog format
```

Key docs: `docs/agents/architecture.md`, `docs/agents/dependencies.md`, `docs/agents/release-process.md`, `docs/agents/new-scanner-quickstart.md`.

## README.md Content Guidelines

The README is published to PyPI and visible to the public. Keep it user-facing: product overview, installation, usage examples, supported formats, CLI options, output formats, and troubleshooting. Describe WHAT we analyze (formats/frameworks), not HOW (detection mechanisms). Implementation details belong in source code and contributor docs.

## DO / DON'T Cheatsheet

- **Do:** Keep responses short; surface only relevant details; prefer targeted tests; propose clear next steps; cite file paths when reporting.
- **Do:** Use iterative refinement—small changes, verify, then proceed.
- **Do:** Always use feature branches and PRs for all changes.
- **Don't:** Commit or push directly to `main`—always use a PR.
- **Don't:** Introduce new dependencies, weaken security checks, or bypass validation.
- **Don't:** Leave formatting/lint failures or unaddressed test regressions.

## Exit Codes

- `0`: No security issues
- `1`: Security issues detected
- `2`: Scan errors

## Persona Notes

- **Claude / Gemini / others:** Follow this guide as canonical. Apply progressive disclosure, confirm ambiguities, and prioritize security.

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

- **NEVER push to main.** Always create a feature branch and open a PR.
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

## Coding & Style Guardrails

- **Python:** 3.10–3.13 supported. Classes PascalCase, functions/vars snake_case, constants UPPER_SNAKE_CASE, always type hints.
- **Comments:** Use sparingly to explain intent, not mechanics.
- **Docs/Markdown:** Keep concise; when formatting markdown/json/yaml, use `npx --yes prettier@latest --write "**/*.{md,yaml,yml,json}"` if instructed or if formatting drifts.
- **Dependencies:** Do not add new packages without explicit approval and updating `pyproject.toml`/locks.
- **Performance & safety:** Prefer safe defaults; avoid destructive commands.

## Scanner/Feature Changes Checklist

- Preserve or strengthen detections; test both benign and malicious samples.
- Follow existing scanner patterns and update registries, CLI wiring, and docs as needed.
- Add comprehensive tests, including edge cases and regression coverage.
- Ensure compatibility across Python 3.10–3.13 and handle missing optional deps gracefully.

## Project Map & References

```bash
modelaudit/
├── modelaudit/           # Main package
│   ├── scanners/         # Scanner implementations
│   ├── utils/            # Utility modules
│   ├── cli.py            # CLI interface
│   └── core.py           # Core scanning logic
├── tests/                # Test suite
├── docs/agents/          # Detailed documentation
└── CHANGELOG.md          # Keep a Changelog format
```

Key docs: `docs/agents/commands.md`, `docs/agents/testing.md`, `docs/agents/security-checks.md`, `docs/agents/architecture.md`, `docs/agents/ci-workflow.md`, `docs/agents/release-process.md`, `docs/agents/dependencies.md`.

## README.md Content Guidelines

The README is published to PyPI and visible to the public. Follow these rules to maintain security while being user-friendly:

**KEEP PUBLIC (user-facing):**

- Product overview, badges, screenshot, documentation links
- Quick start installation and usage examples
- High-level benefits (what problems it solves)
- Supported model formats table (extensions and risk levels)
- Security checks: list WHAT formats/frameworks we analyze (e.g., "TensorFlow/Keras", "ZIP archives")
- CLI options and command examples
- Output formats (text, JSON, SARIF)
- Exit codes and troubleshooting
- Authentication environment variables

**KEEP PRIVATE (do NOT include in README):**

- Internal project structure (file paths, module organization)
- Exact detection patterns (specific opcodes like `REDUCE`, `GLOBAL`, etc.)
- Exact module/function names we detect (e.g., `os.system`, `subprocess`)
- Whitelist system (do not mention false positives, model counts, or mechanism)
- Scanner implementation details
- Internal architecture documentation

**Why this matters:** Exact detection patterns help attackers craft evasion techniques. For security checks, list WHAT we analyze (formats/frameworks) not HOW (detection mechanisms). Keep implementation details in `docs/agents/` for contributors only.

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

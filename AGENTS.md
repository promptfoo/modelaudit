# AGENTS.md — ModelAudit (Canonical Agent Guide)

This is the single source of truth for all AI coding agents (Claude, Gemini, others) working on ModelAudit, a security scanner for AI/ML model files. Follow it exactly and keep instructions concise through progressive disclosure—share only the minimum needed context and iterate.

## Stateless Onboarding

- Agents start with zero context; use this file to bootstrap each session with the essentials: what (stack/project map), why (security-focused scanner), and how (workflow + validation below).
- Prefer pointers over payloads: read the specific docs in `docs/agents/` when needed instead of inlining details here.
- Keep instructions universal and minimal; lean on deterministic tools (ruff, mypy, pytest, prettier) rather than embedding style rules.
- When unsure, ask or fetch targeted context instead of expanding instructions.

## Mission & Principles

- **Security first:** Never weaken detections or bypass safeguards.
- **Match the codebase:** Follow existing patterns, architecture, and naming; no new dependencies without approval.
- **Progressive disclosure:** Be concise, reveal details as needed, and prefer short, scoped messages.
- **Iterative refinement:** Share a plan for non-trivial work, execute incrementally, and verify after each change.
- **Ask when unclear:** Confirm scope before risky or ambiguous actions.
- **Proactive completion:** Provide tests and follow-up steps without waiting to be asked.

## Quick Start Commands

```bash
# Setup
rye sync --features all-ci

# Default validation (run after changes)
rye run ruff format modelaudit/ tests/
rye run ruff check --fix modelaudit/ tests/
rye run mypy modelaudit/
rye run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Standard Workflow

1. **Understand:** Read nearby code, tests, and docs (`docs/agents/*.md`) before editing.
2. **Plan:** For anything non-trivial, present a short multi-step plan; refine iteratively.
3. **Implement:** Preserve security focus, follow `BaseScanner` patterns (see `docs/agents/architecture.md`), handle missing deps gracefully, and update `SCANNER_REGISTRY` when adding scanners.
4. **Verify:** Run the validation commands above. Format/linters must be clean. Use targeted `pytest` when appropriate.
5. **Report:** Summarize changes with file references and note residual risks or follow-ups.

## Branch & Git Hygiene

```bash
# Start clean
git fetch origin main
git checkout main
git merge --no-edit origin/main

# Work on a branch
git checkout -b feat/your-feature-name  # or fix/, chore/, test/

# Commit (conventional)
git commit -m "feat: add scanner for XYZ format

Description here.

Co-Authored-By: Claude <noreply@anthropic.com>"

# PR (after validation)
git push -u origin feat/your-feature-name
gh pr create --title "feat: descriptive title" --body "Brief description"
```

- Use non-interactive flags (`--no-edit`, `-m`). One command per invocation; avoid long `&&` chains.
- If `.git/index.lock` exists and no git process is running, remove the lock file.
- Add only intended paths; avoid committing artifacts. Prefer `gh run rerun <run-id>` over force-pushing to rerun CI.
- Keep CHANGELOG entries in `[Unreleased]` when adding user-visible changes (Keep a Changelog format).

## Coding & Style Guardrails

- **Python:** 3.10–3.13 supported. Classes PascalCase, functions/vars snake_case, constants UPPER_SNAKE_CASE, always type hints.
- **Comments:** Use sparingly to explain intent, not mechanics.
- **Docs/Markdown:** Keep concise; when formatting markdown/json/yaml, use `npx prettier@latest --write "**/*.{md,yaml,yml,json}"` if instructed or if formatting drifts.
- **Dependencies:** Do not add new packages without explicit approval and updating `pyproject.toml`/locks.
- **Performance & safety:** Prefer safe defaults; avoid destructive commands.

## Scanner/Feature Changes Checklist

- Preserve or strengthen detections; test both benign and malicious samples.
- Follow existing scanner patterns and update registries, CLI wiring, and docs as needed.
- Add comprehensive tests, including edge cases and regression coverage.
- Ensure compatibility across Python 3.9–3.13 and handle missing optional deps gracefully.

## Project Map & References

```
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

## DO / DON'T Cheatsheet

- **Do:** Keep responses short; surface only relevant details; prefer targeted tests; propose clear next steps; cite file paths when reporting.
- **Do:** Use iterative refinement—small changes, verify, then proceed.
- **Don't:** Introduce new dependencies, weaken security checks, or bypass validation.
- **Don't:** Leave formatting/lint failures or unaddressed test regressions.

## Exit Codes

- `0`: No security issues
- `1`: Security issues detected
- `2`: Scan errors

## Persona Notes

- **Claude / Gemini / others:** Follow this guide as canonical. Apply progressive disclosure, confirm ambiguities, and prioritize security.

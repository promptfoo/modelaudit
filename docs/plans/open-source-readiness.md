# Open Source Readiness Plan

**Status:** HEAD CHANGES COMPLETE (HISTORY REWRITE PENDING)
**Created:** 2026-02-18
**Branch:** `chore/open-source-readiness`

## Overview

This plan prepares the ModelAudit repository for public open source release. It covers
license compliance, sensitive content redaction, community files, metadata fixes, and
recommendations for git history rewriting.

> **Note:** History rewriting (fresh repo creation) is a separate manual step to be
> performed after all HEAD-level changes are complete and verified.

---

## 1. Clean Sensitive Files from HEAD

### 1a. Delete competitive analysis and internal scripts

- [x] Delete internal competitive-analysis documentation.
- [x] Delete internal benchmarking/comparison scripts.
- [x] Review and remove non-essential context-generation scripts.

### 1b. Redact detection-pattern details from docs

- [x] Redact exact `SUSPICIOUS_GLOBALS` and `DANGEROUS_OPCODES` from `docs/agents/security-checks.md`
- [x] Remove internal CVE threshold and attack-vector details from public docs.
- [x] Redact the "KEEP PRIVATE" section in `AGENTS.md` (it paradoxically reveals what's sensitive)
- [x] Redact "Known Issues & False Positives" evasion details from `CONTRIBUTING.md`

## 2. License Compliance Fixes

- [x] Add `modelaudit/protos/LICENSE` (Apache-2.0 text from TensorFlow)
- [x] Add `modelaudit/protos/NOTICE` (TensorFlow NOTICE file)
- [x] Fix README license badge: `promptfoo/promptfoo` -> `promptfoo/modelaudit`
- [x] Add `"License :: OSI Approved :: MIT License"` trove classifier to pyproject.toml
- [x] Fix bug report URL in `cli.py` to point to `promptfoo/modelaudit/issues`
- [x] Add project URLs (Bug Tracker, Changelog) to pyproject.toml

## 3. Add Community Files

- [x] Create `SECURITY.md` with vulnerability disclosure policy
- [x] Create `CODE_OF_CONDUCT.md` (Contributor Covenant)
- [x] Create `.github/ISSUE_TEMPLATE/bug_report.yml`
- [x] Create `.github/ISSUE_TEMPLATE/feature_request.yml`
- [x] Create `.github/PULL_REQUEST_TEMPLATE.md`
- [x] Create `.github/CODEOWNERS`

## 4. Metadata & Config Improvements

- [x] Remove Python 3.14 classifier from pyproject.toml (not released, not in CI)
- [x] Add `.vscode/` and `.idea/` to `.gitignore`
- [x] Add `.editorconfig`
- [x] Add `.gitattributes`
- [x] Clean up CHANGELOG.md (duplicate `[Unreleased]`, stale comparison link)
- [x] Add `modelaudit/py.typed` marker (PEP 561)

## 5. Code Cleanup

- [x] Resolve TODO comments in `modelaudit/detectors/jit_script.py`
- [x] Remove detection-limitation TODO from `tests/analysis/test_enhanced_pattern_detector.py:243`

## 6. History Rewrite (Manual Step - Post PR)

After all HEAD changes are merged:

1. Archive the full private history
2. Create a fresh repository from clean HEAD
3. Verify no sensitive content leaked
4. Transfer GitHub settings, secrets, environments

---

## Decision Log

| Decision                                | Rationale                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------ |
| Fresh repo over git-filter-repo         | Too many sensitive items across 1,026 commits and 100+ branches; surgical cleanup is risky |
| Keep docs/agents/ (non-sensitive files) | Architecture, testing, CI docs are standard contributor resources                          |
| Keep docs/security/                     | Educational PyTorch security content benefits the community                                |
| Keep CLAUDE.md/AGENTS.md/GEMINI.md      | AI agent config in repos is increasingly common                                            |

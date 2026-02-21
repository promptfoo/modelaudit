# Open-Source Readiness Plan

**Status:** HEAD CHANGES COMPLETE; NEXT-PHASE CHECKLIST ACTIVE
**Created:** 2026-02-18
**Updated:** 2026-02-21
**Branch:** `chore/open-source-readiness`

## Overview

This plan prepares the ModelAudit repository for public open-source release. It covers
license compliance, sensitive content redaction, community files, metadata fixes, and
ongoing launch-readiness operations.

> **Note:** Git history rewrite was considered and explicitly rejected; current strategy is
> to keep history as-is with documented risk acceptance.

---

## 1. Clean Sensitive Files from HEAD

### 1a. Delete competitive analysis and internal scripts

- [x] Delete internal competitive-analysis documentation.
- [x] Delete internal benchmarking/comparison scripts.
- [x] Review and remove non-essential context-generation scripts.
- [x] Move model regression catalog from `docs/models.md` to contributor-facing `docs/agents/model-test-corpus.md`.

### 1b. Redact detection-pattern details from docs

- [x] Keep detection implementation details out of user-facing docs/README.
- [x] Keep actionable security test details in contributor-facing docs (`docs/agents/security-checks.md`).
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

- [x] Remove Python 3.14 classifier from pyproject.toml (not part of current CI support policy)
- [x] Add `.vscode/` and `.idea/` to `.gitignore`
- [x] Add `.editorconfig`
- [x] Add `.gitattributes`
- [x] Clean up CHANGELOG.md (duplicate `[Unreleased]`, stale comparison link)
- [x] Add `modelaudit/py.typed` marker (PEP 561)

## 5. Code Cleanup

- [x] Resolve TODO comments in `modelaudit/detectors/jit_script.py`
- [x] Remove detection-limitation TODO from `tests/analysis/test_enhanced_pattern_detector.py:243`

## 6. History Strategy (Decision)

- [x] Decide to keep git history as-is (no rewrite/filter-repo).
- [x] Accept contributor emails currently present in git history as public.
- [x] Document this decision in this plan for future maintainers.

---

## 7. Next-Phase Open-Source Checklist (Big List)

This section tracks high-value work after the initial hardening pass. Use `[P0]`, `[P1]`, `[P2]` labels to prioritize.

### 7a. GitHub Repository Settings & Governance

- [ ] [P0] Enforce branch protection on `main` (PR-only, no direct pushes).
- [ ] [P0] Require all critical checks before merge (`CI Success`, `Docker CI Success`, docs checks).
- [ ] [P0] Require up-to-date branches before merge.
- [ ] [P1] Enable merge queue for serialized safe merges.
- [ ] [P1] Prevent branch deletions and force-pushes on protected branches.
- [ ] [P1] Restrict who can create/modify tags matching `v*`.
- [ ] [P1] Add at least one backup maintainer to reduce single-maintainer risk.
- [x] [P1] Expand `.github/CODEOWNERS` with per-area ownership (scanners, docs, CI, release).
- [x] [P2] Add `MAINTAINERS.md` with roles (maintainer, reviewer, triage).
- [ ] [P2] Define maintainer response expectations (issues/PR triage SLO).

### 7b. Security Program & Supply Chain

- [ ] [P0] Enable GitHub security features: dependency graph, Dependabot alerts, secret scanning, push protection.
- [ ] [P0] Enable and monitor private vulnerability reporting (via `SECURITY.md` workflow).
- [x] [P0] Add CodeQL workflow for Python and GitHub Actions analysis.
- [x] [P0] Add dependency vulnerability scanning in CI (`pip-audit` or equivalent).
- [x] [P0] Add container vulnerability scanning for Docker images (e.g., Trivy/Grype).
- [ ] [P1] Add provenance attestations for release artifacts (SLSA/Sigstore).
- [ ] [P1] Add artifact signing strategy for wheels/sdists and release tags.
- [ ] [P1] Add SBOM generation to release workflow and attach SBOM to releases.
- [ ] [P1] Add CVE handling process (triage, fix, advisory publication flow).
- [ ] [P1] Add security advisory templates for maintainers.
- [ ] [P1] Add a lightweight public threat model document.
- [ ] [P2] Add fuzzing strategy for binary/model parsers.
- [ ] [P2] Add periodic external security review cadence (quarterly/biannual).

### 7c. Release Engineering & Distribution

- [x] [P0] Add `twine check dist/*` to release workflow.
- [ ] [P0] Add clean-room install smoke tests from built wheel/sdist.
- [ ] [P0] Ensure release workflow validates exactly one version in `dist/` artifacts.
- [ ] [P1] Publish Docker images in CI (if advertised in README), with semver tags and digests.
- [ ] [P1] Add GHCR publish workflow (or remove GHCR usage docs if not publishing).
- [ ] [P1] Document release rollback procedure.
- [ ] [P1] Add explicit pre-release checklist (version, changelog, smoke test, publish, verify).
- [ ] [P1] Validate PyPI metadata and project URLs on every release.
- [ ] [P2] Add post-release verification checklist (pip install, Docker pull, CLI smoke runs).
- [ ] [P2] Add release health dashboard (failed publishes, release timing, package integrity checks).

### 7d. CI/CD Quality Gates

- [x] [P0] Add scheduled nightly CI run for full matrix (including slow/integration/performance tests).
- [ ] [P1] Add compatibility smoke tests for all optional extras bundles.
- [ ] [P1] Add reproducibility checks for generated protobuf artifacts.
- [ ] [P1] Add CI checks for minimum supported Python/NumPy combinations as explicit gates.
- [ ] [P1] Add regression corpus validation for malicious and benign fixtures.
- [ ] [P1] Add `uv lock` consistency check in CI.
- [ ] [P2] Add performance budget checks to catch scanner regressions.
- [ ] [P2] Add mutation/property-based tests for high-risk scanners.
- [ ] [P2] Add flaky-test detector/reporting.
- [ ] [P2] Add periodic dead-link checks with stricter failure policy.

### 7e. Documentation & User Trust

- [x] [P0] Add README section explaining telemetry behavior and explicit opt-out controls.
- [x] [P0] Add clear support policy (supported versions and maintenance window).
- [ ] [P1] Add "security model and limitations" page for users.
- [x] [P1] Add "false positives/false negatives" reporting guidelines.
- [ ] [P1] Add contributor quickstart focused on adding a new scanner safely.
- [ ] [P1] Add compatibility matrix page for file formats vs optional dependencies.
- [ ] [P1] Add offline/air-gapped usage guidance.
- [ ] [P2] Add architecture diagram for scanner pipeline.
- [ ] [P2] Add docs on cache behavior, data retention, and local file handling.
- [ ] [P2] Add troubleshooting decision tree for common scan failures.

### 7f. Legal, Licensing, and Compliance

- [ ] [P0] Generate and review third-party license inventory for runtime + dev dependencies.
- [ ] [P0] Confirm all bundled third-party files include required notices in distributions.
- [ ] [P1] Add `THIRD_PARTY_NOTICES.md` if legal review requires consolidated notices.
- [ ] [P1] Add explicit policy for adding new dependencies (security + license review gate).
- [ ] [P1] Add license compliance check to CI for dependency updates.
- [ ] [P2] Add trademark/branding usage guidance for external forks.
- [ ] [P2] Add policy for test corpus licensing provenance documentation.

### 7g. Community & Project Operations

- [ ] [P1] Enable GitHub Discussions with categories (Q&A, Ideas, Show and Tell).
- [x] [P1] Define label taxonomy (`good first issue`, `help wanted`, `security`, `needs-repro`).
- [ ] [P1] Seed onboarding issues for first-time external contributors.
- [x] [P1] Add issue triage playbook for maintainers.
- [ ] [P2] Add stale-issue policy and automation.
- [ ] [P2] Publish roadmap/milestones for upcoming releases.
- [ ] [P2] Add community acknowledgements/contributors section.
- [ ] [P2] Define escalation path for abuse/moderation beyond CODE_OF_CONDUCT contact.

### 7h. Launch Go/No-Go Gate

- [ ] [P0] Confirm all P0 items above are complete.
- [ ] [P0] Run full validation suite on clean checkout and archive results.
- [ ] [P0] Confirm package publish + install + basic scan smoke test on Linux/macOS/Windows.
- [ ] [P0] Confirm security contact and reporting workflow end-to-end.
- [ ] [P0] Confirm README commands match actual released behavior.
- [ ] [P1] Announce launch with known limitations and support boundaries.

---

## Decision Log

| Decision                                | Rationale                                                                                         |
| --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Keep history as-is                      | History rewrite was deemed unnecessary after hardening; contributor emails are accepted as public |
| Keep docs/agents/ (non-sensitive files) | Architecture, testing, CI docs are standard contributor resources                                 |
| Keep docs/security/                     | Educational PyTorch security content benefits the community                                       |
| Keep CLAUDE.md/AGENTS.md/GEMINI.md      | AI agent config in repos is increasingly common                                                   |

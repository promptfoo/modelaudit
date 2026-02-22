# Security Audit Findings

**Created:** 2026-02-22
**Source:** Cross-agent codebase audit
**Status:** Resolved — all findings fixed

---

## Critical

### 1. ~~ONNX scanning fails open when `onnx` dep is missing~~ RESOLVED (PR #553)

**Files:**

- `modelaudit/scanners/onnx_scanner.py:62` — `can_handle` returns `False` without dep
- `modelaudit/scanners/weight_distribution_scanner.py:46` — `can_handle` allows `.onnx` without onnx import check
- `modelaudit/scanners/weight_distribution_scanner.py:137` — extraction failure logged as DEBUG
- `modelaudit/scanners/weight_distribution_scanner.py:148` — `success=True` on empty weights

**Impact:** A `.onnx` file scanned without the `onnx` package exits 0 with no security issues reported. The OnnxScanner (priority 6) declines the file, WeightDistributionScanner (priority 13) picks it up, fails to extract weights silently, and reports success. Users believe the file is safe when no real analysis occurred.

**Repro:** `modelaudit some_model.onnx` in an env without `onnx` installed → exit 0, no issues.

**Fix:**

- WeightDistributionScanner should check for onnx import in `can_handle` when ext is `.onnx`
- When no scanner can perform real analysis, the result should indicate incomplete coverage (not clean)
- Add regression tests: "missing optional dep must not report clean for formats requiring that dep"

### 2. ~~CI summary job (`ci-success`) references `needs.changes` without depending on it~~ RESOLVED (PR #553)

**Files:**

- `.github/workflows/test.yml:739` — `ci-success.needs` omits `changes`
- `.github/workflows/test.yml:778` — `needs.changes.outputs.dependencies` (evaluates to empty)
- `.github/workflows/test.yml:779` — `needs.changes.outputs.python` (evaluates to empty)

**Impact:** On PRs, `DEPENDENCIES_CHANGED` and `PYTHON_CHANGED` are always empty strings. The conditional failure checks (lines 809-820) for `license-check`, `uv-lock-check`, `test-numpy-compatibility`, `test-extras-smoke`, `test-proto-reproducibility` never execute. These jobs can fail on PRs and `ci-success` still passes, allowing broken PRs to merge.

On `main` this works correctly because `ON_MAIN_BRANCH == "true"` short-circuits the condition.

**Fix:** Add `changes` to the `ci-success` job's `needs` list. Actionlint confirms this issue.

### 3. ~~7z path traversal detection does not prevent extraction~~ RESOLVED (PR #553)

**Files:**

- `modelaudit/scanners/sevenzip_scanner.py:122` — `_check_path_traversal` flags CRITICAL issues
- `modelaudit/scanners/sevenzip_scanner.py:125` — `_identify_scannable_files` uses unfiltered names
- `modelaudit/scanners/sevenzip_scanner.py:218` — `archive.extract` extracts flagged entries

**Impact:** When a 7z archive contains entries with `../` traversal paths, the scanner correctly detects and reports them as CRITICAL. However, those same entries are still included in the extraction list and extracted to the temp directory. py7zr's `extract(path=tmp_dir, targets=["../../evil.pkl"])` writes outside the temp dir.

**Mitigations already present:** Extraction is to a temp dir with limited lifetime. The traversal IS flagged in the result. But defense-in-depth requires not extracting known-bad entries.

**Fix:**

- `_check_path_traversal` should return the set of unsafe names
- `_identify_scannable_files` should exclude unsafe names
- Alternatively, abort extraction entirely if any traversal is detected
- Add test cases for path traversal in 7z archives

---

## High

### 4. ~~Docker publish SHA tag mismatch~~ RESOLVED

**Files:**

- `.github/workflows/docker-publish.yml:50` — `type=sha,prefix=` generates tag without prefix (e.g., `abc1234`)
- `.github/workflows/docker-publish.yml:68-69` — verification pulls `sha-${GITHUB_SHA::7}` (e.g., `sha-abc1234`)

**Impact:** The verification step after publishing always tries to pull a non-existent tag. The generated tag has no prefix, but the verify step assumes `sha-` prefix. This means published images are never verified.

**Fix:** Either change line 50 to `type=sha` (default prefix `sha-`) or change lines 68-69 to `${GITHUB_SHA::7}` (no prefix).

### 5. ~~Docker `workflow_dispatch` tag input is required but unused~~ RESOLVED

**Files:**

- `.github/workflows/docker-publish.yml:8-10` — defines `inputs.tag` as required
- No reference to `${{ inputs.tag }}` or `${{ github.event.inputs.tag }}` anywhere in workflow

**Impact:** Manual dispatch asks the user for a tag but ignores it. The build uses whatever ref the workflow is triggered from, not the user's intended tag. Could result in publishing an unintended image version.

**Fix:** Wire `inputs.tag` into the metadata-action tags configuration, or remove the input if manual tagging isn't needed.

---

## Policy/Doc Consistency

### 6. ~~License CI logic conflicts with dependency policy~~ RESOLVED

**Files:**

- `.github/workflows/test.yml:161` — CI approves `lgpl` keyword
- `.github/workflows/test.yml:207-208` — CI approves any `OSI Approved` classifier
- `docs/maintainers/dependency-policy.md:10` — policy says LGPL "requires maintainer approval"
- `docs/maintainers/dependency-policy.md:11` — policy says GPL/AGPL/proprietary "blocked"

**Impact:**

- **LGPL:** CI auto-approves it, but policy requires manual approval. Currently py7zr (LGPL-2.1+) is the only LGPL dep and it's documented in THIRD_PARTY_NOTICES.md, but the CI wouldn't catch a new LGPL addition that should require review.
- **OSI Approved:** `License :: OSI Approved :: GNU General Public License v3` would pass the CI check despite being blocked by policy. Low practical risk (no GPL deps exist today) but the check is overly permissive.
- **NVIDIA:** CI auto-approves NVIDIA prefixes (proprietary, PyTorch transitive deps). This is deliberate and commented in CI, but not documented in the dependency policy.

**Fix:**

- Move LGPL from CI's approved list to a separate "warn but don't fail" category, or document the approved LGPL exception (py7zr) explicitly
- Tighten the OSI Approved check to exclude GPL/AGPL classifiers
- Add the NVIDIA exception to `dependency-policy.md`

### 7. ~~Threat model document overstates behavior~~ RESOLVED

**Files and claims:**

| Claim | File | Reality |
| --- | --- | --- |
| "ModelAudit does not make outbound network requests during scanning" | `docs/security/threat-model.md:33` | Technically accurate (downloads happen in CLI before scanning), but misleading. CLI at `cli.py:819` and `cli.py:904` downloads from HuggingFace Hub. |
| "ModelAudit never calls `pickle.loads`, `torch.load`, or any deserializer on untrusted input" | `docs/security/threat-model.md:63` | **Directly contradicted.** `weight_distribution_scanner.py:202` calls `torch.load`. |
| "Path traversal checks are applied to member names before any extraction occurs" | `docs/security/threat-model.md:67` | **Misleading.** True for ZIP scanner, but 7z scanner extracts files to temp dir for sub-scanning (finding #3). |

**Fix:**

- Clarify network boundary: "The scanning engine makes no outbound requests. The CLI may download model files from remote sources before invoking the scanner."
- Remove or qualify the `torch.load` claim: "Core scanners use byte-level parsing. The optional weight distribution scanner calls `torch.load` with `map_location='cpu'` for statistical analysis of PyTorch weight tensors."
- Qualify extraction claim: "ZIP-based formats are inspected without extraction. 7z archives are extracted to an ephemeral temp directory for sub-scanning."

### 8. ~~THIRD_PARTY_NOTICES.md is incomplete~~ RESOLVED

**Files:**

- `pyproject.toml:73` — `tensorrt` optional extra exists but is not listed in THIRD_PARTY_NOTICES.md optional deps table
- `pyproject.toml:147` — dev dependencies (`ruff`, `mypy`, `pytest`, etc.) are not represented despite readiness item 7f claiming "runtime + dev inventory"

**Fix:**

- Add `tensorrt` to the optional dependencies table in THIRD_PARTY_NOTICES.md
- Either add a dev dependencies section or explicitly note that dev-only deps are excluded from the notices (since they're not distributed to users)

---

## Recommended Fix Order

1. **CI gate fix** (finding #2) — 1 line, unblocks CI trustworthiness
2. **ONNX fail-closed** (finding #1) — scanner code + regression tests
3. **7z safe extraction** (finding #3) — filter unsafe targets before extraction
4. **Docker publish fixes** (findings #4, #5) — SHA tag + wire input
5. **Threat model doc update** (finding #7) — align claims with code
6. **License policy alignment** (finding #6) — tighten CI check, update policy doc
7. **THIRD_PARTY_NOTICES update** (finding #8) — add tensorrt, clarify dev deps scope

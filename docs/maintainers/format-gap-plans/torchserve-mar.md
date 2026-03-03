# Plan: TorchServe `.mar` Support

## Goal

Add first-class security scanning support for TorchServe Model Archive files (`.mar`) with format-aware checks and recursive scanning of embedded payloads.

## Why This Gap Matters

`.mar` files are ZIP-based deployment bundles that can carry:

- Serialized model weights (often pickle/PyTorch)
- Python handlers and extra code files
- Manifest metadata that controls execution paths at serving time

A scanner that treats `.mar` as unknown misses both malicious payload and deployment-level abuse patterns.

## Scope

In scope:

- `.mar` file recognition and dedicated scanner
- Safe manifest parsing and policy checks
- Recursive scanning of embedded files with existing scanners
- TorchServe-specific exploit checks

Out of scope:

- Runtime emulation of TorchServe startup
- Network reachability checks of live model servers

## Deliverables

- `modelaudit/scanners/torchserve_mar_scanner.py`
- Registry wiring in `modelaudit/scanners/__init__.py`
- Extension detection updates in `modelaudit/utils/file/detection.py`
- Unit tests under `tests/scanners/test_torchserve_mar_scanner.py`
- Fixture allowlist update in `tests/conftest.py`
- User docs and changelog updates

## Detailed Engineering Tasks

1. Format specification and sample corpus

- Collect benign `.mar` samples from official TorchServe examples.
- Create malicious fixtures with synthetic payloads: path traversal member names, suspicious handlers, embedded malicious pickle.
- Record minimal required archive structure (`MAR-INF/MANIFEST.json`, serialized file path).

2. Scanner implementation

- Implement `TorchServeMarScanner(BaseScanner)` with `supported_extensions = [".mar"]`.
- Implement strict `can_handle()`:
  - Verify ZIP signature.
  - Verify presence of `MAR-INF/MANIFEST.json`.
  - Reject non-archive files renamed to `.mar`.
- In `scan()` call `_check_path()` and `_check_size_limit()` before archive parsing.

3. Manifest validation checks

- Parse manifest JSON with bounded read (max 1 MB).
- Validate required keys and path fields (`model`, `handler`, `serializedFile`, `extraFiles`).
- Add checks for:
  - Absolute paths or `..` traversal in manifest file references.
  - Handler values pointing outside archive root.
  - Suspicious URL-like references in local-only fields.

4. Embedded payload scanning

- Iterate archive members without full extraction.
- For each member:
  - Apply path traversal and symlink checks.
  - Dispatch scannable entries to existing scanners by extension/content.
  - Preserve origin path in findings (`<archive>.mar:<member>`).
- Ensure bounded processing limits:
  - max entries
  - max recursion depth
  - max uncompressed bytes budget

5. TorchServe-specific risk checks

- Flag executable handlers (`.py`) that include high-risk primitives (`os.system`, `subprocess`, dynamic import patterns).
- Flag dangerous pickle-like serialized payloads via existing pickle scanner.
- Add explicit check for mismatched manifest references (manifest points to missing/alternate file).

6. Registry and routing

- Add scanner registration entry with priority before generic ZIP scanner.
- Add class mapping in `__getattr__`.
- Add extension mapping for `.mar` in `EXTENSION_FORMAT_MAP`.
- Ensure fallback behavior keeps `.mar` from being treated as unknown.

7. Performance and resilience

- Cap manifest/member reads to avoid decompression bomb behavior.
- Handle corrupt ZIPs gracefully with `INFO`/`WARNING` checks, not crashes.
- Ensure scanner is deterministic for same input.

## False-Positive Reduction Strategy

- Only raise `CRITICAL` when code execution primitives are structurally reachable, not based on single-token string matches.
- Use path normalization and canonical root checks for traversal findings to avoid false alerts on benign relative paths.
- Distinguish user-defined handlers from malicious handlers:
  - user-defined handler without suspicious primitives => `INFO` or pass
  - handler with execution chain + suspicious imports => `CRITICAL`
- Reuse existing allowlists and explanation mappings where applicable.

## Test Plan

1. Unit tests (`tests/scanners/test_torchserve_mar_scanner.py`)

- Benign archive with valid manifest and safe handler.
- Archive with malicious pickle payload referenced by manifest.
- Archive with path traversal member names.
- Archive with missing `MAR-INF/MANIFEST.json`.
- Corrupt archive renamed `.mar`.
- Archive with nested ZIP + malicious member.

2. Regression tests

- Ensure `.mar` no longer produces `unknown` scanner result.
- Ensure benign custom handler code does not produce `CRITICAL` unless risky primitives appear.
- Ensure comment-token bypass attempts do not suppress real findings.

3. Type and quality checks

- Test functions use explicit return type annotations (`-> None`).
- Use `tmp_path: Path` fixtures only; no host path assumptions.

## QA Steps

1. Scanner-level tests:

```bash
uv run pytest tests/scanners/test_torchserve_mar_scanner.py -q
```

2. Core routing smoke test:

```bash
uv run python -m modelaudit.cli tests/fixtures/torchserve/safe.mar --format json
```

3. Full project gate:

```bash
uv run ruff format modelaudit/ tests/
uv run ruff check --fix modelaudit/ tests/
uv run mypy modelaudit/
uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Documentation Tasks

- Update `README.md` Supported Formats table to include TorchServe `.mar`.
- Update `docs/user/compatibility-matrix.md` with dependency posture.
- Add scanner description in user docs scanner page.
- Add `[Unreleased]` changelog entry in `CHANGELOG.md`.

## Release and Telemetry

- Ensure scanner name appears in scanner metrics (`torchserve_mar`).
- Add telemetry validation in debug output to confirm scanner selection.

## Definition of Done

- `.mar` files route to dedicated scanner.
- Embedded malicious payloads are detected with correct severity.
- False-positive rate is acceptable on benign TorchServe samples.
- Full lint/type/test gates pass.

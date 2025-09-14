ModelAudit PR Review — Fickling Integration

Summary

- Overall: This PR significantly reworks pickle scanning by introducing a new `FicklingPickleScanner` and wiring it into the registry as the default `pickle` scanner. The approach is promising and adds stronger static analysis as well as additional heuristics (nested pickles, embedded payloads, trailing binary signatures). However, there are several architectural overlaps, ordering/selection pitfalls, repo hygiene issues, and CI/dependency concerns that should be addressed before merge.

Architecture & Design

- Duplicate implementations: The new `modelaudit/scanners/fickling_pickle_scanner.py` fully replaces pickle handling in the registry, yet `modelaudit/scanners/pickle_scanner.py` is also updated with its own fickling integration. This creates two divergent implementations of the same concern. Recommendation: choose a single source of truth. Either:
  - Keep only `FicklingPickleScanner` and revert fickling-specific changes from `PickleScanner`, or
  - Keep `PickleScanner` and make it internally use fickling behind a feature flag, removing the separate file.
- Registry mapping: `name = "pickle"` on the new scanner and `__getattr__` mapping both `FicklingPickleScanner` and `PickleScanner` to the `pickle` id is acceptable, but increases confusion while both classes coexist. Consolidating to one public class will simplify imports and future maintenance.
- Optional vs core dependency: The registry marks `dependencies: ["fickling"]` for the `pickle` scanner, implying a required dependency, but the implementation gracefully degrades when fickling is unavailable (and tests skip on 3.12+). Decide on policy:
  - If fickling is optional, keep graceful fallback and ensure docs/tests reflect optionality; consider removing the hard dependency from `dependencies` or making messaging clearer.
  - If fickling is required in CI-only, ensure CI extras always include it but keep user installs optional (docs should state this explicitly).

Scanner Selection & Ordering

- Priority/extension handling: `pickle` priority is 1, `pytorch_zip` is 2, but `FicklingPickleScanner.supported_extensions` includes `.pt` and `.pth`. That means `.pt/.pth` files will be claimed by the pickle scanner before the zip scanner. `can_handle` contains a special-case for `.bin` that delegates ZIP to the PyTorch ZIP scanner, but there’s no similar ZIP check for `.pt/.pth`. This will misroute ZIP-based PyTorch models to the pickle path.
  - Fix: In `FicklingPickleScanner.can_handle`, also detect ZIP for `.pt`/`.pth` and return False when ZIP is detected so `pytorch_zip` can claim them.
  - Alternatively, lower the `pickle` priority below `pytorch_zip` for `.pt/.pth` or remove those extensions from the pickle scanner if ZIP-based flows should always win.
- OCI layer prefilter: `oci_layer_scanner` changed from calling `can_handle` (on non-existent files) to checking `supported_extensions` before extraction. That’s a good improvement for tar members, but it loses content-aware gating (like the `.bin` ZIP override). This is mostly fine since selection after extraction still goes through the registry, but be aware that more files will be extracted and then rejected post-facto. Consider a lightweight magic sniff after extraction to minimize unnecessary work.

Correctness & Robustness

- Fallback success semantics: In several exception paths (e.g., unexpected error during fickling load), the scanner calls `result.finish(success=True)` and returns early without running all fallbacks. Given the security domain, consider consistently running content-based CVE and pattern scans when fickling fails, and clearly differentiating parse errors (possibly `success=False` when the pickle is unreadable).
- Metadata consistency: The new scanner writes `ml_confidence` only, while some tests and other scanners (e.g., PyTorch ZIP) read `ml_confidence` but older tests also looked for `ml_context`. You’ve adjusted most references, but consider documenting standard keys and making them consistent across scanners to prevent future breakage.
- Import analysis API usage: Calls like `pickled.unsafe_imports()` and `pickled.non_standard_imports()` depend on fickling’s API surface (0.1.4). If fickling updates, these may change. Add try/except guards (already partly done) and unit tests that lock behavior.
- Severity mapping: Mapping fickling severities to ModelAudit severities looks reasonable. Keep it centralized to avoid drift between the two pickle scanners.

Security & Detection Coverage

- Binary trailing content scanning: Good addition; special-casing PE (MZ + DOS stub) is thoughtful. Ensure the signedness doesn’t create false positives in large `.bin` model shards by default; your ML-context skip is a good mitigation.
- Nested/embedded payloads: Useful checks. Consider centralizing those helpers shared by pickle scanners to avoid logic drift.
- CVE pattern pipeline: The unconditional call to `_analyze_content_patterns` post-analysis is a good belt-and-suspenders approach.

Performance

- Full-file reads: The new scanner reads entire files for CVE/pattern checks. For very large model shards, this can be expensive. Consider chunked scanning where feasible and early exits on matches to reduce memory footprint.
- ML context heuristics: Simple heuristics are fine, but they may read the entire pickle bytes via `pickled.dumps()`. If possible, restrict to a bounded preview or cache results across checks.

Compatibility & API

- Python 3.12: The code disables fickling for 3.12+ and adds test skips. That’s pragmatic, but document it clearly. Also, consider feature gating at runtime via config to make behavior explicit to users.
- Union syntax: The codebase uses `PEP 604` union types broadly, which is fine for 3.10+, but AGENTS.md claims 3.9+ support. If 3.9 support is still required, files should use `from __future__ import annotations` or `typing.Optional[...]` to stay compatible.

Dependencies & CI

- Pinning: `pyproject.toml` pins `fickling==0.1.4` and narrows `onnx` upper bounds. If these are driven by CI stability, capture the rationale in a comment. Also, `all-ci` now includes numpy and ml-dtypes pins; verify cross-platform resolution works reliably.
- Ruff per-file ignores: Blanket ignores for `scripts/*.py` and `modelscan/**` are broad. Consider scoping them tighter or moving non-library scripts under `scripts/` and adding a local `pyproject.toml` for scripts if needed. Avoid suppressing quality checks on library code paths.

Repo Hygiene

- Committed artifacts in repo root: Several binary payloads and JSON comparison outputs are added at the repository root (e.g., `simple_exec.pkl`, `eval_payload.pkl`, `comparison_results_*.json`, `HYBRID_IMPLEMENTATION_TEST_REPORT.md`, `advanced_malicious_pickles.py`, `compare_implementations.py`). These look like one-off experiments.
  - Move example payloads under `tests/assets/` if needed for tests; otherwise remove and .gitignore them.
  - Move analysis scripts under `scripts/` and consider excluding them from packages.
  - Remove generated result JSONs and reports from VCS; add them to `.gitignore`.

Tests

- Coverage: Many tests were updated to use `FicklingPickleScanner`, which matches the registry swap. Good.
- Python 3.12 skips: Constraining the test matrix on 3.12 is pragmatic, but be explicit in CI and docs that fickling is disabled there and ensure the remaining tests still cover critical behavior and fallbacks.
- End-to-end scanner selection: Add tests that verify `.pt/.pth` ZIP models are handled by `PyTorchZipScanner` and not by pickle when both are present.

Documentation

- Update README/docs to explicitly call out fickling usage, Python 3.12 behavior, and optional dependency installation instructions. Ensure CLI help and error messages match the new behavior.

Concrete Action Items

- Unify pickle scanner: pick one implementation, delete or revert the other to avoid drift.
- Fix `.pt/.pth` routing: extend ZIP detection in `FicklingPickleScanner.can_handle` or adjust priorities accordingly.
- Clean repo root: move payloads and scripts to `tests/assets/` and `scripts/`, delete generated outputs, and add proper `.gitignore` entries.
- Clarify dependency policy: decide whether fickling is optional or required in CI; align registry `dependencies`, docs, and error messages.
- Normalize metadata: standardize keys like `ml_confidence` vs `ml_context` across scanners; update docs/tests.
- Review exception paths: ensure fallback CVE/pattern analysis always runs on fickling failure; revisit `success` semantics on parse failures.
- Performance passes: consider chunked reads for large files and limit full `dumps()` calls.
- Document Python 3.12 behavior: clearly state fickling is disabled there; keep tests robust around that path.

Nice-to-haves (post-merge follow-ups)

- Centralize shared helpers between pickle scanners to one module to avoid duplication.
- Add lightweight magic sniffers for archive formats earlier in the pipeline to reduce misrouted scans and unnecessary work.
- Consider a feature flag to force legacy vs fickling-based scan paths for troubleshooting.


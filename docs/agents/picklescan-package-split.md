# Pickle Scanner Package Split

This document describes the current package boundary between ModelAudit's
wrapper scanners and the standalone pickle analysis package in
`packages/modelaudit-picklescan`.

## Package Layout

```text
packages/
  modelaudit-picklescan/
    pyproject.toml
    uv.lock
    src/modelaudit_picklescan/
      __init__.py
      py.typed
      api.py
      options.py
      report.py
      engine/
      _rust.*.so        # generated only by local/native builds; not committed
    rust/
      src/lib.rs
    tests/
modelaudit/
  scanners/
    pickle_scanner.py
    pytorch_zip_scanner.py
    joblib_scanner.py
    numpy_scanner.py
    executorch_scanner.py
```

## Dependency Boundary

- `modelaudit-picklescan` does not import `modelaudit`.
- `modelaudit-picklescan` owns pickle byte/stream analysis, safety verdicts,
  scan completeness, resource limits, and pickle-only metadata.
- `modelaudit` owns file routing, archive/container orchestration, CLI, cache,
  telemetry, SARIF/export integrations, and `PickleReport -> ScanResult`
  adaptation.
- During the migration period, `modelaudit.scanners.pickle_scanner.PickleScanner`
  still merges legacy-only checks after the standalone pass. Keep this fallback
  until the parity harness shows that standalone verdict, status, and required
  rule coverage are sufficient for the root scanner to depend on it alone.
- Wrapper scanners in `modelaudit` pass embedded pickle streams into
  `modelaudit-picklescan`; archive parsing stays in `modelaudit`.
- The root `modelaudit` wheel bundles `modelaudit_picklescan` as a second import
  package, so the adapter and wrapper scanners use the same source tree without
  depending on a separately published artifact.
- The standalone wheel is built with `maturin` and includes the Rust extension
  module `modelaudit_picklescan._rust`.

## API Contract

The standalone package exposes a small native surface:

```python
from modelaudit_picklescan import PickleScanner, ScanOptions, scan_bytes, scan_file, scan_stream

report = scan_file("weights.pkl")
report = scan_bytes(payload, source="weights.pkl")

scanner = PickleScanner(options=ScanOptions(timeout_s=30.0, max_opcodes=1_000_000))
report = scanner.scan_stream(stream, source="archive.pt:data.pkl", size=pickle_size)
```

Resource controls include opcode and wall-clock limits, post-budget tail bytes,
string-literal scan characters, nested-pickle bytes, and nested scan depth.

The standalone package now uses the native Rust extension directly. The deleted
package-engine selector and compare runtime are no longer part of the API.

Report semantics keep these concepts separate:

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: `WARNING`/`CRITICAL` security findings only
- `notices`: `DEBUG`/`INFO` coverage or explainability notes
- `errors`: operational failures
- report mappings are read-only after construction; call `to_dict()` for mutable
  serialized data

## Current Integration

- `modelaudit.scanners.pickle_scanner.PickleScanner` treats the standalone Rust
  package report as the primary pickle result and merges bounded root-only
  compatibility checks as supplemental evidence.
- Embedded-pickle wrapper scanners (`pytorch_zip`, `joblib`, `numpy`, and
  `executorch`) call the public `scan_stream(..., source=...)` API and preserve
  archive-member context in result locations/details.
- `scripts/compare_pickle_scanners.py` is the parity harness for checking
  verdict/status drift and rule-code differences across fixture corpora.
- CI lints, type-checks, tests, builds, and smoke-installs both the root
  `modelaudit` distribution and the standalone `modelaudit-picklescan`
  distribution in separate workflow jobs.
- For the scoped Rust rewrite plan, parity gates, packaging decisions, and
  benchmark methodology, see
  `docs/maintainers/picklescan-rust-rewrite-plan.md`.

## Validation

Root package checks run from the repository root:

```bash
uv run ruff check modelaudit/ tests/
uv run ruff format --check modelaudit/ tests/
uv run mypy modelaudit/ tests/
uv run pytest tests -n auto -m "not slow and not integration" --maxfail=1
```

Standalone package checks run from `packages/modelaudit-picklescan`:

```bash
uv lock --check
uv run --with ruff ruff check src tests
uv run --with ruff ruff format --check src tests
uv run --with mypy mypy src tests
uv run --with pytest --with pytest-xdist pytest -n auto tests --tb=short
uv run --with pytest pytest tests -q
cargo fmt --manifest-path Cargo.toml -- --check
cargo check --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path Cargo.toml
uv build --out-dir /tmp/modelaudit-picklescan-dist
uvx twine check /tmp/modelaudit-picklescan-dist/*
```

## Safety Invariants

- Detection logic must not weaken at the package boundary.
- Each moved detector or routing rule has malicious-positive and benign-negative
  regression coverage.
- Verdict/status drift is a blocker in the differential harness. Legacy and
  standalone rule identifiers may differ, but the safety decision and
  scan-completeness contract must stay aligned.
- Inconclusive analysis is represented as first-class status/metadata, not as a
  hidden success boolean.
- Per-scan state stays isolated so one scan cannot leak source/location context
  into the next.

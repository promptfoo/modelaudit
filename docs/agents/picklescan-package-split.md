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
      _rust.*           # generated only by local/native builds; not committed
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
- `modelaudit.scanners.pickle_scanner.PickleScanner` is a thin ModelAudit
  adapter around the Rust-backed standalone package.
- Wrapper scanners in `modelaudit` pass embedded pickle streams into
  `modelaudit-picklescan`; the root package owns rich archive/container
  orchestration, while standalone `scan_file()` also recognizes PyTorch ZIP
  checkpoints for standalone callers.
- The root `modelaudit` wheel depends on the `modelaudit-picklescan`
  distribution instead of bundling its pure Python package files. This keeps
  wheel installs aligned with the native extension that the scanner requires.
- The standalone wheel is built with `maturin` and includes the Rust extension
  module `modelaudit_picklescan._rust`.

## API Contract

The standalone package exposes a small native surface:

```python
from modelaudit_picklescan import (
    PickleScanner,
    ScanOptions,
    scan_bytes,
    scan_file,
    scan_stream,
    shared_source_sensitive_caches,
)

report = scan_file("weights.pkl")
report = scan_bytes(payload, source="weights.pkl")

scanner = PickleScanner(options=ScanOptions(timeout_s=30.0, max_opcodes=1_000_000))
report = scanner.scan_stream(stream, source="archive.pt:data.pkl", size=pickle_size)

with shared_source_sensitive_caches():
    reports = [scan_file(path) for path in related_paths]
```

Before returning each later report, the shared scope revalidates bounded
analyzed source. A change observed at that validation point fails closed as
inconclusive instead of returning an earlier clean result.

Resource controls include opcode and wall-clock limits, post-budget tail bytes,
string-literal scan characters, nested-pickle bytes, and nested scan depth.

The standalone package uses the native Rust extension directly. Engine selection
and compare runtimes are not part of the public API.

Report semantics keep these concepts separate:

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: `WARNING`/`CRITICAL` security findings only
- `notices`: `DEBUG`/`INFO` coverage or explainability notes
- `errors`: operational failures
- report mappings are read-only after construction; call `to_dict()` for mutable
  serialized data

## Integration

- `modelaudit.scanners.pickle_scanner.PickleScanner` treats the standalone Rust
  package report as the pickle result and only adds ModelAudit wrapper concerns
  such as path validation, file integrity metadata, and `ScanResult` adaptation.
- Embedded-pickle wrapper scanners (`pytorch_zip`, `joblib`, `numpy`, and
  `executorch`) call the public `scan_stream(..., source=...)` API and preserve
  archive-member context in result locations/details.
- When a root scan has multiple dispatch entries and the installed standalone
  package exposes `shared_source_sensitive_caches()`, it reuses source-validated
  call-graph analysis across those entries. Changed sources are refreshed
  before a later report, and changes observed by final validation fail closed;
  older supported installs scan correctly without this optimization.
- CI lints, type-checks, tests, builds, and smoke-installs both the root
  `modelaudit` distribution and the standalone `modelaudit-picklescan`
  distribution. Root wheel smoke tests install the local standalone wheel via
  `--find-links` so the unpublished dependency is exercised exactly as an
  installed package.

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
uv run --with 'ruff==0.15.10' ruff check src tests
uv run --with 'ruff==0.15.10' ruff format --check src tests
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
- ModelAudit-compatible and standalone rule identifiers may differ, but the
  safety decision and scan-completeness contract must stay aligned.
- Inconclusive analysis is represented as first-class status/metadata, not as a
  hidden success boolean.
- Per-scan state stays isolated: scoped reuse revalidates analyzed source before
  each later report, and the next outer scope starts fresh.

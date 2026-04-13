# PickleScan Rust Rewrite Plan

This document scopes a Rust-backed rewrite of the standalone
`modelaudit-picklescan` engine. The goal is faster and more bounded pickle
analysis without changing ModelAudit's public Python API, safety decisions, or
root scanner behavior.

## Implementation Status

The standalone implementation is now Rust-only:

- `packages/modelaudit-picklescan/Cargo.toml` builds a PyO3 extension with
  `maturin`.
- `packages/modelaudit-picklescan/rust/src/lib.rs` implements the native opcode
  parser, policy checks, nested-pickle handling, resource-budget notices,
  report serialization, and parity-oriented fail-closed semantics.
- `modelaudit_picklescan.engine.rust` converts the native report mapping back
  into the existing Python dataclasses.
- If the compatible native extension is not importable, scan calls return an
  explicit `rust_engine_error`; the deleted Python package scanner is not used
  as a fallback.

## Goals

- Preserve the public `modelaudit_picklescan` API:
  `PickleScanner`, `scan_bytes`, `scan_stream`, `scan_file`, `ScanOptions`,
  `PickleReport`, `Finding`, `Notice`, `ScanError`, `CoverageSummary`,
  `SafetyVerdict`, `ScanStatus`, and `Severity`.
- Preserve historical scanner coverage for verdicts, statuses, coverage,
  metadata, findings, notices, errors, locations, and rule codes.
- Preserve root `modelaudit` behavior while the legacy pickle scanner remains
  the compatibility fallback.
- Improve large-payload throughput and memory behavior with measurable
  benchmark artifacts.
- Keep the standalone wheel independent from the root `modelaudit` package.

## Non-Goals

- Do not execute or deserialize pickle payloads.
- Do not change scanner routing, archive parsing, CLI behavior, telemetry,
  cache semantics, SARIF output, or root `ScanResult` models as part of the
  Rust engine.
- Do not remove the Python implementation or legacy root fallback until the
  parity gates in this document pass.
- Do not make Rust the default or remove the Python implementation until the
  release-wheel matrix and long-running parity gates are complete.

## Current Boundary

`packages/modelaudit-picklescan` owns pickle byte and stream analysis, report
semantics, scan completeness, resource limits, and pickle-only metadata. The
root `modelaudit` package owns file routing, archive orchestration, CLI, cache,
telemetry, SARIF/export integrations, and `PickleReport` to `ScanResult`
adaptation.

The root `PickleScanner` still merges legacy-only checks while the standalone
engine continues toward full parity. A Rust rewrite must target the standalone
engine first and keep this migration boundary intact.

## Architecture

The Rust engine sits behind the existing Python API:

- `modelaudit_picklescan.api` remains the only public entry point.
- Python dataclasses in `report.py` and option validation in `options.py`
  remain source-compatible.
- The Rust module returns a plain Python mapping that the Python wrapper
  converts into the existing dataclasses.
- Engine selection is internal and explicit during migration:
  - `python`: current implementation.
  - `rust`: Rust-backed implementation.
  - `compare`: run both, return Python output, and expose diagnostics for tests.
- Default stays `python` until all parity and packaging gates pass.
- On import/build failure for the Rust extension, the package reports a Rust
  engine error. The Python package engine and compare selector have been
  removed.

Rust is the only standalone package engine. CI and release jobs should exercise
the native extension directly.

## Feature Parity Matrix

| Area                                                    | Current Owner               | Rust Port Requirement                                                                                |
| ------------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------- |
| Public API surface                                      | Python wrapper              | No signature or import changes.                                                                      |
| `ScanOptions` defaults and validation                   | Python                      | Preserve validation errors and accepted values.                                                      |
| Report immutability and `to_dict()` shape               | Python                      | Preserve Python dataclasses as public models.                                                        |
| Bounded stream reads                                    | Standalone engine           | No unbounded reads for stream scans; preserve short-read detection.                                  |
| `source`, `bytes_total`, offsets                        | Standalone engine           | Preserve absolute offsets from current stream position.                                              |
| Empty input, IO, short-read, parse errors               | Standalone engine           | Preserve `ScanStatus.ERROR`, `SafetyVerdict.UNKNOWN`, error categories, and coverage flags.          |
| Timeout and opcode budgets                              | Standalone engine           | Preserve fail-closed `INCONCLUSIVE` status, notices, coverage, and shared nested-scan deadline.      |
| Multiple pickle streams                                 | Standalone engine           | Continue scanning follow-on streams after `STOP`.                                                    |
| Opcode parsing                                          | Standalone engine           | Support protocols 0-5 and all opcodes currently handled or safely ignored.                           |
| Stack and memo simulation                               | Standalone engine           | Preserve callable attribution, memoized operands, and stack reset after `STOP`.                      |
| `GLOBAL` and `STACK_GLOBAL`                             | Standalone engine           | Preserve import-reference metadata, malformed operand handling, and dangerous/global findings.       |
| `REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `OBJ`, `INST`, `BUILD` | Standalone engine           | Preserve dangerous-call attribution and redundant global coalescing.                                 |
| `EXT1`, `EXT2`, `EXT4`                                  | Standalone engine           | Preserve warning findings for opaque extension references.                                           |
| Dangerous global policy                                 | Standalone policy           | Port policy tables exactly; add tests for any intentional change.                                    |
| Warning globals                                         | Standalone policy           | Preserve warning severity for `functools.partial`, `partialmethod`, `glob`, and `tempfile.mktemp`.   |
| Benign stdlib references                                | Standalone policy           | Preserve non-failing import metadata for known benign constructors.                                  |
| Suspicious string literals                              | Standalone engine           | Preserve bounded windows, regex labels, truncation notices, and fail-closed unknown verdicts.        |
| Raw nested pickle bytes                                 | Standalone engine           | Preserve `S213`, nested scan surfacing, depth limit, truncation findings, and notices.               |
| Base64, hex, escaped-hex nested payloads                | Standalone engine           | Preserve `S601`/`S602`, bounded decode input, oversized-prefix detection, and false-positive guards. |
| Post-budget tail scan                                   | Standalone engine           | Preserve `POST_BUDGET_GLOBAL` findings and tail-prefix behavior at budget boundaries.                |
| Deduplication                                           | Standalone engine           | Preserve finding, notice, and import-reference dedupe keys.                                          |
| Adapter mapping                                         | Root adapter                | No change except optional engine metadata in experimental mode.                                      |
| Root legacy merge                                       | Root scanner                | No removal until standalone/rust parity gates pass.                                                  |
| Binary tail/JIT/network/secrets scans                   | Root scanner                | Stay outside standalone Rust scope.                                                                  |
| CVE attribution and ML context                          | Root scanner plus detectors | Stay outside initial Rust scope unless explicitly moved later.                                       |
| Archive-member context                                  | Root wrapper scanners       | Preserve `scan_stream(..., source=...)` contract.                                                    |

## Parity Gates

Run these gates before enabling Rust by default:

1. Existing standalone tests pass with the Rust-only package engine.
2. Rust golden comparisons match for all committed pickle fixtures:
   status, verdict, success-equivalent, finding severities, rule codes,
   messages, locations, details, notices, errors, coverage, and metadata.
   `duration_s` is excluded.
3. `scripts/compare_pickle_scanners.py --include-root` has no new
   verdict or status drift relative to the pre-Rust baseline.
4. Safe fixtures in `scripts/compare_pickle_scanners_fixture_labels.json`
   remain `match`; no new false positives are allowed.
5. Root pickle tests, adapter tests, nested-pickle integration tests, and
   regression corpus tests pass.
6. Root and standalone wheel smoke tests pass, including the standalone check
   that `importlib.util.find_spec("modelaudit") is None`.

## Benchmark Plan

Baseline before coding and compare every Rust milestone against that baseline.

Measure at least:

- Small safe pickle.
- Large safe pickle with many literals/opcodes.
- Malicious `REDUCE` payload.
- `STACK_GLOBAL` payload.
- Raw nested pickle.
- Base64/hex nested pickle.
- Multi-stream payload with padding.
- Opcode-budget tail detection.
- Long benign string.
- Long suspicious string outside bounded windows.
- Non-seekable stream with small reads.

Metrics:

- Median and mean runtime via `pytest-benchmark`.
- Bytes per second for payload scans.
- Peak RSS or memory growth for large payloads when available.
- Import/warmup cost for the extension.
- Drift in `duration_s` is informational only; behavior gates use normalized
  report data.

Suggested initial performance target:

- No more than 10 percent slower on small payloads.
- No memory regression on large payloads.
- At least one material win, such as 2x median speedup or 50 percent lower
  peak memory on large or nested scans, before defaulting to Rust.

## Profiling Plan

Use CPU profiles to identify whether time is spent in opcode parsing, regex
matching, nested decode validation, post-budget scanning, or Python/Rust object
conversion. Profile both standalone scans and root scans because root wrapper
cost can dominate small payloads.

Recommended profiling checkpoints:

- Python baseline on the committed fixture corpus.
- Rust parser-only prototype.
- Rust security-policy prototype.
- Rust with Python dataclass conversion.
- Root scanner with the standalone Rust package as primary.

## Test Additions

- Add a package-engine comparison mode to `scripts/compare_pickle_scanners.py`
  so future Rust work can compare `python` vs `rust` without changing the root
  scanner.
- Add standalone pickle microbenchmarks under `tests/benchmarks/`.
- Add golden report fixtures only after the normalization rules are settled.
- Add malformed opcode and resource-budget cases for Rust-specific parser edge
  coverage.

## Packaging Decisions

- The standalone package now uses `maturin` as its build backend and builds
  `modelaudit_picklescan._rust`.
- The root `modelaudit` wheel depends on the `modelaudit-picklescan`
  distribution rather than bundling pure Python package sources without the
  native extension.
- Release work still needs the full wheel matrix: macOS x86_64/arm64,
  manylinux x86_64/aarch64, Windows x86_64, and Python 3.10-3.13.
- Source distribution behavior depends on the standalone package build; missing
  native extensions fail closed with an explicit Rust engine error report.
- CI should validate native standalone wheels, missing-extension error handling,
  and root adapter behavior.

## Rollout Plan

1. RFC and harnesses only. Done.
2. Prototype package-engine selector. Deleted by Rust-only runtime.
3. Rust opcode parser with coverage and import references. Done.
4. Rust dangerous global/call detection. Done.
5. Rust suspicious string and nested-pickle detection. Done.
6. Rust resource limits, post-budget scan, and error parity. Done.
7. Historical parity and regression corpus in CI. Done.
8. Make Rust the standalone package runtime. Done.
9. Remove remaining root-only compatibility analyzer after all parity and
   packaging gates pass.

## Validation Commands

Repository-wide:

```bash
uv run ruff format modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
uv run ruff check --fix modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
uv run mypy modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

Standalone package:

```bash
cd packages/modelaudit-picklescan
uv lock --check
uv run --with ruff ruff check src tests
uv run --with ruff ruff format --check src tests
uv run --with mypy mypy src tests
uv run --with pytest --with pytest-xdist pytest -n auto tests --tb=short
cargo check --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path Cargo.toml
uv build --out-dir /tmp/modelaudit-picklescan-dist
uvx twine check /tmp/modelaudit-picklescan-dist/*
```

Parity and performance:

```bash
PYTHONPATH=packages/modelaudit-picklescan/src uv run python scripts/compare_pickle_scanners.py --include-root
uv run --with pytest-benchmark pytest tests/benchmarks/test_picklescan_benchmarks.py --benchmark-json=/tmp/modelaudit-picklescan-benchmark.json -q
```

## Definition Of Done

The rewrite is complete only when the Rust-only standalone package passes all
current tests, generated historical-parity regressions stay green, root
default/standalone-primary comparison has no untriaged drift, wheel smoke tests
pass for root and standalone packages, and benchmark artifacts show enough value
to justify removing the remaining root-only compatibility analyzer.

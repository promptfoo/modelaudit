# Pickle Scanner Package Split

This document describes the current package boundary between ModelAudit's
wrapper scanners and the standalone pickle analysis package in
`packages/modelaudit-picklescan`.

## Package Layout

```text
packages/
  modelaudit-picklescan/
    src/modelaudit_picklescan/
      __init__.py
      py.typed
      api.py
      options.py
      report.py
      engine/
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
- Wrapper scanners in `modelaudit` pass embedded pickle streams into
  `modelaudit-picklescan`; archive parsing stays in `modelaudit`.
- The root `modelaudit` wheel bundles `modelaudit_picklescan` as a second import
  package, so the adapter and wrapper scanners use the same source tree without
  depending on a separately published artifact.

## API Contract

The standalone package exposes a small native surface:

```python
from modelaudit_picklescan import PickleScanner, ScanOptions, scan_bytes, scan_file, scan_stream

report = scan_file("weights.pkl")
report = scan_bytes(payload, source="weights.pkl")

scanner = PickleScanner(options=ScanOptions(timeout_s=30.0, max_opcodes=1_000_000))
report = scanner.scan_stream(stream, source="archive.pt:data.pkl", size=pickle_size)
```

Report semantics keep these concepts separate:

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: `WARNING`/`CRITICAL` security findings only
- `notices`: `DEBUG`/`INFO` coverage or explainability notes
- `errors`: operational failures

## Current Integration

- `modelaudit.scanners.pickle_scanner.PickleScanner` scans through the
  standalone package first, adapts the `PickleReport` into a `ScanResult`, and
  merges in any legacy-only checks that are still needed for compatibility.
- Embedded-pickle wrapper scanners (`pytorch_zip`, `joblib`, `numpy`, and
  `executorch`) call the public `scan_stream(..., source=...)` API and preserve
  archive-member context in result locations/details.
- `scripts/compare_pickle_scanners.py` is the parity harness for checking
  verdict/status drift and rule-code differences across fixture corpora.
- CI lints, type-checks, tests, builds, and smoke-installs both the root
  `modelaudit` distribution and the standalone `modelaudit-picklescan`
  distribution.

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

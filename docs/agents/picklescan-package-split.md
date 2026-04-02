# Pickle Scanner Package Split

This document defines the package boundary for extracting ModelAudit's pickle
scanner into a standalone package while preserving ModelAudit's current scanner
behavior.

## Target Layout

```text
packages/
  modelaudit-picklescan/
    src/modelaudit_picklescan/
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

- `modelaudit-picklescan` must not import `modelaudit`.
- `modelaudit-picklescan` owns pickle byte/stream analysis, safety verdicts,
  scan completeness, resource limits, and pickle-only metadata.
- `modelaudit` owns file routing, archive/container orchestration, CLI, cache,
  telemetry, SARIF/export integrations, and `PickleReport -> ScanResult`
  adaptation.
- Wrapper scanners in `modelaudit` may pass embedded pickle bytes into
  `modelaudit-picklescan`, but archive parsing stays in `modelaudit`.
- Until `modelaudit-picklescan` is published independently, the root
  `modelaudit` wheel bundles `modelaudit_picklescan` as a second import package
  instead of declaring a PyPI dependency on an unreleased artifact.

## API Contract

The standalone package should converge on a small native surface:

```python
from modelaudit_picklescan import PickleScanner, ScanOptions, scan_bytes, scan_file, scan_stream

report = scan_file("weights.pkl")
report = scan_bytes(payload, source="weights.pkl")

scanner = PickleScanner(options=ScanOptions(timeout_s=30.0, max_opcodes=1_000_000))
report = scanner.scan_stream(stream, source="archive.pt:data.pkl", size=pickle_size)
```

Report semantics must keep these concepts separate:

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: `WARNING`/`CRITICAL` security findings only
- `notices`: `DEBUG`/`INFO` coverage or explainability notes
- `errors`: operational failures

## Migration Sequence

1. Add standalone report/options types and package skeleton.
2. Add a ModelAudit-side adapter that converts standalone reports into
   `ScanResult` without changing exit-code semantics.
3. Extract the pickle opcode engine and dangerous-reference policy into
   `packages/modelaudit-picklescan/src/modelaudit_picklescan/engine/`.
4. Switch `modelaudit/scanners/pickle_scanner.py` and embedded-pickle wrapper
   scanners to call the standalone engine.
5. Add differential tests and benchmark gates against the current implementation
   plus `picklescan`, `modelscan`, and `fickling`.
6. Add release automation for a separate `modelaudit-picklescan` wheel.
7. Publish `modelaudit-picklescan` only after parity, benchmark, and clean-wheel
   install gates pass.

## Safety Rules

- Do not weaken detections during extraction.
- Add one malicious positive and one benign negative regression for each moved
  detector or routing rule.
- Treat inconclusive analysis as a first-class status instead of encoding it as
  a hidden success boolean.
- Keep per-scan state isolated so one scan cannot leak source/location context
  into the next.

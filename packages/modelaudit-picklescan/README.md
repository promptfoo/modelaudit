# modelaudit-picklescan

Standalone pickle security scanner package extracted from ModelAudit.

This package is intentionally small: it exposes pickle byte/stream analysis,
safety verdicts, and typed findings without importing the broader ModelAudit
scanner framework.

## Installation

The package is currently bundled in the root `modelaudit` wheel while standalone
publishing is staged. For local package work from a checkout, install the
package directory directly:

```bash
python -m pip install packages/modelaudit-picklescan
```

## Usage

```python
from modelaudit_picklescan import ScanOptions, scan_bytes, scan_file

report = scan_file("model.pkl")
if report.has_security_findings:
    for finding in report.findings:
        print(finding.rule_code, finding.severity.value, finding.message)

report = scan_bytes(
    payload,
    source="archive.pt:data.pkl",
    options=ScanOptions(timeout_s=30.0, max_opcodes=1_000_000),
)
```

## Report Contract

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: warning/critical security findings
- `notices`: informational coverage notes
- `errors`: operational failures

## Package Boundary

`modelaudit-picklescan` only analyzes pickle payloads. Archive/container
routing, SARIF export, CLI behavior, and `ScanResult` adaptation stay in the
root `modelaudit` package.

The engine is still being migrated toward full parity with the legacy
`modelaudit.scanners.pickle_scanner.PickleScanner`, so use the differential
harness in `scripts/compare_pickle_scanners.py` when changing detection logic.

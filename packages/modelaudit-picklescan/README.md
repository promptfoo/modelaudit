# modelaudit-picklescan

Standalone pickle security scanner package used by ModelAudit's pickle scanners.

This package is intentionally small: it exposes pickle byte/stream analysis,
safety verdicts, and typed findings without importing the broader ModelAudit
scanner framework.

## Installation

The root `modelaudit` wheel bundles `modelaudit_picklescan` as an import package.
For local package work from a checkout, install the package directory directly:

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
    options=ScanOptions(
        timeout_s=30.0,
        max_opcodes=1_000_000,
        max_string_literal_scan_chars=8 * 1024 * 1024,
        max_nested_pickle_bytes=2 * 1024 * 1024,
        max_nested_depth=1,
    ),
)
```

## Report Contract

- `status`: scan completeness (`complete`, `inconclusive`, `error`)
- `verdict`: safety decision (`clean`, `suspicious`, `malicious`, `unknown`)
- `findings`: warning/critical security findings
- `notices`: informational coverage notes, including explicit partial-analysis
  notices when literal or nested-pickle budgets are reached
- `errors`: operational failures

Report mappings are read-only after construction. Use `to_dict()` when a mutable
plain-Python representation is needed.

## Package Boundary

`modelaudit-picklescan` only analyzes pickle payloads. Archive/container
routing, SARIF export, CLI behavior, and ModelAudit result adaptation stay in
the root `modelaudit` package.

The root `modelaudit` pickle scanner currently runs this standalone engine first
and then merges legacy-only compatibility checks while detector parity continues
to improve. Standalone users should rely on this package for pickle payload
analysis, but full ModelAudit scans may still report additional root-package
context such as archive metadata, CVE checks, and legacy rule identifiers.

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

The root `modelaudit.scanners.pickle_scanner.PickleScanner` keeps a compatibility
fallback path and merges legacy-only checks into standalone package results.
Use `scripts/compare_pickle_scanners.py` when changing detection logic to verify
that verdict/status semantics stay aligned across fixture corpora.

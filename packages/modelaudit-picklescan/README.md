# modelaudit-picklescan

Standalone pickle security scanner package used by ModelAudit's pickle scanners.

This package is intentionally small: it exposes pickle byte/stream analysis,
safety verdicts, typed findings, and direct scanning of pickle members inside
common PyTorch ZIP checkpoints without importing the broader ModelAudit scanner
framework.

## Installation

The standalone `modelaudit-picklescan` wheel includes the Python API and the
native Rust scanner extension. The root `modelaudit` wheel depends on this
distribution so installed ModelAudit scans use the same native Rust scanner for
pickle payload analysis.

For local package work from a checkout, install the package directory directly:

```bash
python -m pip install packages/modelaudit-picklescan
```

## Usage

```python
from modelaudit_picklescan import ScanOptions, scan_bytes, scan_file

report = scan_file("model.pt")  # raw pickle files and PyTorch ZIP checkpoints
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

## Native Scanner

The wheel includes a native Rust scanner for pickle payload analysis. Maintainer
migration notes and failure-mode details live in the repository maintainer docs.
Release wheels are published for the primary Linux x86_64, macOS arm64, and
Windows targets. macOS x86_64 and Linux aarch64 users may install from the
source distribution and need a local Rust toolchain available during install.

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

`modelaudit-picklescan` analyzes raw pickle payloads and PyTorch ZIP checkpoint
pickle members. For full model-file routing, archive context, CLI output,
SARIF/export integrations, and broader scanner coverage, use the root
`modelaudit` package.

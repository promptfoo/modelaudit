# modelaudit-picklescan

**Rust-backed, bounded, static pickle security scanner.** Inspects Python pickle streams and PyTorch ZIP checkpoints without unpickling them, and returns a typed report you can feed into CI, SARIF exporters, or custom policy engines.

[![PyPI version](https://img.shields.io/pypi/v/modelaudit-picklescan.svg)](https://pypi.org/project/modelaudit-picklescan/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit-picklescan.svg)](https://pypi.org/project/modelaudit-picklescan/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/promptfoo/modelaudit/blob/main/LICENSE)
[![Wheel platforms](https://img.shields.io/badge/wheels-linux%20x86__64%20%7C%20linux%20aarch64%20%7C%20macos%20arm64%20%7C%20macos%20x86__64%20%7C%20windows-informational)](https://pypi.org/project/modelaudit-picklescan/#files)

## Why this package

Pickle deserialization is the most common supply-chain attack vector in ML checkpoints, and existing Python-only scanners either unpickle the payload (unsafe), scan string literals only (imprecise), or fail open on large/malformed inputs (dangerous in CI). This package is a direct response:

- **Rust scanner engine.** Opcode walker, string analyzer, and nested-payload decoder are all native code.
- **Fail-closed semantics.** Every scan returns both a `status` (complete / inconclusive / error) and a `verdict` (clean / suspicious / malicious / unknown). Truncation, timeouts, budget exhaustion, and parser errors downgrade the verdict instead of silently returning clean.
- **Bounded by construction.** Opcode count, wall-clock timeout, string-literal bytes, nested-payload bytes, and recursion depth are all configurable caps with safe defaults. A malicious producer cannot force unbounded memory or CPU.
- **Zero Python runtime dependencies.** The wheel is self-contained — `pip install modelaudit-picklescan` and nothing else.
- **Attested provenance.** Release wheels are published to PyPI with sigstore attestations via GitHub Actions trusted publishing.
- **Typed, immutable reports.** `PickleReport`, `Finding`, `Notice`, and `ScanError` are frozen dataclasses with `to_dict()` for serialization. The package ships `py.typed` for mypy / pyright.

## Install

```bash
pip install modelaudit-picklescan
```

Pre-built `abi3` wheels ship for Python 3.10–3.13 on five targets: Linux `x86_64`, Linux `aarch64`, macOS `arm64`, macOS `x86_64`, and Windows `x64`. Other platforms install from the sdist and require a Rust toolchain (see [Building from source](#building-from-source)).

## Quickstart

```python
from modelaudit_picklescan import scan_file

report = scan_file("suspicious_model.pt")  # raw pickle or PyTorch ZIP checkpoint

print(f"status={report.status.value} verdict={report.verdict.value}")
for finding in report.findings:
    print(f"  [{finding.severity.value}] {finding.rule_code}: {finding.message}")
    if finding.location:
        print(f"    at {finding.location}")
```

Example output on a PyTorch ZIP whose inner pickle reduces on `os.system`:

```
status=complete verdict=malicious
  [critical] DANGEROUS_CALL: Found REDUCE opcode invoking os.system
    at suspicious_model.pt:archive/data.pkl (pos 42)
```

Example output on a truncated or oversized pickle where analysis is incomplete:

```
status=inconclusive verdict=unknown
  (no findings — scan was truncated, inspect report.notices and report.coverage)
```

The `finding.location` string follows the format `{source} (pos {byte_offset})`. The `source` on PyTorch ZIP members is `{archive_path}:{member_name}`.

## What it detects

Each finding carries a `rule_code` so downstream tooling can allowlist, suppress, or route alerts:

| Rule code                | What it flags                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------- |
| `DANGEROUS_CALL`         | REDUCE/NEWOBJ/NEWOBJ_EX opcodes invoking a callable known to execute code             |
| `DANGEROUS_GLOBAL`       | Imports of modules or classes that enable code execution when the pickle is loaded    |
| `EXTENSION_REF`          | `copyreg.extension` / `EXT1`/`EXT2`/`EXT4` opcodes that resolve through process state |
| `MALFORMED_STACK_GLOBAL` | `STACK_GLOBAL` operands crafted to bypass naive string-matching scanners              |
| `PERSISTENT_ID`          | `PERSID` / `BINPERSID` references that delegate object construction to the loader     |
| `PICKLE_EXPANSION`       | Oversized or amplified pickle structures consistent with zip-bomb-style payloads      |
| `POST_BUDGET_GLOBAL`     | Dangerous globals observed after the opcode budget, surfaced conservatively           |
| `STRUCTURAL_TAMPER`      | Opcode sequences that do not correspond to any legitimate pickle producer             |
| `SUSPICIOUS_STRING`      | High-signal string literals (shell metacharacters, import payloads, URLs)             |
| `S203`                   | Non-allowlisted `__main__` global reference (requires manual review before loading)   |
| `S213`                   | Raw (unencoded) nested pickle payload inside a byte field                             |
| `S601`                   | Base64-encoded nested pickle payload inside a string literal                          |
| `S602`                   | Hex-encoded nested pickle payload inside a string literal                             |

The scanner covers pickle protocols 0 through 5, recognizes short and extended opcodes, and reconstructs `module.class` targets for `STACK_GLOBAL` without executing them.

## When to use this vs. `modelaudit`

Use **`modelaudit-picklescan`** if you want a single-purpose library to embed in another tool: a linter, a model registry gate, a custom CI step, or a server-side scanner. It does pickle analysis and nothing else.

Use **[`modelaudit`](https://pypi.org/project/modelaudit/)** if you want the full static scanner CLI: 40+ model/archive format scanners, SARIF and JSON output, remote-source scanning (Hugging Face, S3, GCS, JFrog, MLflow, DVC), license and secret detection, caching, progress reporting, and CI recipes. `modelaudit` uses this package internally for its pickle scanner.

## API overview

```python
from modelaudit_picklescan import (
    PickleScanner, ScanOptions,
    scan_file, scan_bytes, scan_stream,
    PickleReport, Finding, Notice, ScanError,
    Severity, ScanStatus, SafetyVerdict, CoverageSummary,
)
```

Three convenience entry points, each returning a `PickleReport`:

- `scan_file(path, *, options=None)` — scan a `.pkl` / `.pickle` or a PyTorch ZIP checkpoint (detects the container, enumerates pickle members, combines reports).
- `scan_bytes(data, *, source="<bytes>", options=None)` — scan an in-memory payload.
- `scan_stream(stream, *, source="<stream>", size=None, options=None)` — scan a binary file-like object; falls back to bounded spooling when `size` is unknown.

For long-running services, construct `PickleScanner(options=...)` once and reuse it across calls.

### Resource controls — `ScanOptions`

All fields have safe defaults; override only what you need.

| Field                             | Default     | Meaning                                                |
| --------------------------------- | ----------- | ------------------------------------------------------ |
| `timeout_s`                       | `3600.0`    | Per-scan wall clock, capped at `86_400` seconds        |
| `max_opcodes`                     | `1_000_000` | Opcode budget before the scanner downgrades to partial |
| `post_budget_scan_bytes`          | `100 MiB`   | Bytes to keep scanning for globals after the budget    |
| `max_known_stream_read_bytes`     | `100 MiB`   | Cap on streams with a known `size`                     |
| `max_unbounded_stream_read_bytes` | `8 MiB`     | Cap on streams without a known `size`                  |
| `max_string_literal_scan_chars`   | `8 MiB`     | Cap on bytes inspected for `SUSPICIOUS_STRING`         |
| `max_nested_pickle_bytes`         | `2 MiB`     | Cap on each decoded nested-payload inspection          |
| `max_nested_depth`                | `2`         | Recursion depth for base64/hex-encoded pickles         |

Construction validates every field; pass invalid values and you'll get a `ValueError` immediately instead of a misleading scan result.

### Report contract — `PickleReport`

- `status: ScanStatus` — `complete`, `inconclusive`, or `error`.
- `verdict: SafetyVerdict` — `clean`, `suspicious`, `malicious`, or `unknown`. `clean` requires `status=complete` with no findings.
- `findings: tuple[Finding, ...]` — WARNING or CRITICAL security results.
- `notices: tuple[Notice, ...]` — DEBUG/INFO explainability and coverage notes (budget hits, truncation, unsupported members).
- `errors: tuple[ScanError, ...]` — operational failures (short reads, malformed containers, engine errors).
- `coverage: CoverageSummary` — `bytes_scanned`, `bytes_total`, `opcode_count`, and per-phase completion flags.
- `metadata: Mapping[str, Any]` — container info (e.g. `container_type="pytorch_zip"`, archive size, pickle members).
- `duration_s: float` — scan wall clock.

Convenience accessors: `report.has_security_findings`, `report.is_clean`, `report.to_dict()`.

Reports and all nested models are frozen — call `to_dict()` if you need a mutable payload for serialization. For aggregation, treat `findings` at `warning`/`critical` as security alerts; group `notices` by `code` rather than showing every INFO row as actionable.

## PyTorch ZIP checkpoints

`scan_file` auto-detects PyTorch ZIP containers from PyTorch metadata plus pickle members, including hidden members identified by content sniffing rather than suffix alone, and combines per-member reports into a single container-level report with `metadata.container_type="pytorch_zip"`. Archive member count is capped at 10,000 entries; per-member pickles are capped at 512 MiB. Both limits are enforced by structured notices, not silent skips.

## Building from source

Wheels cover five targets; any other platform or a custom Python ABI requires building from source:

```bash
# Requires Rust 1.83+ and a working C toolchain
pip install modelaudit-picklescan --no-binary modelaudit-picklescan
```

From a checkout:

```bash
pip install packages/modelaudit-picklescan
# or, for development with hot-reload of the Rust extension:
maturin develop --release -m packages/modelaudit-picklescan/Cargo.toml
```

## Stability and versioning

`modelaudit-picklescan` follows semantic versioning. `0.x` should be read as pre-1.0 — expect small adjustments as the API settles. The working intent, reflected in the current code, is:

- **Resource-control defaults** (`ScanOptions`) are tuned conservatively; changes that relax a default will be called out in the changelog.
- **Public report models** (`PickleReport`, `Finding`, `Notice`, `ScanError`) and their field names are the supported surface for serialization and downstream tooling.
- **Rule codes** are intended to be additive — new codes rather than renames — so that downstream allowlists and suppressions remain stable.
- **Verdict semantics** — `SafetyVerdict.CLEAN` is only returned when `ScanStatus.COMPLETE` holds and there are no findings; truncation, timeouts, and engine errors never produce `CLEAN`. This is enforced in `_combine_verdict` / `_with_*_notice` in `api.py`.

Any change to the items above will be announced in [CHANGELOG.md](https://github.com/promptfoo/modelaudit/blob/main/packages/modelaudit-picklescan/CHANGELOG.md) and the GitHub release notes.

## Security and reporting

Please do **not** open public GitHub issues for suspected vulnerabilities. See the project [security policy](https://github.com/promptfoo/modelaudit/security/policy) for coordinated disclosure.

## Links

- **Changelog**: https://github.com/promptfoo/modelaudit/blob/main/packages/modelaudit-picklescan/CHANGELOG.md
- **Repository**: https://github.com/promptfoo/modelaudit
- **Issues**: https://github.com/promptfoo/modelaudit/issues
- **Parent package**: https://pypi.org/project/modelaudit/
- **Security model (docs)**: https://github.com/promptfoo/modelaudit/blob/main/docs/user/security-model.md

## License

MIT. See [LICENSE](https://github.com/promptfoo/modelaudit/blob/main/LICENSE).

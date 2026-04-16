# Changelog

All notable changes to `modelaudit-picklescan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Introduce the Rust-native pickle scanning engine and standalone Python API package.
- Add `scan_bytes`, `scan_stream`, and `scan_file` entrypoints with typed immutable
  reports for findings, notices, errors, coverage, verdict, and scan status.
- Add direct PyTorch ZIP container handling for `data.pkl` and other pickle
  members, including per-member source locations and combined archive reports.
- Add detection coverage for dangerous pickle globals and executed calls,
  malformed `STACK_GLOBAL` operands, copyreg extension references, persistent
  IDs, `__main__` call escalation, `__dict__` import-only references, structural
  tamper, protocol-5 external-buffer opcodes, and memo/`DUP` expansion patterns.
- Add nested-pickle detection for raw bytes plus base64, hex, escaped-hex, and
  comment-wrapped encoded payloads, with recursive scans and bounded deep-scan
  limits.
- Add suspicious string-literal matching for execution helpers, loader helpers,
  `getattr` variants, `os.system`/`subprocess`/`runpy`/`webbrowser` patterns,
  encoded code strings, and pickle loader references.
- Improve detection so dangerous globals and expansion patterns remain
  reportable even when opcode-budget limits are reached.
- Add resource controls for timeout, opcode budget, post-budget byte scans,
  known-size and unknown-size stream reads, long string literal probing, nested
  pickle byte budgets, nested depth, and import-reference metadata volume.
- Add Python package tests, Rust unit tests, parity-corpus tests, wheel smoke
  checks, Ruff, mypy, cargo fmt/check/clippy/test, MSRV check, and manylinux
  release-wheel gates.
- Probe binary pickle operands for nested pickle streams while intentionally
  leaving arbitrary non-pickle text extraction from BINBYTES/tensor blobs to the
  root ModelAudit raw detector layer.

### Changed

- Use the Rust scanner as the only runtime engine; runtime engine selection and
  Python-engine fallback behavior are not part of the public API.
- Release the Python GIL during native scans and avoid hot-path byte-literal
  cloning by retaining borrowed payload spans for variable-length operands.
- Stream declared-size inputs in bounded chunks, normalize negative sizes as
  unknown-size streams, cap both known-size and unbounded streams, and scan
  partial bytes on declared-size short reads before returning an operational
  error.
- Preserve standalone rule details while exposing ModelAudit-compatible rule
  mappings for the root package, including dedicated nested-pickle, encoding,
  persistent-ID, extension, structural-tamper, and expansion findings.

### Fixed

- Detect policy-backed dangerous globals in post-budget tails instead of relying
  on a small hardcoded byte-needle table.
- Detect nested payloads that use PERSID/BINPERSID semantics, proto-0 payloads,
  uppercase escaped-hex prefixes, multiline/comment-wrapped encodings, and long
  literals with suspicious content outside prefix/suffix windows.
- Preserve stack state on operand underflow.
- Avoid wrapping MARK sentinels.
- Preserve `GLOBAL`/`INST` module/name operands without string roundtrips.
- Keep follow-on pickle streams at sibling depth.
- Cap import-reference metadata with an explicit notice, summarize repeated
  persistent IDs, coalesce protocol-5 buffer notices, and surface structural
  tamper severity without adapter downgrades.

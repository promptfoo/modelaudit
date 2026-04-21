# Changelog

All notable changes to `modelaudit-picklescan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2](https://github.com/promptfoo/modelaudit/releases/tag/modelaudit-picklescan-v0.1.2) (2026-04-17)

### Bug Fixes

- repair picklescan release wheel jobs ([#1051](https://github.com/promptfoo/modelaudit/issues/1051)) ([6c23190](https://github.com/promptfoo/modelaudit/commit/6c23190f9b23686d33d5da0a8b5522a59490084e))

## [0.1.1](https://github.com/promptfoo/modelaudit/releases/tag/modelaudit-picklescan-v0.1.1) (2026-04-17)

### Features

- extract standalone pickle scanner package with parity harness ([#832](https://github.com/promptfoo/modelaudit/issues/832)) ([e2986cd](https://github.com/promptfoo/modelaudit/commit/e2986cddaa592306cc10541865f011b3dc99a0ba))

### Bug Fixes

- address code quality findings ([#1038](https://github.com/promptfoo/modelaudit/issues/1038)) ([7af03cf](https://github.com/promptfoo/modelaudit/commit/7af03cf42f33f1b255eb9f9cbcaac6caccd48bc1))
- bound standalone pickle stream reads ([4d0cb84](https://github.com/promptfoo/modelaudit/commit/4d0cb84af010b4ed332ebbf17fc8bd0769fa8b6e))
- **deps:** update rust crate pyo3 to 0.28.0 ([#1006](https://github.com/promptfoo/modelaudit/issues/1006)) ([fe93b47](https://github.com/promptfoo/modelaudit/commit/fe93b47c839588b3f33cfd21f4380306ec418f2a))
- detect hidden pytorch zip pickles ([#1043](https://github.com/promptfoo/modelaudit/issues/1043)) ([19b6ebe](https://github.com/promptfoo/modelaudit/commit/19b6ebe505d2ba90f81d6284d07e111f77cbf0b5))
- flag pickle persistent ids ([#938](https://github.com/promptfoo/modelaudit/issues/938)) ([2cfba40](https://github.com/promptfoo/modelaudit/commit/2cfba403e21d53f46ba7089b655cebc564dcddaf))
- harden pickle nested bypass detection ([#1027](https://github.com/promptfoo/modelaudit/issues/1027)) ([c3a3b9d](https://github.com/promptfoo/modelaudit/commit/c3a3b9d1e4ffbd854e6003afbf6ebef1e708a619))
- harden standalone pickle scanner ([#901](https://github.com/promptfoo/modelaudit/issues/901)) ([31f7dd3](https://github.com/promptfoo/modelaudit/commit/31f7dd38c6bd77631ccdca90438312c4db2ac857))
- narrow suspicious dunder string detection ([#947](https://github.com/promptfoo/modelaudit/issues/947)) ([e866760](https://github.com/promptfoo/modelaudit/commit/e8667609d293d4391205ce4e8884fa3559030604))
- preserve picklescan stack state ([#910](https://github.com/promptfoo/modelaudit/issues/910)) ([fabac5c](https://github.com/promptfoo/modelaudit/commit/fabac5c9ead49c2ed5f8357dfa53ccdcce946527))

### Documentation

- align markdown with current repo state ([#1035](https://github.com/promptfoo/modelaudit/issues/1035)) ([690bc52](https://github.com/promptfoo/modelaudit/commit/690bc5274198eb3428db9779ada0bdc2d40702ee))

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

- Detect additional stdlib callable pickle targets that can access files,
  mutate registries, suppress diagnostics, or change process state, including
  Python 3.13 `pathlib._local` concrete path aliases, public `operator.setitem`
  registry poisoning, and target-aware handling for list/dict mutators.
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

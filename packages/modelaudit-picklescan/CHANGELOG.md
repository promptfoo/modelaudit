# Changelog

All notable changes to `modelaudit-picklescan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5](https://github.com/promptfoo/modelaudit/compare/modelaudit-picklescan-v0.1.4...modelaudit-picklescan-v0.1.5) (2026-05-03)

### Bug Fixes

- address ai quality findings ([#1218](https://github.com/promptfoo/modelaudit/issues/1218)) ([30f4ef2](https://github.com/promptfoo/modelaudit/commit/30f4ef246f7e26a4c6f85e684bfb35ceaea7c43d))
- clear remaining security-quality findings ([#1219](https://github.com/promptfoo/modelaudit/issues/1219)) ([259f931](https://github.com/promptfoo/modelaudit/commit/259f931fa573e234734b7d72850e0ca09d775f45))

### Performance Improvements

- cache call graph call nodes ([#1215](https://github.com/promptfoo/modelaudit/issues/1215)) ([aa52759](https://github.com/promptfoo/modelaudit/commit/aa52759aabaac335b87e30e2cbf042d141dc4e9f))
- cache function import aliases ([#1214](https://github.com/promptfoo/modelaudit/issues/1214)) ([d56eef2](https://github.com/promptfoo/modelaudit/commit/d56eef2de18652fee1a759642165e404b8202be9))
- cache parameter controlled names ([#1213](https://github.com/promptfoo/modelaudit/issues/1213)) ([41b8f45](https://github.com/promptfoo/modelaudit/commit/41b8f4541c9b62204c74c04199931ef0484ba1a5))
- cache split call graph names ([#1212](https://github.com/promptfoo/modelaudit/issues/1212)) ([77ab177](https://github.com/promptfoo/modelaudit/commit/77ab17782f23de46c57f6e2a7302a539fb0bfb98))
- reuse call graph controlled names ([#1198](https://github.com/promptfoo/modelaudit/issues/1198)) ([84e6a9b](https://github.com/promptfoo/modelaudit/commit/84e6a9bd841095917e2199e9004759bcbe9c0eb3))
- reuse call graph module parses ([#1167](https://github.com/promptfoo/modelaudit/issues/1167)) ([0822b40](https://github.com/promptfoo/modelaudit/commit/0822b4043db270882b8fd14ff04de1cf3d3fb134))
- share call graph caches within reports ([#1156](https://github.com/promptfoo/modelaudit/issues/1156)) ([b16d37c](https://github.com/promptfoo/modelaudit/commit/b16d37c3b4439b4e6d966b8b9624642307c2a322))
- share getattr assignment candidates ([#1199](https://github.com/promptfoo/modelaudit/issues/1199)) ([5d12903](https://github.com/promptfoo/modelaudit/commit/5d1290330328ad4fb6e6f88bddc34e7bfba9d310))
- skip call graph enrichment in pickle validation ([#1196](https://github.com/promptfoo/modelaudit/issues/1196)) ([2347d80](https://github.com/promptfoo/modelaudit/commit/2347d80a2d110f582c188679b4a0c04489779745))

## [0.1.4](https://github.com/promptfoo/modelaudit/compare/modelaudit-picklescan-v0.1.3...modelaudit-picklescan-v0.1.4) (2026-05-01)

### Bug Fixes

- cover eager statistics consumers in picklescan ([#1148](https://github.com/promptfoo/modelaudit/issues/1148)) ([0d5ea8e](https://github.com/promptfoo/modelaudit/commit/0d5ea8e5a0be4f96d3ca97c55640cdb35b55215c))
- detect nested brace-format mapping lookups ([#1151](https://github.com/promptfoo/modelaudit/issues/1151)) ([fc296ad](https://github.com/promptfoo/modelaudit/commit/fc296adaa97815b4067f0a764e653cdf777a5724))
- fail closed on call graph errors ([#1143](https://github.com/promptfoo/modelaudit/issues/1143)) ([1a08449](https://github.com/promptfoo/modelaudit/commit/1a084493b16b5c62b0cd7022b79e60795e88b07b))
- fail closed on unanalyzable call graphs ([#1108](https://github.com/promptfoo/modelaudit/issues/1108)) ([dcb8bbe](https://github.com/promptfoo/modelaudit/commit/dcb8bbe4683c284a1ea6c84231dee6808a93fc52))
- ignore inert format placeholders ([#1142](https://github.com/promptfoo/modelaudit/issues/1142)) ([8f728e8](https://github.com/promptfoo/modelaudit/commit/8f728e8454578ba34ce5b28389258fa2eba29fe8))
- keep inert dotted global metadata clean ([#1150](https://github.com/promptfoo/modelaudit/issues/1150)) ([9a76915](https://github.com/promptfoo/modelaudit/commit/9a769151c0ffd29a1638f1dacc78d2eb77b0f268))
- **picklescan:** detect hidden-only pytorch zips ([#1098](https://github.com/promptfoo/modelaudit/issues/1098)) ([3e94f70](https://github.com/promptfoo/modelaudit/commit/3e94f7020d5a28fc150afed1520adcac8d58ce73))
- **picklescan:** detect statistics quantiles iterator consumption ([#1152](https://github.com/promptfoo/modelaudit/issues/1152)) ([b357fdb](https://github.com/promptfoo/modelaudit/commit/b357fdb7db320d3485cf0458a4cf0f16b86717c1))
- **picklescan:** fail closed on late encoded payload probes ([#1107](https://github.com/promptfoo/modelaudit/issues/1107)) ([55b43a5](https://github.com/promptfoo/modelaudit/commit/55b43a5229baadf1c3673b4d89838e55c5cf6ae3))
- **picklescan:** model str.format lookups ([#1097](https://github.com/promptfoo/modelaudit/issues/1097)) ([2c87acb](https://github.com/promptfoo/modelaudit/commit/2c87acbb01285289872203063074baf51d0cd28c))
- preserve str.format lookup keys in picklescan ([#1149](https://github.com/promptfoo/modelaudit/issues/1149)) ([feb3e1c](https://github.com/promptfoo/modelaudit/commit/feb3e1ccb629344180e3a27e093e24b707c671e6))
- require startup hook invocations ([#1140](https://github.com/promptfoo/modelaudit/issues/1140)) ([7e0777d](https://github.com/promptfoo/modelaudit/commit/7e0777dcc71bfdbd8212358aa548ee45d3808642))
- resync post-budget pickle replay ([#1141](https://github.com/promptfoo/modelaudit/issues/1141)) ([e275676](https://github.com/promptfoo/modelaudit/commit/e27567661295a96d94cd1ea29abd4f42c6c249e3))
- stabilize non-pytorch zip status ([7449aae](https://github.com/promptfoo/modelaudit/commit/7449aae0e36a38de7681acfd0f5f77033afea059))

### Documentation

- narrow scan coverage claims ([#1139](https://github.com/promptfoo/modelaudit/issues/1139)) ([47ec8cf](https://github.com/promptfoo/modelaudit/commit/47ec8cf3bc5a5ac3166757bbaae0c5a3c6adb73d))

## [Unreleased]

### Bug Fixes

- detect dynamic `type()` namespaces that can hide callable protocol hooks
- fail closed when encoded nested-pickle probe candidates exhaust the analysis cap
- prevent call-graph alias cycles from hanging scans
- detect nested brace-format lookups that reach tracked `defaultdict` factories
- avoid `str.format` false positives when a `ChainMap` shadows a `defaultdict`
- block `statistics.quantiles` call-iterator consumption in call-graph analysis
- block additional eager `statistics` consumers in call-graph analysis
- avoid false positives for inert metadata under dangerous dotted globals
- detect dangerous positional lookups inside `str.format` replacement fields
- recognize PyTorch ZIP archives that contain only hidden pickle members

### Performance Improvements

- expose a bounded, source-validated analysis cache scope for multi-artifact scan operations

## [0.1.3](https://github.com/promptfoo/modelaudit/compare/modelaudit-picklescan-v0.1.2...modelaudit-picklescan-v0.1.3) (2026-04-27)

### Bug Fixes

- **ci:** skip POSIX proof cases on Windows ([#1072](https://github.com/promptfoo/modelaudit/issues/1072)) ([bfa17a3](https://github.com/promptfoo/modelaudit/commit/bfa17a3e152cd178c5d1fdbfec55dd3f124778ef))
- harden picklescan call graph RCE detection ([#1061](https://github.com/promptfoo/modelaudit/issues/1061)) ([19c4fc4](https://github.com/promptfoo/modelaudit/commit/19c4fc487b4758462ac2107a3f3e59463e5d888b))
- harden picklescan stdlib callable detection ([f0f57b4](https://github.com/promptfoo/modelaudit/commit/f0f57b47f3355bea008a48779dbd856e6f550ec7))
- improve test isolation, reduce duplication, and fix command injection risk in test suite ([#1078](https://github.com/promptfoo/modelaudit/issues/1078)) ([3867c83](https://github.com/promptfoo/modelaudit/commit/3867c83b2dd0d5ab6a83b650c28d64122a675dea))
- **picklescan:** avoid call-graph false positives for PyTorch storage IDs ([#1069](https://github.com/promptfoo/modelaudit/issues/1069)) ([e75ed24](https://github.com/promptfoo/modelaudit/commit/e75ed249948558864d8f56882a02f1327323205d))

### Documentation

- improve PyPI READMEs ([#1057](https://github.com/promptfoo/modelaudit/issues/1057)) ([1cfb27d](https://github.com/promptfoo/modelaudit/commit/1cfb27de814125470d1e1a38eec03a83d79ff3d9))

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

- Detect `mailcap.findmatch` pickle call targets that can execute
  attacker-controlled mailcap `test` commands on Python versions that still
  provide `mailcap`.
- Detect `setuptools._distutils.spawn.spawn` pickle call targets that can
  execute attacker-controlled subprocess command lists when `setuptools` is
  installed.
- Detect `pipes.Template` pickle call targets that can execute
  attacker-controlled shell pipelines on Python versions that still provide
  `pipes`.
- Detect high-level `tkinter.Misc` pickle call targets that can forward
  attacker-controlled commands into Tcl interpreter dispatch.
- Resolve module-level bound-method aliases and same-module constructor call
  paths in pickle call-graph analysis so process-dispatch wrappers are blocked.
- Resolve function-local import aliases in pickle call-graph analysis so
  wrappers that import RCE sinks inside function bodies are blocked.
- Preserve callable invocation aliases when import-reference metadata is
  crowded, while ignoring uninvoked nested function and lambda bodies during
  pickle call-graph analysis.
- Detect `typing._eval_type` pickle call targets that can evaluate
  attacker-controlled `ForwardRef` expressions.
- Detect `dataclasses._create_fn` pickle call targets that can execute
  attacker-controlled generated Python source.
- Detect `typing.get_type_hints` pickle call targets that can evaluate
  attacker-controlled annotation strings.
- Detect public `operator.call` pickle call targets that can invoke
  attacker-controlled callables.
- Detect `builtins.map` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
- Detect `itertools.starmap` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
- Detect `builtins.filter` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
- Detect `itertools.accumulate` pickle call targets that can lazily invoke
  attacker-controlled binary functions when iterated.
- Detect `itertools.dropwhile` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
- Detect `itertools.filterfalse` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
- Detect `itertools.groupby` pickle call targets that can lazily invoke
  attacker-controlled key functions when iterated.
- Detect `itertools.takewhile` pickle call targets that can lazily invoke
  attacker-controlled callables when iterated.
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

- Fail closed when encoded nested-pickle discovery only searched a bounded interior window of a still-budgeted string literal.
- Fail closed when a whole-pass Python call-graph enrichment step raises.
- Avoid synthesizing format-helper lookups for literals with no executable
  placeholders.
- Resynchronize bounded post-budget replay after malformed bytes so later
  self-contained modern globals still surface critical findings.
- Require actual callable invocations before pairing startup-hook opener and
  writer imports, avoiding critical findings for pickles that only reconstruct
  those function objects.
- Mark invoked call-graph targets as incomplete when Python source cannot be
  analyzed, and refresh source-derived call-graph caches between scans.
- Detect additional stdlib callable pickle targets that can access files,
  mutate registries, suppress diagnostics, or change process state, including
  Python 3.13 `pathlib._local` concrete path aliases, public `operator.setitem`
  registry poisoning, target-aware `operator.imul` warning-filter mutation, and
  target-aware handling for list/dict mutators.
- Detect public `operator.setitem` pickle calls, preserve callable-invocation
  aliases before import-reference budget exhaustion, and dedupe repeated
  invocation metadata before applying the reporting cap.
- Track literal mapping keys through memoized dicts and mapping wrappers so
  shadowed `ChainMap` lookups stay clean while deeply wrapped `defaultdict`
  factories remain detected.
- Ignore nested function and lambda bodies when modeling an outer function's
  call graph.
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

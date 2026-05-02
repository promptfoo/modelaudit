# Performance Audit

Status: active audit started 2026-05-01

## Goals

- Explain where scan wall time goes for representative workloads.
- Separate necessary security cost from avoidable repeated work.
- Record reproducible measurements before changing behavior.
- Build a ranked implementation plan with correctness constraints.

## Current Measurement Setup

- Host: local developer machine, macOS, Python 3.12 via `uv run`
- Telemetry disabled for benchmarks with `PROMPTFOO_DISABLE_TELEMETRY=1`
- Cache disabled unless a benchmark explicitly measures cache behavior
- Profiles collected with `cProfile`
- Existing benchmark surfaces:
  - `tests/benchmarks/test_scan_benchmarks.py`
  - `tests/benchmarks/test_picklescan_benchmarks.py`
  - `tests/test_performance_benchmarks.py`

## Initial Baseline

| Scenario                                                                 |          Wall time | Notes                                                    |
| ------------------------------------------------------------------------ | -----------------: | -------------------------------------------------------- |
| `tests/assets` warm directory scan                                       | `1.841717s` median | `90` scanned files, `2,052,565` bytes                    |
| same corpus with call-graph cache clearing monkeypatched out             |        `0.813108s` | controlled experiment only                               |
| `tests/assets/samples/pickles/safe_large_model.pkl`                      | `0.047192s` median | `562,936` bytes                                          |
| `tests/assets/scenarios/license_scenarios/agpl_component/agpl_model.pkl` | `0.292767s` median | nested-pickle-heavy                                      |
| `tests/assets/samples/pickles/dill_func.pkl`                             | `0.519226s` median | imported-function call-graph-heavy                       |
| synthetic `64 MiB` `.dat` single-file scan                               | `0.295140s` median | dominated by license metadata scan                       |
| synthetic `64 MiB` `.safetensors` single-file scan                       | `0.182532s` median | scanner integrity hashing dominates                      |
| synthetic `64 MiB` manifest-style `.json` single-file scan               | `0.056719s` median | repeated reads exist, but not a top hotspot on local SSD |
| synthetic `64 MiB` `.safetensors` cache miss                             |        `0.564129s` | cache hashing adds another full-file pass                |
| synthetic `64 MiB` `.safetensors` cache hit                              |        `0.083838s` | cache helps repeated scans materially                    |
| synthetic `2000` empty `.dat` files                                      | `3.748604s` median | many-file overhead even when payload bytes are zero      |
| synthetic `500` tiny `.pkl` files                                        | `1.264593s` median | per-file routing/scanner overhead                        |
| synthetic `32` duplicate `safe_large_model.pkl` files                    | `1.519745s` median | repeated per-file scanner work despite identical bytes   |

Benchmark artifacts:

- Manual canonical harness output: `/tmp/modelaudit-perf-audit-baseline.json`
- Per-file fixture timing output: `/tmp/modelaudit-perf-per-file.json`
- `scripts/profile_scan.py` outputs:
  - `/tmp/modelaudit-profile-assets.{json,pstats}`
  - `/tmp/modelaudit-profile-dill.{json,pstats}`
  - `/tmp/modelaudit-profile-safe-large.{json,pstats}`
- Existing `pytest-benchmark` suites currently skip on Python `3.12` because the global test allowlist in `tests/conftest.py` excludes the benchmark files on reduced-version lanes. Running with `uv run --with pytest-benchmark ...` installs the plugin, but the tests still skip under the repo's current lane policy.

Slowest fixture files in the current corpus:

| File                                                                     | Median wall time | Notes                              |
| ------------------------------------------------------------------------ | ---------------: | ---------------------------------- |
| `tests/assets/samples/pickles/dill_func.pkl`                             |      `0.523042s` | imported-function call-graph-heavy |
| `tests/assets/scenarios/license_scenarios/agpl_component/agpl_model.pkl` |      `0.288373s` | nested-pickle-heavy                |
| `tests/assets/exploits/exploit7_nested_collections.pkl`                  |      `0.152323s` | tiny file, expensive enrichment    |
| `tests/assets/exploits/exploit9_manual_construction.pkl`                 |      `0.102370s` | tiny file, expensive enrichment    |
| `tests/assets/exploits/exploit_ultimate_50pct.pkl`                       |      `0.101479s` | tiny file, expensive enrichment    |

## Initial Hotspots

### 1. Pickle call-graph enrichment

- Directory `cProfile` showed most warm corpus time under:
  - `modelaudit_picklescan.call_graph.find_dangerous_call_graphs`
  - `modelaudit_picklescan.call_graph.find_startup_hook_write_call_graphs`
  - repeated `ast.parse` and AST walks
- `find_dangerous_call_graphs()` and `find_startup_hook_write_call_graphs()` both clear the same source-sensitive caches before work.
- A controlled monkeypatch preserving those caches reduced the warm corpus scan from `2.016631s` to `0.813108s`.

Plan:

1. Add benchmark coverage that isolates call-graph enrichment across repeated pickle scans.
2. Replace unconditional cache clearing with source-fingerprint invalidation or an explicit per-enrichment cache context.
3. Make the three enrichment passes share one cache lifetime.
4. Keep tests that prove edits to source files are observed when they should be.

Expected upside:

- Largest measured win so far for mixed pickle-heavy workloads.

Correctness constraints:

- Do not let stale source analysis hide newly added dangerous behavior.
- Preserve behavior when modules are monkeypatched or temp source files change during tests.

### 2. Repeated full-file hashing

- Top-level scans hash files for aggregate content hashes.
- Several scanners independently compute MD5, SHA256, and SHA512 integrity hashes.
- Cache storage and content-hash cache keys can add more full-file hashing.
- `64 MiB` safetensors profile:
  - scanner integrity hashing: about `0.154s`
  - core SHA256: about `0.035s`
  - cache miss path: `0.564129s` total vs `0.181035s` without cache

Plan:

1. Inventory every hash consumer and the exact algorithms it needs.
2. Reuse scanner-emitted complete hashes for aggregate results when the bytes match the scanned asset.
3. Reuse one digest pass across cache metadata and scanner metadata where possible.
4. Revisit whether every scanner needs MD5, SHA256, and SHA512 on every invocation.
5. Benchmark larger files and cache miss/hit behavior before and after.

Expected upside:

- Strong improvement for large single-file models and repeated cache-enabled scans.

Correctness constraints:

- Preserve archive-wrapper semantics where nested-member hashes differ from top-level asset hashes.
- Do not weaken integrity guarantees silently.

### 3. License metadata scanning

- Single-file scans call `collect_license_metadata()` for every asset.
- Large text-like files with few or no newlines can cause a near full-file read while gathering only the first `50` logical lines.
- On a synthetic `64 MiB` one-line `.dat`, `collect_license_metadata()` consumed about `0.275s` of a `0.317s` profile.
- Directory scans also call `find_license_files()` once per scanned asset; on `2000` empty `.dat` files, this repeated nearby-license walk consumed about `3.391s` inside `collect_license_metadata()`.
- The final `check_commercial_use_warnings()` pass can become quadratic for same-directory inputs because `detect_unlicensed_datasets()` performs `Path.iterdir()` per candidate file; on `500` tiny `.pkl` files, the final license warning pass consumed about `1.384s`.

Plan:

1. Add targeted benchmarks for large binary files, large text files, and long one-line files.
2. Bound non-license-file header reads by bytes as well as lines.
3. Keep the existing richer behavior for actual license files.
4. Cache nearby-license discovery by directory during a scan.
5. Precompute per-directory sibling filename sets before `detect_unlicensed_datasets()` loops over files.

Expected upside:

- Large win for arbitrary text-like files and broad directories containing many sibling assets.

Correctness constraints:

- Preserve detection for real license headers and explicit license files.

### 4. Many-file directory overhead

- Directory scans currently:
  - optionally count files with `rglob`
  - walk the tree
  - hash every candidate path
  - scan each path independently
- Synthetic results:
  - `2000` empty `.dat` files: `3.748604s` median
  - `500` tiny `.pkl` files: `1.264593s` median
- The `2000`-file profile also exposed repeated per-file scanner-selection normalization and HuggingFace cache path checks:
  - `scanner_selection.policy_from_config()` / alias rebuilding: about `3.568s`
  - `_is_huggingface_cache_file()` family: about `1.540s`

Plan:

1. Break directory timing into discovery, filtering, hashing, and scanning phases.
2. Skip file counting unless progress reporting needs it.
3. Normalize scanner selection once per top-level scan and pass the resolved policy down instead of rebuilding aliases per file.
4. Avoid repeated nearby-license directory walks.
5. Short-circuit HuggingFace bookkeeping checks when the scan root is not under a known HuggingFace cache layout.
6. Consider scanner-aware dedupe only where a scanner is provably content-only.
7. Measure HuggingFace-cache and duplicate-heavy directory cases separately.

Expected upside:

- Better scaling on repositories, checkpoints, and model folders with many support files.

Correctness constraints:

- Preserve path-specific results for scanners that depend on neighboring files or parent directories.

### 5. Pickle wrapper passes

- Root pickle scans do extra wrapper work after the Rust engine:
  - raw root window detectors
  - binary-tail checks
  - legacy metadata detectors
  - unconditional JAX checkpoint pass
- Some of that is necessary security depth, but the JAX pass imports scanner code and reads the file even for ordinary pickles.
- A cold-process `safe_large_model.pkl` profile spent about `0.063s` inside `_scan_jax_checkpoint_patterns_if_needed()`, mostly importing `jax_checkpoint_scanner` and `numpy`; subsequent warm scans are much faster.

Plan:

1. Benchmark ordinary safe pickles, JAX-like pickles, nested-pickle-heavy files, and malicious call-graph fixtures separately.
2. Add cheap evidence gates before optional wrapper passes where semantics allow.
3. Keep every bypass-sensitive detector covered by malicious and benign fixtures.

Expected upside:

- Moderate improvement for common clean pickle scans.

Correctness constraints:

- Do not weaken nested-pickle, encoded-payload, or JAX checkpoint coverage.

### 6. Scanner selection rebuilds

- Every file normalizes scanner selection repeatedly even when no scanner filters were requested.
- On `2000` empty `.dat` files`, scanner-selection work consumed about `3.568s` in aggregate.
- `_scanner_aliases()` rebuilds a registry-derived alias map for every resolution.

Plan:

1. Cache scanner aliases from static registry metadata.
2. Preserve one resolved `ScannerSelectionPolicy` in normalized config for the duration of a scan.
3. Avoid re-normalizing config in nested calls when the normalized payload is already present and unchanged.

Expected upside:

- Large many-file directory improvement with low behavioral risk.

### 7. HuggingFace cache probing on ordinary local paths

- `_is_huggingface_cache_file()` invokes HuggingFace path-resolution helpers for every file.
- On `2000` ordinary local `.dat` files, this family consumed about `1.540s`.

Plan:

1. Carry top-level `is_hf_cache` state from directory discovery into lower layers.
2. Skip expensive HuggingFace bookkeeping resolution for files under roots already known not to be HF caches.
3. Keep the existing symlink protections for true HF cache layouts.

Expected upside:

- Noticeable improvement for large ordinary local folders.

## Rust Rewrite Candidates

### 1. Pickle call-graph enrichment

- Highest-value Rust candidate from current measurements.
- `packages/modelaudit-picklescan/src/modelaudit_picklescan/call_graph.py` is the largest confirmed CPU hotspot so far:
  - repeated parsing and AST walks dominate pickle-heavy workloads
  - the controlled cache experiment reduced warm-corpus time from about `2.0s` to `0.8s`
- Why Rust fits:
  - syntax-heavy deterministic analysis
  - repeated tree traversal over Python source
- Caveat:
  - finish the cheaper Python cache and invalidation work first
  - preserve source freshness and Python-resolution semantics exactly before moving this across the FFI boundary

### 2. Raw byte-oriented pickle wrapper detectors

- Good second-tier Rust candidate once remaining Python-side duplicate passes are trimmed.
- The best targets are bounded byte scans in `modelaudit/scanners/pickle_scanner.py`, not orchestration logic.
- Why Rust fits:
  - tight loops over bytes
  - stable inputs and a simpler correctness envelope than AST resolution

### 3. Other CPU-dense byte parsers after duplicate reads are removed

- Potential future candidates:
  - archive-member triage
  - manifest or metadata parsing passes that remain CPU-hot after I/O cleanup
  - large-buffer detector kernels
- Rule:
  - only port paths that stay hot after duplicate I/O and repeated setup work are removed

### Not Yet Good Rust Candidates

- Repeated hashing:
  - current issue is duplicate full-file passes, not slow digest implementations
- License metadata:
  - current issue is read strategy and repeated directory walks
- Directory orchestration, scanner selection, and HuggingFace path checks:
  - current wins come from caching and short-circuiting, not from a faster language boundary

## File-by-File Audit Queue

Priority 0:

- `packages/modelaudit-picklescan/src/modelaudit_picklescan/call_graph.py`
- `modelaudit/core.py`
- `modelaudit/scanners/base.py`
- `modelaudit/integrations/license_checker.py`
- `modelaudit/scanner_selection.py`
- `modelaudit/scanners/pickle_scanner.py`
- `modelaudit/cache/adaptive_cache_keys.py`
- `modelaudit/cache/scan_results_cache.py`

Priority 1:

- `modelaudit/utils/file/detection.py`
- `modelaudit/scanners/pytorch_zip_scanner.py`
- `modelaudit/scanners/zip_scanner.py`
- `modelaudit/scanners/tar_scanner.py`
- `modelaudit/scanners/sevenzip_scanner.py`
- `modelaudit/scanners/compressed_scanner.py`
- `modelaudit/scanners/safetensors_scanner.py`
- `modelaudit/scanners/tf_savedmodel_scanner.py`
- `modelaudit/scanners/keras_h5_scanner.py`
- `modelaudit/scanners/keras_zip_scanner.py`
- `modelaudit/scanners/manifest_scanner.py`
- `modelaudit/detectors/secrets.py`
- `modelaudit/detectors/network_comm.py`
- `modelaudit/detectors/jit_script.py`

## File-by-File Notes

| File                                                                     | Current read     | Audit note                                                                                                                                                            |
| ------------------------------------------------------------------------ | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/modelaudit-picklescan/src/modelaudit_picklescan/call_graph.py` | profiled         | Highest measured hotspot; repeated cache clearing and repeated AST analysis dominate pickle-heavy workloads.                                                          |
| `modelaudit/core.py`                                                     | profiled         | Directory orchestration performs discovery, prehash, repeated config normalization, per-file HF cache checks, and path-specific scans. Phase timings land in `#1170`. |
| `modelaudit/scanner_selection.py`                                        | profiled         | Alias maps and policies are rebuilt per file even when config is unchanged. Strong many-file optimization candidate.                                                  |
| `modelaudit/integrations/license_checker.py`                             | profiled         | Repeated directory walks and sibling directory scans create large many-file costs; header reading is also expensive for long one-line text-like files.                |
| `modelaudit/scanners/base.py`                                            | profiled         | Multi-hash integrity pass is a meaningful large-file cost and duplicates other hashing work.                                                                          |
| `modelaudit/scanners/pickle_scanner.py`                                  | profiled         | Clean duplicate pickle workloads spend heavily in raw detectors and the JAX wrapper pass after the Rust engine.                                                       |
| `modelaudit/cache/adaptive_cache_keys.py`                                | inspected        | Large-file cache keys can trigger content hashing; must be considered together with scanner and aggregate hashes.                                                     |
| `modelaudit/cache/scan_results_cache.py`                                 | inspected        | Cache storage computes a secure file hash after scan completion, adding another full-file pass on misses.                                                             |
| `modelaudit/utils/file/detection.py`                                     | inspected        | Mostly bounded probes; this is a good local pattern to preserve.                                                                                                      |
| `modelaudit/scanners/pytorch_zip_scanner.py`                             | lightly profiled | Tiny fixture is fast, but archive-member passes are numerous; needs larger archive benchmark before changing.                                                         |
| `modelaudit/scanners/zip_scanner.py`                                     | lightly profiled | Generic archive flow is currently fast on tiny fixtures; nested archive fan-out needs larger corpus benchmarks.                                                       |
| `modelaudit/scanners/tar_scanner.py`                                     | inspected        | Mostly streaming/bounded extraction; needs benchmark coverage rather than speculative edits.                                                                          |
| `modelaudit/scanners/compressed_scanner.py`                              | inspected        | Chunked and budgeted; likely lower priority unless decompression-heavy inputs show otherwise.                                                                         |
| `modelaudit/scanners/onnx_scanner.py`                                    | inspected        | Reads whole file for raw detectors after protobuf load; candidate for shared-buffer or bounded-detector review.                                                       |
| `modelaudit/scanners/tflite_scanner.py`                                  | inspected        | Metadata extraction reads whole file up to a `2 GiB` cap. Needs large-file benchmark and maybe parser-driven reuse.                                                   |
| `modelaudit/scanners/flax_msgpack_scanner.py`                            | inspected        | Whole-file read to detect trailing objects; repeated JAX-transform lowercase passes are fixed in `#1169`, but a large-file benchmark is still needed.                 |
| `modelaudit/scanners/jinja2_template_scanner.py`                         | inspected        | Whole-file read is bounded by `max_template_size`; lower priority.                                                                                                    |
| `modelaudit/scanners/manifest_scanner.py`                                | inspected        | Multiple whole-file text reads across parse and blacklist paths; candidate for one-read reuse on larger manifests.                                                    |
| `modelaudit/scanners/metadata_scanner.py`                                | inspected        | Whole-file read for text metadata; likely acceptable for small docs but should be bounded by type/size.                                                               |
| `modelaudit/scanners/tf_savedmodel_scanner.py`                           | lightly profiled | Tiny fixture cost was mostly lazy imports; Keras metadata text had repeated lowercase passes, now fixed in `#1168`. Large SavedModel benchmarks remain.               |
| `modelaudit/scanners/keras_zip_scanner.py`                               | inspected        | Lambda-code scanning reused repeated whole-string lowercase passes, now fixed in `#1168`; larger archive benchmarks are still needed.                                 |
| `modelaudit/scanners/keras_utils.py`                                     | inspected        | Shared Lambda helpers had the same repeated lowercase pattern, now consolidated behind one reusable matcher in `#1168`.                                               |
| `modelaudit/detectors/secrets.py`                                        | inspected        | Fixed detector heuristics now reuse module-level state in `#1189`; convenience file API still reads whole files, while the core pickle path already gates execution.   |
| `modelaudit/detectors/network_comm.py`                                   | inspected        | Convenience file API reads whole files and regex work can be expensive on large buffers.                                                                              |
| `modelaudit/detectors/jit_script.py`                                     | inspected        | Convenience file API reads whole files and AST walks parsed code; keep behind bounded callers.                                                                        |
| `modelaudit/scanners/catboost_scanner.py`                                | inspected        | Uses bounded head/core/trailer reads; low priority until a CatBoost-specific benchmark says otherwise.                                                                |
| `modelaudit/scanners/cntk_scanner.py`                                    | inspected        | Uses explicit read limits; low priority.                                                                                                                              |
| `modelaudit/scanners/executorch_scanner.py`                              | inspected        | Length-delimited reads; low priority.                                                                                                                                 |
| `modelaudit/scanners/gguf_scanner.py`                                    | inspected        | Structured parser advances by bounded field reads; benchmark malformed/huge-metadata cases before changing.                                                           |
| `modelaudit/scanners/nemo_scanner.py`                                    | inspected        | Config extraction is explicitly capped; low priority.                                                                                                                 |
| `modelaudit/scanners/paddle_scanner.py`                                  | inspected        | Chunked raw scanning; low priority.                                                                                                                                   |
| `modelaudit/scanners/pytorch_binary_scanner.py`                          | inspected        | Chunked raw scanning and bounded header reads; low priority.                                                                                                          |
| `modelaudit/scanners/tf_metagraph_scanner.py`                            | inspected        | Uses an explicit read cap; low priority.                                                                                                                              |
| `modelaudit/scanners/xgboost_scanner.py`                                 | inspected        | Most routing probes are bounded, but UBJSON parsing still materializes the file; add large `.bst` benchmark if this format matters.                                   |
| `modelaudit/scanners/oci_layer_scanner.py`                               | inspected        | Manifest probing is chunked, but full text read remains in one path; add an OCI-layer benchmark before changing.                                                      |
| `modelaudit/scanners/pmml_scanner.py`                                    | inspected        | Whole-file XML read remains, but repeated case-insensitive extension-pattern searches are fixed in `#1172`.                                                           |

## Open Questions

- Which integrity hashes are product requirements versus legacy convenience?
- Should cache keys use full content hashes for files above `10 MiB` when scan results themselves already include strong hashes?
- How much source freshness does call-graph analysis truly need within one process, and can module mtimes provide a sufficient invalidation boundary?
- Which scanners are content-only enough for duplicate-result reuse without changing semantics?

## Performance Backlog

### Measurement Infrastructure

- [ ] Make the existing benchmark suites runnable in the intended benchmark lane.
- [ ] Decide whether benchmark files belong in the reduced-Python allowlist or should run only in a dedicated full lane.
- [ ] Add a checked-in benchmark command matrix for:
  - [ ] single-file scans
  - [ ] directory scans
  - [ ] cache miss scans
  - [ ] cache hit scans
  - [ ] duplicate-heavy scans
  - [ ] many-small-file scans
- [ ] Add stable JSON output generation for benchmark runs.
- [ ] Add a small script that compares current benchmark JSON against a prior baseline.
- [ ] Add explicit benchmark tags for:
  - [ ] pickle-heavy
  - [ ] large-file
  - [ ] many-file
  - [ ] archive-heavy
  - [ ] metadata-heavy
- [ ] Record host, Python, dependency set, cache state, and git revision with every benchmark artifact.
- [ ] Add a benchmark corpus inventory file so future runs use the same representative inputs.
- [ ] Add a benchmark for cold-process startup cost versus warm-process repeated scan cost.
- [ ] Add a benchmark for first import cost of optional scanner families.
- [ ] Add a benchmark for scan result serialization overhead.
- [ ] Add a benchmark for progress-enabled versus progress-disabled directory scans.
- [ ] Add a benchmark for aggregate result construction on very large directory scans.
- [ ] Add a benchmark for SBOM generation when scan results are large.
- [ ] Add a benchmark for telemetry-disabled and telemetry-enabled paths, only if telemetry behavior is intentionally in scope.

### Core Pipeline Instrumentation

- [ ] Add phase timings around top-level scan orchestration.
- [ ] Measure:
  - [ ] path expansion
  - [ ] directory discovery
  - [ ] file counting
  - [ ] file filtering
  - [ ] scanner selection
  - [ ] top-level hashing
  - [ ] per-file scan dispatch
  - [ ] license metadata collection
  - [ ] result merge
  - [ ] commercial-use warning aggregation
  - [ ] cache lookup
  - [ ] cache store
- [ ] Emit optional timing metadata in debug/perf mode without changing normal user output.
- [ ] Add a helper to aggregate timing metadata across directory scans.
- [ ] Add a way to compare scanner self-time versus orchestration time.
- [ ] Add profiling docs for `scripts/profile_scan.py`.
- [ ] Add one canonical command for profiling a directory scan and one for profiling a single file.
- [ ] Add a way to suppress finding logs during perf runs so output does not drown the profile.
- [ ] Add a benchmark/profiling smoke test to keep the profiling script working.

### Pickle / PickleScan Hotspots

- [ ] Replace unconditional call-graph cache clearing with source-aware invalidation.
- [ ] Make dangerous-call, startup-hook, and related enrichment passes share one cache lifetime.
- [ ] Add tests proving changed source files invalidate cached analysis.
- [ ] Add tests proving monkeypatched/temp-module scenarios still invalidate correctly.
- [ ] Add a benchmark that scans many small call-graph-heavy pickles in one process.
- [ ] Add a benchmark that scans many call-graph-light pickles in one process.
- [ ] Add a benchmark that scans the same pickle repeatedly in one process.
- [ ] Separate call-graph parsing time from actual pickle opcode scanning time in measurements.
- [ ] Inspect whether `_safe_call_graph_entrypoints()` repeats equivalent reference expansion work.
- [ ] Inspect whether `_split_function_name()` and `_resolve_function_target()` can share more intermediate work.
- [ ] Inspect repeated `ast.walk()` usage for opportunities to precompute indexes during module analysis.
- [ ] Audit repeated source reads in `call_graph.py`.
- [ ] Audit repeated `ast.parse()` calls in `call_graph.py`.
- [ ] Evaluate whether module-level function metadata can be materialized once per source fingerprint.
- [ ] Add a microbenchmark around `_analyze_module()`.
- [ ] Add a microbenchmark around `_collect_function_calls()`.
- [ ] Add a microbenchmark around nested reference resolution.
- [ ] Review whether startup-hook detection needs the same source surface as dangerous-call detection.
- [ ] Review whether all wrapper passes must run for all ordinary root pickles.
- [ ] Add cheap evidence gating before optional JAX wrapper work if detection coverage permits.
- [ ] Avoid cold-importing heavy JAX dependencies for obviously non-JAX pickles if a safe prefilter exists.
- [ ] Benchmark root raw detector passes separately:
  - [ ] encoded text indicators
  - [ ] raw root window detectors
  - [ ] binary tail checks
  - [ ] JAX checkpoint heuristics
- [ ] Add explicit correctness fixtures before changing any bypass-sensitive detector gating.

### Hashing and Cache Passes

- [ ] Inventory every full-file hash consumer and the algorithms each one needs.
- [ ] Map where SHA256, SHA512, MD5, BLAKE2, and secure aggregate hashes are produced.
- [ ] Decide which integrity hashes are product requirements versus legacy conveniences.
- [ ] Reuse scanner-emitted hashes for top-level aggregate hashes when semantics match.
- [ ] Reuse one digest pass for cache metadata and scanner metadata where possible.
- [ ] Avoid rehashing the same top-level file separately in core and scanner layers when bytes are identical.
- [ ] Preserve nested archive-member hash semantics while optimizing top-level files.
- [ ] Evaluate whether cache content hashing can reuse already-computed digests on cache miss.
- [ ] Evaluate whether cache keys need full-content hashes for very large files in all cases.
- [ ] Add benchmarks for:
  - [ ] `10 MiB`
  - [ ] `64 MiB`
  - [ ] `256 MiB`
  - [ ] `1 GiB`, if practical locally
- [ ] Add benchmark coverage for cache miss versus cache hit across multiple file sizes.
- [ ] Add a regression benchmark for duplicate-heavy directories with cache disabled.
- [ ] Add a regression benchmark for duplicate-heavy directories with cache enabled.
- [ ] Inspect whether cache store can avoid secure rehashing when a strong digest is already available and trusted.
- [ ] Record RSS impact of any digest reuse strategy.

### License Metadata and Commercial-Use Checks

- [ ] Bound non-license-file header reads by bytes as well as lines.
- [ ] Keep richer reads for actual license files where full text matters.
- [ ] Cache nearby-license discovery by directory during a scan.
- [ ] Precompute sibling filename sets for commercial-use warning aggregation.
- [ ] Avoid repeated `Path.iterdir()` for each candidate file in the same directory.
- [ ] Add a benchmark for many sibling files with no license file.
- [ ] Add a benchmark for many sibling files with one nearby license file.
- [ ] Add a benchmark for a large binary file with no license metadata.
- [ ] Add a benchmark for a large text file with normal newlines.
- [ ] Add a benchmark for a large one-line text file.
- [ ] Add negative tests proving bounded reads still find nearby explicit license files.
- [ ] Add positive tests proving real license headers are still detected after byte limits.
- [ ] Consider separating directory-level license discovery from per-file metadata extraction.
- [ ] Inspect whether license warning aggregation can operate on grouped directories instead of individual paths.
- [ ] Record how much of `collect_license_metadata()` time is header reading versus nearby-file discovery.

### Directory Scan Scaling

- [ ] Normalize scanner-selection config once per top-level scan.
- [ ] Cache scanner aliases derived from static registry metadata.
- [ ] Reuse one resolved `ScannerSelectionPolicy` during child scans.
- [ ] Avoid re-normalizing already-normalized config on nested calls.
- [ ] Skip expensive file pre-counting unless progress reporting actually requires it.
- [ ] Measure `rglob()` pre-count cost separately from `os.walk()` discovery.
- [ ] Carry top-level HuggingFace-cache state into lower layers.
- [ ] Short-circuit HuggingFace cache resolution for roots known not to be HF caches.
- [ ] Preserve existing symlink and provenance protections for true HF cache layouts.
- [ ] Measure scan cost for:
  - [ ] `100`
  - [ ] `1,000`
  - [ ] `10,000`
  - [ ] `50,000` tiny files
- [ ] Add benchmarks for shallow directories and deep directory trees separately.
- [ ] Add benchmarks for extension-heavy directories and mixed-content directories separately.
- [ ] Add benchmarks for true HF-cache roots and ordinary local roots.
- [ ] Consider grouping work by directory to amortize nearby-file checks.
- [ ] Consider batching scanner-selection lookups by file type if that can be done without changing semantics.
- [ ] Investigate content-aware duplicate-result reuse only for scanners proven path-independent.
- [ ] Define a scanner capability flag for content-only versus path-sensitive behavior before deduplication.
- [ ] Add correctness tests for duplicate files in different directories when path context changes results.

### Scanner Routing and Detection

- [ ] Audit all scanner routing paths for repeated header reads.
- [ ] Audit file-type detection for repeated suffix/path checks that can be memoized per file.
- [ ] Keep the current bounded-read patterns in `modelaudit/utils/file/detection.py`.
- [ ] Measure whether scanner candidate ordering causes avoidable work on common file types.
- [ ] Measure whether scanner registry lookup itself is meaningful outside many-file cases.
- [ ] Add a benchmark for disguised extensions and routed archives so optimizations do not weaken safety.
- [ ] Add a benchmark for files rejected early by cheap routing versus files that fan out to deeper scanners.

### Large-Input Scanner Follow-Ups

- [ ] Add a large ONNX benchmark before changing `onnx_scanner.py`.
- [ ] Decide whether ONNX raw detector passes can share an already-loaded buffer or safely use bounded windows.
- [ ] Add a large TFLite benchmark before changing `tflite_scanner.py`.
- [ ] Review whether TFLite metadata extraction truly needs to materialize the whole file.
- [ ] Add a large Flax msgpack benchmark before changing `flax_msgpack_scanner.py`.
- [ ] Review whether trailing-object detection in Flax can be streamed or partially indexed.
- [ ] Add a large manifest benchmark with:
  - [ ] no blacklist patterns
  - [ ] blacklist patterns
  - [ ] cloud URL checks
  - [ ] embedded Jinja templates
- [ ] Consider one-read reuse across manifest parse, blacklist, and cloud URL checks.
- [ ] Add a large SavedModel benchmark before changing `tf_savedmodel_scanner.py`.
- [ ] Add a large XGBoost UBJSON benchmark before changing `xgboost_scanner.py`.
- [ ] Add a large PMML benchmark before changing `pmml_scanner.py`.
- [ ] Add an OCI-layer benchmark before changing `oci_layer_scanner.py`.
- [ ] Add a large metadata-text benchmark before changing `metadata_scanner.py`.
- [ ] Add benchmarks for archive scanners with:
  - [ ] many tiny members
  - [ ] a few large members
  - [ ] nested archives
  - [ ] malicious positive members
  - [ ] benign near-match members
- [ ] Add a large PyTorch ZIP benchmark before touching member traversal logic.
- [ ] Add a large generic ZIP benchmark before touching generic archive traversal logic.
- [ ] Add a large TAR benchmark before touching TAR traversal logic.
- [ ] Add a decompression-heavy benchmark before touching compressed wrapper scanners.

### Memory and Allocation Work

- [ ] Record peak RSS for the main benchmark scenarios.
- [ ] Add allocation profiling for:
  - [ ] call-graph-heavy pickle scans
  - [ ] large ONNX scans
  - [ ] large TFLite scans
  - [ ] large manifest scans
- [ ] Identify scanners that duplicate large byte buffers.
- [ ] Identify scanners that parse once and then reread the same file into memory.
- [ ] Inspect regex-heavy detectors for large temporary strings or repeated lowercasing.
- [ ] Inspect whole-file `.lower()` calls on large text inputs.
- [ ] Prefer streaming or bounded windows where detection semantics allow.
- [ ] Record the memory cost of any digest sharing or buffer reuse proposal.

### Logging and UX Overhead

- [ ] Measure effect of finding-log volume on perf runs.
- [ ] Add a quiet profiling mode if logs materially distort timings.
- [ ] Measure progress callback overhead on very large directory scans.
- [ ] Measure debug metadata overhead when many findings are emitted.
- [ ] Measure cost of result explanation generation if enabled on large result sets.

### Correctness Guardrails for Optimizations

- [ ] For every optimization, record:
  - [ ] expected win
  - [ ] changed code paths
  - [ ] failure mode if wrong
  - [ ] benchmark proving the win
  - [ ] malicious fixture proving detection is preserved
  - [ ] benign near-match proving false positives do not regress
- [ ] Treat path-sensitive scanners as non-deduplicable until proven otherwise.
- [ ] Keep fail-closed behavior explicit when bounded reads truncate analysis.
- [ ] Preserve archive-member semantics when reusing hashes or buffers.
- [ ] Preserve source freshness semantics in call-graph caching.
- [ ] Preserve true HF-cache behavior while optimizing ordinary local roots.
- [ ] Preserve reduced-Python-lane test coverage for every benchmark-adjacent change that needs it.

### Documentation and Process

- [ ] Keep this audit file updated after every benchmark tranche.
- [ ] Record benchmark commands next to every measurement.
- [ ] Record profile artifacts for every new hotspot claim.
- [ ] Keep a “measured” versus “suspected” label on every backlog item.
- [ ] Add a small changelog section to this doc for completed perf wins.
- [ ] Track before/after numbers for every landed optimization.
- [ ] Add a release-note rubric for user-visible scan-time improvements.
- [ ] Decide whether perf work should land as:
  - [ ] many small PRs
  - [ ] a small stack of thematic PRs
  - [ ] one instrumentation PR followed by focused optimization PRs

## Completed Wins

### 2026-05-01 - Scanner selection reuse

- PR:
  - `#1153`
- Change:
  - cached static scanner metadata and alias resolution
  - rehydrated already-normalized selection payloads without re-running alias resolution
- Targeted regression:
  - `tests/test_scanner_selection.py::test_normalized_selection_rehydrates_without_alias_resolution`
- Benchmarks:
  - `2000` empty `.dat` files: `3.740284s` -> `3.066438s`
  - `500` tiny `.pkl` files: `1.543400s` -> `1.326489s`
- Notes:
  - this is the first low-risk directory-scale win from the backlog
  - larger remaining costs in the same path are still license directory work and non-HF bookkeeping

### 2026-05-01 - HuggingFace bookkeeping short-circuit

- PR:
  - `#1154`
- Change:
  - ordinary filenames now return before HuggingFace bookkeeping path resolution starts
  - bookkeeping-shaped names retain the existing trust checks
- Targeted regression:
  - `tests/test_directory_file_filtering.py::TestDirectoryFileFiltering::test_non_bookkeeping_filenames_skip_hf_path_resolution`
- Benchmarks:
  - ordinary `weights.dat` helper calls, `20,000` iterations: `2.504382s` -> `0.004380s`
  - `2000`-file directory profile: HF helper family reduced to `0.009s` aggregate
- Notes:
  - full-directory wall time is still dominated by scanner-selection and license work on branches without those fixes

### 2026-05-01 - Nearby-license discovery reuse

- PR:
  - `#1155`
- Change:
  - nearby-license discovery is cached per scan and reused across sibling files
  - reduced-lane coverage now includes the license checker and license integration tests
- Targeted regressions:
  - `tests/integrations/test_license_checker.py::TestLicenseMetadataCollection::test_collect_license_metadata_reuses_nearby_license_cache`
  - `tests/integrations/test_license_integration.py::TestLicenseIntegration::test_directory_scan_reuses_nearby_license_discovery`
- Benchmarks:
  - synthetic `2000`-file profile:
    - `find_license_files()`: about `5.479s` / `2000` calls -> `0.003s` / `1` call
    - `collect_license_metadata()`: about `5.694s` -> `0.153s`
- Notes:
  - sibling-name reuse in `detect_unlicensed_datasets()` landed separately in `#1157`

### 2026-05-01 - Report-scoped call-graph cache sharing

- PR:
  - `#1156`
- Change:
  - call-graph enrichment passes now share one fresh source-sensitive cache generation per report
  - direct public helper calls still clear caches independently outside that report scope
- Targeted regressions:
  - `packages/modelaudit-picklescan/tests/test_call_graph_import_statements.py::test_shared_source_sensitive_caches_clears_once_per_scope`
  - `packages/modelaudit-picklescan/tests/test_call_graph_import_statements.py::test_scan_bytes_refreshes_call_graph_after_source_rewrite`
- Benchmarks:
  - same-process `dill_func.pkl` A/B:
    - old three-clear behavior: `0.538389s` median
    - report-scoped sharing: `0.196939s` median
- Notes:
  - this fixes repeated clearing inside one report only; broader source-fingerprint invalidation remains open work

### 2026-05-01 - Sibling license-directory reuse

- PR:
  - `#1157`
- Change:
  - `detect_unlicensed_datasets()` now lists each sibling directory once per pass instead of once per candidate file
  - reduced-Python coverage now includes the focused license checker regression
- Targeted regression:
  - `tests/integrations/test_license_checker.py::TestUnlicensedDatasetDetection::test_reuses_sibling_directory_listing`
- Benchmarks:
  - isolated `500` sibling dataset files:
    - repeated directory listings: `0.736675s` median
    - one cached listing per directory: `0.005581s` median
- Notes:
  - this addresses the remaining measured directory-scale license hotspot after nearby-license discovery reuse

### 2026-05-01 - Ordinary-pickle JAX delegation gate

- PR:
  - `#1158`
- Change:
  - complete non-JAX root pickle windows now skip the extra JAX checkpoint delegation pass
  - truncated windows and JAX-bearing payloads keep the existing conservative path
- Targeted regressions:
  - `tests/scanners/test_pickle_scanner.py::test_pickle_scanner_skips_jax_delegation_for_complete_non_jax_payloads`
  - `tests/scanners/test_pickle_scanner.py::test_pickle_scanner_uses_jax_window_beyond_root_raw_scan_limit`
- Benchmarks:
  - synthetic `4 MiB` ordinary pickle:
    - unconditional delegation: `0.191007s` median
    - complete-window non-JAX skip: `0.065762s` median
- Notes:
  - broader pickle-wrapper cleanup remains open, but this removes a safe common-case pass

### 2026-05-01 - Manifest text reuse

- PR:
  - `#1160`
- Change:
  - manifest scans now cache decoded text for the lifetime of one scan
  - blacklist, cloud URL, and parse passes reuse the same text instead of reopening the file
- Targeted regression:
  - `tests/scanners/test_manifest_scanner.py::test_manifest_scanner_reuses_manifest_text_during_scan`
- Benchmarks:
  - same-process synthetic `8 MiB` manifest:
    - forced uncached reads: `0.673513s` median
    - per-scan text cache: `0.423788s` median
- Notes:
  - this removes the first confirmed repeated-read hotspot outside the larger hash redesign

### 2026-05-01 - JAX probe handle reuse

- PR:
  - `#1161`
- Change:
  - pickle-shaped JAX routing probes now reuse the initial open handle
  - the helper extends the already-read header window instead of reopening the file
- Targeted regression:
  - `tests/scanners/test_jax_checkpoint_scanner.py::test_pickle_candidate_probe_reuses_open_file`
- Benchmarks:
  - repeated pickle-candidate probe, `200` calls:
    - previous two-open path: `0.045949s` median
    - single-handle path: `0.026661s` median
- Notes:
  - this is a small routing win, but it removes avoidable duplicate I/O on every pickle-shaped JAX candidate

### 2026-05-01 - Shared license-header lowercase view

- PR:
  - `#1162`
- Change:
  - `collect_license_metadata()` now lowers the shared header text once
  - license and copyright prefilters reuse that lowercase view instead of recomputing it independently
- Targeted regression:
  - `tests/integrations/test_license_checker.py::TestLicenseMetadataCollection::test_collect_license_metadata_reuses_lowered_header`
- Benchmarks:
  - synthetic `8 MiB` one-line header, same-process controlled A/B:
    - forced duplicate lowercasing: `0.687008s` median
    - shared lowercase view: `0.616486s` median
- Notes:
  - this is a narrow CPU cleanup on the long-text license path; the larger header-read semantics tradeoff remains open

### 2026-05-01 - Large-file cache hash reuse

- PR:
  - `#1171`
- Change:
  - large-file cache stores now reuse the secure digest already computed while building the cache key
  - avoids an immediate second full-file secure hash inside `store_result()`
- Targeted regression:
  - `tests/cache/test_cache_correctness.py::test_large_file_store_reuses_cache_key_content_hash`
- Benchmarks:
  - synthetic `64 MiB` cache store:
    - before: `0.126905s` median, `5` key-hash calls, `5` store-hash calls
    - after: `0.110148s` median, `5` key-hash calls, `0` store-hash calls
- Notes:
  - this is the first landed slice of the repeated-hashing backlog
  - broader SHA256 and integrity-hash reuse still needs product-level hash-output constraints settled

### 2026-05-01 - PMML extension-pattern reuse

- PR:
  - `#1172`
- Change:
  - PMML suspicious extension patterns are compiled once at import time
  - extension content is already lowercased, so the scan now uses case-sensitive compiled regexes instead of repeated ignore-case regex searches
- Targeted regression:
  - `tests/scanners/test_pmml_scanner.py::test_pmml_scanner_mixed_case_system_call_is_flagged`
- Benchmarks:
  - synthetic `8 MiB` no-match extension text:
    - repeated ignore-case search loop: `0.770225s` median
    - compiled case-sensitive search loop over lowered text: `0.460403s` median
- Notes:
  - this is a scanner-local large-text CPU cleanup that keeps mixed-case malicious input detection intact

### 2026-05-02 - Skip directory pre-count without progress

- PR:
  - `#1173`
- Change:
  - directory scans now skip the lazy `rglob()` file pre-count when callers did not request progress callbacks
  - progress-enabled scans keep the existing percentage denominator behavior
- Targeted regression:
  - `tests/test_core.py::test_scan_directory_without_progress_skips_file_counting`
- Benchmarks:
  - synthetic `10,000`-file tree (`100` directories x `100` skipped files), removed pre-count pass:
    - current pre-count work: `0.094856s` median
    - after the guard: no `Path.rglob()` pass on no-progress scans
- Notes:
  - an earlier `5000`-file end-to-end probe treated this as too small to prioritize, but the direct-path measurement made it a clean low-risk orchestration cleanup
  - this is still a modest many-file win; the larger directory-scaling costs remain in scan dispatch and per-file work

### 2026-05-02 - Bounded directory progress pre-counts

- PR:
  - `#1174`
- Change:
  - progress-enabled directory scans now stop probing immediate children once they reach the existing `1000`-entry threshold
  - recursive progress pre-counting also stops once a tree is already known to exceed that threshold
  - wide roots no longer materialize every top-level entry, and deep roots no longer count every nested file just to decide whether percentages are worthwhile
- Targeted regressions:
  - `tests/test_core.py::test_directory_child_probe_stops_at_limit`
  - `tests/test_core.py::test_directory_file_probe_stops_after_limit`
- Benchmarks:
  - synthetic wide directory with `20,000` immediate children, same-process A/B:
    - eager child-list materialization: `0.017017s` median
    - bounded child probe helper: `0.008936s` median
  - synthetic deep directory with `20,000` nested files, same-process A/B:
    - full recursive count: `0.138195s` median
    - bounded recursive probe: `0.014900s` median
- Notes:
  - this preserves exact totals for small trees while falling back to open-ended progress once a tree is already large enough that the recursive count is the costlier choice

### 2026-05-02 - Hardlink hash reuse

- PR:
  - `#1175`
- Change:
  - directory hash prepasses now reuse a digest when multiple paths resolve to the same hardlinked inode fingerprint
  - scan results stay path-specific while repeated reads of identical hardlinked bytes are avoided
- Targeted regression:
  - `tests/test_regular_scan_hash.py::TestHashGenerationEdgeCases::test_hash_files_by_path_reuses_hash_for_hardlinks`
- Benchmarks:
  - synthetic `32 MiB` file exposed through `16` hardlinked paths:
    - before: `0.248237s` median
    - after: `0.020348s` median
- Notes:
  - this is a narrow I/O win inside the repeated-hashing backlog; broader top-level and scanner-layer hash reuse still needs the product-level digest policy work called out above

### 2026-05-02 - Nearby-license directory cache

- PR:
  - `#1176`
- Change:
  - dataset-license detection now caches whether a directory contains a nearby license file during one pass
  - sibling datasets in the same directory no longer rebuild the same lowercase sibling-name set independently
- Targeted regression:
  - `tests/integrations/test_license_checker.py::TestUnlicensedDatasetDetection::test_detect_unlicensed_datasets_reuses_nearby_license_lookup_per_directory`
- Benchmarks:
  - synthetic directory with `800` sibling `.csv` datasets and no nearby license:
    - before: `1.924856s` median
    - after: `0.008298s` median
- Notes:
  - this closes the clearest repeated directory-walk hotspot in `detect_unlicensed_datasets()`; broader license-header read semantics remain separate work

### 2026-05-02 - Scanner-selection policy cache

- PR:
  - `#1177`
- Change:
  - scanner aliases are now built once from the static registry metadata
  - equivalent normalized scanner-selection inputs reuse one bounded cached frozen policy object
- Targeted regression:
  - `tests/test_scanner_selection.py::test_selection_policy_reuses_normalized_cached_results`
- Benchmarks:
  - `20,000` repeated `resolve_scanner_ids()` calls:
    - before: `0.857873s` median
    - after: `0.288100s` median
  - `20,000` repeated equivalent policy resolutions:
    - before: `2.038787s` median
    - after: `0.007434s` median
- Notes:
  - this trims repeated setup from many-file scans while leaving the actual scanner-selection semantics unchanged

### 2026-05-02 - Shared Lambda pattern lowercase view

- PR:
  - `#1178`
- Change:
  - shared Lambda dangerous-pattern matching now lowers decoded text once per payload
  - Keras utility, Keras ZIP, and TensorFlow SavedModel Lambda checks reuse the same helper while preserving their current pattern sets
- Targeted regression:
  - `tests/scanners/test_keras_utils.py::test_find_lambda_dangerous_patterns_lowers_once`
- Benchmarks:
  - synthetic `8 MiB` decoded Lambda text across `18` patterns:
    - before: `0.049654s` median
    - after: `0.017521s` median
- Notes:
  - this is a narrow scanner-local CPU cleanup; the PR intentionally avoids changing detection coverage while removing repeated long-text lowercasing

### 2026-05-02 - HuggingFace bookkeeping filename short-circuit

- PR:
  - `#1179`
- Change:
  - `_is_huggingface_cache_file()` now returns immediately for filenames that can never be HuggingFace bookkeeping artifacts
  - ordinary local assets no longer pay the hub/download layout-resolution cost before being scanned
- Targeted regression:
  - `tests/test_directory_file_filtering.py::TestDirectoryFileFiltering::test_non_bookkeeping_filenames_skip_hf_layout_probes`
- Benchmarks:
  - `20,000` ordinary local filenames:
    - before: `2.326372s` median
    - after: `0.027346s` median
- Notes:
  - this closes the clearest ordinary-path slice of the HuggingFace probing backlog while keeping the existing true-cache layout checks intact

### 2026-05-02 - Per-scan nearby-license file cache

- PR:
  - `#1180`
- Change:
  - scan orchestration now passes a short-lived per-scan nearby-license cache into `collect_license_metadata()`
  - sibling assets reuse the same `find_license_files()` result without introducing a process-global cache
- Targeted regression:
  - `tests/integrations/test_license_checker.py::TestLicenseMetadataCollection::test_collect_license_metadata_reuses_nearby_license_cache`
- Benchmarks:
  - `800` sibling files with no nearby license files:
    - before: `0.316707s` median
    - after: `0.024294s` median
- Notes:
  - this closes the metadata-collection side of repeated nearby-license discovery; the separate commercial-warning sibling cache landed in `#1176`

### 2026-05-02 - Scanner-selection renormalization fast path

- PR:
  - `#1181`
- Change:
  - already-normalized scanner-selection payloads now bypass a second policy-resolution pass
  - repeated scan-file calls can reuse the canonical config shape emitted by the first normalization
- Targeted regression:
  - `tests/test_scanner_selection.py::test_normalize_scanner_selection_config_reuses_normalized_payload`
- Benchmarks:
  - `50,000` repeated `normalize_scanner_selection_config()` calls on an already-normalized payload:
    - before: `5.097017s` median
    - after: `0.014622s` median
- Notes:
  - this is a follow-up to the scanner-selection cache work and removes the remaining duplicate normalization work on already-canonical configs

### 2026-05-02 - One-pass CLI progress tree summary

- PR:
  - `#1182`
- Change:
  - enhanced CLI progress initialization now summarizes directory bytes and descendant items in one recursive traversal
  - preserves the existing totals while removing a duplicate `Path.rglob("*")` walk
- Targeted regression:
  - `tests/test_cli.py::test_summarize_progress_tree_walks_once`
- Benchmarks:
  - synthetic `20,000`-file tree (`100` directories x `200` files):
    - before: `0.553156s` median
    - after: `0.413021s` median
- Notes:
  - this is a modest progress-enabled CLI win, separate from the larger core directory pre-count work in `#1173` and `#1174`

### 2026-05-02 - SavedModel function-pattern reuse

- PR:
  - `#1183`
- Change:
  - TensorFlow SavedModel suspicious-function regexes are now compiled once at module load instead of once per checked function name
  - the helper keeps the same token-boundary matching while removing repeated static setup
- Targeted regression:
  - `tests/scanners/test_tf_savedmodel_scanner.py::test_suspicious_function_name_reuses_precompiled_patterns`
- Benchmarks:
  - `100,000` safe function-name checks:
    - before: `1.497486s` median
    - after: `0.563691s` median
- Notes:
  - this is a scanner-local cleanup for models with many function references; the broad non-slow suite still has a separate noisy picklescan timing guard on this machine

### 2026-05-02 - Shared Jinja scanner pattern set

- PR:
  - `#1184`
- Change:
  - Jinja SSTI regexes are now compiled once at module load and reused across fresh scanner instances
  - this removes repeated static setup from the per-file scanner-construction path
- Targeted regression:
  - `tests/scanners/test_jinja2_template_scanner.py::test_jinja_scanner_reuses_precompiled_patterns`
- Benchmarks:
  - `2,000` `Jinja2TemplateScanner()` constructions:
    - before: `0.078247s` median
    - after: `0.000606s` median
- Notes:
  - this is a many-file routing win because `get_scanner_for_file()` creates a fresh scanner instance for each matched path

### 2026-05-02 - Default secret-pattern reuse

- PR:
  - `#1185`
- Change:
  - default embedded-secret regex banks are now compiled once at module load
  - custom secret-pattern configs keep the existing dynamic compile path
- Targeted regression:
  - `tests/detectors/test_secrets_detector.py::TestSecretsDetector::test_default_detector_reuses_precompiled_patterns`
- Benchmarks:
  - `2,000` default `SecretsDetector()` constructions:
    - before: `0.065173s` median
    - after: `0.001091s` median
- Notes:
  - this is a common-path detector win because `BaseScanner.check_for_embedded_secrets()` constructs the detector during scans

### 2026-05-02 - Manifest trusted-URL allowlist cache

- PR:
  - `#1186`
- Change:
  - manifest URL trust checks now normalize the allowlist once at import time
  - exact-host lookups use a precomputed set before falling back to suffix checks for trusted parent domains
- Targeted regression:
  - `tests/scanners/test_manifest_scanner.py::TestIsTrustedUrlDomain::test_exact_trusted_domain_skips_suffix_scan`
- Benchmarks:
  - `20,000` exact trusted URL checks:
    - before: `0.342448s` median
    - after: `0.059979s` median
  - `20,000` untrusted URL checks:
    - before: `0.359739s` median
    - after: `0.247666s` median
  - `20,000` trusted subdomain checks:
    - before: `0.090956s` median
    - after: `0.082338s` median
- Notes:
  - this is a manifest-scanner CPU cleanup for URL-heavy configs that preserves the exact-only hosting-domain boundary

### 2026-05-02 - Shared Flax layer keyword text

- PR:
  - `#1187`
- Change:
  - Flax ML-structure analysis now stringifies and lowercases the checkpoint object once before layer-keyword checks
  - the hierarchical-structure pass reuses that one lowercase view across all indicators
- Targeted regression:
  - `tests/scanners/test_flax_msgpack_scanner.py::test_flax_ml_structure_reuses_lowered_object_text`
- Benchmarks:
  - synthetic `8 MiB` object in `_analyze_ml_structure()`:
    - before: `0.076024s` median
    - after: `0.015901s` median
- Notes:
  - this is a scanner-local large-object cleanup distinct from the earlier JAX transform lowercase reuse in `#1169`

### 2026-05-02 - Reused Flax structure analysis

- PR:
  - `#1188`
- Change:
  - Flax scans now reuse one deep ML-structure analysis result across metadata extraction and format validation
  - direct helper calls keep their previous behavior by computing the analysis locally when no precomputed result is supplied
- Targeted regression:
  - `tests/scanners/test_flax_msgpack_scanner.py::test_flax_scan_reuses_ml_structure_analysis`
- Benchmarks:
  - synthetic `8 MiB` object across metadata extraction plus format validation:
    - before: `0.351241s` median
    - after: `0.182844s` median
- Notes:
  - this trims duplicate structural traversal in the nonstandard-checkpoint path without changing detection semantics

### 2026-05-02 - Shared secrets detector heuristics

- PR:
  - `#1189`
- Change:
  - fixed ML-context, confidence, example-secret, and binary-filter heuristics now live at module scope instead of being rebuilt for each candidate finding
  - lowercased text/context values and compiled helper regexes are reused within each scoring pass
- Benchmarks:
  - synthetic secret-heavy workload with `200` candidate findings scanned `200` times per run, same-process controlled A/B:
    - before: `2.707902s` median
    - after: `1.970997s` median
- Notes:
  - this is a detector-local CPU cleanup for hit-heavy inputs; it leaves the rule surface unchanged

### 2026-05-01 - Shared C2 payload lowercase view

- PR:
  - `#1163`
- Change:
  - C2 scanning now lowers each payload once before checking all patterns
  - repeated membership plus offset lookups were folded into one `find()` pass on the lowered bytes
- Targeted regression:
  - `tests/detectors/test_network_comm_detector.py::TestNetworkCommDetector::test_cc_pattern_scan_reuses_lowered_payload`
- Benchmarks:
  - synthetic `8 MiB` no-match payload, same-process controlled A/B:
    - repeated lowercasing path: `0.246317s` median
    - shared lowercase payload: `0.068608s` median
- Notes:
  - this is a detector-local CPU win and does not change the C2 pattern surface

### 2026-05-01 - Shared JAX context lowercase view

- PR:
  - `#1164`
- Change:
  - delegated JAX wrapper checks now lowercase decoded text once before testing all framework indicators
  - the helper preserves the existing indicator set while avoiding repeated long-text scans
- Targeted regression:
  - `tests/scanners/test_pickle_scanner.py::test_contains_any_jax_indicator_reuses_lowered_text`
- Benchmarks:
  - synthetic `8 MiB` non-JAX text, same-process controlled A/B:
    - repeated lowercasing path: `0.212387s` median
    - shared lowercase text: `0.103317s` median
- Notes:
  - this is a narrow wrapper cleanup that composes with the larger ordinary-pickle JAX delegation gate from `#1158`

### 2026-05-01 - Shared blacklist payload lowercase view

- PR:
  - `#1165`
- Change:
  - configured blacklist scans now lowercase each payload once before checking all blocked domains
  - matching semantics stay unchanged for user-supplied blacklist entries
- Targeted regression:
  - `tests/detectors/test_network_comm_detector.py::TestNetworkCommDetector::test_blacklist_scan_reuses_lowered_payload`
- Benchmarks:
  - synthetic `8 MiB` no-match payload with `12` configured domains, same-process controlled A/B:
    - repeated lowercasing path: `0.270927s` median
    - shared lowercase payload: `0.085328s` median
- Notes:
  - this is a configured-path counterpart to the default C2 detector cleanup from `#1163`

### 2026-05-01 - Early metadata URL dedupe

- PR:
  - `#1166`
- Change:
  - metadata URL scans now mark URLs as seen before parsing
  - repeated benign links are skipped just like repeated suspicious links already were
- Targeted regression:
  - `tests/scanners/test_metadata_scanner.py::TestMetadataScanner::test_repeated_benign_urls_are_parsed_once`
- Benchmarks:
  - synthetic README text with `20,000` copies of one benign URL, same-process controlled A/B:
    - late dedupe path: `0.034692s` median
    - early dedupe path: `0.005104s` median
- Notes:
  - this is a metadata-doc hot-path cleanup that preserves the suspicious URL finding surface

### 2026-05-01 - Shared call-graph module parse context

- PR:
  - `#1167`
- Change:
  - wildcard export summaries and full module analysis now reuse one cached source parse
  - the shared parse context is cleared with the existing source-sensitive call-graph caches
- Targeted regression:
  - `packages/modelaudit-picklescan/tests/test_call_graph_import_statements.py::test_wildcard_summary_and_analysis_share_module_parse`
- Benchmarks:
  - synthetic module with `200` local functions, `20` cache-cleared wildcard-summary plus full-analysis pairs:
    - duplicate parse path: `0.115265s` median
    - shared source-context path: `0.095118s` median
- Notes:
  - this narrows one remaining piece of the broader call-graph invalidation backlog without changing freshness semantics

### 2026-05-01 - Shared Keras metadata lowercase view

- PR:
  - `#1168`
- Change:
  - Keras metadata helpers now lowercase decoded text once before testing configured substrings
  - the shared matcher is reused by Keras dict-format Lambda scans, Keras ZIP Lambda scans, and TensorFlow SavedModel Keras metadata checks
- Targeted regression:
  - `tests/scanners/test_keras_utils.py::test_find_case_insensitive_substrings_reuses_lowered_text`
- Benchmarks:
  - synthetic `8 MiB` no-match decoded Lambda text, same-process controlled A/B:
    - repeated lowercasing path: `0.966723s` median
    - shared lowercase text: `0.211598s` median
  - synthetic `8 MiB` no-match direct Keras metadata text, same-process controlled A/B:
    - repeated lowercasing path: `0.580823s` median
    - shared lowercase text: `0.233578s` median
- Notes:
  - this closes one more long-text scanner pass without broadening the existing Keras detection surface

### 2026-05-01 - Shared Flax transform lowercase view

- PR:
  - `#1169`
- Change:
  - JAX transform matching now lowercases decoded value text once before checking all transform indicators
  - the transform list moved behind one helper so the one-pass behavior has focused coverage
- Targeted regression:
  - `tests/scanners/test_flax_msgpack_scanner.py::test_matching_jax_transforms_reuses_lowered_value_text`
- Benchmarks:
  - synthetic `8 MiB` no-match value text, same-process controlled A/B:
    - repeated lowercasing path: `0.386153s` median
    - shared lowercase text: `0.210867s` median
- Notes:
  - this is a smaller text-path cleanup than the Keras wins, but still removes repeated large-string scans in a scanner-specific hot loop

### 2026-05-01 - Opt-in core phase timings

- PR:
  - `#1170`
- Change:
  - `scan_model_directory_or_file(..., profile_timings=True)` now emits coarse per-phase timings without changing the default result shape
  - the first pass covers scanner selection, directory counting/discovery, top-level hashing, scan dispatch, result merge, license metadata, consolidation, commercial-use warnings, and aggregate hashing
- Targeted regressions:
  - `tests/test_core.py::test_scan_model_omits_phase_timings_by_default`
  - `tests/test_core.py::test_scan_model_emits_opt_in_phase_timings`
- Benchmarks:
  - synthetic directory with `25` tiny pickles, same-process controlled A/B:
    - default result path: `0.201428s` median
    - `profile_timings=True`: `0.189312s` median
- Notes:
  - the benchmark is intentionally an overhead smoke test; the value of this PR is better observability for the larger hashing and orchestration backlog

## Measured Non-Wins

### 2026-05-02 - Metadata URL regex precompile

- Hypothesis:
  - precompile the metadata URL extractor instead of relying on `re.findall()` with a literal regex at each call site
- Result:
  - synthetic README text with no URLs:
    - literal regex: `0.065490s`
    - precompiled regex: `0.040135s`
  - synthetic README text with many URLs:
    - literal regex: `0.666813s`
    - precompiled regex: `0.704760s`
- Decision:
  - do not land the change; the benefit only appeared on the no-match path and reversed on the URL-heavy case that matters more for this scanner

### 2026-05-02 - Metadata secret-pattern precompile

- Hypothesis:
  - precompile the metadata secret-pattern bank instead of rebuilding the literal regex list inside each document scan
- Result:
  - controlled no-match README workload after testing the real helper shape:
    - literal regex path: `1.626721s` median
    - precompiled pattern bank: `1.936317s` median
- Decision:
  - do not land the change; once Python's regex cache and the actual helper structure were included, the precompiled path regressed

### 2026-05-02 - Metadata `can_handle()` README-name set

- Hypothesis:
  - replace the per-call README-name list with a shared `frozenset`
- Result:
  - synthetic mixed path list:
    - current list path: `0.205046s` median
    - shared set path: `0.220426s` median
- Decision:
  - do not land the change; the current tiny list is already cheap enough that the shared-set form was slower in the measured route

### 2026-05-02 - Generic ZIP config-name lowercase reuse

- Hypothesis:
  - lowercase archive entry names once while extracting generic ZIP metadata instead of repeating `.lower()` inside each config-name probe
- Result:
  - synthetic `200,000`-entry archive-name list:
    - current path: `0.135729s`
    - shared lowercase probe: `0.133178s`
- Decision:
  - do not land the change; the improvement was too small to justify another dedicated optimization branch

### 2026-05-02 - Integrity hash chunk-size increase

- Hypothesis:
  - replace the `8 KiB` reads in `BaseScanner.calculate_file_hashes()` with larger chunks to reduce syscall overhead
- Result:
  - synthetic `128 MiB` triple-hash loop:
    - `8 KiB`: `0.400828s` median
    - `2 MiB`: `0.390379s` median
  - steadier synthetic `256 MiB` rerun:
    - `8 KiB`: `0.835377s` median
    - `2 MiB`: `0.926068s` median
- Decision:
  - do not land the change; the apparent win did not hold up under the steadier rerun, and hash computation itself dominates this path more than read-buffer overhead

### 2026-05-01 - Streaming SHA256 reuse from scanner metadata

- Hypothesis:
  - reuse scanner-emitted SHA256 values in streaming mode to skip the extra pre-aggregation SHA256 pass
- Result:
  - direct SHA256 cost on a synthetic `16 MiB` pickle was only `0.018932s` median
  - controlled same-process A/B on the full streaming scan was within noise:
    - forced fallback hash pass: `1.189368s` median
    - scanner-metadata reuse: `1.224190s` median
- Decision:
  - do not land the extra branch yet; the regular large-file hashing work needs a broader design rather than this tiny streaming-only slice

### 2026-05-01 - PyTorch ZIP metadata lowercase reuse

- Hypothesis:
  - lowercase each archive member name once while estimating parameter-like entries
- Result:
  - synthetic `50,000`-entry file list:
    - repeated per-term lowercasing: `0.011629s` median
    - one lowercase per name: `0.010124s` median
- Decision:
  - the measured gain is too small and too localized to justify a dedicated PR right now

### 2026-05-01 - Metadata secret-match lowercase reuse

- Hypothesis:
  - lowercase each matched secret string and description once before placeholder / known-format checks
- Result:
  - exact inner-loop benchmark across `20,000` synthetic matches:
    - repeated lowercasing: `0.010581s` median
    - shared lowercase values: `0.009800s` median
- Decision:
  - the exact changed work is too small to justify a PR; keep focus on larger scanner paths

### 2026-05-01 - Explicit ML network regex precompilation

- Hypothesis:
  - precompile the four explicit-network regexes used for ML-model false-positive filtering
- Result:
  - `20,000` tiny-payload calls:
    - current path: `0.095730s` median
    - precompiled probe: `0.082867s` median
- Decision:
  - measurable but still too small for a dedicated PR compared with larger detector and call-graph work

### 2026-05-01 - Jinja malformed-JSON fallback text reuse

- Hypothesis:
  - reuse the decoded JSON text after parse failure instead of falling back to a second file scan
- Result:
  - synthetic `64 MiB` malformed tokenizer config:
    - current bounded file-window fallback: `0.122820s` median
    - reused decoded-text fallback: `0.130862s` median
- Decision:
  - keep the existing file-window path; it is faster than scanning the whole decoded string

### 2026-05-01 - Weight-key lowercase reuse

- Hypothesis:
  - reuse each state-dict key's lowercase view across multiple weight-name predicates
- Result:
  - synthetic `100,000`-key loop:
    - repeated inline lowercase checks: `0.097083s` median
    - shared lowercase variable: `0.124303s` median
- Decision:
  - do not optimize this path; the extra local bookkeeping outweighed the saved lowercase calls in the measured loop

### 2026-05-01 - Metadata secret-pattern precompilation

- Hypothesis:
  - precompile the static metadata secret regex set once instead of passing string patterns to `re.finditer()` on each scan
- Result:
  - synthetic `8 MiB` no-match documentation payload after the regex cache was warm:
    - current path: `0.585789s` median
    - explicit precompiled path: `0.802890s` median
- Decision:
  - do not land this change; Python's regex cache already covers the steady-state case and the explicit precompiled path was not a repeatable win

### 2026-05-02 - JAX indicator lowercasing split

- Hypothesis:
  - avoid a second lowercase pass inside `_contains_jax_indicator()` when routing helpers already pass lowered text
- Result:
  - synthetic `64 MiB` no-match streamed checkpoint search:
    - current path: `0.147748s` median
    - helper split over already-lowered text: `0.148195s` median
- Decision:
  - do not land the change; the realistic streamed path did not improve despite the apparent duplicate work in the helper boundary

### 2026-05-02 - Explicit ML network regex precompilation

- Hypothesis:
  - precompile the four explicit-network regexes used by `NetworkCommDetector` for ML-model payloads
- Result:
  - `20,000` tiny no-match payload calls:
    - current path: `0.091411s` median
    - shared compiled regexes: `0.087378s` median
- Decision:
  - do not land the change; the measured win is too small for a dedicated PR

### 2026-05-02 - JIT ONNX Python-op regex precompilation

- Hypothesis:
  - hoist the static ONNX Python-operator regex out of `scan_onnx()`
- Result:
  - `20,000` tiny no-match payload calls:
    - current path: `0.046086s` median
    - shared compiled regex path: `0.042912s` median
- Decision:
  - do not land the change; the exact helper win is measurable but too small to prioritize

### 2026-05-02 - ZIP metadata one-pass rewrite

- Hypothesis:
  - replace repeated model/config archive-member scans with one combined member-summary loop
- Result:
  - synthetic `200,000`-member archive name list:
    - current short-circuiting passes: `0.184341s` median
    - one-pass rewrite: `0.256282s` median
- Decision:
  - keep the current passes; the short-circuiting `any()` checks are faster than the one-pass bookkeeping rewrite

### 2026-05-02 - Manifest `can_handle()` constant hoist

- Hypothesis:
  - move `ManifestScanner.can_handle()`'s local filename lists to module constants
- Result:
  - mixed `50,000`-path loop over existing config-like files:
    - current path: `0.112712s` median
    - hoisted-constant probe: `0.111887s` median
- Decision:
  - do not land the change; the exact path was effectively flat after keeping `os.path.isfile()` in the benchmark

### 2026-05-02 - Network-library byte-pattern prebuild

- Hypothesis:
  - prebuild the five import/connect/request byte patterns for each network library
- Result:
  - `2,000` no-match `_scan_network_libraries()` calls:
    - current path: `0.072140s` median
    - prebuilt-pattern probe: `0.075990s` median
- Decision:
  - do not land the change; the proposed setup cleanup was slightly slower in the measured path

### 2026-05-02 - Generic-domain TLD set hoist

- Hypothesis:
  - move the generic-domain valid-TLD and suspicious-TLD lists out of the per-match loop
- Result:
  - controlled same-process `20,000`-domain helper loop:
    - current path: `0.086000s` median
    - shared-set probe: `0.082068s` median
- Decision:
  - do not land the change; the real helper-level win was too small once the rest of the domain-finding work stayed identical

### 2026-05-02 - Keras `get_file` lowercase reuse

- Hypothesis:
  - reuse one stripped lowercase string while checking the `get_file` callable variants
- Result:
  - `200,000` direct callable-string checks:
    - current path: `0.134620s` median
    - shared lowercase path: `0.141144s` median
- Decision:
  - do not land the change; the supposedly cleaner form was slightly slower in the measured loop

## Remaining Recommended Implementation Order

1. Unify or reuse hashing passes.
   - First cache-local slice landed in `#1171`; broader product-level hash reuse still needs hash-output requirements settled.
2. Replace report-scoped call-graph sharing with source-aware invalidation where safe.
   - Higher upside remains, but freshness semantics still need careful proof.
3. Tighten license header reads for non-license large text-like files only if detection semantics stay explicit.
   - Binary probes are already bounded; the remaining long-text case is a deliberate behavior tradeoff.
4. Revisit duplicate-aware reuse and the remaining pickle wrapper passes.
   - Worth doing, but both need stronger path-sensitivity analysis first.

## Next Measurement Pass

- Add benchmark files to the reduced-Python allowlist or run them in a full lane so their JSON outputs are actually produced.
- Add custom one-shot scripts for:
  - cache miss vs hit
  - many tiny files
  - duplicate-heavy directories
  - large text-like vs binary files
  - call-graph-heavy pickle fixtures
- Add phase-level instrumentation experiments around the core scan loop.
- Add dedicated benchmarks for:
  - scanner-selection normalization on thousands of files
  - nearby-license discovery on many siblings
  - HuggingFace cache probing under non-HF roots
  - large archive members and large SavedModel / ONNX / TFLite inputs

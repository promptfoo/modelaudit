# Performance Audit

Status: active maintainer guide

This file is the operating guide for ModelAudit performance work. Keep it short,
current, and decision-oriented. Historical detail belongs in PRs, benchmark
artifacts, and profiler output rather than in a growing diary here.

## What We Optimize For

ModelAudit is used in a few meaningfully different ways. Benchmarks should map
to those people and their real waits, not just to convenient helper functions.

| Persona           | Real question                                          | Canonical workload                |
| ----------------- | ------------------------------------------------------ | --------------------------------- |
| ML engineer       | "Can I safely load this checkpoint?"                   | single checkpoint preflight       |
| Release engineer  | "Is this model repo safe to ship?"                     | mixed model repository            |
| Platform engineer | "How expensive is scanning stored artifacts at scale?" | duplicate-heavy registry snapshot |
| Security analyst  | "How quickly can I triage suspicious uploads?"         | suspicious pickle intake          |
| CI operator       | "How fast is a repeat scan after cache warm-up?"       | warm-cache repository re-scan     |
| Service operator  | "What happens on streamed uploads?"                    | chunked upload stream             |

## Benchmark Design Rules

- Prefer end-to-end scan workloads over helper microbenchmarks for top-line
  release claims.
- Keep benchmark corpora deterministic, generated under `tmp_path`, and small
  enough for CI while still resembling actual user inputs.
- Tag every benchmark with `persona`, `workload`, `path`, `bytes`, and `files`
  so the report explains what changed, not just which test name moved.
- Keep cache-disabled workloads and warm-cache workloads separate. Do not mix
  first-run and repeat-run timings into one number.
- Preserve security meaning in the assertions. A benchmark for malicious input
  must still prove that the malicious path is detected.
- Use lower-level benchmarks only when they protect an important scanner surface
  that would be invisible in a top-level workload.

## Checked-In Benchmark Suite

The PR benchmark lane lives in:

- `tests/benchmarks/test_scan_benchmarks.py`
- `tests/benchmarks/test_picklescan_benchmarks.py`
- `.github/workflows/perf.yml`
- `scripts/benchmark_report.py`

### End-To-End Scanner Workloads

| Workload                      | Persona             | Corpus shape                                                                      | Why it matters                   |
| ----------------------------- | ------------------- | --------------------------------------------------------------------------------- | -------------------------------- |
| `single-checkpoint-preflight` | `ml_engineer`       | one realistic pickle checkpoint                                                   | common local pre-load scan       |
| `mixed-model-repository`      | `release_engineer`  | pickle, PyTorch ZIP, manifest, license, tokenizer, nested adapter, metadata files | repo-level release scan          |
| `duplicate-heavy-registry`    | `platform_engineer` | repeated model versions plus manifests and docs                                   | duplicate-heavy stored artifacts |
| `suspicious-pickle-intake`    | `security_analyst`  | known-good plus direct and encoded malicious pickles                              | security triage throughput       |
| `warm-cache-rescan`           | `ci_operator`       | warmed repeat scan of the mixed repo                                              | repeated CI / local verification |

### Pickle Engine Workloads

| Workload                     | Persona            | Why it stays                                       |
| ---------------------------- | ------------------ | -------------------------------------------------- |
| `clean-training-checkpoint`  | `ml_engineer`      | common benign pickle path                          |
| `direct-malicious-upload`    | `security_analyst` | fast-path dangerous global detection               |
| `nested-payload-review`      | `security_analyst` | encoded nested payloads remain a core bypass class |
| `padded-multi-stream-upload` | `security_analyst` | concatenated stream handling is security-sensitive |
| `chunked-upload-stream`      | `service_operator` | streamed scans exercise a different ingestion path |

These are intentionally fewer and more meaningful than a long list of
micro-probes. Add a new checked-in benchmark only when it represents a stable,
user-relevant workload or guards a security-critical hot path.

## How To Measure

### PR Comparison Lane

The GitHub Actions performance workflow runs the benchmark suite on the PR base
and head, posts a sticky summary comment, and uploads JSON plus Markdown
artifacts. It is advisory: it reports regressions without blocking the PR.

### Local Benchmark Run

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 uv run --with pytest-benchmark pytest \
  tests/benchmarks/test_scan_benchmarks.py \
  tests/benchmarks/test_picklescan_benchmarks.py \
  --benchmark-json=/tmp/modelaudit-benchmark.json \
  -q
```

```bash
uv run python scripts/benchmark_report.py \
  --current /tmp/modelaudit-benchmark.json
```

### Local Profiling Run

Use `scripts/profile_scan.py` when you need to explain a result rather than just
measure it.

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 uv run python scripts/profile_scan.py \
  tests/assets \
  --profile-out /tmp/modelaudit-assets.pstats \
  --json-out /tmp/modelaudit-assets.json
```

Useful larger ad hoc profiles:

- many tiny files
- duplicate-heavy directories
- large single-file models
- cache miss versus warm-cache re-scan
- pickle-heavy suspicious intake

Keep those as maintainer workflows unless they become stable enough and cheap
enough to graduate into CI.

## Current Hotspots

These are the main measured areas that still deserve attention:

1. Hash reuse across core, scanners, and cache storage for large files.
2. Source-aware pickle call-graph cache invalidation that preserves freshness
   without throwing away reusable work.
3. Path-sensitive duplicate handling, especially for directories with repeated
   identical artifacts.
4. Remaining wrapper passes around ordinary pickle scans where we can prove a
   cheap gate does not weaken detection.

## Recent Wins Worth Preserving

| Area                                   | Why it mattered                                               |
| -------------------------------------- | ------------------------------------------------------------- |
| scanner-selection reuse                | removed repeated registry and alias work in large directories |
| Hugging Face bookkeeping short-circuit | avoided expensive non-HF path checks on ordinary folders      |
| nearby-license reuse                   | cut repeated sibling-directory scans                          |
| report-scoped call-graph cache sharing | reduced repeated AST work in pickle-heavy scans               |
| bounded ordinary license-header reads  | removed long scans over huge non-license text files           |
| cache-key hash reuse                   | avoided one duplicate full-file hash on cache miss            |
| ONNX raw-buffer reuse                  | avoided rereading successful ONNX scans                       |
| native-only pickle validation          | kept a validation path from doing full enrichment work        |

## Decision Checklist

Before landing a performance change, record:

1. Which persona and workload become faster.
2. The baseline and new benchmark result.
3. The code path that changed.
4. The failure mode if the optimization is wrong.
5. The malicious fixture that still passes.
6. The benign near-match that still stays clean.

## Backlog

Priority 1:

- unify or reuse remaining hashing passes
- replace report-scoped call-graph sharing with safe source-aware invalidation
- measure duplicate-aware reuse only for scanners proven path-independent

Priority 2:

- add larger archive-member workloads when archive traversal becomes a target
- record peak RSS for large-file scans, not only wall time
- add cold-start measurements for scanner families with expensive imports
- decide whether any more helper-level benchmarks justify their maintenance cost

## What Not To Do

- Do not make release claims from a single local machine without a comparable
  baseline from the same environment.
- Do not treat synthetic zero-byte directories as the main story once they have
  served their diagnostic purpose.
- Do not add microbenchmarks merely because a helper is easy to time.
- Do not optimize away a security check unless a malicious positive and benign
  near-match prove the replacement preserves behavior.

# PickleScan Rust Large-Corpus QA Notes - 2026-04-11

These notes track the implementation and execution of
`docs/maintainers/picklescan-rust-large-corpus-qa-plan.md` for the Rust-backed
`modelaudit-picklescan` rewrite. Large artifacts and raw outputs are stored
outside the repository under `/tmp/modelaudit-large-pickle-corpus`.

## Session Setup

- Enabled Codex loop mode with the nudge:
  `Continue implementing the PickleScan Rust large-corpus QA plan. Keep detailed notes, run the next safest verification step, and continue until the plan is implemented and QA status is clear.`
- Working branch: `mdangelo/codex/rust-picklescan-rewrite`.
- Scratch space check: `/tmp` has about 271 GiB available.
- `huggingface_hub` is available in the repository virtualenv.
- Hugging Face online metadata needed `ALL_PROXY`, `all_proxy`, `FTP_PROXY`,
  and `ftp_proxy` cleared so `huggingface_hub` used the HTTP proxy instead of
  requiring the missing `socksio` package.

## Code Changes Implemented

- Fixed root ModelAudit Rust-engine parity in
  `modelaudit/scanners/picklescan_adapter.py` and
  `modelaudit/scanners/pickle_scanner.py`:
  - Rust `ParseError` unknown-opcode parse-incomplete notices are now handled
    like Python benign-tail parse limitations when appropriate.
  - Root fallback scanner limitation issues are skipped when the standalone
    result already captured the expected scanner limitation.
- Added `scripts/large_pickle_corpus_qa.py` with:
  - built-in 25-entry primary corpus manifest;
  - five-entry replacement queue;
  - `list-corpus`, `sync-tools`, `preflight`, `finalize-lock`, `download`,
    `classify`, `generate-synthetic`, `scan`, and `report` commands;
  - deterministic synthetic variants V01-V15;
  - Rust-only standalone scans;
  - root ModelAudit default and standalone-primary scan modes;
  - third-party scanner differentials for Fickling, ModelScan, and PickleScan;
  - parity drift, coverage matrix, benchmark JSON/CSV, and Markdown reports.
- Added selected-corpus support:
  - `finalize-lock` selects preflight-ok primary entries and fills unavailable
    primary slots from the replacement queue.
  - `download --direct-only` streams pinned Hugging Face `resolve` URLs from a
    completed lockfile, which avoids repeated metadata `HEAD` failures.
  - `download --ids` permits resuming or probing selected artifacts without a
    single blocked artifact stopping the rest of the corpus work.
  - `download --etag-timeout-s` controls Hugging Face metadata timeout when
    using normal `hf_hub_download`.
- Added `tests/scripts/test_large_pickle_corpus_qa.py` and registered it in
  `tests/conftest.py`.
- Fixed third-party command execution to run source-pinned tools from `~/code`
  via isolated editable `uv run` environments, avoiding accidental use of
  globally installed console scripts.
- Tightened ModelScan verdict normalization to use JSON issue counts instead
  of matching strings like `PyTorchUnsafeOpScan`.
- Tightened upstream PickleScan verdict normalization to parse numeric
  `Infected files` and `Dangerous globals` summary counts instead of matching
  the word `infected`.
- Implemented standalone PyTorch ZIP checkpoint scanning in
  `modelaudit-picklescan`:
  - `scan_file()` now detects PyTorch ZIP-like `.pt`, `.pth`, `.ckpt`, `.pkl`,
    and `.bin` files.
  - The package scans discovered `data.pkl`, `*/data.pkl`, `.pkl`, and
    `.pickle` members through the selected Python, Rust, or compare engine.
  - Container reports include `container_type=pytorch_zip`, discovered
    `pickle_files`, per-member summaries, archive size, and aggregate coverage.
  - Generic non-PyTorch ZIPs remain outside the standalone package boundary.
- Updated the large-corpus QA harness so ZIP-backed PyTorch artifacts exercise
  the direct standalone `scan_file()` path rather than extracting `data.pkl`
  first.
- Follow-up parity probing found and fixed Rust suspicious-string matcher drift:
  numeric/embedded dunder strings like `__1__` and `a__b__c` no longer
  overmatch the Python magic-method regex, and whitespace-tolerant
  `getattr (x, "system")` style patterns now match the Python heuristics.
- Additional protocol-0 text probing found and fixed Rust argument decoding drift:
  `UNICODE` opcodes now use Python-compatible raw-unicode-escape decoding, and
  `STRING` opcodes now decode common Python string escapes such as `\xNN` and
  octal escapes before suspicious-string analysis.
- Tightened Rust parse-incomplete diagnostics for fixed-width short reads and
  unknown opcodes so the generated malformed-tail corpus now matches Python
  stable reports exactly instead of only matching status, verdict, and rules.
- Follow-up prefix-truncation fuzzing found and fixed a Rust fail-open bug
  where streams that reached EOF before `STOP` could be marked `complete` and
  `clean`; these now match Python `pickletools` as `parse_incomplete`.
- Aligned Rust malformed line-argument and length-prefixed argument diagnostics
  with Python for protocol-0 line readers, `BINSTRING`, `BINUNICODE`,
  `BINBYTES`, `BYTEARRAY8`, `LONG1`, `LONG4`, and `BINFLOAT` truncations.
- Added guardrail tests that compare the Rust parser opcode declarations against
  Python `pickletools.opcodes` and compare duplicated Rust dangerous-global
  policy tables against the Python policy module.
- Added an exact Python-vs-Rust stable-report regression over 459 deterministic
  prefix truncations spanning benign, malicious, nested, GLOBAL, STACK_GLOBAL,
  length-prefixed, and FRAME-bearing pickle streams.
- Increased the Rust stream read chunk from 32 bytes to 1 MiB. The bounded-read
  stream regression test now monkeypatches the chunk size down to 32 bytes so it
  still verifies incremental reads without forcing production scans through tiny
  read calls.
- Profiled the Rust string-literal hot path and added fast paths for large
  benign literals:
  - full-string clones are avoided for untruncated suspicious-string and
    encoded-nested-pickle scans;
  - magic-method and `getattr(...)` scans now use cheap substring guards before
    building char vectors;
  - base64 and hex encoded-pickle probes now require a pickle-looking decoded
    prefix before validating the full candidate;
  - encoded-literal probes use ASCII prefix/suffix byte slices instead of
    counting every character before bounded scans.
- Fixed malformed `STACK_GLOBAL` diagnostic drift by preserving primitive stack
  previews in Rust. Integer malformed operands now match Python details such as
  `int:1` and `int:2`.

## Third-Party Tool Sync

Command:

```bash
.venv/bin/python scripts/large_pickle_corpus_qa.py sync-tools --out /tmp/modelaudit-large-pickle-corpus/tool-sync.json
```

Recorded clean source checkouts:

| Tool       | Branch   | Commit                                     | Describe              |
| ---------- | -------- | ------------------------------------------ | --------------------- |
| Fickling   | `master` | `ee2a6e3465913e5f8771ba9173e472bd502d78fd` | `v0.1.10-13-gee2a6e3` |
| ModelScan  | `main`   | `61fcec9c2a37c24c1fb12d84ede30fe248a364bd` | `v0.8.8`              |
| PickleScan | `main`   | `bf26452ae2e3204429762c2bb1aa9eacd40436bb` | `v1.0.4`              |

`uv run --project` created untracked `uv.lock` files in two third-party
checkouts during probing. Those generated locks were removed, and the harness
now uses isolated editable execution so the source checkouts remain clean.

## Existing Rust Regression Test Results

Rust-only package tests:

```bash
.venv/bin/pytest packages/modelaudit-picklescan/tests -q
```

Result: `124 passed`.

Root pickle scanner and comparison tests:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/pytest tests/scanners/test_pickle_scanner.py \
  tests/scripts/test_compare_pickle_scanners.py -q
```

Result after parity fixes: `398 passed, 14 subtests passed`.

Harness tests:

```bash
.venv/bin/pytest tests/scripts/test_large_pickle_corpus_qa.py -q
```

Current result after standalone ZIP support: `12 passed`.

## Synthetic Smoke QA

Offline smoke lock:

```bash
.venv/bin/python scripts/large_pickle_corpus_qa.py preflight --offline \
  --tier smoke --out /tmp/modelaudit-large-pickle-corpus/smoke-lock.json
```

Synthetic ModelAudit scan:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/smoke-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-3 \
  --engines rust \
  --root-modes default,standalone-primary \
  --skip-tool-pull
```

Artifacts:

- `/tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-3/parity-drift.json`
- `/tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-3/coverage-matrix.json`
- `/tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-3/benchmark-results.json`
- `/tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-3/qa-report.md`

Results:

- Parity drift count: `0`.
- Required coverage missing: none.
- Synthetic coverage included:
  - `DANGEROUS_CALL`: V01, V02, V06, V07, V08, V12 member.
  - `DANGEROUS_GLOBAL`: V03, V14.
  - `EXTENSION_REF`: V05.
  - `MALFORMED_STACK_GLOBAL`: V04.
  - `POST_BUDGET_GLOBAL`: V10.
  - `S213`: V06, V14.
  - `S601`: V07.
  - `S602`: V08.
  - `SUSPICIOUS_STRING`: V08, V09.

## Third-Party Synthetic Smoke QA

Command after isolated-tool and ModelScan normalization fixes:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/smoke-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/smoke-third-party-normalized \
  --engines rust \
  --root-modes default \
  --third-party-tools fickling,modelscan,picklescan \
  --skip-tool-pull \
  --third-party-timeout-s 60
```

Results:

- ModelAudit parity drift count: `0`.
- Required coverage missing: none.
- Third-party rows: `45`.
- Third-party verdicts: `27 malicious`, `14 clean`, `4 error`.
- Third-party non-zero/error observations:
  - Fickling returned error for V12 PyTorch ZIP member container.
  - Fickling returned error for V13 malformed 7z-like container.
  - ModelScan returned unsupported/error for V13 malformed 7z-like container.
  - PickleScan returned error for V13 because its current source checkout does
    not install the optional `py7zr` dependency in the isolated run.

These are cross-tool limitations, not ModelAudit regressions. ModelAudit Rust
and Python both covered the synthetic required signals.

## Online Corpus Preflight

Initial smoke preflight:

```bash
env ALL_PROXY= all_proxy= FTP_PROXY= ftp_proxy= \
  .venv/bin/python scripts/large_pickle_corpus_qa.py preflight \
  --tier smoke \
  --out /tmp/modelaudit-large-pickle-corpus/online-smoke-lock.json
```

Result: B01 and P01 resolved; B05 is currently unavailable or gated.

Full primary preflight:

```bash
env ALL_PROXY= all_proxy= FTP_PROXY= ftp_proxy= \
  .venv/bin/python scripts/large_pickle_corpus_qa.py preflight \
  --tier full \
  --out /tmp/modelaudit-large-pickle-corpus/online-full-lock.json
```

Result: 22 primary entries resolved; 3 primary entries failed:

- B03 `glazzova/body_type_resnet_v1/pytorch_model.bin`
- B04 `glazzova/body_type_resnet_v1/optimizer.pt`
- B05 `joaogante/test_text_generation_pipeline_a/pytorch_model.bin`

Full preflight with replacement queue:

```bash
env ALL_PROXY= all_proxy= FTP_PROXY= ftp_proxy= \
  .venv/bin/python scripts/large_pickle_corpus_qa.py preflight \
  --tier full \
  --include-replacements \
  --out /tmp/modelaudit-large-pickle-corpus/online-full-with-replacements-lock.json
```

Result: 26 entries resolved. R04 failed because the file no longer exists.

Selected final 25-entry lock:

```bash
.venv/bin/python scripts/large_pickle_corpus_qa.py finalize-lock \
  --lock /tmp/modelaudit-large-pickle-corpus/online-full-with-replacements-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json \
  --target-count 25
```

Selection:

- Unavailable primary IDs: B03, B04, B05.
- Selected replacement IDs: R01, R02, R03.
- Final selected corpus: 18 benign/stress and 7 positive entries.
- Approximate selected remote size: 61.99 GiB.
- `classify` now preserves the `finalize-lock` selection metadata when
  rewriting the lock.

## Full Corpus Download

Started:

```bash
env ALL_PROXY= all_proxy= FTP_PROXY= ftp_proxy= \
  .venv/bin/python scripts/large_pickle_corpus_qa.py download \
  --lock /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json \
  --budget-gb 70
```

Status at note creation:

- B01, B02, and B06 are present.
- Scratch raw directory size is about 415 MiB.
- B07 repeatedly blocked in this environment:
  - `hf_hub_download` timed out during repeated metadata `HEAD` requests for
    `dima806/closed_eyes_image_detection/checkpoint-2148/optimizer.pt`.
  - `download --direct-only` established an HTTP-proxy connection but wrote no
    `.part` file or response bytes after several minutes.
- A follow-up `download --ids B08 --direct-only` probe also established a
  proxy connection but wrote no response bytes, so the direct streaming blocker
  is not limited to B07.
- The full 25-entry, 61.99 GiB download is therefore not complete in this
  environment. The selected lock remains valid, and the blocker is network or
  proxy behavior rather than a scanner failure.

## Real Downloaded Subset QA

Classified the selected lock after partial download:

```bash
.venv/bin/python scripts/large_pickle_corpus_qa.py classify \
  --lock /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json
```

Downloaded real artifacts:

| ID  | Kind                          |              Size |
| --- | ----------------------------- | ----------------: |
| B01 | ZIP-backed PyTorch checkpoint |  44,786,029 bytes |
| B02 | ZIP-backed PyTorch checkpoint |  46,837,369 bytes |
| B06 | ZIP-backed PyTorch checkpoint | 343,268,717 bytes |

Normalized real-subset scan:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/real-subset-b01-b02-b06-normalized \
  --ids B01 B02 B06 \
  --engines rust \
  --root-modes default,standalone-primary \
  --third-party-tools fickling,modelscan,picklescan \
  --skip-tool-pull \
  --third-party-timeout-s 300
```

Results:

- ModelAudit parity drift count: `0`.
- Required synthetic coverage missing: none.
- B01, B02, and B06 were clean across standalone `modelaudit-picklescan`
  Rust and root ModelAudit default/standalone-primary modes.
- ModelScan and upstream PickleScan reported B01, B02, and B06 clean.
- Fickling returned `No pickle files detected` for those ZIP containers.
- Normalized third-party verdicts across real subset plus synthetic suite:
  `27 clean`, `20 malicious`, `7 error`.
- Third-party error observations were Fickling ZIP/container limitations and
  V13 malformed 7z-like container handling.
- Benchmark summary for the real subset plus synthetic suite:
  - `modelaudit-picklescan:rust`: mean `0.000756s`, total `0.0136s`.
  - `modelaudit-root:default:rust`: mean `0.0662s`, total `1.191s`.

After implementing standalone PyTorch ZIP support, reran:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/real-subset-b01-b02-b06-standalone-zip \
  --ids B01 B02 B06 \
  --engines rust \
  --root-modes default,standalone-primary \
  --skip-tool-pull
```

Results:

- Parity drift count: `0`.
- Required synthetic coverage missing: none.
- Standalone package rows for B01, B02, B06, and V12 now report
  `metadata.container_type=pytorch_zip`.
- B01/B02/B06 remain clean under standalone Rust and root Rust-primary modes.
- V12 malicious PyTorch ZIP synthetic is detected directly by standalone Rust.

## Open QA Work

- Complete the 25-entry download from a network path that can stream B07 and
  the remaining large files.
- Run full selected-corpus scan with standalone Rust, root ModelAudit, and
  third-party tools once downloads are available.
- Review and triage parity drift, third-party disagreement, scanner errors,
  resource use, and benchmark summary.
- Run profiler-level memory/RSS measurements on the full corpus once the
  artifacts are available.

## Synthetic Performance Follow-Up - 2026-04-12

Commands:

```bash
uv run --with pytest-benchmark pytest \
  tests/benchmarks/test_picklescan_benchmarks.py \
  --benchmark-json=/tmp/modelaudit-picklescan-benchmark-rust-after-probe-fastpath.json -q
```

Results after the string fast path:

- `long_benign_string`: Rust mean `0.080354s` versus prior Rust `0.539798s`
  and Python `0.099273s` (`6.72x` faster than prior Rust, `1.24x` faster than
  Python on this fixture).
- `safe_large`: Rust mean `0.013104s` versus prior Rust `0.028466s` and Python
  `0.036269s` (`2.17x` faster than prior Rust, `2.77x` faster than Python).
- `hidden_suspicious_string_budget`: Rust mean `0.000150s` versus prior Rust
  `0.000589s` and Python `0.000138s`; Rust improved `3.92x` and is now within
  about `8%` of Python on this small budgeted string fixture.

The reusable parity corpus now includes a 1 MiB base64-like benign string so
the optimized path remains locked to exact historical-parity report behavior.

## Synthetic Smoke Rerun - 2026-04-12

Command:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/smoke-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-iteration12 \
  --engines rust \
  --root-modes default,standalone-primary \
  --skip-tool-pull
.venv/bin/python scripts/large_pickle_corpus_qa.py report \
  --run /tmp/modelaudit-large-pickle-corpus/runs/smoke-synthetic-iteration12
```

Results:

- ModelAudit scan rows: `114`.
- Parity drift count: `0`.
- Required coverage missing: none.
- Standalone package benchmark mean: Rust `0.000576s`.

## Real Downloaded Subset Rerun - 2026-04-12

Command:

```bash
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/selected-25-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/real-subset-b01-b02-b06-iteration13 \
  --ids B01 B02 B06 \
  --engines rust \
  --root-modes default,standalone-primary \
  --skip-tool-pull
.venv/bin/python scripts/large_pickle_corpus_qa.py report \
  --run /tmp/modelaudit-large-pickle-corpus/runs/real-subset-b01-b02-b06-iteration13
```

Results:

- ModelAudit scan rows: `126`.
- Parity drift count: `0`.
- Required coverage missing: none.
- B01, B02, and B06 remained clean across standalone Rust and root
  default/standalone-primary modes.
- Standalone package benchmark means:
  - Python: `0.001525s`.
  - Rust: `0.001099s`.
  - Compare: `0.002089s`.

## Release-Mode Standalone Benchmark - 2026-04-12

Command:

```bash
uv run --with maturin maturin develop --release \
  --manifest-path packages/modelaudit-picklescan/Cargo.toml
uv run --with pytest-benchmark pytest \
  tests/benchmarks/test_picklescan_benchmarks.py \
  --benchmark-json=/tmp/modelaudit-picklescan-benchmark-rust-release.json -q
```

Results:

- Rust parity tests after the release build: `7 passed`.
- Benchmark suite: `12 passed`.
- `long_benign_string`: release Rust mean `0.010107s` versus Python
  `0.099273s` (`9.82x` faster).
- `safe_large`: release Rust mean `0.002908s` versus Python `0.036269s`
  (`12.47x` faster).
- `chunked_stream`: release Rust mean `0.003569s` versus Python `0.040896s`
  (`11.46x` faster).
- `hidden_suspicious_string_budget`: release Rust mean `0.000038s` versus
  Python `0.000138s` (`3.66x` faster).

## Iteration 16 Parser Module Refactor

The Rust opcode decoder was moved from `rust/src/lib.rs` into
`rust/src/opcode.rs` so parser behavior can be audited independently from scan
state, policy matching, nested-pickle detection, and PyO3 report assembly.
`rust/src/lib.rs` dropped from 3,301 lines to 2,569 lines after this split.

Validation after rebuilding the release extension:

- `cargo fmt --check --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  passed.
- `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  passed.
- `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml
--all-targets -- -D warnings`: passed.
- `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  `5 passed`.
- `uv run --with maturin maturin develop --release --manifest-path
packages/modelaudit-picklescan/Cargo.toml`: passed.
- Rust regression tests:
  `PROMPTFOO_DISABLE_TELEMETRY=1
.venv/bin/pytest packages/modelaudit-picklescan/tests/test_rust_engine.py -q`
  reported `7 passed`.
- Package tests:
  `PROMPTFOO_DISABLE_TELEMETRY=1 .venv/bin/pytest packages/modelaudit-picklescan/tests -q`
  reported `133 passed`.
- Root pickle scanner/adapter/script lane:
  `PROMPTFOO_DISABLE_TELEMETRY=1
.venv/bin/pytest tests/scanners/test_pickle_scanner.py
tests/scripts/test_compare_pickle_scanners.py
tests/scanners/test_picklescan_adapter.py -q` reported
  `423 passed, 14 subtests passed`.

Follow-up parser API cleanup replaced free opcode-argument helper functions with
crate-local `ArgValue` methods. Validation after rebuilding the release
extension: Rust format/check/clippy/test passed, Rust regression tests reported
`7 passed`, and package tests reported `133 passed`.

## Iteration 18 Benchmark And Third-Party Differential Refresh

Tool sync was refreshed through the QA harness:

- Fickling: `ee2a6e3465913e5f8771ba9173e472bd502d78fd`
  (`v0.1.10-13-gee2a6e3`), clean worktree.
- ModelScan: `61fcec9c2a37c24c1fb12d84ede30fe248a364bd` (`v0.8.8`),
  clean worktree.
- PickleScan: `bf26452ae2e3204429762c2bb1aa9eacd40436bb` (`v1.0.4`),
  clean worktree.

Rust benchmark command:

```bash
uv run --with pytest-benchmark pytest \
  tests/benchmarks/test_picklescan_benchmarks.py \
  --benchmark-json=/tmp/modelaudit-picklescan-benchmark-iteration18.json -q
```

Results: `12 passed`. In this run, `safe_large` mean was `0.002371s`,
`chunked_stream` mean was `0.002955s`, and `long_benign_string` mean was
`0.009860s`.

Synthetic third-party QA command:

```bash
PYTHONPATH=packages/modelaudit-picklescan/src \
  PROMPTFOO_DISABLE_TELEMETRY=1 NO_ANALYTICS=1 POSTHOG_DISABLED=1 \
  .venv/bin/python scripts/large_pickle_corpus_qa.py scan \
  --lock /tmp/modelaudit-large-pickle-corpus/smoke-lock.json \
  --out /tmp/modelaudit-large-pickle-corpus/runs/iteration18-synthetic-third-party-fixed \
  --ids SYNTHETIC_ONLY \
  --engines rust \
  --root-modes default,standalone-primary \
  --third-party-tools fickling,modelscan,picklescan \
  --skip-tool-pull \
  --third-party-timeout-s 120
```

Results after rebuilding the report:

- ModelAudit scan rows: `105`.
- Third-party scan rows: `45`.
- Historical parity drift count: `0`.
- Required coverage missing: none.
- Third-party failure count: `5`.
- Standalone Rust mean: `0.000264s`; historical standalone Python mean:
  `0.000445s`.
- ModelAudit flagged nested raw/base64/hex pickle payloads that Fickling,
  ModelScan, and upstream PickleScan reported as clean in this synthetic set.
  This is retained as positive differential evidence, not a ModelAudit false
  positive.

QA harness follow-up:

- Third-party tracebacks and unhandled exceptions are now normalized as
  `verdict=error` before exit-code interpretation.
- Third-party differential summaries now count `verdict=error` rows as
  failures, even when the scanner exits with code `1`.
- This corrected the synthetic Fickling `EXT` reference crash from a misleading
  malicious verdict into an explicit tool error.
- Third-party differentials now compare each third-party verdict against the
  preferred ModelAudit baseline (`modelaudit-picklescan:rust` when available)
  and classify disagreements as `modelaudit_only_positive`,
  `third_party_only_positive`, or `severity_drift`.
- Rebuilding
  `/tmp/modelaudit-large-pickle-corpus/runs/iteration18-synthetic-third-party-fixed`
  after this change produced `40` valid comparisons, `22` agreements, `18`
  disagreements, and `15` ModelAudit-only positives. The ModelAudit-only
  positives include nested raw/base64/hex pickle payload detections that
  Fickling, ModelScan, and upstream PickleScan marked clean in this synthetic
  set.

Validation:

- `ruff` check and format checks passed for `scripts/large_pickle_corpus_qa.py`
  and `tests/scripts/test_large_pickle_corpus_qa.py`.
- Harness tests reported `15 passed`.
- `MYPYPATH=. .venv/bin/mypy --explicit-package-bases
scripts/large_pickle_corpus_qa.py tests/scripts/test_large_pickle_corpus_qa.py`
  reported success.
- Rust parity tests reported `7 passed`.
- Cargo tests reported `5 passed`.

## Iteration 20 Rust Module-Structure Audit

The dangerous-global policy table and `global_severity` decision function were
moved from `rust/src/lib.rs` into `rust/src/policy.rs`. This keeps the scanner
core focused on stack/memo state and report generation while leaving policy
tables in a smaller, independently auditable module. `rust/src/lib.rs` is now
`2,387` lines, down from `2,566` before this pass.

During validation, the Python/Rust policy-table guardrail caught an omitted
`("uuid", "_ip_getnode")` entry from the manual move. That entry was restored
before completing the iteration; this is exactly the regression class the
guardrail is meant to catch.

Validation after rebuilding the release extension:

- `cargo fmt --check --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  passed.
- `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  passed.
- `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml
--all-targets -- -D warnings`: passed.
- `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml`:
  `5 passed`.
- `uv run --with maturin maturin develop --release --manifest-path
packages/modelaudit-picklescan/Cargo.toml`: passed.
- `PROMPTFOO_DISABLE_TELEMETRY=1
.venv/bin/pytest packages/modelaudit-picklescan/tests/test_rust_engine.py -q`:
  `7 passed`.
- `PROMPTFOO_DISABLE_TELEMETRY=1
.venv/bin/pytest packages/modelaudit-picklescan/tests -q`: `133 passed`.
- `PROMPTFOO_DISABLE_TELEMETRY=1
.venv/bin/pytest tests/scanners/test_pickle_scanner.py
tests/scripts/test_compare_pickle_scanners.py
tests/scanners/test_picklescan_adapter.py -q`:
  `423 passed, 14 subtests passed`.

## Iteration 21 Rust-Default Migration And Benchmark Gate

The standalone package is now Rust-only. The Python package engine and compare
mode have been removed. A subprocess guardrail verifies that a default Rust scan
does not import `modelaudit_picklescan.engine.scanner`.

Backwards-compatibility validation after flipping the default:

- Rust-only package tests: `124 passed`.
- Root pickle scanner, comparison-script, and adapter tests with no engine
  override: `421 passed, 14 subtests passed`.
- Broad non-slow, non-integration suite with no engine override:
  `3590 passed, 78 skipped, 16 warnings`.

Benchmark evidence from `pytest-benchmark` JSON outputs:

| Payload                    | Python mean |  Rust mean |  Speedup |
| -------------------------- | ----------: | ---------: | -------: |
| `safe_small`               |  `0.039 ms` | `0.019 ms` |  `2.02x` |
| `safe_large`               | `37.620 ms` | `2.643 ms` | `14.23x` |
| `long_benign_string`       | `96.604 ms` | `9.861 ms` |  `9.80x` |
| `chunked_stream`           | `40.746 ms` | `3.122 ms` | `13.05x` |
| `nested_raw`               |  `0.069 ms` | `0.021 ms` |  `3.23x` |
| `nested_base64`            |  `0.072 ms` | `0.021 ms` |  `3.48x` |
| `nested_hex`               |  `0.071 ms` | `0.022 ms` |  `3.22x` |
| `malicious_reduce`         |  `0.050 ms` | `0.029 ms` |  `1.76x` |
| `stack_global`             |  `0.031 ms` | `0.025 ms` |  `1.26x` |
| `multi_stream_padded`      |  `0.045 ms` | `0.023 ms` |  `1.94x` |
| `opcode_budget_tail`       |  `0.033 ms` | `0.022 ms` |  `1.52x` |
| `hidden_suspicious_string` |  `0.139 ms` | `0.025 ms` |  `5.47x` |

The geometric-mean speedup across the 12 benchmark cases was `3.60x`, and Rust
was faster on every measured case in this local environment.

## Final Local Validation In This Environment

```bash
.venv/bin/ruff check modelaudit/scanners/pickle_scanner.py \
  modelaudit/scanners/picklescan_adapter.py \
  packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py \
  packages/modelaudit-picklescan/tests/test_api.py \
  packages/modelaudit-picklescan/tests/test_rust_engine.py \
  scripts/large_pickle_corpus_qa.py tests/scripts/test_large_pickle_corpus_qa.py \
  tests/conftest.py
.venv/bin/ruff format --check modelaudit/scanners/pickle_scanner.py \
  modelaudit/scanners/picklescan_adapter.py \
  packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py \
  packages/modelaudit-picklescan/tests/test_api.py \
  packages/modelaudit-picklescan/tests/test_rust_engine.py \
  scripts/large_pickle_corpus_qa.py tests/scripts/test_large_pickle_corpus_qa.py \
  tests/conftest.py
.venv/bin/pytest packages/modelaudit-picklescan/tests -q
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/pytest tests/scanners/test_pickle_scanner.py \
  tests/scripts/test_compare_pickle_scanners.py -q
PROMPTFOO_DISABLE_TELEMETRY=1 \
  .venv/bin/pytest -n auto -m 'not slow and not integration' --maxfail=1
.venv/bin/mypy modelaudit/scanners/pickle_scanner.py \
  modelaudit/scanners/picklescan_adapter.py \
  packages/modelaudit-picklescan/src/modelaudit_picklescan \
  packages/modelaudit-picklescan/tests/test_api.py \
  packages/modelaudit-picklescan/tests/test_rust_engine.py \
  tests/scripts/test_large_pickle_corpus_qa.py
```

Results:

- Ruff check: passed.
- Ruff format check: passed.
- Harness tests: `12 passed`.
- Python package tests: `133 passed`.
- Rust package tests: `133 passed`.
- Compare-mode package tests: `133 passed`.
- Root pickle/comparison/picklescan-adapter tests under Rust:
  `423 passed, 14 subtests passed`.
- Standard non-slow, non-integration suite under Rust:
  `3585 passed, 78 skipped, 16 warnings`.
- Targeted mypy: success.
- Cargo format/check/test: passed after the suspicious-string matcher parity
  follow-up.
- Ad hoc generated parity probe after the protocol-0 and parse-diagnostic fixes covered 303
  Python-vs-Rust payloads across protocols 0-5, suspicious string variants,
  nested raw/base64/hex pickles, extension opcodes, multi-stream payloads, and
  opcode budgets. Stable report drift count: `0`.
- Prefix-truncation parity probe covered 459 Python-vs-Rust prefixes across
  benign, malicious, nested, GLOBAL, STACK_GLOBAL, length-prefixed, and
  FRAME-bearing streams. Stable report drift count: `0`.
- Stream chunk timing probe on an 8,388,636-byte pickle under the Rust engine:
  median scan time improved from `0.0170s` with 32-byte chunks to `0.000811s`
  with 1 MiB chunks, about `20.98x` faster for the stream-read portion of the
  path in this local environment.

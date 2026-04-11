# ModelAudit Correctness Audit Ledger

Status: active
Owner: agent-maintained
Started: 2026-04-10

This file is the running plan, evidence log, and findings ledger for a repo-wide
correctness audit. It is intentionally conservative: a finite audit cannot prove
that every future input is safe or that the code is "perfect." The practical goal
is stronger than ad hoc review: define explicit proof obligations, record which
ones have evidence, and turn every concrete gap into a small PR with regression
tests.

## Correctness Standard

A component is not considered proven until it has evidence for all relevant
obligations below.

1. Routing correctness
   - Content/structure wins over suffix-only routing where feasible.
   - Spoofed extensions and nested archive members route to the intended scanner.
   - Benign near-matches stay clean.
   - Malicious positives hit the security scanner that owns the format.

2. Parser and structure boundaries
   - Malformed input does not crash.
   - Malformed or unsupported structure is not reported as clean when coverage is
     incomplete.
   - If scanning cannot cover the intended security surface, the result is
     operationally explicit: `scan_outcome=inconclusive`, `success=False`, or an
     operational error depending on the component contract.
   - If a bounded raw fallback can safely recover security evidence, it runs
     before returning inconclusive.

3. Security precedence
   - Warning/critical security findings keep exit code 1 even when the scan is
     also inconclusive.
   - Operational or coverage failures without security findings return exit code 2.
   - INFO-only review notes do not create security failures.

4. Bounded resource use
   - Reads are size-limited for metadata, archive members, tensors, and embedded
     payloads.
   - Recursive archive scans have depth, file count, byte, and timeout budgets.
   - Temporary extraction paths are sanitized, contained, and cleaned up.

5. Cache and repeatability
   - Cached results preserve `scan_outcome`, issue severity, scanner name, and
     exit-code semantics.
   - Deterministic fixtures do not depend on host paths, global temp names, or
     installed heavyweight frameworks unless explicitly gated.

6. Optional dependency behavior
   - Missing optional dependencies fail gracefully.
   - A missing parser cannot silently turn security coverage into a clean pass.
   - Tests cover at least one missing-dependency path for dependency-sensitive
     scanners.

7. Output and integration consistency
   - CLI, JSON, SARIF, asset inventory, cache, and programmatic APIs agree on
     success, issue severity, scanner name, and exit code.
   - File metadata can round-trip through Pydantic models without dropping
     safety-relevant fields.

## Evidence Levels

- E0: Inventory only. No current audit evidence.
- E1: Existing test coverage observed, but proof obligations not fully checked.
- E2: Focused audit found no defect for the selected obligations.
- E3: Focused audit found a defect and a PR was opened with regression tests.
- E4: Full obligation suite implemented and passing for the component.

E4 is the target. Most components start below E4.

## Audit Scope Map

### Core and Cross-Cutting Layers

| Area                      | Files                                                                                                              | Initial risks                                                                                 | Evidence                         |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | -------------------------------- |
| Core orchestration        | `modelaudit/core.py`, `modelaudit/models.py`, `modelaudit/scanner_results.py`                                      | exit-code precedence, scan metadata preservation, directory dedupe, cache and stream behavior | E1                               |
| Scanner registry/routing  | `modelaudit/scanners/__init__.py`, `modelaudit/scanner_registry_metadata.py`, `modelaudit/utils/file/detection.py` | suffix routing, header aliases, optional dependency fallback, lazy loading                    | E1                               |
| CLI/output                | `modelaudit/cli.py`, output helpers, SARIF/JFrog integrations                                                      | JSON/SARIF consistency, exit codes, partial scans                                             | E0                               |
| Cache                     | `modelaudit/cache/`, `modelaudit/utils/helpers/cache_decorator.py`                                                 | stale safety metadata, inconclusive persistence, config-sensitive keys                        | E1                               |
| Archive recursion         | `zip`, `tar`, `sevenzip`, `compressed`, `oci_layer`, `torchserve_mar` scanners                                     | traversal, temp cleanup, nested routing, partial coverage                                     | E3 through recent PRs            |
| Standalone pickle package | `packages/modelaudit-picklescan/`                                                                                  | parity with adapter, opcode budgets, immutable results                                        | E3 through recent PRs            |
| Test infrastructure       | `tests/conftest.py`, CI allowlists                                                                                 | regression tests skipped in reduced Python lanes                                              | E3 for current allowlist updates |

### Scanner Inventory

| Scanner               | Primary files/formats                                      | Current evidence | Next proof target                                               |
| --------------------- | ---------------------------------------------------------- | ---------------- | --------------------------------------------------------------- |
| `pickle`              | `.pkl`, `.pickle`, `.dill`, `.bin`, `.pt`, `.pth`, `.ckpt` | E3               | post-budget and malformed opcode corpus parity                  |
| `picklescan_adapter`  | standalone picklescan bridge                               | E3               | adapter/cache equivalence for inconclusive reports              |
| `pytorch_zip`         | ZIP-backed PyTorch checkpoints                             | E3               | ZIP metadata parse boundaries and nested pickle cache semantics |
| `pytorch_binary`      | raw `.bin` PyTorch-like blobs                              | E1               | bounded binary fallback and benign weight near-matches          |
| `joblib`              | `.joblib`, compressed/raw pickle wrappers                  | E3               | codec failure semantics and cache preservation                  |
| `jax_checkpoint`      | JAX/Orbax/checkpoint pickles                               | E1               | index/metadata structure failures and nested pickle routing     |
| `flax_msgpack`        | `.msgpack`, `.flax`, `.orbax`, `.jax`                      | E1               | msgpack extension types, depth, and partial unpack coverage     |
| `numpy`               | `.npy`, `.npz`                                             | E3               | object-array pickle failures and `.npz` member routing          |
| `safetensors`         | `.safetensors`                                             | E3               | malformed header/schema and dtype consistency                   |
| `keras_h5`            | HDF5 Keras models                                          | E3, PR #917      | cache and aggregate semantics after malformed config fixes      |
| `keras_zip`           | `.keras` ZIP models                                        | E3, PR #918      | metadata/weights alias ambiguity after malformed config fixes   |
| `tf_savedmodel`       | SavedModel dirs, `.pb`                                     | E1               | protobuf parse budgets and function library edges               |
| `tf_metagraph`        | `.meta`                                                    | E1               | protobuf parse budgets and attr truncation semantics            |
| `tflite`              | `.tflite`, routed `.bin`                                   | E3, PR #916      | flatbuffer table bounds and custom-op recovery                  |
| `onnx`                | `.onnx`                                                    | E3, PR #915      | external data path policy and dtype coverage                    |
| `coreml`              | `.mlmodel`                                                 | E3               | protobuf truncation, linked model paths, custom layer strings   |
| `openvino`            | `.xml` IR                                                  | E3               | XML parse failures, entity/DOCTYPE boundaries, companion `.bin` |
| `gguf`                | `.gguf`, `.ggml`, related                                  | E3, PR #914      | metadata value type matrix and tensor offset checks             |
| `xgboost`             | `.bst`, `.model`, `.json`, `.ubj`                          | E1               | JSON/UBJSON malformed root, subprocess isolation                |
| `lightgbm`            | `.model`, `.txt`, `.lgb`, `.lightgbm`                      | E1               | text parser bounds and native-library indicators                |
| `catboost`            | `.cbm`                                                     | E3, PR #924      | binary marker bounds and metadata strings                       |
| `mxnet`               | `*-symbol.json`, `*-NNNN.params`                           | E3, PR #923      | graph reference traversal and metadata payload recovery         |
| `nemo`                | `.nemo` tar archives                                       | E3, PR #919      | multi-config precedence and malformed member combinations       |
| `jinja2_template`     | tokenizer configs, YAML, templates, GGUF metadata          | E3, PR #920      | cache preservation and GGUF metadata extraction failures        |
| `skops`               | `.skops` ZIP archives                                      | E3               | JSON schema variations and duplicate member precedence          |
| `torchserve_mar`      | `.mar` archives                                            | E3               | manifest schema roots and handler AST edge cases                |
| `oci_layer`           | OCI `.manifest`                                            | E3               | manifest schema roots, local-vs-remote layer resolution         |
| `zip`                 | generic ZIP/NPZ/MAR fallback                               | E3               | unsupported member failure semantics and cleanup                |
| `tar`                 | tar families                                               | E3               | unsupported member failure semantics and cleanup                |
| `sevenzip`            | `.7z`                                                      | E3               | nested routing parity with ZIP/TAR                              |
| `compressed`          | `.gz`, `.bz2`, `.xz`, `.lz4`, `.zlib`                      | E3               | wrapper extension inference and temporary cleanup               |
| `manifest`            | model/config manifests                                     | E3, PR #922      | JSON/YAML/TOML malformed roots and nested scanning              |
| `metadata`            | model cards/docs/text                                      | E1               | secret/security pattern false positives and truncation          |
| `text`                | general text docs                                          | E0               | duplicate responsibility with metadata/manifest                 |
| `pmml`                | `.pmml`                                                    | E3               | XML parse boundaries and extension payload recovery             |
| `paddle`              | `.pdmodel`, `.pdiparams`                                   | E3, PR #925      | protobuf/op descriptor parse failures                           |
| `cntk`                | `.dnn`, `.cmf`                                             | E3               | split reference tracking and malformed binary handling          |
| `rknn`                | `.rknn`                                                    | E1               | marker and string extraction bounds                             |
| `torch7`              | `.t7`, `.th`, `.net`                                       | E1               | legacy serialization parse failures                             |
| `r_serialized`        | `.rds`, `.rda`, `.rdata`                                   | E1               | format header variants and string extraction bounds             |
| `executorch`          | `.ptl`, `.pte`                                             | E1               | archive/table parse failures and nested payloads                |
| `tensorrt`            | `.engine`, `.plan`, `.trt`                                 | E3               | plugin marker matrix and binary truncation                      |
| `llamafile`           | `.llamafile`, `.exe`, extensionless                        | E1               | executable header routing and model payload boundaries          |
| `weight_distribution` | optional secondary analysis                                | E0               | optional dependency isolation and non-security failure behavior |

## Current Findings and PR Ledger

Recent concrete fixes from this audit stream:

| PR   | Component         | Finding                                                                                                                            | Status               |
| ---- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| #917 | Keras H5          | Malformed config/training config could be treated as clean or wrong security failure instead of inconclusive coverage              | Open, review pending |
| #918 | Keras ZIP         | Malformed `config.json` structures could scan clean or crash as the wrong failure type                                             | Open, review pending |
| #919 | NeMo              | Top-level YAML lists were not traversed for Hydra `_target_`; malformed/scalar configs looked like missing config                  | Open, review pending |
| #920 | Jinja2 template   | Malformed tokenizer/YAML configs swallowed parse failures and returned "No templates found"; raw visible SSTI payloads were missed | Open, review pending |
| #922 | Manifest          | `.config` INI manifests with section headers could skip structured parsing and lose URL/hash checks                                | Open, review pending |
| #923 | MXNet             | Malformed symbol artifacts needed routing into fail-closed scanner outcomes instead of aggregate clean/unknown results             | Open, review pending |
| #924 | CatBoost          | Corrupt declared-section scans fail closed as inconclusive instead of returning incomplete coverage as clean                       | Open, review pending |
| #925 | Paddle            | Suspicious Paddle code indicators are warnings, preserving signal without escalating review-only findings to errors                | Open, review pending |
| #926 | Native code tests | Expanded native-code detection regression coverage and benign executable-suffix near-match negatives                               | Open, review pending |

Earlier open PRs from the same boundary-hardening campaign include #901 and
#907 through #916. All open PR entries remain provisional until CI and review
complete; treat them as evidence of audited findings, not landed behavior.

## Audit Workflow

Each iteration should do the following:

1. Sync from `main` and check open PR CI/review state.
2. Pick one high-risk component from the inventory, preferring E0/E1 items and
   parser/routing boundaries that can create clean false negatives.
3. Reproduce a concrete failure before editing.
4. Patch the narrow behavior with existing architecture patterns.
5. Add typed, deterministic tests:
   - malicious positive
   - benign near-match negative
   - malformed/unsupported structure
   - aggregate exit-code semantics
   - cache semantics when safety metadata is involved
6. Run targeted tests, then the canonical validation gate from `AGENTS.md`.
7. Update this ledger with the finding, evidence level, residual risk, and PR.
8. Open or update a PR.

## High-Risk Backlog

1. `manifest_scanner`: structured config parser failures and unsupported roots.
   Check JSON/YAML/TOML/INI parse behavior, nested list roots, and whether
   malformed AIML manifests can return clean.
2. `torchserve_mar_scanner`: manifest schema roots and parse errors. Verify that
   handler AST findings and manifest failures preserve security precedence.
3. `oci_layer_scanner`: manifest schema roots and local-vs-remote layer
   resolution. Confirm remote URLs cannot be treated as local layers and local
   malformed manifests fail closed.
4. `mxnet_scanner`: symbol JSON schema and metadata payload traversal. Verify
   list/dict roots, malformed JSON, and encoded payload recovery.
5. `xgboost_scanner`: JSON/UBJSON parse failures and subprocess isolation.
   Confirm malformed model configs cannot hide suspicious attributes.
6. `tf_savedmodel` and `tf_metagraph`: protobuf parse budgets, attr truncation,
   and function references.
7. `llamafile`, `rknn`, `torch7`, `r_serialized`: binary string extraction
   bounds and malformed file semantics.
8. Cross-cutting cache tests for all inconclusive scanner families.
9. SARIF/CLI/asset output consistency for inconclusive scans with and without
   security findings.

## Notes Log

### 2026-04-10

- Established this repo-wide audit ledger and proof standard.
- Confirmed loop mode is enabled for continued audit iterations.
- Current strongest recurring defect class: structured parser failures or
  unsupported root shapes collapsing into clean scans. Fixed examples exist in
  Keras H5, Keras ZIP, NeMo, and Jinja2 template scanners.
- Next recommended target: `manifest_scanner`, because it owns many AIML config
  filenames and parses several structured formats.

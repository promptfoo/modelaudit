# PickleScan Rust Large-Corpus QA Plan

This plan defines the release-candidate QA task for the Rust-backed
`modelaudit-picklescan` engine and its integration through root ModelAudit.
The intent is to prove that the Rust engine is feature-equivalent to the
current Python implementation on real, large pickle-bearing model artifacts,
and that any eventual default switch is a security and operations improvement.

The large files in this plan must never be committed. Store them under an
external cache such as `/tmp/modelaudit-large-pickle-corpus` or a dedicated
scratch volume, and commit only manifests, scripts, and summarized QA reports.

## Executive Goal

Run a controlled, repeatable QA campaign across:

- the standalone `modelaudit-picklescan` package in `python`, `rust`, and
  `compare` engine modes;
- root ModelAudit pickle scanning in default and adapter-only migration
  modes;
- third-party scanner cross-checks with Fickling, ModelScan, and upstream
  PickleScan;
- a real 25-artifact Hugging Face corpus spanning tens of megabytes to
  multi-gigabyte pickle-backed PyTorch and checkpoint files;
- deterministic synthetic malicious variants seeded from large benign model
  files, so every existing detection class remains covered even when public
  malicious model availability changes.

Rust is now the only standalone package engine. The gates below must pass
without untriaged parity drift, false negatives, panics, unbounded resource
behavior, or documentation gaps before removing the remaining root-only
compatibility analyzer.

## Non-Negotiable Safety Rules

- Do not call `pickle.load`, `torch.load`, `joblib.load`, `dill.load`, or any
  framework loader on corpus artifacts.
- Treat every `Unsafe`, `Suspicious`, or synthetic-positive artifact as
  hostile. Scan bytes and archive members only.
- Download only explicit allowlisted files from the manifest. Do not recurse
  over arbitrary model repositories.
- Resolve and pin exact repository revisions before downloading. Do not use
  floating `main` in the lockfile.
- Hash every downloaded file before scanning and after any synthetic mutation.
- Keep third-party scanner repositories clean and fast-forwarded before each
  QA campaign. If a local clone is dirty, fail preflight rather than
  overwriting local work.
- Never commit large artifacts, extracted archive members, generated malicious
  files, raw scan outputs containing full paths, or profiler dumps with local
  usernames.
- Disable telemetry during all local and CI QA unless the task explicitly tests
  telemetry behavior.

## What "Strictly Better" Means

"Strictly better" is defined as measurable release criteria:

- **Security parity:** Rust produces no false negatives relative to the Python
  standalone baseline or the root ModelAudit baseline.
- **Security strengthening:** Rust may add findings only when they are
  validated as true positives or fail-closed coverage findings.
- **Operational parity:** statuses, verdicts, exit codes, cache semantics,
  archive routing, and scan-result adaptation remain stable.
- **Performance improvement:** release-build Rust materially improves large
  corpus throughput while staying within small-file regression limits.
- **Resource discipline:** Rust does not introduce unacceptable peak RSS,
  panics, hangs, descriptor leaks, or large-output bloat.
- **Documentation quality:** users and maintainers know exactly how to select,
  compare, benchmark, roll back, and debug engines.

No QA plan can prove every conceivable future input. This plan instead turns
that bar into exhaustive, repeatable coverage over current behavior, real
large files, known bypass classes, and deterministic seeded variants.

## Candidate Real Corpus

The corpus has 25 initial candidates: 18 benign or expected-clean stress files
and 7 expected-positive public files. Hugging Face safety labels are not used
as the final oracle. They are discovery metadata only. Ground truth for this
rewrite is the current Python standalone engine plus root ModelAudit behavior,
augmented by manual triage for any new Rust findings.

Before downloading, run a preflight that resolves each repo to a commit SHA,
confirms the file still exists, records license metadata, records remote size,
and writes a lockfile. Replace unavailable files from the replacement queue
rather than silently skipping them.

| ID  | Bucket        | Repository                                  | File                                | Initial Size | Discovery Label | QA Purpose                                                         |
| --- | ------------- | ------------------------------------------- | ----------------------------------- | -----------: | --------------- | ------------------------------------------------------------------ |
| B01 | Benign-small  | `fullstuck/transformers_resnet18_cifar100`  | `pytorch_model.bin`                 |      44.8 MB | Safe            | Lower-bound large pickle, common Torch globals.                    |
| B02 | Benign-small  | `fullstuck/transformers_resnet18_cifar100`  | `resnet18_cifar100_classifier.pth`  |      46.8 MB | Safe            | `.pth` extension routing and standalone direct scan.               |
| B03 | Benign-small  | `glazzova/body_type_resnet_v1`              | `pytorch_model.bin`                 |      94.4 MB | Pickle imports  | ResNet-style state dict.                                           |
| B04 | Benign-medium | `glazzova/body_type_resnet_v1`              | `optimizer.pt`                      |       188 MB | Safe            | Optimizer checkpoint with PyTorch storage metadata.                |
| B05 | Benign-medium | `joaogante/test_text_generation_pipeline_a` | `pytorch_model.bin`                 |       268 MB | Pickle imports  | Transformers state dict.                                           |
| B06 | Benign-medium | `dima806/closed_eyes_image_detection`       | `checkpoint-2148/pytorch_model.bin` |       343 MB | Safe            | Checkpoint subdirectory path handling.                             |
| B07 | Benign-medium | `dima806/closed_eyes_image_detection`       | `checkpoint-2148/optimizer.pt`      |       687 MB | Safe            | Large optimizer object with expected-safe imports.                 |
| B08 | Benign-medium | `intfloat/multilingual-e5-small`            | `pytorch_model.bin`                 |       471 MB | Safe            | LongStorage plus FloatStorage import references.                   |
| B09 | Benign-medium | `nealcly/detection-longformer`              | `pytorch_model.bin`                 |       595 MB | Safe            | Longformer checkpoint, medium file baseline.                       |
| B10 | Benign-large  | `nealcly/detection-longformer`              | `optimizer.pt`                      |      1.19 GB | Safe            | Large optimizer stress, root memory behavior.                      |
| B11 | Benign-medium | `sagawa/CompoundT5`                         | `pytorch_model.bin`                 |       794 MB | Pickle imports  | T5 state dict and JAX-adjacent repo mix.                           |
| B12 | Benign-large  | `csebuetnlp/mT5_multilingual_XLSum`         | `pytorch_model.bin`                 |      2.33 GB | Safe            | Multi-GB model scan throughput.                                    |
| B13 | Benign-large  | `emre/whisper-medium-turkish-2`             | `pytorch_model.bin`                 |      3.06 GB | Safe            | Whisper checkpoint, large file routing.                            |
| B14 | Benign-large  | `ash56/ssl-aasist`                          | `xlsr2_300m.pt`                     |      3.81 GB | Safe            | `.pt` file, multi-GB direct candidate.                             |
| B15 | Benign-large  | `timm/vit_large_patch14_clip_224.openai`    | `pytorch_model.bin`                 |      1.71 GB | Safe            | ViT state dict with common Torch globals.                          |
| B16 | Benign-large  | `timm/vit_large_patch14_clip_224.openai`    | `open_clip_pytorch_model.bin`       |      1.71 GB | Pickle imports  | Same model family, alternate filename.                             |
| B17 | Benign-xl     | `InternScience/ChartVLM-large`              | `base_decoder/pytorch_model.bin`    |      5.34 GB | Safe            | Very large PyTorch binary.                                         |
| B18 | Benign-xl     | `tencent/Hunyuan3D-Omni`                    | `model/pytorch_model.bin`           |      12.2 GB | Pickle imports  | Upper-bound stress file.                                           |
| P01 | Positive-real | `ykilcher/totally-harmless-model`           | `pytorch_model.bin`                 |       265 MB | Unsafe          | Known public malicious/PoC model payload.                          |
| P02 | Positive-real | `sheigel/best-llm`                          | `pytorch_model.bin`                 |       265 MB | Unsafe          | Public unsafe model with distilbert-sized payload.                 |
| P03 | Positive-real | `dbmdz/flair-historic-ner-lft`              | `pytorch_model.bin`                 |       444 MB | Unsafe          | Large unsafe file with `builtins.getattr` and ML imports.          |
| P04 | Positive-real | `dbmdz/flair-historic-ner-onb`              | `pytorch_model.bin`                 |       444 MB | Unsafe          | Independent Flair unsafe model, same size class.                   |
| P05 | Positive-real | `ecmwf/aifs-single-1.0`                     | `aifs-single-mse-1.0.ckpt`          |       994 MB | Unsafe          | Near-1GB checkpoint unsafe by public scanner metadata.             |
| P06 | Positive-real | `alphacep/vosk-tts-ru-stabletts`            | `vosk_tts_ru_0.10.ckpt`             |       561 MB | Unsafe          | TTS checkpoint unsafe by public scanner metadata.                  |
| P07 | Positive-real | `projecte-aina/matxa-tts-cat-multispeaker`  | `checkpoint_epoch=2399.ckpt`        |       251 MB | Unsafe          | Checkpoint with `functools.partial`, OmegaConf, optimizer globals. |

Approximate initial download size is 38 to 40 GB before extracted members,
synthetic variants, profiles, and reports. Require at least 120 GB free scratch
space for the full release-candidate run.

### Replacement Queue

Use these if a primary candidate disappears, becomes gated, changes format, or
fails preflight:

- `InternScience/ChartVLM-large`, `base_decoder/state_dict.pth`, 10.7 GB.
- `tencent/Hunyuan3D-Omni`, `model/pytorch_model_ema.bin`, 12.2 GB.
- `emre/whisper-medium-turkish-2`, `optimizer.pt`, 6.11 GB.
- `projecte-aina/matxa-tts-cat-multiaccent`,
  `checkpoint_epoch=2399.ckpt`, 251 MB.
- `dbmdz/flair-historic-ner-onb`, `pytorch_model.bin`, 444 MB.

## Corpus Lockfile

Create `large-corpus.lock.json` outside the repo by default, and optionally
copy a redacted version into `docs/maintainers/reports/` after QA.

Each entry must include:

```json
{
  "id": "B01",
  "repo_id": "fullstuck/transformers_resnet18_cifar100",
  "revision": "resolved_commit_sha",
  "path": "pytorch_model.bin",
  "expected_bucket": "benign-small",
  "discovery_label": "safe",
  "remote_size_bytes": 44800000,
  "sha256": "downloaded_file_sha256",
  "etag": "remote_etag_if_available",
  "license": "apache-2.0",
  "source_url": "https://huggingface.co/fullstuck/transformers_resnet18_cifar100/tree/main",
  "downloaded_at": "2026-04-11T00:00:00Z",
  "local_path": "/tmp/modelaudit-large-pickle-corpus/raw/B01/pytorch_model.bin"
}
```

The lockfile is the source of truth for scan runs. Scanners must read the
lockfile rather than reconstructing URLs from repo names.

## Required Harness Work

Implement or extend a QA harness before running the full campaign. Suggested
entrypoint:

```bash
uv run python scripts/large_pickle_corpus_qa.py sync-tools --tools-root ~/code
uv run python scripts/large_pickle_corpus_qa.py preflight --tier full --include-replacements --out /tmp/modelaudit-large-pickle-corpus/large-corpus.preflight.json
uv run python scripts/large_pickle_corpus_qa.py finalize-lock --lock /tmp/modelaudit-large-pickle-corpus/large-corpus.preflight.json --out /tmp/modelaudit-large-pickle-corpus/large-corpus.lock.json --target-count 25
uv run python scripts/large_pickle_corpus_qa.py download --lock /tmp/modelaudit-large-pickle-corpus/large-corpus.lock.json --budget-gb 70 --etag-timeout-s 60
uv run python scripts/large_pickle_corpus_qa.py classify --lock /tmp/modelaudit-large-pickle-corpus/large-corpus.lock.json
uv run python scripts/large_pickle_corpus_qa.py scan --lock /tmp/modelaudit-large-pickle-corpus/large-corpus.lock.json --out /tmp/modelaudit-large-pickle-corpus/runs/rc1
uv run python scripts/large_pickle_corpus_qa.py report --run /tmp/modelaudit-large-pickle-corpus/runs/rc1
```

The harness should support:

- `--tier smoke|medium|full`.
- `--ids B01,P01,...`.
- `--engines rust`.
- `--root-modes default,adapter-only`.
- `--third-party-tools fickling,modelscan,picklescan`.
- `--tools-root ~/code`.
- `--include-replacements` on preflight.
- `finalize-lock` for selecting preflight-ok primaries plus replacement queue
  entries.
- `--budget-gb`.
- `--etag-timeout-s` and `--direct-only` for constrained proxy or metadata
  timeout environments.
- `--offline` to reuse a populated cache.
- `--fail-on-drift`.
- JSONL, CSV, JSON, and Markdown report output.
- `--no-synthetic` for corpus-only timing runs.

Do not add new runtime dependencies to the package for this harness without
approval. If `huggingface_hub` is not already available in the dev
environment, use a one-off tool dependency or a documented manual download
step, not a package dependency change.

## Third-Party Scanner Baselines

Use Fickling, ModelScan, and upstream PickleScan as external differential
oracles. They are not the source of truth for ModelAudit behavior, but they are
valuable for finding blind spots, explaining disagreement, and proving that the
Rust rewrite is not only equivalent to our Python baseline but competitive with
the surrounding ecosystem.

Default local clone locations:

| Tool       | Repository                                     | Default Path        | Current Local Preflight                                            |
| ---------- | ---------------------------------------------- | ------------------- | ------------------------------------------------------------------ |
| Fickling   | `https://github.com/trailofbits/fickling.git`  | `~/code/fickling`   | `ee2a6e3465913e5f8771ba9173e472bd502d78fd` (`v0.1.10-13-gee2a6e3`) |
| ModelScan  | `https://github.com/protectai/modelscan.git`   | `~/code/modelscan`  | `61fcec9c2a37c24c1fb12d84ede30fe248a364bd` (`v0.8.8`)              |
| PickleScan | `https://github.com/mmaitre314/picklescan.git` | `~/code/picklescan` | `bf26452ae2e3204429762c2bb1aa9eacd40436bb` (`v1.0.4`)              |

The current preflight above was recorded on 2026-04-11 after checking that all
three clones existed under `~/code`, fast-forwarding Fickling, and confirming
ModelScan and PickleScan were already up to date. Future QA runs must repeat
the update step and write fresh SHAs into the run's `environment.json`.

### Tool Sync Requirements

The `sync-tools` command must:

- create `~/code` if needed;
- clone missing repositories into the default paths above;
- verify each existing path is a Git repository with the expected remote URL;
- reject dirty worktrees unless the caller passes an explicit read-only mode;
- fetch tags and remotes;
- switch to the upstream default branch if the clone is on an old local branch
  and has no local modifications;
- run `git pull --ff-only` to select the most recent version;
- record branch, commit SHA, `git describe --tags --always --dirty`, remote
  URL, and dirty status in `environment.json`;
- never use third-party tools from PyPI when a local clone was requested,
  because the QA goal is to compare against the latest upstream source.

Suggested manual sync commands:

```bash
git -C ~/code/fickling status --short
git -C ~/code/fickling pull --ff-only
git -C ~/code/modelscan status --short
git -C ~/code/modelscan pull --ff-only
git -C ~/code/picklescan status --short
git -C ~/code/picklescan pull --ff-only
```

If a repository is missing:

```bash
git clone https://github.com/trailofbits/fickling.git ~/code/fickling
git clone https://github.com/protectai/modelscan.git ~/code/modelscan
git clone https://github.com/mmaitre314/picklescan.git ~/code/picklescan
```

### Tool Invocation Matrix

Run third-party tools in isolated subprocesses with telemetry/network disabled
where supported, a per-file timeout, captured stdout/stderr, and peak RSS
measurement. Do not let third-party failures stop ModelAudit scans from
running; record failures as cross-tool observations unless the failure blocks
the QA harness itself.

Suggested local-source invocations:

| Tool       | Local Invocation                                                              | Primary Output To Normalize                                                  |
| ---------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Fickling   | `uv run --project ~/code/fickling fickling --check-safety -p <path>`          | exit code, unsafe/safe decision, analyzer names, details JSON when available |
| ModelScan  | `uv run --project ~/code/modelscan modelscan -p <path> -r json -o <out.json>` | exit code, issue category, operator/module, severity/status                  |
| PickleScan | `uv run --project ~/code/picklescan picklescan --path <path>`                 | exit code, globals, infected files, scanner errors                           |

If a tool cannot be run from source with `uv run --project`, the harness may
create a temporary virtual environment under the corpus cache and install the
local checkout in editable mode. That environment must be outside this repo and
recorded in `environment.json`.

### Cross-Tool Comparison Rules

Normalize third-party output into a common shape:

```json
{
  "tool": "fickling",
  "tool_commit": "ee2a6e3465913e5f8771ba9173e472bd502d78fd",
  "artifact_id": "P01",
  "status": "complete",
  "verdict": "malicious",
  "exit_code": 1,
  "signals": [
    {
      "kind": "dangerous_import",
      "module": "builtins",
      "name": "eval",
      "raw_rule": "OvertlyBadEval"
    }
  ],
  "stderr_tail": "",
  "duration_s": 0.0,
  "peak_rss_bytes": 0
}
```

Cross-tool findings are advisory, not direct release blockers. Escalate them
as blockers only when they demonstrate a likely ModelAudit false negative or a
false positive in ModelAudit's intended behavior.

Required cross-tool gates:

- Every real expected-positive artifact and synthetic positive must be flagged
  by ModelAudit even if third-party tools disagree.
- If Fickling, ModelScan, or upstream PickleScan flags a positive that
  ModelAudit marks clean, triage the artifact manually and either add a
  ModelAudit regression test or document why the third-party signal is not
  applicable.
- If ModelAudit flags a benign corpus file that all three third-party tools
  treat as safe, triage for false-positive risk before default enablement.
- If a third-party scanner crashes or times out on large files, record the
  failure as ecosystem context, but do not relax ModelAudit's pass criteria.
- Compare runtime and peak RSS across tools, but do not require ModelAudit to
  be the fastest on every file. Require ModelAudit Rust to be materially better
  than ModelAudit Python on large-file scenarios before default enablement.
- Record whether each tool supports the artifact type directly, skips it, or
  only scans extracted pickle members.

The QA report must include a dedicated "Third-Party Differential" section with:

- tool versions, SHAs, and dirty status;
- per-artifact verdict table;
- disagreements grouped by likely false negative, likely false positive,
  unsupported format, crash/timeout, and expected policy difference;
- any new ModelAudit tests or detections added because of the comparison;
- a conclusion on whether Rust ModelAudit is at least as protective as the
  external scanner set for the tested corpus.

## Scan Modes

Run each corpus artifact through all applicable modes.

### Standalone Package

For raw pickle-like files or extracted pickle members, run the standalone
`modelaudit-picklescan` package in its Rust-only default mode.

Normalize reports by removing `duration_s`, sorting findings/notices/errors by
stable semantic keys, normalizing absolute paths to corpus IDs, and preserving
all status, verdict, coverage, metadata, locations, messages, details, and rule
codes.

Any Rust engine import/build failure is a release-candidate failure.

### Root ModelAudit

For the full artifact path:

- default root scan with the Rust standalone package;
- adapter-only mode with the Rust standalone package.

For root comparison, normalize:

- `ScanResult.success`;
- scanner name and routed scanner;
- issue name, status, severity, rule code, message, location, and details;
- check list and issue list;
- `metadata.scan_outcome`, `metadata.pickle_primary_engine`,
  `metadata.first_pickle_end_pos`, `metadata.import_references`,
  `metadata.operational_error`, and cache-relevant fields;
- CLI exit code when scanning through the CLI.

Ignore only timing fields, local absolute path prefixes, ordering differences
that are semantically sorted by the harness, and intentionally documented
engine-selection metadata.

### Archive and Container Members

For `.pt`, `.pth`, `.ckpt`, and `.bin` files that are ZIP-backed PyTorch
containers:

- run root ModelAudit on the whole file;
- classify archive members without extracting arbitrary paths into the repo;
- scan pickle-bearing members such as `data.pkl` directly with the standalone
  package;
- preserve member path context in report locations;
- verify that unsafe ZIP entries are surfaced at root with member names.

For files that are direct pickle streams or concatenated pickle streams:

- scan full file with standalone package;
- scan full file with root ModelAudit;
- verify follow-on streams after `STOP` are considered.

## Synthetic Seeded-Large Variants

Real public malicious GB-scale files are rare and unstable because platforms
remove or relabel them. To prove detection completeness, generate deterministic
malicious variants from large benign seed files. These variants must never be
loaded or executed.

Generate at least these variants from a representative subset of B01, B05,
B08, B10, B12, B14, B17, and B18:

| Variant | Construction                                                                                                                                                              | Required Existing Signal                            |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| V01     | Append a second pickle stream containing `os.system` via `REDUCE` after a benign first stream.                                                                            | Follow-on stream detection and `DANGEROUS_CALL`.    |
| V02     | Insert protocol-4 `STACK_GLOBAL` for `builtins.eval` followed by `REDUCE`.                                                                                                | `STACK_GLOBAL` attribution and dangerous call.      |
| V03     | Use memoized module/name operands before `STACK_GLOBAL`.                                                                                                                  | Memo resolution parity.                             |
| V04     | Use malformed `STACK_GLOBAL` integer operands.                                                                                                                            | `MALFORMED_STACK_GLOBAL` or root `S205` equivalent. |
| V05     | Use `EXT1`, `EXT2`, and `EXT4` extension opcodes with `REDUCE`.                                                                                                           | Opaque extension warning/critical behavior.         |
| V06     | Embed a raw nested pickle literal containing `os.system`.                                                                                                                 | `S213` and surfaced nested inner finding.           |
| V07     | Embed base64-encoded nested pickle.                                                                                                                                       | `S601`, bounded decode, nested finding.             |
| V08     | Embed hex and escaped-hex nested pickle.                                                                                                                                  | `S602`, bounded decode, nested finding.             |
| V09     | Place suspicious strings beyond the bounded literal window.                                                                                                               | Fail-closed inconclusive or coverage notice.        |
| V10     | Put dangerous globals just after opcode-budget boundary.                                                                                                                  | Post-budget tail scan finding.                      |
| V11     | Create a large benign decoy blob with pickle-like prefix fragments.                                                                                                       | No false-positive nested detection.                 |
| V12     | Build ZIP-backed `.pt` with malicious `data.pkl`.                                                                                                                         | Root PyTorch ZIP routing and member scan.           |
| V13     | Build malformed ZIP or 7z-like PyTorch evasion fixture with malicious prefix pickle.                                                                                      | Fail-closed and no missed prefix payload.           |
| V14     | Include `pip.main`, `torch.load`, `numpy.load`, `joblib.load`, `dill.loads`, `tarfile.open`, `zipfile.ZipFile`, `logging.config.dictConfig`, and `uuid._popen` callables. | Dangerous global policy parity.                     |
| V15     | Include benign stdlib and Torch state-dict globals only.                                                                                                                  | No new false positives on safe globals.             |

Each generated variant must have a manifest record with:

- seed artifact ID and seed SHA256;
- mutation type and deterministic seed;
- resulting SHA256;
- expected package rule codes;
- expected root issue names or rule codes;
- expected status, verdict, and exit code.

## Existing Detection Coverage Matrix

The QA report must prove that every current detection family is exercised by at
least one committed fixture, one synthetic large variant, or one real corpus
artifact.

Required standalone/package coverage:

- `DANGEROUS_GLOBAL`.
- `DANGEROUS_CALL`.
- `MALFORMED_STACK_GLOBAL`.
- `OPAQUE_EXTENSION` or equivalent `EXT1`/`EXT2`/`EXT4` finding.
- `SUSPICIOUS_STRING`.
- `S213` raw nested pickle.
- `S601` base64 nested pickle.
- `S602` hex and escaped-hex nested pickle.
- `POST_BUDGET_GLOBAL`.
- `opcode_budget` notice.
- `timeout` notice.
- `parse_incomplete` notice.
- `empty_input`, `parse_error`, `short_read`, and `io_error`.
- Multiple pickle streams.
- String literal truncation and fail-closed unknown behavior.
- Nested payload truncation.
- Encoded nested payload truncation.
- Deadline reuse for nested scans.
- Deduplication of repeated findings.
- Import-reference metadata for benign Torch globals.

Required root ModelAudit coverage:

- `GLOBAL` module reference checks.
- `STACK_GLOBAL` module and context checks.
- `REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `OBJ`, `INST`, and `BUILD` call checks.
- Mixed-case and implausible module handling.
- Memoized `STACK_GLOBAL` helper references.
- Malformed `STACK_GLOBAL` severity and bounded detail payloads.
- Opcode-budget and post-budget behavior.
- Raw, base64, hex, and offset nested pickle detection.
- PyTorch ZIP routing.
- ZIP entry pickle detection.
- Direct `.pkl`, `.pickle`, `.dill`, `.joblib`, `.pt`, `.pth`, `.ckpt`, and
  `.bin` routing.
- Legitimate large PyTorch memory-limit handling.
- Operational issue classification versus security finding classification.
- Cache semantics for clean, malicious, inconclusive, and error scans.
- CLI exit code `0` for clean, `1` for security findings, and `2` for scan
  errors.

## Parity Gates

### Gate 1: Standalone Package Parity

For every real artifact member and synthetic variant:

- Python and Rust statuses match.
- Python and Rust verdicts match, unless Rust is stricter and the finding is
  manually triaged as a true positive.
- Rust never has fewer warning or critical security findings than Python.
- Rust finding severities are never lower than Python for matching rule codes.
- Rust rule-code set is a superset of Python for expected-positive inputs.
- Clean corpus files remain clean when Python baseline is clean.
- Coverage bytes and scan-complete flags match, or Rust is more complete
  without reducing security findings.
- Errors and notices match for malformed, short-read, and budgeted inputs.
- No native panics, Python exceptions from the wrapper, or fallback notices.

### Gate 2: Root ModelAudit Parity

For every whole artifact and applicable archive member:

- Default root scan and adapter-only scan match on success,
  issue severity floor, rule codes, scan outcome, and exit code unless the
  difference is explicitly triaged.
- Root scan never downgrades a historical baseline security issue under the
  Rust-only standalone package.
- Archive/member locations remain intelligible and stable.
- Cache hits do not mask engine drift. Run once with a cold cache and once with
  a warm cache, then verify the cached result key includes any config needed to
  avoid cross-engine contamination.

### Gate 3: Positive Coverage

For P01 through P07 and every synthetic positive:

- At least one security finding is produced by standalone or root as expected
  from baseline.
- Known dangerous callables are attributed to the correct import reference
  where the current Python implementation does so.
- Any inconclusive result without a security finding is a failure unless the
  Python baseline is also inconclusive and a maintainer approves the behavior.

### Gate 4: Negative Coverage

For B01 through B18 and benign synthetic variants:

- No new warning or critical security findings are allowed unless manually
  triaged and documented as true positives.
- Benign Torch storage, `collections.OrderedDict`, and safe optimizer metadata
  must remain non-failing.
- Large benign blobs and encoded decoys must not trigger nested-pickle false
  positives.

### Gate 5: Performance and Resource Behavior

Measure release builds, not debug builds.

Required performance gates:

- Small payload median runtime no more than 10 percent slower than Python.
- Large payload median runtime materially faster than Python on at least the
  medium and large tiers.
- Full-corpus wall time improves or is neutral after root wrapper overhead is
  included.
- Peak RSS does not regress for root scans in a way that would make Rust unsafe
  as a default.
- No individual scan exceeds the configured timeout without an explicit
  inconclusive status and coverage notice.

Important current-risk gate:

- The Rust `scan_stream` integration currently reads the stream into memory
  before calling the native scanner, so the full-corpus QA must measure peak RSS
  on B10, B12, B14, B17, and B18. If peak RSS materially regresses large root
  scans, native streaming becomes a release blocker.

### Gate 6: Documentation and Packaging

- `docs/maintainers/picklescan-rust-rewrite-plan.md` reflects the actual QA
  status and rollout state.
- Standalone README documents that the package runtime is Rust-only.
- Root README remains user-facing and does not expose implementation internals
  unless a supported user feature requires it.
- Changelog has one `[Unreleased]` entry for user-visible behavior.
- Wheel smoke tests cover the native Rust wheel and clear missing-extension
  error behavior.
- CI has a lane that exercises the Rust package and root adapter behavior.

## Profiling Protocol

Run profiles in isolated subprocesses so peak RSS is meaningful and failures do
not poison the whole run.

Capture for each scan:

- artifact ID and SHA256;
- engine;
- root mode;
- wall-clock seconds;
- CPU seconds;
- peak RSS;
- bytes per second;
- opcode count;
- finding count;
- status and verdict;
- timeout or budget notices;
- exception or panic details.

Use platform-native RSS measurement:

- macOS: `/usr/bin/time -l`.
- Linux: `/usr/bin/time -v`.
- Portable helper: `resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss`.

Optional deeper profiles:

- Python bridge CPU profile with `cProfile` for the Rust-backed package API on
  B01, B08, P01, V06, and V10.
- Rust symbol profile with platform profiler on release wheel scans.
- Heap sampling on B17 and B18 if peak RSS is unexpectedly high.

Profile these scenarios:

- standalone package direct scan on extracted `data.pkl` or direct pickle;
- root scan of whole artifact;
- synthetic nested payload variants;
- post-budget tail variants;
- malformed archive or malformed stream variants.

## QA Report Format

Write one run directory per campaign:

```text
/tmp/modelaudit-large-pickle-corpus/runs/2026-04-11-rc1/
|-- environment.json
|-- large-corpus.lock.json
|-- scan-results.jsonl
|-- third-party-results.jsonl
|-- third-party-differential.json
|-- parity-drift.json
|-- benchmark-results.json
|-- benchmark-summary.csv
|-- coverage-matrix.json
|-- qa-report.md
`-- profiles/
```

`environment.json` must include:

- git commit;
- branch;
- dirty-worktree status;
- OS, CPU, memory, and disk;
- Python version;
- Rust compiler version;
- package versions;
- wheel filename and hash if testing a wheel;
- selected engine environment variables;
- ModelAudit config used for root scans.
- Fickling, ModelScan, and upstream PickleScan local paths, remotes, branches,
  SHAs, `git describe` values, and dirty statuses.

`qa-report.md` must include:

- executive pass/fail summary;
- corpus table with resolved revisions and SHA256 values;
- skipped or replaced artifacts with reasons;
- standalone parity summary;
- root parity summary;
- third-party differential summary for Fickling, ModelScan, and upstream
  PickleScan;
- performance summary;
- peak RSS summary;
- coverage matrix;
- all drifts grouped by severity;
- manual triage decisions;
- documentation and packaging checklist;
- final recommendation: keep the root compatibility analyzer, remove it, or
  block release.

## CI and Scheduling Strategy

Large corpus QA should not run on every PR.

Recommended lanes:

- **PR lane:** committed fixture parity, synthetic small variants, Rust unit
  tests, no network, no large downloads.
- **Manual medium lane:** all real artifacts under 1 GB plus synthetic seeded
  variants, run on demand before risky changes.
- **Nightly large lane:** rotating subset of large files, using cache and
  revision pins.
- **Release-candidate full lane:** all 25 real artifacts plus synthetic
  variants, full profiling, full QA report.

All networked lanes must use explicit allowlists and fail loudly if an artifact
cannot be downloaded or hash-verified.

## Documentation QA Checklist

Before declaring the Rust rewrite ready:

- Maintainer docs explain Rust-only package behavior, root compatibility
  analysis, and known limitations.
- User-facing docs mention Rust as the package runtime where relevant.
- README examples remain accurate for the Rust-only package behavior.
- Troubleshooting covers missing native extension errors.
- Release notes include upgrade impact and rollback instructions.
- Security notes state that scanners never deserialize model files.
- Performance claims are backed by the full-corpus QA report, not only
  microbenchmarks.
- QA report paths and corpus lockfiles are discoverable by future maintainers.

## Failure Triage Rules

Treat failures as follows:

- **P0:** Rust misses a Python/root critical finding, panics, hangs without
  timeout, executes a payload, corrupts cache semantics, or causes unbounded
  memory on large files.
- **P1:** Rust downgrades severity, loses locations/details needed for
  triage, changes root exit codes, or introduces false positives on clean
  large public models. Also P1: a third-party scanner flags a likely real
  issue that ModelAudit misses after manual triage.
- **P2:** Report metadata drift, wording drift, benchmark noise above target,
  or documentation mismatch.
- **P3:** Harness ergonomics, formatting, or non-blocking profile gaps.

P0 and P1 issues block default enablement. P2 issues require owner signoff and
tracking before beta. P3 issues can be follow-ups if the report records them.

## Agent Task Prompt

Use this prompt for the coding agent that implements and runs the QA campaign:

```text
You are working in ModelAudit on the Rust-backed modelaudit-picklescan rewrite.
Implement the large-corpus QA harness and execute the archived QA plan in
docs/maintainers/archive/picklescan-rust-large-corpus-qa-plan.md.

Hard requirements:
- Do not deserialize or execute pickle/model files.
- Use only allowlisted corpus entries and resolved revision pins.
- Store downloaded artifacts and generated variants outside the repo.
- Run standalone PickleScan in Rust-only mode.
- Run root ModelAudit in default and adapter-only modes.
- Sync and run Fickling, ModelScan, and upstream PickleScan from local clones
  under ~/code, using the most recent fast-forwarded revisions.
- Generate deterministic synthetic large malicious variants from benign seeds.
- Compare normalized reports and fail on false negatives, status/verdict drift,
  severity downgrades, unexpected false positives, panics, fallback notices, or
  root exit-code drift.
- Normalize third-party scanner results and triage every disagreement where
  Fickling, ModelScan, or upstream PickleScan finds a signal ModelAudit misses.
- Measure wall time, CPU time, peak RSS, bytes/sec, status, verdict, and rule
  coverage for every scan.
- Produce environment.json, scan-results.jsonl, third-party-results.jsonl,
  third-party-differential.json, parity-drift.json, benchmark-results.json,
  coverage-matrix.json, and qa-report.md.
- Update maintainer docs and changelog only for user-visible or rollout
  changes.

Validation before handoff:
- cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml
- Rust-only package tests
- root pickle scanner tests relevant to ModelAudit integration
- tool sync verification for ~/code/fickling, ~/code/modelscan, and
  ~/code/picklescan
- full non-slow, non-integration pytest if time and dependencies allow
- medium or full large-corpus QA run, depending on available disk and time

Final handoff must include:
- exact commands run;
- pass/fail table for every gate;
- unresolved drifts with severity and owner recommendation;
- third-party scanner SHAs and disagreement triage;
- performance and RSS summary;
- recommendation on whether the remaining root compatibility analyzer can be
  removed.
```

## Release Recommendation Rule

Do not make Rust the default unless:

- all P0/P1 items are closed;
- full 25-artifact corpus run passes;
- synthetic coverage matrix is complete;
- root memory behavior is acceptable or native streaming is implemented;
- release wheels pass on all supported platforms;
- maintainers approve the QA report.

Until then, keep the root compatibility analyzer in place and continue treating
any Rust/root drift as a release blocker.

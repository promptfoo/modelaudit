# Plan: CoreML `.mlmodel` Support

## Goal

Add secure static scanning support for Apple CoreML model files (`.mlmodel`) with parser-safe protobuf inspection and risk checks for custom layers and external references.

## Why This Gap Matters

CoreML models are common for edge/mobile deployment. Treating them as unknown removes visibility into metadata abuse, custom operation loading, and suspicious embedded content.

## Scope

In scope:

- `.mlmodel` scanner with strict format checks
- Protobuf/structured metadata parsing with bounded reads
- Detection of suspicious references and custom layer constructs

Out of scope:

- Executing CoreML runtime
- Full inference graph simulation

## Deliverables

- `modelaudit/scanners/coreml_scanner.py`
- Scanner registry and extension map updates
- Tests in `tests/scanners/test_coreml_scanner.py`
- `tests/conftest.py` allowlist update
- README/docs/changelog updates

## Detailed Engineering Tasks

1. Format research and fixture generation

- Collect benign `.mlmodel` examples from different model families.
- Capture minimal binary/protobuf signatures used for strict identification.
- Build malicious fixtures with suspicious string payloads in metadata and custom layer blocks.

1. Scanner implementation

- Implement `CoreMLScanner(BaseScanner)` with `supported_extensions = [".mlmodel"]`.
- Implement `can_handle()` with signature and structural sanity checks.
- Enforce `_check_path()` and `_check_size_limit()` before parsing.

1. Parsing and validation strategy

- Parse only required model description fields and metadata sections.
- Set maximum message size and field count thresholds.
- Handle parse errors deterministically with explicit checks.

1. Security checks

- Detect custom layer/class fields that can load untrusted code paths.
- Detect suspicious network and command strings in metadata.
- Detect encoded payload indicators in user-defined metadata.
- Detect unsafe file path references for external resources.

1. Routing and registration

- Add scanner entry and class mapping.
- Add `.mlmodel` mapping to extension detection.
- Ensure scanner priority is above generic manifest/text handling.

1. Optional deep-validation path

- If optional `coremltools` integration is introduced, make it optional and failure-safe.
- Keep baseline static checks dependency-light.

## False-Positive Reduction Strategy

- Restrict `CRITICAL` alerts to structurally meaningful fields (custom layer definitions, executable-like metadata), not arbitrary strings.
- Use allowlist of common CoreML metadata keys and known-safe value patterns.
- Treat ambiguous encoded blobs as `WARNING` unless combined with additional signals.
- Validate path risk findings only after canonicalization.

## Test Plan

1. Unit tests (`tests/scanners/test_coreml_scanner.py`)

- Benign `.mlmodel` with standard layers.
- Malicious fixture with suspicious custom layer metadata.
- Malicious fixture with command/network patterns in metadata.
- Corrupt protobuf fixture handling.
- Non-CoreML file renamed `.mlmodel` should fail strict detection.

1. False-positive tests

- Benign metadata containing words like `exec` in non-executable context should not be `CRITICAL`.
- Standard model cards or labels inside metadata should not trigger high severity.

1. Regression tests

- `.mlmodel` no longer returns `unknown`.
- Findings include precise field path context in `details`.

## QA Steps

1. Focused tests:

```bash
uv run pytest tests/scanners/test_coreml_scanner.py -q
```

1. CLI smoke checks:

```bash
uv run python -m modelaudit.cli tests/fixtures/coreml/safe.mlmodel --format text
uv run python -m modelaudit.cli tests/fixtures/coreml/malicious.mlmodel --format json
```

1. Full gate:

```bash
uv run ruff format modelaudit/ tests/
uv run ruff check --fix modelaudit/ tests/
uv run mypy modelaudit/
uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## Documentation Tasks

- Add CoreML to supported formats in `README.md`.
- Extend compatibility matrix with dependency guidance.
- Add scanner notes in user docs.
- Add `[Unreleased]` changelog entry.

## Definition of Done

- `.mlmodel` files are format-routed and scanned.
- Custom-layer and metadata abuse patterns are covered with bounded false positives.
- CI gates pass.

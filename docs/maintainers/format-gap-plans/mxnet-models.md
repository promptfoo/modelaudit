# Plan: MXNet Model Format Support

## Goal

Add dedicated static scanning support for MXNet model artifacts (symbol/params and relevant packaged variants) with secure parsing and risk-focused checks.

## Why This Gap Matters

MXNet persists in legacy and embedded deployments. Artifact-level scanning is required to identify suspicious metadata, unsafe custom-op references, and payload-bearing wrappers.

## Scope

In scope:

- Support for primary MXNet artifact set (for example symbol JSON + params pairing)
- Optional support for packaged variants after discovery
- Security checks on graph metadata and external references

Out of scope:

- Executing MXNet runtime
- Dynamic operator loading tests at runtime

## Deliverables

- `modelaudit/scanners/mxnet_scanner.py`
- Registry and extension/detection updates
- Tests in `tests/scanners/test_mxnet_scanner.py`
- Fixture allowlist update
- Docs/changelog updates

## Detailed Engineering Tasks

1. Discovery and format contract

- Define exact v1 scope for MXNet formats:
  - symbol graph files
  - params files
  - packaged archives if common
- Document required file relationships for multi-file models.

2. Scanner implementation

- Implement strict `can_handle()` with extension and structural checks.
- For paired artifacts, support directory-aware scanning and correlation checks.
- Enforce path and size validation via base scanner helpers.

3. Security checks

- Detect suspicious custom operator/library references.
- Detect unsafe filesystem/network references in graph attributes.
- Detect suspicious encoded payload strings in metadata sections.
- Detect archive traversal risks if packaged variant is supported.

4. Routing and integration

- Register scanner with proper priority relative to manifest/text scanners.
- Add extension mapping entries for selected MXNet artifacts.
- Ensure lazy loader class mapping is added.

5. Robustness

- Handle missing companion files with explicit informational checks.
- Keep bounded reads for params blobs and graph files.
- Prevent recursion/memory issues on malformed inputs.

## False-Positive Reduction Strategy

- Only escalate when risky references are in executable or load-affecting graph fields.
- Treat generic framework identifiers as benign unless paired with dangerous context.
- Add allowlist for known-safe built-in MXNet operators.
- Gate network/path findings through canonicalized parse and context checks.

## Test Plan

1. Unit tests (`tests/scanners/test_mxnet_scanner.py`)

- Benign symbol+params pair.
- Missing companion file scenarios.
- Malicious graph attribute with suspicious external reference.
- Corrupt params file handling.
- Non-MXNet files renamed to MXNet-like names.

2. False-positive tests

- Common operator names and graph metadata should not trigger high severity.
- Numeric-heavy params blobs should not trigger encoded-payload false alarms.

3. Regression tests

- Directory scan correctly identifies MXNet model pairs.
- Issues include file-specific location context.

## QA Steps

1. Focused tests:

```bash
uv run pytest tests/scanners/test_mxnet_scanner.py -q
```

2. Directory-level CLI smoke:

```bash
uv run python -m modelaudit.cli tests/fixtures/mxnet/ --format json
```

3. Full validation gate.

## Documentation Tasks

- Add MXNet entries to README and compatibility matrix.
- Document multi-file scan behavior and expected layout.
- Add changelog entry.

## Definition of Done

- Primary MXNet artifacts are scanable and no longer unknown.
- Detection quality validated on benign and malicious fixtures.
- False-positive guardrails and full CI checks pass.

# Plan: TensorFlow MetaGraph (`.meta`) Support

## Goal

Add static scanner support for TensorFlow 1.x MetaGraph checkpoint files (`.meta`) with protobuf-level checks for unsafe operation patterns.

## Why This Gap Matters

Legacy TensorFlow deployments still use checkpoint bundles that include `.meta` files. Unknown handling misses graph-level indicators of dangerous operations.

## Scope

In scope:

- `.meta` detection and parsing as MetaGraph protobuf
- Graph/function-level security checks
- Integration with existing TensorFlow scanner logic where possible

Out of scope:

- Graph execution
- Full TensorFlow runtime compatibility in scanning path

## Deliverables

- `modelaudit/scanners/tf_metagraph_scanner.py` or extension of existing TF scanner
- Detection/routing updates for `.meta`
- Tests in `tests/scanners/test_tf_metagraph_scanner.py`
- Docs/changelog updates

## Detailed Engineering Tasks

1. Discovery and parser strategy

- Confirm protobuf message types for supported `.meta` variants.
- Reuse vendored TensorFlow protobuf stubs where possible.
- Define bounded parse limits for message size and node counts.

1. Scanner implementation

- Implement strict `can_handle()` for `.meta` with protobuf parse sanity check.
- Enforce path/size validation pre-parse.
- Extract graph ops, function defs, and collection metadata.

1. Security checks

- Flag unsafe ops and constructs (`PyFunc`, dynamic library loading patterns, external path references).
- Flag suspicious command/network strings in node attributes where relevant.
- Flag graph anomalies indicating payload stuffing.

1. Integration

- Add scanner registration and extension map entry for `.meta`.
- Ensure coexistence with current SavedModel `.pb` handling.
- Reuse shared TensorFlow explanation mappings where appropriate.

1. Robustness

- Gracefully handle partial/corrupt protobuf data.
- Keep deterministic output across Python versions.

## False-Positive Reduction Strategy

- Require op-level context for high severity findings; do not alert on token-only matches in non-executable metadata.
- Maintain allowlist for common benign TensorFlow ops.
- Downgrade ambiguous signals unless corroborated by multiple risk indicators.

## Test Plan

1. Unit tests (`tests/scanners/test_tf_metagraph_scanner.py`)

- Benign `.meta` graph fixture.
- Malicious fixture including unsafe op patterns.
- Corrupt protobuf fixture.
- Non-meta file renamed `.meta`.

1. False-positive tests

- Benign graphs with ops whose names contain risky substrings should not escalate incorrectly.

1. Regression tests

- Existing TensorFlow SavedModel scanner tests remain green.
- `.meta` no longer routes to unknown.

## QA Steps

1. Focused tests:

```bash
uv run pytest tests/scanners/test_tf_metagraph_scanner.py -q
```

1. TensorFlow scanner regression subset.
1. Full validation gate.

## Documentation Tasks

- Update README TensorFlow row to include `.meta` support.
- Update compatibility matrix and user docs scanner details.
- Add changelog entry.

## Definition of Done

- `.meta` artifacts are recognized and scanned with protobuf-aware checks.
- Unsafe graph patterns are detected with low false positives.
- CI quality gates pass.

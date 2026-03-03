# Offline and Air-Gapped Usage Guide

This guide covers running ModelAudit in environments with no outbound internet access.

## Goals for air-gapped operation

- Keep all scanning local to your controlled environment
- Avoid remote model downloads at runtime
- Disable telemetry explicitly
- Keep cache and temporary artifacts under your control

## 1. Install dependencies from an internal wheelhouse

On a connected machine (one-time prep):

```bash
mkdir -p wheelhouse
pip download "modelaudit[all]" -d wheelhouse
```

Transfer `wheelhouse/` to the air-gapped environment, then install:

```bash
pip install --no-index --find-links wheelhouse "modelaudit[all]"
```

If you only need specific scanners, replace `[all]` with targeted extras.

## 2. Disable telemetry

Set either variable (both is fine):

```bash
export PROMPTFOO_DISABLE_TELEMETRY=1
export NO_ANALYTICS=1
```

## 3. Scan only local paths

Use local files/directories, not remote URIs:

- Do use: `modelaudit scan ./models/`
- Do not use: `hf://...`, `models:/...`, `s3://...`, `gs://...`, or hosted HTTP model URLs

## 4. Control caching and artifacts

For fully ephemeral scans:

```bash
modelaudit scan ./models --no-cache --format json --output results.json
```

If cache is enabled, inspect and clear it as needed:

```bash
modelaudit cache stats
modelaudit cache clear
```

## 5. Recommended CI flags for restricted environments

```bash
modelaudit scan ./models \
  --strict \
  --format json \
  --output modelaudit-report.json
```

Optional controls:

- `--max-size` to enforce artifact size boundaries
- `--timeout` for deterministic runtime limits
- `--stream` when scanning very large local directories with constrained disk

## 6. Operational checklist

1. Install from internal artifacts only.
2. Set telemetry-off environment variables.
3. Restrict inputs to local paths.
4. Export JSON/SARIF output for audit retention.
5. Review non-zero exit codes (`1` findings, `2` errors) in CI policy.

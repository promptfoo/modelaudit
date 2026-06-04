# Metadata Extraction Guide

Use `modelaudit metadata` to inspect model metadata without running a full security scan.

## Safe defaults

By default, metadata extraction does **not** deserialize model objects.
This is safer for untrusted artifacts and should be your default workflow.

```bash
modelaudit metadata model.safetensors
```

## Common usage

```bash
# Directory summary + per-file metadata (table output)
modelaudit metadata ./models

# JSON output for automation
modelaudit metadata ./models --format json --output metadata.json

# YAML output
modelaudit metadata model.onnx --format yaml

# Security-focused metadata fields only
modelaudit metadata model.onnx --security-only
```

## Directory limits

Directory metadata extraction stops after 10,000 file entries, 20,000 total filesystem entries,
1 GiB of aggregate file size, or 64 directory levels. When a limit is reached, table output shows
an incomplete-extraction warning. JSON and YAML output include `analysis_incomplete: true`,
`scan_outcome: inconclusive`, and a `budget_events` list describing the exceeded limit.

Special filesystem entries such as named pipes and sockets are reported as errors and are not
opened or sent to scanners. Regular files and in-directory symlinks to regular files remain
eligible for metadata extraction.

## Trusting loaders (advanced)

`--trust-loaders` allows scanner metadata loaders that may deserialize model content.
Only use this for trusted artifacts, and only in isolated environments.

```bash
modelaudit metadata model.pkl --trust-loaders
```

## Notes

- `modelaudit metadata` supports both files and directories.
- Unknown or unsupported files are reported with `format: unknown`.
- For full detection coverage (CVE checks, suspicious patterns, and policy outcomes), use `modelaudit scan`.

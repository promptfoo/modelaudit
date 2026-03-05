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

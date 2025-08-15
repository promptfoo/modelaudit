# Large Model Support Documentation

## Overview

ModelAudit now includes enhanced support for scanning large ML models (up to 8GB+) with optimized strategies based on file size.

## Default Configuration Changes

### Timeout Settings

- **Previous**: 300 seconds (5 minutes)
- **New**: 1800 seconds (30 minutes)
- **Rationale**: Large models (1-8GB) require more time for thorough scanning

### File Size Limits

- **Previous**: Various limits based on scanner
- **New**: Unlimited (0) by default
- **Rationale**: Support scanning of production models without artificial restrictions
- **Override**: Use `--max-file-size` to set limits if needed

## Scanning Strategies

ModelAudit automatically selects the appropriate scanning strategy based on file size:

### 1. Normal Scanning (<10MB)

- Full file loaded into memory
- Complete analysis of all content
- Fastest performance for small files

### 2. Chunked Scanning (10MB - 100MB)

- File read in 10MB chunks
- Progress reporting for each chunk
- Memory-efficient processing
- Complete coverage of file content

### 3. Streaming Scanning (100MB - 1GB)

- Analyzes file header (first 10MB)
- Samples middle and end sections
- Reports partial scan completion
- Suitable for most large models

### 4. Optimized Scanning (>1GB)

- Quick header analysis only
- Heuristic-based detection
- Minimal memory usage
- Recommended to split very large models

## CLI Usage

### Basic Large Model Scan

```bash
modelaudit scan large_model.bin
```

### With Progress Reporting

```bash
modelaudit scan large_model.bin --verbose
```

### Disable Large Model Support

```bash
modelaudit scan model.bin --no-large-model-support
```

### Custom Timeout for Very Large Models

```bash
modelaudit scan huge_model.bin --timeout 3600  # 1 hour
```

## Production Recommendations

### 1. For CI/CD Pipelines

```bash
# Use JSON output for parsing
modelaudit scan model.bin --format json --output results.json

# Set appropriate timeout for your models
modelaudit scan model.bin --timeout 1800
```

### 2. For Batch Processing

```python
import subprocess
import json

models = ["model1.bin", "model2.pt", "model3.safetensors"]

for model in models:
    result = subprocess.run(
        ["modelaudit", "scan", model, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=1800
    )

    if result.returncode == 0:
        print(f"✅ {model}: No issues")
    elif result.returncode == 1:
        data = json.loads(result.stdout)
        issues = len(data.get("issues", []))
        print(f"⚠️ {model}: {issues} issues found")
    else:
        print(f"❌ {model}: Scan error")
```

### 3. For HuggingFace Models

```bash
# Pre-download for better performance
modelaudit scan hf://bert-large-uncased --cache

# Or scan directly with appropriate timeout
modelaudit scan hf://bert-large-uncased --timeout 1800
```

## Performance Considerations

### Memory Usage

- Small files (<10MB): ~2x file size
- Medium files (10-100MB): ~50MB constant
- Large files (>100MB): ~20MB constant
- Very large files (>1GB): ~10MB constant

### Scan Times

- Small files: 1-5 seconds
- Medium files: 5-30 seconds
- Large files: 30-120 seconds
- Very large files: 60-300 seconds

### Network Considerations

When scanning remote models:

- Pre-download large models if scanning multiple times
- Use `--cache` flag to keep downloaded files
- Consider `--max-download-size` to limit downloads

## Limitations

### Partial Scanning

For files over 100MB, ModelAudit uses sampling strategies that may not detect:

- Issues in unsampled sections
- Patterns distributed throughout the file
- Small malicious payloads in large models

### Recommendations for Very Large Models

1. **Use SafeTensors format** when possible - more secure and efficient
2. **Split models** into smaller components if feasible
3. **Run periodic full scans** with extended timeouts for critical models
4. **Monitor scan logs** for timeout and partial scan warnings

## Configuration File

Create `.modelaudit.yml` for persistent settings:

```yaml
# Large model support configuration
scan:
  timeout: 1800 # 30 minutes
  max_file_size: 0 # Unlimited
  large_model_support: true
  chunk_size: 10485760 # 10MB chunks

# Progress reporting
output:
  verbose: true
  progress: true

# Performance tuning
performance:
  max_memory: 2048 # MB
  parallel_scans: 4
```

## Troubleshooting

### Timeout Issues

```bash
# Increase timeout for very large models
modelaudit scan model.bin --timeout 3600

# Or disable timeout (not recommended)
modelaudit scan model.bin --timeout 0
```

### Memory Issues

```bash
# Limit file size to prevent OOM
modelaudit scan model.bin --max-file-size 1073741824  # 1GB

# Use streaming for all files >10MB
modelaudit scan model.bin --stream
```

### Slow Performance

```bash
# Pre-download HuggingFace models
modelaudit scan hf://model --cache --cache-dir ./model_cache

# Then scan from cache
modelaudit scan ./model_cache/models--*/snapshots/*/
```

## Best Practices

1. **Test timeout settings** with your typical model sizes
2. **Monitor scan performance** in production
3. **Use appropriate strategies** for different model types
4. **Keep ModelAudit updated** for latest optimizations
5. **Report issues** with large models to help improve support

## Future Improvements

Planned enhancements for large model support:

- Distributed scanning for model shards
- GPU-accelerated pattern matching
- Incremental scanning for model updates
- Cloud-native scanning without downloads
- Real-time progress visualization

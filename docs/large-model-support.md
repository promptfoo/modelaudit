# Large Model Support Documentation

## Overview

ModelAudit includes enhanced support for scanning large ML models (up to 1 TB+) with optimized strategies based on file size. This includes advanced support for scanning extremely large AI models (400B+ parameters) that can exceed 1TB in size.

## Scanning Strategies by File Size

ModelAudit automatically detects file sizes and chooses the optimal scanning strategy:

### 1. Normal Scanning (<100 GB)

- **Small files (<10MB)**: Normal in-memory scanning
- **Medium files (10MB-100MB)**: Chunked reading
- **Large files (100MB-1GB)**: Streaming analysis
- **Performance**: Full file loaded into memory, complete analysis of all content, fastest performance for smaller models

### 2. Chunked Scanning (100 GB - 1 TB)

- **Very large files (1GB-50GB)**: Optimized scanning with the large file handler
- **Process**: File read in 50 GB chunks with progress reporting for each chunk
- **Benefits**: Memory-efficient processing, complete coverage of file content

### 3. Streaming Scanning (1 TB - 5 TB)

- **Extreme files (50GB-200GB)**: Memory-mapped I/O scanning
- **Process**: Analyzes file header (first 100 GB), samples middle and end sections
- **Features**: Reports partial scan completion, suitable for very large models
- **Memory Usage**: Efficient access without loading entire file into memory

### 4. Advanced Distributed Scanning (>5 TB)

- **Massive files (>200GB)**: Distributed/signature-based scanning
- **Process**: Enhanced header analysis (first 100 GB), heuristic-based detection with large sampling
- **Benefits**: Minimal memory usage with advanced techniques, supports extremely large models up to 10 TB+

## Sharded Model Support

Many large models are distributed across multiple files (shards). ModelAudit automatically detects and scans sharded models from:

- **HuggingFace**: `pytorch_model-00001-of-00005.bin`
- **SafeTensors**: `model-00001-of-00003.safetensors`
- **TensorFlow**: `model.ckpt-1.data-00000-of-00001`
- **Keras**: `model_weights_1.h5`

### Sharded Model Processing

When a sharded model is detected:

1. **Automatic Detection**: All shards are identified automatically
2. **Parallel Processing**: Shards are scanned in parallel (up to 4 workers)
3. **Result Combination**: Results are combined into a single report
4. **Configuration Analysis**: Configuration files are analyzed for metadata

## Memory-Mapped I/O

For files between 50GB-200GB, ModelAudit uses memory-mapped I/O:

- **Efficient Access**: Efficient access without loading entire file into memory
- **Sliding Windows**: Scans data in sliding windows (up to 500MB)
- **Complete Coverage**: Overlapping windows ensure no patterns are missed
- **Memory Footprint**: Minimal memory footprint even for huge files

## Progressive Timeout Scaling

Timeouts automatically scale with file size:

- **Standard files**: 30 minutes (increased from previous 5 minutes)
- **Extreme files (>50GB)**: 60 minutes
- **Massive files (>200GB)**: 2 hours
- **Per-shard timeout**: 10 minutes

### Previous vs Current Timeout Settings

- **Previous**: 300 seconds (5 minutes)
- **Current**: 1800 seconds (30 minutes)
- **Rationale**: Large models (1-8 GB) require more time for thorough scanning

## File Size Limits

- **Previous**: Various limits based on scanner
- **Current**: Unlimited (0) by default
- **Rationale**: Support scanning of production models without artificial restrictions
- **Override**: Use `--max-file-size` to set limits if needed

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

### Scanning Sharded Models

```bash
# Automatically detects all shards
modelaudit llama-405b/pytorch_model-00001-of-00100.bin

# Output:
# Scanning sharded model with 100 parts
# Total size: 810GB
# Using parallel shard scanning...
# Scanned shard 1/100...
# Scanned shard 2/100...
```

### Scanning Massive Single Files

```bash
# Scans a 400GB model file
modelaudit massive_model.bin

# Output:
# Using extreme large file handler for massive_model.bin
# File size: 400GB - using memory-mapped I/O
# Memory-mapped scan: 10GB/400GB (2.5%)...
```

### Force Large File Handling

```bash
# Use --large-models flag to optimize for large files
modelaudit --large-models model.bin
```

## Performance Considerations

### Memory Usage

ModelAudit automatically optimizes memory usage based on file size:

- **Small files (<10 MB)**: typically ~2x file size
- **Medium files (10-100 MB)**: typically ~50 MB constant
- **Large files (>100 MB)**: typically ~20 MB constant
- **Very large files (>1 GB)**: typically ~10 MB constant
- **Memory-mapped I/O**: keeps memory usage under 1GB even for TB-sized files
- **Chunked reading**: uses configurable buffer sizes (default 10MB)
- **Parallel shard scanning**: uses ~500MB per worker

### Scan Times

Expected scanning times vary by model size:

- **Small files**: 1-5 seconds
- **Medium files**: 5-30 seconds
- **Large files**: 30-120 seconds
- **Very large files**: 60-300 seconds

### Network Considerations

When scanning remote models:

- Pre-download large models if scanning multiple times
- Use `--cache` flag to keep downloaded files
- Consider `--max-download-size` to limit downloads

### Scan Coverage

For extremely large files, ModelAudit maintains COMPLETE security coverage:

- **Full validation**: Every security check is performed, no shortcuts
- **Memory-efficient reading**: Data is read in chunks/windows to manage memory
- **Complete pattern matching**: All dangerous patterns are checked throughout the file
- **No sampling shortcuts**: Unlike other tools, we don't skip checks based on size
- **Time vs Security**: Scans may take longer, but security is never compromised

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

## Configuration

### Environment Variables

```bash
# Increase timeout for massive models
export MODELAUDIT_TIMEOUT=7200  # 2 hours

# Configure parallel workers
export MODELAUDIT_MAX_WORKERS=8  # For machines with many cores

# Set memory mapping window size
export MODELAUDIT_MMAP_WINDOW=1073741824  # 1GB windows
```

### Configuration File

Create `.modelaudit.yml` for persistent settings:

```yaml
# Large model support configuration
scan:
  timeout: 1800 # 30 minutes
  max_file_size: 0 # Unlimited
  large_model_support: true
  chunk_size: 53687091200 # bytes (50 GB chunks)

# Progress reporting
output:
  verbose: true
  progress: true

# Performance tuning
performance:
  max_memory: 2048 # MB
  parallel_scans: 4
```

### Python API

```python
from modelaudit import scan_model_directory_or_file

# Scan with custom timeout for extreme model
results = scan_model_directory_or_file(
    "llama-405b/",
    timeout=7200,  # 2 hours
    max_file_size=0,  # No size limit
)
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
modelaudit scan model.bin --max-file-size 1073741824  # 1 GB

# Use streaming for all files > 10 MB
modelaudit scan model.bin --stream
```

### Slow Performance

```bash
# Pre-download HuggingFace models
modelaudit scan hf://model --cache --cache-dir ./model_cache

# Then scan from cache
modelaudit scan ./model_cache/models--*/snapshots/*/
```

## Limitations

### Partial Scanning

For files over certain thresholds, ModelAudit uses sampling strategies that may not detect:

- **Files over 100 MB**: Some sampling strategies applied
- **Issues in unsampled sections**: Patterns distributed throughout the file may be missed
- **Small malicious payloads**: Small payloads in very large models might be missed

### Other Limitations

1. **Network models**: Remote model scanning limited to streaming analysis
2. **Encrypted models**: Cannot scan encrypted model files
3. **Compression**: Heavily compressed models need extraction first

## Recommendations

### For Very Large Models

1. **Use SafeTensors format** when possible - more secure and efficient
2. **Split models** into smaller components if feasible
3. **Run periodic full scans** with extended timeouts for critical models
4. **Monitor scan logs** for timeout and partial scan warnings
5. **Enable sharding** for models over 50GB
6. **Run scans on machines with SSDs** for better I/O performance
7. **Consider distributed scanning** for models over 1TB

## Best Practices

1. **Test timeout settings** with your typical model sizes
2. **Monitor scan performance** in production
3. **Use appropriate strategies** for different model types
4. **Keep ModelAudit updated** for latest optimizations
5. **Report issues** with large models to help improve support

## Future Enhancements

Planned enhancements for large model support:

- **Distributed scanning** across multiple machines
- **GPU-accelerated pattern matching**
- **Incremental scanning** for model updates
- **Cloud-native scanning** without downloads
- **Real-time progress visualization**
- **Caching of scan results** for repeated scans

---

**IMPORTANT: ALL security checks are performed regardless of file size.** ModelAudit never compromises on security - it runs the complete set of validations on every file, including:

- Pickle deserialization exploits in headers
- Malicious code patterns in any scanned section
- Suspicious model configurations
- Embedded executables in archives
- Known malicious model signatures

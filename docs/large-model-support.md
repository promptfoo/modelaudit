# Large Model Support Documentation

## Overview

ModelAudit includes enhanced support for scanning large ML models (up to 1 TB+) with optimized strategies based on file size. This includes advanced support for scanning extremely large AI models (400B+ parameters) that can exceed 1TB in size.

## Scanning Strategies by File Size

ModelAudit automatically detects file sizes and chooses the optimal scanning strategy:

### 1. Normal Scanning (≤10 GB)

- **Small to medium files**: Standard in-memory or chunked scanning
- **Performance**: Complete analysis of all content, fastest performance
- **Memory Usage**: Optimized for available system memory

### 2. Chunked Scanning (10 GB - 500 GB)

- **Large files**: File read in configurable chunks (default 10GB) with progress reporting
- **Process**: Sequential chunk processing with memory-efficient handling
- **Benefits**: Complete coverage while managing memory usage
- **Special Support**: Enhanced pickle file scanning with chunk-aware analysis

### 3. Large File Optimization (500 GB - 1 TB)

- **Very large files**: Automatic fallback to complete scanning with optimized I/O
- **Process**: Full file analysis with enhanced progress reporting and timeout scaling
- **Memory Management**: Efficient buffer usage to prevent memory exhaustion

### 4. Extreme File Handling (>1 TB)

- **Massive files**: Complete security scanning with extended timeouts
- **Process**: Full file analysis ensuring no security shortcuts are taken
- **Benefits**: Maintains complete security coverage regardless of file size

**Note**: All scanning strategies perform complete security analysis - no sampling or partial scanning is used that could miss security issues.

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

## Memory Management

ModelAudit uses efficient memory management strategies for large files:

- **Chunked Reading**: Files are processed in manageable chunks to control memory usage
- **Buffer Management**: Configurable buffer sizes optimize I/O performance
- **Progress Tracking**: Real-time progress reporting for long-running scans
- **Memory Footprint**: Minimal memory footprint through streaming and chunked processing

## Progressive Timeout Scaling

Timeouts automatically scale with file size:

- **Standard files**: 60 minutes (increased from previous 5 minutes)
- **Extreme files (>50GB)**: 120 minutes
- **Massive files (>200GB)**: 2 hours
- **Per-shard timeout**: 10 minutes

### Previous vs Current Timeout Settings

- **Previous**: 300 seconds (5 minutes)
- **Current**: 3600 seconds (60 minutes)
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
# Using large file handler for massive_model.bin
# File size: 400GB - using chunked processing
# Processing: 10GB/400GB (2.5%)...
```

### Control Large File Handling

```bash
# Large file support is enabled by default, disable if needed
modelaudit scan model.bin --no-large-model-support

# Or explicitly enable (default behavior)
modelaudit scan model.bin --large-model-support
```

## Performance Considerations

### Memory Usage

ModelAudit optimizes memory usage based on file size and scanning strategy:

- **Chunked reading**: Uses configurable buffer sizes (default 10GB for large files)
- **Streaming analysis**: Minimal memory footprint for cloud storage scanning
- **Parallel shard scanning**: Memory usage scales with number of workers
- **Buffer management**: Automatically adjusts based on available system memory

_Note: Specific memory usage patterns depend on file format, content complexity, and system configuration._

### Scan Times

Expected scanning times are approximate and vary based on file format, content, and system performance:

- **Small files**: Usually under 30 seconds
- **Large files**: Several minutes depending on size and complexity
- **Very large files**: May take 30+ minutes with extended timeouts

_Note: Scanning times depend heavily on storage speed, CPU performance, file format complexity, and security content found._

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

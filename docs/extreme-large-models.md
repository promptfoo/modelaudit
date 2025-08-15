# Extreme Large Model Support

ModelAudit now includes advanced support for scanning extremely large AI models (400B+ parameters) that can exceed 1TB in size. This documentation covers the specialized features designed for these massive models.

## Features

### 1. Automatic Detection and Strategy Selection

ModelAudit automatically detects file sizes and chooses the optimal scanning strategy:

- **Small files (<10MB)**: Normal in-memory scanning
- **Medium files (10MB-100MB)**: Chunked reading
- **Large files (100MB-1GB)**: Streaming analysis
- **Very large files (1GB-50GB)**: Optimized scanning with the large file handler
- **Extreme files (50GB-200GB)**: Memory-mapped I/O scanning
- **Massive files (>200GB)**: Distributed/signature-based scanning

### 2. Sharded Model Support

Many large models are distributed across multiple files (shards). ModelAudit automatically detects and scans sharded models from:

- **HuggingFace**: `pytorch_model-00001-of-00005.bin`
- **SafeTensors**: `model-00001-of-00003.safetensors`
- **TensorFlow**: `model.ckpt-1.data-00000-of-00001`
- **Keras**: `model_weights_1.h5`

When a sharded model is detected:

1. All shards are identified automatically
2. Shards are scanned in parallel (up to 4 workers)
3. Results are combined into a single report
4. Configuration files are analyzed for metadata

### 3. Memory-Mapped I/O

For files between 50GB-200GB, ModelAudit uses memory-mapped I/O:

- Efficient access without loading entire file into memory
- Scans data in sliding windows (up to 500MB)
- Overlapping windows ensure no patterns are missed
- Minimal memory footprint even for huge files

### 4. Parallel Processing

Sharded models benefit from parallel processing:

- Up to 4 shards scanned simultaneously
- Independent timeout per shard (10 minutes default)
- Graceful handling of individual shard failures
- Combined results with detailed per-shard information

### 5. Progressive Timeout Scaling

Timeouts automatically scale with file size:

- Standard files: 30 minutes
- Extreme files (>50GB): 60 minutes
- Massive files (>200GB): 2 hours
- Per-shard timeout: 10 minutes

## Usage Examples

### Scanning a Sharded Llama Model

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

### Scanning a Massive Single File

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

- Memory-mapped I/O keeps memory usage under 1GB even for TB-sized files
- Chunked reading uses configurable buffer sizes (default 10MB)
- Parallel shard scanning uses ~500MB per worker

### Scan Coverage

For extremely large files, ModelAudit maintains COMPLETE security coverage:

- **Full validation**: Every security check is performed, no shortcuts
- **Memory-efficient reading**: Data is read in chunks/windows to manage memory
- **Complete pattern matching**: All dangerous patterns are checked throughout the file
- **No sampling shortcuts**: Unlike other tools, we don't skip checks based on size
- **Time vs Security**: Scans may take longer, but security is never compromised

### Recommendations

1. **Use SafeTensors format** when possible - more secure and efficient
2. **Enable sharding** for models over 50GB
3. **Run scans on machines with SSDs** for better I/O performance
4. **Consider distributed scanning** for models over 1TB

## Security Considerations

**IMPORTANT: ALL security checks are performed regardless of file size.** ModelAudit never compromises on security - it runs the complete set of validations on every file, including:

- Pickle deserialization exploits in headers
- Malicious code patterns in any scanned section
- Suspicious model configurations
- Embedded executables in archives
- Known malicious model signatures

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

## Limitations

1. **Partial scanning**: Files over 200GB are only partially scanned
2. **Network models**: Remote model scanning limited to streaming analysis
3. **Encrypted models**: Cannot scan encrypted model files
4. **Compression**: Heavily compressed models need extraction first

## Future Enhancements

- Distributed scanning across multiple machines
- GPU-accelerated pattern matching
- Cloud-native scanning for S3/GCS stored models
- Incremental scanning for model updates
- Caching of scan results for repeated scans

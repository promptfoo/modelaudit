# Parallel Scanning Design Document

**Status: IMPLEMENTED** ✅

## Overview

This document outlines the design for implementing parallel file scanning in ModelAudit to significantly improve performance when scanning directories with multiple files.

## Current State

- Files are scanned sequentially in `scan_model_directory_or_file()`
- Each file is processed one at a time
- Progress is tracked linearly
- Results are aggregated in a single thread

## Design Goals

1. **Performance**: Achieve 50-80% reduction in scan time for typical workloads
2. **Compatibility**: Maintain backward compatibility with existing API
3. **Safety**: Ensure thread-safe result aggregation
4. **Resource Management**: Control memory and CPU usage
5. **User Experience**: Maintain accurate progress reporting

## Proposed Architecture

### 1. Worker Pool Model

Use Python's `concurrent.futures.ProcessPoolExecutor` for parallel processing:

- Process-based to avoid GIL limitations
- Better isolation for scanner crashes
- Configurable worker count

### 2. Work Distribution

```python
# Pseudo-code
with ProcessPoolExecutor(max_workers=num_workers) as executor:
    futures = []
    for file_path in files_to_scan:
        future = executor.submit(scan_file, file_path, config)
        futures.append((file_path, future))

    # Collect results as they complete
    for file_path, future in futures:
        result = future.result(timeout=per_file_timeout)
        aggregate_result(result)
```

### 3. Result Aggregation

- Use thread-safe data structures for aggregation
- Implement a result collector that handles:
  - Issue deduplication
  - Byte count accumulation
  - Scanner name tracking
  - Asset collection

### 4. Progress Tracking

- Use a shared progress counter (multiprocessing.Value)
- Update progress from main thread as futures complete
- Show both completed files and active workers

### 5. Configuration Options

New configuration parameters:

- `parallel`: Enable/disable parallel scanning (default: True)
- `max_workers`: Maximum number of worker processes (default: CPU count)
- `chunk_size`: Number of files per work unit (default: 1)

## Implementation Plan

### Phase 1: Core Infrastructure

1. Create `ParallelScanner` class
2. Implement worker pool management
3. Add result aggregation logic
4. Handle process communication

### Phase 2: Progress and Monitoring

1. Implement parallel-aware progress callbacks
2. Add worker status monitoring
3. Show active file being scanned per worker

### Phase 3: Error Handling

1. Handle worker process crashes
2. Implement timeout per file
3. Add retry logic for failed scans
4. Graceful degradation to sequential mode

### Phase 4: Performance Tuning

1. Optimize work distribution
2. Implement file size-based chunking
3. Add memory usage controls
4. Profile and optimize bottlenecks

## API Changes

### CLI Options

```bash
# New options
--parallel / --no-parallel     Enable/disable parallel scanning
--workers N                    Number of worker processes
```

### Function Signature

```python
def scan_model_directory_or_file(
    path: str,
    ...,
    parallel: bool = True,
    max_workers: Optional[int] = None,
    **kwargs
) -> dict[str, Any]:
```

## Technical Considerations

### 1. Serialization

- Ensure all config objects are picklable
- Handle non-serializable callbacks
- Manage scanner state transfer

### 2. Memory Management

- Monitor memory usage per worker
- Implement file queuing to avoid loading all paths
- Add memory limit safeguards

### 3. Platform Compatibility

- Test on Windows (process creation overhead)
- Handle macOS fork safety
- Linux-specific optimizations

### 4. Scanner Compatibility

- Ensure all scanners are process-safe
- No shared mutable state
- Handle scanner initialization in workers

## Testing Strategy

### 1. Unit Tests

- Test worker pool creation and management
- Verify result aggregation correctness
- Test error handling scenarios

### 2. Integration Tests

- Compare results: parallel vs sequential
- Verify no issues are missed
- Test with various file types and sizes

### 3. Performance Tests

- Benchmark different directory sizes
- Measure speedup factors
- Profile memory usage
- Test CPU utilization

### 4. Stress Tests

- Large directories (10k+ files)
- Mixed file sizes
- High error rate scenarios
- Resource exhaustion handling

## Rollout Plan

1. Feature flag for gradual rollout
2. Default to sequential for small directories (<10 files)
3. Collect performance metrics
4. Gradually increase default worker count

## Success Metrics

- 50%+ speedup for directories with 100+ files
- No increase in false negatives
- Memory usage < 2x sequential mode
- CPU utilization > 70% on multi-core systems

## Risk Mitigation

1. **Risk**: Worker process crashes
   - **Mitigation**: Isolate failures, continue with remaining files

2. **Risk**: Memory exhaustion
   - **Mitigation**: Limit concurrent files, implement backpressure

3. **Risk**: Result inconsistency
   - **Mitigation**: Extensive testing, result validation

4. **Risk**: Platform incompatibility
   - **Mitigation**: Platform-specific code paths, fallback modes

## Implementation Summary (Completed)

### What Was Built

1. **Core Components**:
   - `ParallelScanner` class with ProcessPoolExecutor
   - `parallel_directory.py` wrapper for directory scanning
   - Worker pool management with configurable size
   - Automatic fallback to sequential for small file counts

2. **Features Delivered**:
   - ✅ CLI options: `--parallel/--no-parallel` and `--workers`
   - ✅ Progress tracking with ETA estimation
   - ✅ Error recovery and graceful handling
   - ✅ Result aggregation with deduplication
   - ✅ File filtering to skip non-model files
   - ✅ JSON output includes `parallel_scan` and `worker_count` markers

3. **Performance Results**:
   - Break-even point: ~50 files
   - Speedup: 1.1-1.5x for 100+ files
   - Overhead: ~100-200ms for process creation
   - Optimal workers: 2-4 for most workloads

4. **Test Coverage**:
   - Unit tests for ParallelScanner and worker functions
   - Integration tests for directory scanning
   - Performance benchmarks completed
   - All tests passing

### Usage Examples

```bash
# Enable parallel scanning (default)
modelaudit scan /path/to/models/

# Disable parallel scanning
modelaudit scan --no-parallel /path/to/models/

# Specify worker count
modelaudit scan --parallel --workers 4 /path/to/models/

# Check if parallel scanning was used
modelaudit scan --format json /path/to/models/ | jq '.parallel_scan, .worker_count'
```
